//! Bounded Claude/OpenAI managed-agent session discovery and prompting.
//!
//! Public CLI commands call this module through [`crate::ai_cli`]. Credentials
//! are environment-only and are never accepted on argv. HTTPS requests use the
//! repository's existing bounded `curl` subprocess boundary; the complete curl
//! configuration, including authorization headers and request bodies, is sent
//! over stdin so credentials and prompts are not exposed in process argv.

use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use tokio::process::Command;
use tokio::task::JoinSet;

use crate::error::RuntimeError;
use crate::model::{CommandReport, Finding};
use crate::process::{CaptureLimits, run_bounded_with_input};

const OPENAI_ORIGIN: &str = "https://api.openai.com";
const ANTHROPIC_ORIGIN: &str = "https://api.anthropic.com";
const OPENAI_BASE_ENV: &str = "ORES_CLI_OPENAI_BASE_URL";
const ANTHROPIC_BASE_ENV: &str = "ORES_CLI_ANTHROPIC_BASE_URL";
const OPENAI_KEY_ENV: &str = "OPENAI_API_KEY";
const ANTHROPIC_KEY_ENV: &str = "ANTHROPIC_API_KEY";
const ANTHROPIC_BETA: &str = "managed-agents-2026-04-01";
const OPENAI_BETA: &str = "agents=v1";
const PAGE_SIZE: usize = 50;
const MAX_SCAN_PAGES: usize = 200;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const CURL_DEADLINE: Duration = Duration::from_secs(30);
const SECONDS_PER_DAY: u64 = 86_400;
const MAX_BROADCAST_THREADS: usize = 20;
const MAX_PROMPT_BYTES: usize = 16 * 1024;

/// Provider backing one normalized ORES AI thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AiProvider {
    /// Anthropic Managed Agents sessions.
    Claude,
    /// OpenAI Managed Agents sessions, exposed to users as the Codex lane.
    Codex,
}

impl AiProvider {
    /// Stable CLI/provider label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }
}

/// Provider selection accepted by the AI command subtree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiProviderSelection {
    /// Query only Anthropic Managed Agents sessions.
    Claude,
    /// Query only OpenAI Managed Agents sessions.
    Codex,
    /// Query both providers and normalize the results before selection.
    All,
}

impl AiProviderSelection {
    /// Parse a public provider selector.
    pub fn parse(value: &str) -> Result<Self, RuntimeError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "claude" | "anthropic" => Ok(Self::Claude),
            "codex" | "openai" => Ok(Self::Codex),
            "all" | "both" => Ok(Self::All),
            _ => Err(RuntimeError::Usage(
                "--provider must be claude, codex, or all".to_owned(),
            )),
        }
    }

    fn providers(self) -> Vec<AiProvider> {
        match self {
            Self::Claude => vec![AiProvider::Claude],
            Self::Codex => vec![AiProvider::Codex],
            Self::All => vec![AiProvider::Claude, AiProvider::Codex],
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::All => "all",
        }
    }
}

/// Stale-thread selection criteria.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadQueryOptions {
    /// Provider(s) to search.
    pub provider: AiProviderSelection,
    /// Require creation strictly more than this many days ago.
    pub older_than_days: u64,
    /// Require last activity strictly more than this many days ago.
    pub inactive_days: u64,
    /// Maximum number of normalized threads selected after filtering.
    pub max_threads: usize,
}

/// Options for one bounded multi-thread prompt broadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadPromptOptions {
    /// Stale-thread discovery criteria applied before any writes occur.
    pub query: ThreadQueryOptions,
    /// Exact user message sent to every selected thread.
    pub prompt: String,
    /// Maximum simultaneous provider write requests.
    pub concurrency: usize,
}

/// Normalized provider session exposed as one ORES AI thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiThread {
    /// Provider owning the session.
    pub provider: AiProvider,
    /// Provider session identifier.
    pub id: String,
    /// Creation time as a Unix timestamp in seconds.
    pub created_at: u64,
    /// Last provider-recorded activity/update time as a Unix timestamp in seconds.
    pub last_touched_at: u64,
    /// Provider session status.
    pub status: String,
    /// Optional provider title.
    pub title: Option<String>,
}

#[derive(Debug)]
struct Discovery {
    selected: Vec<AiThread>,
    matched_count: usize,
}

#[derive(Debug)]
struct ProviderConfig {
    provider: AiProvider,
    origin: String,
    api_key: String,
}

/// Verify configured provider credentials with bounded read-only API probes.
///
/// Authentication failures become report findings so `--provider=all` can show
/// the state of both providers without ever echoing remote response bodies.
pub async fn auth(provider: AiProviderSelection) -> CommandReport {
    let mut report = CommandReport::new("ai auth");
    report.insert_metadata("provider", json!(provider.as_str()));
    for item in provider.providers() {
        match probe_provider(item).await {
            Ok(()) => report.push(
                Finding::info(
                    "ai-provider-authenticated",
                    format!("{} API authentication probe passed", item.as_str()),
                )
                .with_target(item.as_str()),
            ),
            Err(_) => report.push(
                Finding::error(
                    "ai-provider-auth-failed",
                    format!(
                        "{} API authentication probe failed; credentials and remote diagnostics are suppressed",
                        item.as_str()
                    ),
                )
                .with_target(item.as_str()),
            ),
        }
    }
    report.finalize()
}

/// Discover stale idle sessions and return them as structured report metadata.
pub async fn list_threads(options: &ThreadQueryOptions) -> Result<CommandReport, RuntimeError> {
    let discovery = discover(options).await?;
    let mut report = CommandReport::new("ai threads list");
    insert_discovery_metadata(&mut report, options, &discovery);
    report.push(Finding::info(
        "ai-stale-threads-selected",
        format!(
            "selected {} stale idle thread(s) from {} matching candidate(s)",
            discovery.selected.len(),
            discovery.matched_count
        ),
    ));
    Ok(report.finalize())
}

/// Discover stale idle sessions first, then prompt the selected sessions with
/// bounded concurrency. Discovery/authentication completes for all selected
/// providers before the first write request is issued.
pub async fn prompt_threads(options: &ThreadPromptOptions) -> Result<CommandReport, RuntimeError> {
    validate_prompt_options(options)?;
    let discovery = discover(&options.query).await?;
    let mut report = CommandReport::new("ai threads prompt");
    insert_discovery_metadata(&mut report, &options.query, &discovery);
    report.insert_metadata("concurrency", json!(options.concurrency));

    if discovery.selected.is_empty() {
        report.push(Finding::info(
            "ai-thread-broadcast-noop",
            "no stale idle threads matched; no provider write requests were issued",
        ));
        report.insert_metadata("delivered", json!(0));
        report.insert_metadata("failed", json!(0));
        return Ok(report.finalize());
    }

    let mut pending = discovery.selected.into_iter();
    let mut workers = JoinSet::new();
    for _ in 0..options.concurrency {
        let Some(thread) = pending.next() else {
            break;
        };
        spawn_delivery(&mut workers, thread, options.prompt.clone());
    }

    let mut delivered = 0_usize;
    let mut failed = 0_usize;
    while let Some(joined) = workers.join_next().await {
        match joined {
            Ok((thread, Ok(status))) => {
                delivered += 1;
                report.push(
                    Finding::info(
                        "ai-thread-prompt-sent",
                        format!("prompt accepted with HTTP {status}"),
                    )
                    .with_target(format!("{}:{}", thread.provider.as_str(), thread.id))
                    .with_detail("provider", json!(thread.provider.as_str())),
                );
            }
            Ok((thread, Err(_))) => {
                failed += 1;
                report.push(
                    Finding::error(
                        "ai-thread-prompt-failed",
                        "prompt delivery failed; provider response body and credentials are suppressed",
                    )
                    .with_target(format!("{}:{}", thread.provider.as_str(), thread.id))
                    .with_detail("provider", json!(thread.provider.as_str())),
                );
            }
            Err(_) => {
                failed += 1;
                report.push(Finding::error(
                    "ai-thread-worker-failed",
                    "a bounded prompt worker terminated unexpectedly",
                ));
            }
        }

        if let Some(thread) = pending.next() {
            spawn_delivery(&mut workers, thread, options.prompt.clone());
        }
    }

    report.insert_metadata("delivered", json!(delivered));
    report.insert_metadata("failed", json!(failed));
    Ok(report.finalize())
}

fn spawn_delivery(
    workers: &mut JoinSet<(AiThread, Result<u16, RuntimeError>)>,
    thread: AiThread,
    prompt: String,
) {
    workers.spawn(async move {
        let result = send_prompt(&thread, &prompt).await;
        (thread, result)
    });
}

async fn discover(options: &ThreadQueryOptions) -> Result<Discovery, RuntimeError> {
    validate_query_options(options)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuntimeError::Invariant("system clock predates the Unix epoch".to_owned()))?
        .as_secs();
    let created_cutoff = now.saturating_sub(options.older_than_days * SECONDS_PER_DAY);
    let inactive_cutoff = now.saturating_sub(options.inactive_days * SECONDS_PER_DAY);

    let mut matched = Vec::new();
    for provider in options.provider.providers() {
        matched.extend(discover_provider(provider, created_cutoff, inactive_cutoff).await?);
    }
    matched.sort_by(|left, right| {
        left.last_touched_at
            .cmp(&right.last_touched_at)
            .then_with(|| left.created_at.cmp(&right.created_at))
            .then_with(|| left.provider.cmp(&right.provider))
            .then_with(|| left.id.cmp(&right.id))
    });
    let matched_count = matched.len();
    matched.truncate(options.max_threads);
    Ok(Discovery {
        selected: matched,
        matched_count,
    })
}

async fn discover_provider(
    provider: AiProvider,
    created_cutoff: u64,
    inactive_cutoff: u64,
) -> Result<Vec<AiThread>, RuntimeError> {
    let config = provider_config(provider)?;
    match provider {
        AiProvider::Claude => {
            discover_claude(&config, created_cutoff, inactive_cutoff).await
        }
        AiProvider::Codex => discover_codex(&config, created_cutoff, inactive_cutoff).await,
    }
}

async fn discover_claude(
    config: &ProviderConfig,
    created_cutoff: u64,
    inactive_cutoff: u64,
) -> Result<Vec<AiThread>, RuntimeError> {
    let mut selected = Vec::new();
    let mut page: Option<String> = None;
    for _ in 0..MAX_SCAN_PAGES {
        let mut url = format!(
            "{}/v1/sessions?limit={PAGE_SIZE}&order=asc&statuses=idle",
            config.origin
        );
        if let Some(cursor) = &page {
            url.push_str("&page=");
            url.push_str(&percent_encode(cursor));
        }
        let value = request_json(config, "GET", &url, None).await?;
        let data = value
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(|| provider_shape_error(config.provider))?;
        let mut reached_cutoff = false;
        for item in data {
            let thread = parse_claude_session(item)?;
            if thread.created_at >= created_cutoff {
                reached_cutoff = true;
                break;
            }
            if thread.last_touched_at < inactive_cutoff {
                selected.push(thread);
            }
        }
        if reached_cutoff {
            return Ok(selected);
        }
        page = value
            .get("next_page")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        if page.is_none() {
            return Ok(selected);
        }
    }
    Err(scan_limit_error(config.provider))
}

async fn discover_codex(
    config: &ProviderConfig,
    created_cutoff: u64,
    inactive_cutoff: u64,
) -> Result<Vec<AiThread>, RuntimeError> {
    let mut selected = Vec::new();
    let mut after: Option<String> = None;
    for _ in 0..MAX_SCAN_PAGES {
        let mut url = format!(
            "{}/v1/agents/sessions?limit={PAGE_SIZE}&order=asc",
            config.origin
        );
        if let Some(cursor) = &after {
            url.push_str("&after=");
            url.push_str(&percent_encode(cursor));
        }
        let value = request_json(config, "GET", &url, None).await?;
        let data = value
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(|| provider_shape_error(config.provider))?;
        let mut reached_cutoff = false;
        for item in data {
            let thread = parse_codex_session(item)?;
            if thread.created_at >= created_cutoff {
                reached_cutoff = true;
                break;
            }
            if thread.status == "idle" && thread.last_touched_at < inactive_cutoff {
                selected.push(thread);
            }
        }
        if reached_cutoff || !value.get("has_more").and_then(Value::as_bool).unwrap_or(false) {
            return Ok(selected);
        }
        after = value
            .get("last_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        if after.is_none() {
            return Err(provider_shape_error(config.provider));
        }
    }
    Err(scan_limit_error(config.provider))
}

async fn probe_provider(provider: AiProvider) -> Result<(), RuntimeError> {
    let config = provider_config(provider)?;
    let url = match provider {
        AiProvider::Claude => format!("{}/v1/sessions?limit=1", config.origin),
        AiProvider::Codex => format!("{}/v1/agents/sessions?limit=1", config.origin),
    };
    let value = request_json(&config, "GET", &url, None).await?;
    if value.get("data").and_then(Value::as_array).is_none() {
        return Err(provider_shape_error(provider));
    }
    Ok(())
}

async fn send_prompt(thread: &AiThread, prompt: &str) -> Result<u16, RuntimeError> {
    let config = provider_config(thread.provider)?;
    let session_id = percent_encode(&thread.id);
    let (url, body) = match thread.provider {
        AiProvider::Claude => (
            format!("{}/v1/sessions/{session_id}/events", config.origin),
            json!({
                "events": [{
                    "type": "user.message",
                    "content": [{"type": "text", "text": prompt}]
                }]
            }),
        ),
        AiProvider::Codex => (
            format!("{}/v1/agents/sessions/{session_id}/events", config.origin),
            json!({
                "events": [{
                    "type": "agent.session.input.message",
                    "input": [{
                        "role": "user",
                        "content": [{"type": "input_text", "text": prompt}]
                    }]
                }]
            }),
        ),
    };
    let response = request(&config, "POST", &url, Some(&body)).await?;
    Ok(response.0)
}

fn parse_claude_session(value: &Value) -> Result<AiThread, RuntimeError> {
    let id = required_string(value, "id", AiProvider::Claude)?;
    let created_at = required_string(value, "created_at", AiProvider::Claude)
        .and_then(|item| parse_rfc3339_epoch(&item).ok_or_else(|| provider_shape_error(AiProvider::Claude)))?;
    let last_touched_at = required_string(value, "updated_at", AiProvider::Claude)
        .and_then(|item| parse_rfc3339_epoch(&item).ok_or_else(|| provider_shape_error(AiProvider::Claude)))?;
    let status = required_string(value, "status", AiProvider::Claude)?;
    let title = value
        .get("title")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    Ok(AiThread {
        provider: AiProvider::Claude,
        id,
        created_at,
        last_touched_at,
        status,
        title,
    })
}

fn parse_codex_session(value: &Value) -> Result<AiThread, RuntimeError> {
    let id = required_string(value, "id", AiProvider::Codex)?;
    let created_at = value
        .get("created_at")
        .and_then(Value::as_u64)
        .ok_or_else(|| provider_shape_error(AiProvider::Codex))?;
    let last_touched_at = value
        .get("last_active_at")
        .and_then(Value::as_u64)
        .ok_or_else(|| provider_shape_error(AiProvider::Codex))?;
    let status = required_string(value, "status", AiProvider::Codex)?;
    Ok(AiThread {
        provider: AiProvider::Codex,
        id,
        created_at,
        last_touched_at,
        status,
        title: None,
    })
}

fn required_string(
    value: &Value,
    key: &str,
    provider: AiProvider,
) -> Result<String, RuntimeError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| provider_shape_error(provider))
}

async fn request_json(
    config: &ProviderConfig,
    method: &str,
    url: &str,
    body: Option<&Value>,
) -> Result<Value, RuntimeError> {
    let (status, response_body) = request(config, method, url, body).await?;
    serde_json::from_str(&response_body).map_err(|_| RuntimeError::Dependency {
        command: format!("{} managed-agent API", config.provider.as_str()),
        exit_code: None,
        message: format!(
            "provider returned HTTP {status} with invalid JSON; response body suppressed"
        ),
    })
}

async fn request(
    config: &ProviderConfig,
    method: &str,
    url: &str,
    body: Option<&Value>,
) -> Result<(u16, String), RuntimeError> {
    let body = body.map(serde_json::to_string).transpose()?;
    let input = build_curl_config(config, method, url, body.as_deref())?;
    let mut command = Command::new("curl");
    command.args(["--config", "-"]);
    let label = format!("{} managed-agent API", config.provider.as_str());
    let output = run_bounded_with_input(
        command,
        &label,
        CaptureLimits::new(CURL_DEADLINE, MAX_RESPONSE_BYTES + 16, 8 * 1024),
        input.as_bytes(),
    )
    .await?;
    if !output.status.success() {
        return Err(RuntimeError::Dependency {
            command: label,
            exit_code: output.status.code(),
            message: "provider transport failed; remote diagnostics suppressed".to_owned(),
        });
    }
    let (response_body, status) = split_curl_response(&output.stdout, config.provider)?;
    if !(200..300).contains(&status) {
        return Err(RuntimeError::Dependency {
            command: label,
            exit_code: None,
            message: format!("provider returned HTTP {status}; response body suppressed"),
        });
    }
    Ok((status, response_body.to_owned()))
}

fn build_curl_config(
    config: &ProviderConfig,
    method: &str,
    url: &str,
    body: Option<&str>,
) -> Result<String, RuntimeError> {
    if !matches!(method, "GET" | "POST") {
        return Err(RuntimeError::Invariant(
            "AI transport only permits GET and POST".to_owned(),
        ));
    }
    let mut lines = vec![
        "silent".to_owned(),
        format!("request = \"{}\"", curl_quote(method)?),
        "connect-timeout = 5".to_owned(),
        "max-time = 25".to_owned(),
        "max-redirs = 0".to_owned(),
        "proto = \"=https,http\"".to_owned(),
        format!(
            "header = \"{}\"",
            curl_quote("Accept: application/json")?
        ),
    ];
    match config.provider {
        AiProvider::Claude => {
            lines.push(format!(
                "header = \"{}\"",
                curl_quote("anthropic-version: 2023-06-01")?
            ));
            lines.push(format!(
                "header = \"{}\"",
                curl_quote(&format!("anthropic-beta: {ANTHROPIC_BETA}"))?
            ));
            lines.push(format!(
                "header = \"{}\"",
                curl_quote(&format!("x-api-key: {}", config.api_key))?
            ));
        }
        AiProvider::Codex => {
            lines.push(format!(
                "header = \"{}\"",
                curl_quote(&format!("Authorization: Bearer {}", config.api_key))?
            ));
            lines.push(format!(
                "header = \"{}\"",
                curl_quote(&format!("OpenAI-Beta: {OPENAI_BETA}"))?
            ));
        }
    }
    if let Some(body) = body {
        lines.push(format!(
            "header = \"{}\"",
            curl_quote("Content-Type: application/json")?
        ));
        lines.push(format!("data-binary = \"{}\"", curl_quote(body)?));
    }
    lines.push("write-out = \"\\n%{http_code}\"".to_owned());
    lines.push(format!("url = \"{}\"", curl_quote(url)?));
    lines.push(String::new());
    Ok(lines.join("\n"))
}

fn curl_quote(value: &str) -> Result<String, RuntimeError> {
    if value.chars().any(|item| matches!(item, '\r' | '\n' | '\0')) {
        return Err(RuntimeError::Usage(
            "AI request material must not contain raw control-line characters".to_owned(),
        ));
    }
    Ok(value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn split_curl_response(
    stdout: &str,
    provider: AiProvider,
) -> Result<(&str, u16), RuntimeError> {
    let (body, status) = stdout
        .rsplit_once('\n')
        .ok_or_else(|| provider_receipt_error(provider))?;
    let status = status
        .parse::<u16>()
        .ok()
        .filter(|value| (100..=599).contains(value))
        .ok_or_else(|| provider_receipt_error(provider))?;
    Ok((body, status))
}

fn provider_config(provider: AiProvider) -> Result<ProviderConfig, RuntimeError> {
    let (key_env, base_env, default_origin) = match provider {
        AiProvider::Claude => (ANTHROPIC_KEY_ENV, ANTHROPIC_BASE_ENV, ANTHROPIC_ORIGIN),
        AiProvider::Codex => (OPENAI_KEY_ENV, OPENAI_BASE_ENV, OPENAI_ORIGIN),
    };
    let api_key = env::var(key_env)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            RuntimeError::Usage(format!(
                "{} requires {key_env} in the process environment",
                provider.as_str()
            ))
        })?;
    if api_key.chars().any(|item| matches!(item, '\r' | '\n' | '\0')) {
        return Err(RuntimeError::Usage(format!(
            "{key_env} contains invalid control characters"
        )));
    }
    let origin = env::var(base_env).unwrap_or_else(|_| default_origin.to_owned());
    let origin = normalize_origin(&origin, base_env)?;
    Ok(ProviderConfig {
        provider,
        origin,
        api_key,
    })
}

fn normalize_origin(value: &str, env_name: &str) -> Result<String, RuntimeError> {
    if value.is_empty()
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.contains('?')
        || value.contains('#')
    {
        return Err(invalid_origin(env_name));
    }
    let (scheme, rest) = if let Some(rest) = value.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = value.strip_prefix("http://") {
        ("http", rest)
    } else {
        return Err(invalid_origin(env_name));
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty()
        || rest.contains('/')
        || rest.contains('@')
        || rest.chars().any(char::is_whitespace)
    {
        return Err(invalid_origin(env_name));
    }
    let host = host_without_port(rest).ok_or_else(|| invalid_origin(env_name))?;
    if scheme == "http" && !matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return Err(RuntimeError::Usage(format!(
            "{env_name} requires HTTPS except for loopback test endpoints"
        )));
    }
    Ok(format!("{scheme}://{rest}"))
}

fn host_without_port(authority: &str) -> Option<&str> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let suffix = &rest[end + 1..];
        if !suffix.is_empty() && !valid_port_suffix(suffix) {
            return None;
        }
        return (!host.is_empty()).then_some(host);
    }

    if let Some((host, port)) = authority.rsplit_once(':') {
        if port.bytes().all(|byte| byte.is_ascii_digit()) && !port.is_empty() {
            return (!host.is_empty()).then_some(host);
        }
        if authority.matches(':').count() > 1 {
            return None;
        }
    }
    (!authority.is_empty()).then_some(authority)
}

fn valid_port_suffix(value: &str) -> bool {
    let Some(port) = value.strip_prefix(':') else {
        return false;
    };
    !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
}

fn invalid_origin(env_name: &str) -> RuntimeError {
    RuntimeError::Usage(format!(
        "{env_name} must be an origin only (https://host[:port], or loopback http)"
    ))
}

fn percent_encode(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(&mut output, "%{byte:02X}");
        }
    }
    output
}

fn validate_query_options(options: &ThreadQueryOptions) -> Result<(), RuntimeError> {
    if options.older_than_days == 0 || options.older_than_days > 3_650 {
        return Err(RuntimeError::Usage(
            "--older-than-days must be between 1 and 3650".to_owned(),
        ));
    }
    if options.inactive_days == 0 || options.inactive_days > 3_650 {
        return Err(RuntimeError::Usage(
            "--inactive-days must be between 1 and 3650".to_owned(),
        ));
    }
    if !(1..=MAX_BROADCAST_THREADS).contains(&options.max_threads) {
        return Err(RuntimeError::Usage(format!(
            "--max-threads must be between 1 and {MAX_BROADCAST_THREADS}"
        )));
    }
    Ok(())
}

fn validate_prompt_options(options: &ThreadPromptOptions) -> Result<(), RuntimeError> {
    validate_query_options(&options.query)?;
    if options.prompt.trim().is_empty() {
        return Err(RuntimeError::Usage("--prompt must not be empty".to_owned()));
    }
    if options.prompt.len() > MAX_PROMPT_BYTES {
        return Err(RuntimeError::Usage(format!(
            "--prompt exceeds the {MAX_PROMPT_BYTES}-byte safety limit"
        )));
    }
    if !(1..=MAX_BROADCAST_THREADS).contains(&options.concurrency) {
        return Err(RuntimeError::Usage(format!(
            "--concurrency must be between 1 and {MAX_BROADCAST_THREADS}"
        )));
    }
    Ok(())
}

fn insert_discovery_metadata(
    report: &mut CommandReport,
    options: &ThreadQueryOptions,
    discovery: &Discovery,
) {
    report.insert_metadata(
        "criteria",
        json!({
            "provider": options.provider.as_str(),
            "olderThanDays": options.older_than_days,
            "inactiveDays": options.inactive_days,
            "maxThreads": options.max_threads,
            "status": "idle"
        }),
    );
    report.insert_metadata("matchedThreads", json!(discovery.matched_count));
    report.insert_metadata(
        "selectedThreads",
        Value::Array(discovery.selected.iter().map(thread_json).collect()),
    );
}

fn thread_json(thread: &AiThread) -> Value {
    json!({
        "provider": thread.provider.as_str(),
        "id": thread.id,
        "createdAt": thread.created_at,
        "lastTouchedAt": thread.last_touched_at,
        "status": thread.status,
        "title": thread.title,
    })
}

fn provider_shape_error(provider: AiProvider) -> RuntimeError {
    RuntimeError::Dependency {
        command: format!("{} managed-agent API", provider.as_str()),
        exit_code: None,
        message: "provider response did not match the expected managed-agent session contract; body suppressed"
            .to_owned(),
    }
}

fn provider_receipt_error(provider: AiProvider) -> RuntimeError {
    RuntimeError::Dependency {
        command: format!("{} managed-agent API", provider.as_str()),
        exit_code: None,
        message: "provider transport omitted a valid HTTP status receipt".to_owned(),
    }
}

fn scan_limit_error(provider: AiProvider) -> RuntimeError {
    RuntimeError::Dependency {
        command: format!("{} managed-agent API", provider.as_str()),
        exit_code: None,
        message: format!(
            "provider session scan exceeded {MAX_SCAN_PAGES} pages; refusing a truncated stale-thread inventory"
        ),
    }
}

fn parse_rfc3339_epoch(value: &str) -> Option<u64> {
    if value.len() < 20
        || value.get(4..5)? != "-"
        || value.get(7..8)? != "-"
        || value.get(10..11)? != "T"
        || value.get(13..14)? != ":"
        || value.get(16..17)? != ":"
    {
        return None;
    }
    let year = parse_i64(value.get(0..4)?)?;
    let month = parse_i64(value.get(5..7)?)?;
    let day = parse_i64(value.get(8..10)?)?;
    let hour = parse_i64(value.get(11..13)?)?;
    let minute = parse_i64(value.get(14..16)?)?;
    let second = parse_i64(value.get(17..19)?)?;
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
        return None;
    }

    let mut zone = value.get(19..)?;
    if let Some(fraction) = zone.strip_prefix('.') {
        let zone_index = fraction.find(['Z', '+', '-'])?;
        let digits = fraction.get(..zone_index)?;
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        zone = fraction.get(zone_index..)?;
    }
    let offset = if zone == "Z" {
        0_i64
    } else {
        if zone.len() != 6 || zone.get(3..4)? != ":" {
            return None;
        }
        let sign = match zone.get(0..1)? {
            "+" => 1_i64,
            "-" => -1_i64,
            _ => return None,
        };
        let zone_hour = parse_i64(zone.get(1..3)?)?;
        let zone_minute = parse_i64(zone.get(4..6)?)?;
        if !(0..=23).contains(&zone_hour) || !(0..=59).contains(&zone_minute) {
            return None;
        }
        sign * (zone_hour * 3_600 + zone_minute * 60)
    };
    let days = days_from_civil(year, month, day);
    let timestamp = days
        .checked_mul(SECONDS_PER_DAY as i64)?
        .checked_add(hour * 3_600 + minute * 60 + second)?
        .checked_sub(offset)?;
    u64::try_from(timestamp).ok()
}

fn parse_i64(value: &str) -> Option<i64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

const fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let adjusted_year = year - if month <= 2 { 1 } else { 0 };
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_parser_handles_utc_fraction_and_offsets() {
        assert_eq!(parse_rfc3339_epoch("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_epoch("2026-09-12T22:37:00-05:00"),
            parse_rfc3339_epoch("2026-09-13T03:37:00Z")
        );
        assert_eq!(
            parse_rfc3339_epoch("2026-03-15T10:00:00.123456Z"),
            parse_rfc3339_epoch("2026-03-15T10:00:00Z")
        );
        assert!(parse_rfc3339_epoch("2026-02-30T10:00:00Z").is_none());
    }

    #[test]
    fn percent_encoding_is_path_and_query_safe() {
        assert_eq!(percent_encode("abc-_.~123"), "abc-_.~123");
        assert_eq!(percent_encode("page a/b+"), "page%20a%2Fb%2B");
    }

    #[test]
    fn curl_command_line_never_contains_credentials_or_prompt_material() {
        let secret = "sk-test-secret";
        let prompt = "private prompt";
        let config = ProviderConfig {
            provider: AiProvider::Codex,
            origin: OPENAI_ORIGIN.to_owned(),
            api_key: secret.to_owned(),
        };
        let body = serde_json::to_string(&json!({"prompt": prompt})).unwrap();
        let stdin_config = build_curl_config(&config, "POST", "https://api.openai.com/test", Some(&body)).unwrap();
        assert!(stdin_config.contains(secret));
        assert!(stdin_config.contains(prompt));

        let mut command = Command::new("curl");
        command.args(["--config", "-"]);
        let debug = format!("{command:?}");
        assert!(!debug.contains(secret));
        assert!(!debug.contains(prompt));
    }

    #[test]
    fn query_safety_bounds_cap_broadcasts_at_twenty() {
        let valid = ThreadQueryOptions {
            provider: AiProviderSelection::All,
            older_than_days: 7,
            inactive_days: 5,
            max_threads: 20,
        };
        assert!(validate_query_options(&valid).is_ok());
        let invalid = ThreadQueryOptions {
            max_threads: 21,
            ..valid
        };
        assert!(validate_query_options(&invalid).is_err());
    }
}
