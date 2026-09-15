//! flags-2-env adapter for Claude/Codex managed-agent session commands.
//!
//! `.cli-flags.toml` remains the only public argv authority. Provider API keys
//! are read only by [`crate::ai`] from the process environment.

use std::collections::HashMap;
use std::env;

use flags2env::BundledFlags2Env;
use serde::Deserialize;

use crate::ai::{
    AiProviderSelection, ThreadPromptOptions, ThreadQueryOptions, auth, list_threads,
    prompt_threads,
};
use crate::error::RuntimeError;
use crate::flags::active_flag_contract_path;
use crate::output::emit_report;

#[derive(Debug, Default, Deserialize)]
struct ResolvedValues {
    #[serde(rename = "ORES_CLI_JSON", default = "default_true")]
    json: bool,
    #[serde(rename = "ORES_CLI_AI_PROVIDER", default = "default_provider")]
    provider: String,
    #[serde(
        rename = "ORES_CLI_AI_OLDER_THAN_DAYS",
        default = "default_older_than_days"
    )]
    older_than_days: u64,
    #[serde(
        rename = "ORES_CLI_AI_INACTIVE_DAYS",
        default = "default_inactive_days"
    )]
    inactive_days: u64,
    #[serde(rename = "ORES_CLI_AI_MAX_THREADS", default = "default_max_threads")]
    max_threads: usize,
    #[serde(rename = "ORES_CLI_AI_CONCURRENCY", default = "default_concurrency")]
    concurrency: usize,
    #[serde(rename = "ORES_CLI_AI_PROMPT", default)]
    prompt: String,
}

const fn default_true() -> bool {
    true
}

fn default_provider() -> String {
    "all".to_owned()
}

const fn default_older_than_days() -> u64 {
    7
}

const fn default_inactive_days() -> u64 {
    5
}

const fn default_max_threads() -> usize {
    20
}

const fn default_concurrency() -> usize {
    20
}

/// Parse and execute the `ai` command subtree without introducing a second
/// command-line parser.
pub async fn run_process(argv: &[String]) -> Result<u8, RuntimeError> {
    let parser = BundledFlags2Env::new();
    let contract_path = active_flag_contract_path()?;
    parser
        .audit_config(Some(&contract_path))
        .map_err(|_| RuntimeError::Usage("flag contract audit failed".to_owned()))?;
    let structured = parser
        .parse_structured(argv, Some(&contract_path))
        .map_err(|_| {
            RuntimeError::Usage("flag parsing failed: unknown option or invalid value".to_owned())
        })?;
    if !structured.unknown_options.is_empty() {
        return Err(RuntimeError::Usage(format!(
            "unknown options: {} rejected argument(s)",
            structured.unknown_options.len()
        )));
    }
    if !structured.errors.is_empty() {
        return Err(RuntimeError::Usage(format!(
            "flag parsing failed: {} invalid argument(s)",
            structured.errors.len()
        )));
    }
    if !structured.extras.is_empty() {
        return Err(RuntimeError::Usage(format!(
            "AI commands do not accept positional arguments (received {})",
            structured.extras.len()
        )));
    }

    let resolved = parser
        .resolve_commands(argv, Some(&contract_path))
        .map_err(|_| RuntimeError::Usage("command resolution failed".to_owned()))?;
    let values = coerce_values(
        &parser,
        &structured.dotenv,
        &structured.dotenv_overrides,
        &structured.provided_flags,
        &contract_path,
    )?;
    let path = if resolved.path.is_empty() {
        let mut fallback = Vec::new();
        if !structured.command.trim().is_empty() {
            fallback.push(structured.command.trim().to_owned());
        }
        fallback.extend(
            structured
                .subcommands
                .iter()
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        );
        fallback
    } else {
        resolved.path
    };

    let provider = AiProviderSelection::parse(&values.provider)?;
    let report = match path.as_slice() {
        [ai] if ai == "ai" => auth(provider).await,
        [ai, auth_command] if ai == "ai" && auth_command == "auth" => auth(provider).await,
        [ai, threads] if ai == "ai" && threads == "threads" => {
            list_threads(&build_query(&values, provider)).await?
        }
        [ai, threads, list] if ai == "ai" && threads == "threads" && list == "list" => {
            list_threads(&build_query(&values, provider)).await?
        }
        [ai, threads, prompt] if ai == "ai" && threads == "threads" && prompt == "prompt" => {
            let options = ThreadPromptOptions {
                query: build_query(&values, provider),
                prompt: values.prompt,
                concurrency: values.concurrency,
            };
            prompt_threads(&options).await?
        }
        _ => {
            return Err(RuntimeError::Usage(
                "unknown AI command: expected ai auth, ai threads list, or ai threads prompt"
                    .to_owned(),
            ));
        }
    };
    let exit_code = report.exit_code();
    emit_report(&report, values.json)?;
    Ok(exit_code)
}

fn build_query(values: &ResolvedValues, provider: AiProviderSelection) -> ThreadQueryOptions {
    ThreadQueryOptions {
        provider,
        older_than_days: values.older_than_days,
        inactive_days: values.inactive_days,
        max_threads: values.max_threads,
    }
}

fn coerce_values(
    parser: &BundledFlags2Env,
    dotenv: &HashMap<String, String>,
    dotenv_overrides: &HashMap<String, String>,
    provided_flags: &HashMap<String, String>,
    contract_path: &str,
) -> Result<ResolvedValues, RuntimeError> {
    let mut values = dotenv.clone();
    values.extend(env::vars());
    values.extend(dotenv_overrides.clone());
    values.extend(provided_flags.clone());
    parser
        .coerce(&values, Some(contract_path))
        .map_err(|_| RuntimeError::Usage("invalid typed AI flag or environment value".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_thread_defaults_match_the_broadcast_use_case() {
        assert_eq!(default_provider(), "all");
        assert_eq!(default_older_than_days(), 7);
        assert_eq!(default_inactive_days(), 5);
        assert_eq!(default_max_threads(), 20);
        assert_eq!(default_concurrency(), 20);
    }
}
