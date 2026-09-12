use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::Path;

use serde_json::json;
use toml::Value;

use super::RepositoryAuditOptions;
use crate::model::{CommandReport, Finding};

const CLI_CONTRACT: &str = ".cli-flags.toml";
const MAX_INPUT_BYTES: u64 = 2 * 1024 * 1024;

/// Cross-check runtime configuration environment declarations against the one
/// public argv authority.
///
/// Runtime contracts are allowed to name secret environment variables, but a
/// credential-class binding must never also be exposed as a public CLI flag.
/// This complements the name-based CLI secret lint with explicit declarations
/// from the runtime config families themselves.
pub(super) fn augment_runtime_toml_env_boundary_audit(
    options: &RepositoryAuditOptions,
    mut report: CommandReport,
) -> CommandReport {
    let issues_before = report.issue_count();
    let public_envs = public_flag_envs(&options.path, &mut report);
    let mut env_only_sources = BTreeMap::<String, BTreeSet<String>>::new();

    audit_keyed_env_family(
        &options.path,
        ".ores-mw.toml",
        "key",
        true,
        &mut env_only_sources,
        &mut report,
    );
    audit_keyed_env_family(
        &options.path,
        ".fanwaave-cfg.toml",
        "key",
        true,
        &mut env_only_sources,
        &mut report,
    );
    audit_rpc(&options.path, &mut env_only_sources, &mut report);
    audit_rate_limit(&options.path, &mut env_only_sources, &mut report);
    audit_lru(&options.path, &mut env_only_sources, &mut report);

    for (env_key, sources) in &env_only_sources {
        if public_envs.contains(env_key) {
            report.push(
                Finding::error(
                    "runtime-secret-env-exposed-via-cli",
                    "runtime configuration declares an environment-only credential binding that is also exposed as a public CLI flag",
                )
                .with_target(CLI_CONTRACT)
                .with_detail("envKey", json!(env_key))
                .with_detail("declaredBy", json!(sources)),
            );
        }
    }

    report.insert_metadata("runtimeEnvPublicCliBindingCount", json!(public_envs.len()));
    report.insert_metadata(
        "runtimeEnvEnvironmentOnlyBindingCount",
        json!(env_only_sources.len()),
    );

    if report.issue_count() == issues_before && !env_only_sources.is_empty() {
        report.push(Finding::info(
            "runtime-env-argv-boundary-clean",
            "runtime config credential bindings remain environment-only and are not exposed through .cli-flags.toml",
        ));
    }

    report.finalize()
}

fn public_flag_envs(root: &Path, report: &mut CommandReport) -> BTreeSet<String> {
    let Some(document) = read_toml(root, CLI_CONTRACT, report) else {
        return BTreeSet::new();
    };
    let mut envs = BTreeSet::new();
    collect_flag_envs(&document, &mut Vec::new(), &mut envs);
    envs
}

fn collect_flag_envs(value: &Value, path: &mut Vec<String>, envs: &mut BTreeSet<String>) {
    match value {
        Value::Table(table) => {
            if path.len() >= 2 && path[path.len() - 2] == "flags" {
                if let Some(env_key) = table.get("env").and_then(Value::as_str) {
                    envs.insert(env_key.to_owned());
                }
            }
            for (key, child) in table {
                path.push(key.clone());
                collect_flag_envs(child, path, envs);
                path.pop();
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_flag_envs(child, path, envs);
            }
        }
        _ => {}
    }
}

fn audit_keyed_env_family(
    root: &Path,
    file: &str,
    key_field: &str,
    require_cli_contract: bool,
    env_only_sources: &mut BTreeMap<String, BTreeSet<String>>,
    report: &mut CommandReport,
) {
    let Some(document) = read_toml(root, file, report) else {
        return;
    };
    if require_cli_contract {
        let contract = document
            .get("flags2env")
            .and_then(Value::as_table)
            .and_then(|table| table.get("contract"))
            .and_then(Value::as_str);
        if contract != Some(CLI_CONTRACT) {
            report.push(
                Finding::error(
                    "runtime-flags2env-contract-mismatch",
                    "runtime config must bind argv precedence to the canonical .cli-flags.toml contract",
                )
                .with_target(file)
                .with_detail("expectedContract", json!(CLI_CONTRACT))
                .with_detail("actualContract", json!(contract)),
            );
        }
    }

    let Some(entries) = document.get("env").and_then(Value::as_array) else {
        return;
    };
    for (index, entry) in entries.iter().enumerate() {
        let Some(table) = entry.as_table() else {
            continue;
        };
        if table.get("secret").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        if let Some(env_key) = table.get(key_field).and_then(Value::as_str) {
            record_env_only(env_only_sources, env_key, format!("{file}:env[{index}]"));
        }
    }
}

fn audit_rpc(
    root: &Path,
    env_only_sources: &mut BTreeMap<String, BTreeSet<String>>,
    report: &mut CommandReport,
) {
    const FILE: &str = ".ores-rpc.toml";
    let Some(document) = read_toml(root, FILE, report) else {
        return;
    };
    let contract = document.get("flagsContract").and_then(Value::as_str);
    if contract != Some(CLI_CONTRACT) {
        report.push(
            Finding::error(
                "runtime-rpc-flags-contract-mismatch",
                ".ores-rpc.toml must reference the canonical .cli-flags.toml argv contract",
            )
            .with_target(FILE)
            .with_detail("expectedContract", json!(CLI_CONTRACT))
            .with_detail("actualContract", json!(contract)),
        );
    }

    let Some(entries) = document.get("env").and_then(Value::as_array) else {
        return;
    };
    for (index, entry) in entries.iter().enumerate() {
        let Some(table) = entry.as_table() else {
            continue;
        };
        if table.get("secret").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        if table.get("allowArgv").and_then(Value::as_bool) != Some(false) {
            report.push(
                Finding::error(
                    "runtime-rpc-secret-allows-argv",
                    "secret RPC environment bindings must explicitly set allowArgv=false",
                )
                .with_target(format!("{FILE}:env[{index}]")),
            );
        }
        if let Some(env_key) = table.get("env").and_then(Value::as_str) {
            record_env_only(env_only_sources, env_key, format!("{FILE}:env[{index}]"));
        }
    }
}

fn audit_rate_limit(
    root: &Path,
    env_only_sources: &mut BTreeMap<String, BTreeSet<String>>,
    report: &mut CommandReport,
) {
    const FILE: &str = ".ores-rl.toml";
    let Some(document) = read_toml(root, FILE, report) else {
        return;
    };
    let Some(server) = document.get("server").and_then(Value::as_table) else {
        return;
    };
    for field in ["redisUrlEnv", "keyHmacEnv"] {
        if let Some(env_key) = server.get(field).and_then(Value::as_str) {
            record_env_only(env_only_sources, env_key, format!("{FILE}:server.{field}"));
        }
    }
}

fn audit_lru(
    root: &Path,
    env_only_sources: &mut BTreeMap<String, BTreeSet<String>>,
    report: &mut CommandReport,
) {
    const FILE: &str = ".ores-lru.toml";
    let Some(document) = read_toml(root, FILE, report) else {
        return;
    };
    if let Some(env_key) = document
        .get("redis")
        .and_then(Value::as_table)
        .and_then(|table| table.get("urlEnv"))
        .and_then(Value::as_str)
    {
        record_env_only(env_only_sources, env_key, format!("{FILE}:redis.urlEnv"));
    }
}

fn record_env_only(
    sources: &mut BTreeMap<String, BTreeSet<String>>,
    env_key: &str,
    source: String,
) {
    if env_key.trim().is_empty() {
        return;
    }
    sources
        .entry(env_key.to_owned())
        .or_default()
        .insert(source);
}

fn read_toml(root: &Path, file: &str, report: &mut CommandReport) -> Option<Value> {
    let path = root.join(file);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
        Err(error) => {
            report.push(
                Finding::error(
                    "runtime-env-contract-unreadable",
                    format!("runtime config metadata could not be read: {error}"),
                )
                .with_target(file),
            );
            return None;
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_INPUT_BYTES
    {
        report.push(
            Finding::error(
                "runtime-env-contract-unsafe",
                "runtime env-boundary audit requires bounded regular non-symlink TOML files",
            )
            .with_target(file),
        );
        return None;
    }
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            report.push(
                Finding::error(
                    "runtime-env-contract-unreadable",
                    format!("runtime config could not be read as UTF-8: {error}"),
                )
                .with_target(file),
            );
            return None;
        }
    };
    match toml::from_str::<Value>(&text) {
        Ok(document) => Some(document),
        Err(error) => {
            report.push(
                Finding::error(
                    "runtime-env-contract-invalid",
                    format!("runtime config could not be parsed as TOML: {error}"),
                )
                .with_target(file),
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::augment_runtime_toml_env_boundary_audit;
    use crate::audit::RepositoryAuditOptions;
    use crate::model::CommandReport;

    fn audit(files: &[(&str, &str)]) -> CommandReport {
        let root = tempdir().expect("temporary repository");
        for (name, content) in files {
            fs::write(root.path().join(name), content).expect("fixture write");
        }
        augment_runtime_toml_env_boundary_audit(
            &RepositoryAuditOptions {
                path: root.path().to_path_buf(),
                profile: "baseline".to_owned(),
                additional_required_paths: Vec::new(),
            },
            CommandReport::new("runtime env boundary test"),
        )
    }

    fn has(report: &CommandReport, code: &str) -> bool {
        report.findings.iter().any(|finding| finding.code == code)
    }

    #[test]
    fn middleware_secret_env_must_not_be_a_public_flag() {
        let report = audit(&[
            (
                ".cli-flags.toml",
                "[flags.redis]\nenv = \"REDIS_URL\"\ntype = \"string\"\n",
            ),
            (
                ".ores-mw.toml",
                "[flags2env]\ncontract = \".cli-flags.toml\"\n[[env]]\nkey = \"REDIS_URL\"\nsecret = true\n",
            ),
        ]);
        assert!(has(&report, "runtime-secret-env-exposed-via-cli"));
    }

    #[test]
    fn nonsecret_runtime_env_may_be_public() {
        let report = audit(&[
            (
                ".cli-flags.toml",
                "[flags.port]\nenv = \"PORT\"\ntype = \"integer\"\n",
            ),
            (
                ".ores-mw.toml",
                "[flags2env]\ncontract = \".cli-flags.toml\"\n[[env]]\nkey = \"PORT\"\nsecret = false\n",
            ),
        ]);
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
    }

    #[test]
    fn rpc_secret_must_disable_argv_even_without_public_flag() {
        let report = audit(&[(
            ".ores-rpc.toml",
            "flagsContract = \".cli-flags.toml\"\n[[env]]\nenv = \"ORES_RPC_AUTH_TOKEN\"\nsecret = true\nallowArgv = true\n",
        )]);
        assert!(has(&report, "runtime-rpc-secret-allows-argv"));
    }

    #[test]
    fn rate_limit_and_lru_bindings_are_environment_only() {
        let report = audit(&[
            (
                ".cli-flags.toml",
                "[flags.hmac]\nenv = \"ORES_RL_HMAC_KEY\"\ntype = \"string\"\n",
            ),
            (
                ".ores-rl.toml",
                "[server]\nredisUrlEnv = \"REDIS_URL\"\nkeyHmacEnv = \"ORES_RL_HMAC_KEY\"\n",
            ),
            (".ores-lru.toml", "[redis]\nurlEnv = \"REDIS_URL\"\n"),
        ]);
        assert!(has(&report, "runtime-secret-env-exposed-via-cli"));
    }

    #[test]
    fn fanwaave_secret_binding_is_cross_checked_against_flags() {
        let report = audit(&[
            (
                ".cli-flags.toml",
                "[flags.auth]\nenv = \"FANWAAVE_AUTH_TOKEN\"\ntype = \"string\"\n",
            ),
            (
                ".fanwaave-cfg.toml",
                "[flags2env]\ncontract = \".cli-flags.toml\"\n[[env]]\nkey = \"FANWAAVE_AUTH_TOKEN\"\nsecret = true\n",
            ),
        ]);
        assert!(has(&report, "runtime-secret-env-exposed-via-cli"));
    }

    #[test]
    fn runtime_family_must_reference_canonical_cli_contract() {
        let report = audit(&[(
            ".ores-mw.toml",
            "[flags2env]\ncontract = \"other-flags.toml\"\n",
        )]);
        assert!(has(&report, "runtime-flags2env-contract-mismatch"));
    }
}
