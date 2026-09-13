use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde_json::json;
use toml::Value;

use super::{RepositoryAuditOptions, runtime_toml_registry::REGISTERED_RUNTIME_CONFIGS};
use crate::model::{CommandReport, Finding};

const CLI_FLAGS: &str = ".cli-flags.toml";
const MAX_CONFIG_BYTES: u64 = 512 * 1024;

#[derive(Debug, Default)]
struct EnvEntry {
    sources: BTreeSet<String>,
    public_cli_bindings: BTreeSet<String>,
    control_bindings: BTreeSet<String>,
    required_by: BTreeSet<String>,
    optional_by: BTreeSet<String>,
    secret_by: BTreeSet<String>,
    nonsecret_by: BTreeSet<String>,
    cli_default_by: BTreeSet<String>,
    types: BTreeMap<String, BTreeSet<String>>,
}

/// Derive one value-free runtime-environment inventory from the two repository
/// declaration families that already own the boundary:
///
/// - `.cli-flags.toml` declares environment keys that flags2env may emit from
///   public argv flags, command markers, or parser channels;
/// - registered runtime TOMLs declare runtime-only keys and attach runtime
///   policy such as `required`, `secret`, and symbolic type.
///
/// Requiredness is intentionally derived only from explicit runtime-TOML
/// `required=true`. A CLI flag without a default is not automatically a runtime
/// requirement, and a secret runtime key never needs to become a public flag in
/// order to appear in this inventory. Environment values and literal defaults
/// are never read or reflected.
pub(super) fn augment_runtime_env_contract_audit(
    options: &RepositoryAuditOptions,
    mut report: CommandReport,
) -> CommandReport {
    let mut entries = BTreeMap::<String, EnvEntry>::new();
    let mut duplicate_runtime_declarations = 0usize;

    if let Some(document) = read_bounded_toml(&options.path.join(CLI_FLAGS)) {
        collect_cli_entries(&document, "root", &mut entries);
    }

    for name in REGISTERED_RUNTIME_CONFIGS {
        let Some(document) = read_bounded_toml(&options.path.join(name)) else {
            continue;
        };
        let mut per_file = BTreeMap::<String, BTreeSet<String>>::new();
        collect_runtime_entries(&document, "root", name, &mut entries, &mut per_file);
        for (key, locations) in per_file {
            if locations.len() <= 1 {
                continue;
            }
            duplicate_runtime_declarations += 1;
            report.push(
                Finding::error(
                    "runtime-env-duplicate-declaration",
                    "the same environment key is declared more than once within one runtime TOML",
                )
                .with_target(key)
                .with_detail("source", json!(name))
                .with_detail("declarations", json!(locations)),
            );
        }
    }

    let mut required_keys = Vec::new();
    let mut optional_keys = Vec::new();
    let mut unspecified_keys = Vec::new();
    let mut secret_keys = Vec::new();
    let mut public_cli_keys = Vec::new();
    let mut control_keys = Vec::new();
    let mut inventory = Vec::new();
    let mut role_conflicts = 0usize;
    let mut type_conflicts = 0usize;
    let mut secret_conflicts = 0usize;

    for (key, entry) in &entries {
        if entry.public_cli_bindings.len() > 1 {
            role_conflicts += 1;
            report.push(
                Finding::error(
                    "runtime-env-cli-public-binding-collision",
                    "one environment key is bound to multiple public CLI flags; use one canonical flag plus aliases",
                )
                .with_target(key.clone())
                .with_detail("bindings", json!(entry.public_cli_bindings)),
            );
        }
        if !entry.public_cli_bindings.is_empty() && !entry.control_bindings.is_empty() {
            role_conflicts += 1;
            report.push(
                Finding::error(
                    "runtime-env-cli-role-collision",
                    "one environment key is used both as a public flag value and as flags2env command/parser control state",
                )
                .with_target(key.clone())
                .with_detail("publicBindings", json!(entry.public_cli_bindings))
                .with_detail("controlBindings", json!(entry.control_bindings)),
            );
        }

        if incompatible_types(&entry.types) {
            type_conflicts += 1;
            report.push(
                Finding::error(
                    "runtime-env-type-conflict",
                    "one environment key has incompatible symbolic types across CLI/runtime declarations",
                )
                .with_target(key.clone())
                .with_detail("types", json!(entry.types)),
            );
        }

        if !entry.secret_by.is_empty() && !entry.nonsecret_by.is_empty() {
            secret_conflicts += 1;
            report.push(
                Finding::error(
                    "runtime-env-secret-conflict",
                    "one environment key is classified as both secret and non-secret across runtime TOMLs",
                )
                .with_target(key.clone())
                .with_detail("secretBy", json!(entry.secret_by))
                .with_detail("nonSecretBy", json!(entry.nonsecret_by)),
            );
        }

        let requiredness = if !entry.required_by.is_empty() {
            required_keys.push(key.clone());
            "required"
        } else if !entry.optional_by.is_empty() {
            optional_keys.push(key.clone());
            "optional"
        } else {
            unspecified_keys.push(key.clone());
            "unspecified"
        };
        let secret = !entry.secret_by.is_empty();
        if secret {
            secret_keys.push(key.clone());
        }
        if !entry.public_cli_bindings.is_empty() {
            public_cli_keys.push(key.clone());
        }
        if !entry.control_bindings.is_empty() {
            control_keys.push(key.clone());
        }

        inventory.push(json!({
            "key": key,
            "sources": entry.sources,
            "publicCliBindings": entry.public_cli_bindings,
            "controlBindings": entry.control_bindings,
            "requiredBy": entry.required_by,
            "optionalBy": entry.optional_by,
            "requiredness": requiredness,
            "secretBy": entry.secret_by,
            "nonSecretBy": entry.nonsecret_by,
            "secret": secret,
            "environmentOnly": secret && entry.public_cli_bindings.is_empty(),
            "cliDefaultDeclaredBy": entry.cli_default_by,
            "types": entry.types,
        }));
    }

    report.insert_metadata("runtimeEnvContract", json!(inventory));
    report.insert_metadata("runtimeEnvContractKeyCount", json!(entries.len()));
    report.insert_metadata("runtimeEnvRequiredKeys", json!(required_keys));
    report.insert_metadata("runtimeEnvRequiredKeyCount", json!(required_keys.len()));
    report.insert_metadata("runtimeEnvOptionalKeys", json!(optional_keys));
    report.insert_metadata("runtimeEnvOptionalKeyCount", json!(optional_keys.len()));
    report.insert_metadata("runtimeEnvRequirednessUnspecifiedKeys", json!(unspecified_keys));
    report.insert_metadata(
        "runtimeEnvRequirednessUnspecifiedKeyCount",
        json!(unspecified_keys.len()),
    );
    report.insert_metadata("runtimeEnvSecretKeys", json!(secret_keys));
    report.insert_metadata("runtimeEnvSecretKeyCount", json!(secret_keys.len()));
    report.insert_metadata("runtimeEnvPublicCliKeys", json!(public_cli_keys));
    report.insert_metadata("runtimeEnvControlKeys", json!(control_keys));
    report.insert_metadata(
        "runtimeEnvDuplicateDeclarationCount",
        json!(duplicate_runtime_declarations),
    );
    report.insert_metadata("runtimeEnvRoleConflictCount", json!(role_conflicts));
    report.insert_metadata("runtimeEnvTypeConflictCount", json!(type_conflicts));
    report.insert_metadata("runtimeEnvSecretConflictCount", json!(secret_conflicts));
    report.insert_metadata("runtimeEnvValuesRead", json!(false));
    report.insert_metadata("runtimeEnvLiteralDefaultsRead", json!(false));
    report.insert_metadata(
        "runtimeEnvAuthorities",
        json!([CLI_FLAGS, "registered-runtime-tomls"]),
    );

    if !entries.is_empty()
        && duplicate_runtime_declarations == 0
        && role_conflicts == 0
        && type_conflicts == 0
        && secret_conflicts == 0
    {
        report.push(Finding::info(
            "runtime-env-contract-derived",
            "derived a deterministic runtime environment inventory from .cli-flags.toml plus registered runtime TOMLs without reading values",
        ));
    }

    report.finalize()
}

fn collect_cli_entries(value: &Value, path: &str, entries: &mut BTreeMap<String, EnvEntry>) {
    match value {
        Value::Table(table) => {
            if let Some(key) = table
                .get("env")
                .and_then(Value::as_str)
                .filter(|key| valid_env_key(key))
            {
                let entry = entries.entry(key.to_owned()).or_default();
                entry.sources.insert(CLI_FLAGS.to_owned());
                let location = format!("{CLI_FLAGS}:{path}.env");
                if path.split('.').any(|segment| segment == "flags") {
                    entry.public_cli_bindings.insert(location.clone());
                    if table.contains_key("default") {
                        entry.cli_default_by.insert(location.clone());
                    }
                    if let Some(kind) = table
                        .get("type")
                        .and_then(Value::as_str)
                        .and_then(normalize_type)
                    {
                        entry
                            .types
                            .entry(kind.to_owned())
                            .or_default()
                            .insert(location);
                    }
                } else {
                    entry.control_bindings.insert(location);
                }
            }

            for control in [
                "command_env",
                "positionals_env",
                "unknown_options_env",
                "errors_env",
            ] {
                if let Some(key) = table
                    .get(control)
                    .and_then(Value::as_str)
                    .filter(|key| valid_env_key(key))
                {
                    let location = format!("{CLI_FLAGS}:{path}.{control}");
                    let entry = entries.entry(key.to_owned()).or_default();
                    entry.sources.insert(CLI_FLAGS.to_owned());
                    entry.control_bindings.insert(location);
                }
            }

            for (name, child) in table {
                let child_path = format!("{path}.{name}");
                collect_cli_entries(child, &child_path, entries);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                collect_cli_entries(child, &format!("{path}[{index}]"), entries);
            }
        }
        _ => {}
    }
}

fn collect_runtime_entries(
    value: &Value,
    path: &str,
    source: &str,
    entries: &mut BTreeMap<String, EnvEntry>,
    per_file: &mut BTreeMap<String, BTreeSet<String>>,
) {
    match value {
        Value::Table(table) => {
            if let Some(key) = env_name_from_table(table, path) {
                let location = format!("{source}:{path}");
                let entry = entries.entry(key.clone()).or_default();
                entry.sources.insert(source.to_owned());
                per_file
                    .entry(key)
                    .or_default()
                    .insert(location.clone());

                if let Some(required) = table.get("required").and_then(Value::as_bool) {
                    if required {
                        entry.required_by.insert(location.clone());
                    } else {
                        entry.optional_by.insert(location.clone());
                    }
                }
                if let Some(secret) = table.get("secret").and_then(Value::as_bool) {
                    if secret {
                        entry.secret_by.insert(location.clone());
                    } else {
                        entry.nonsecret_by.insert(location.clone());
                    }
                }
                if let Some(kind) = ["kind", "valueType", "type"]
                    .iter()
                    .find_map(|name| table.get(*name).and_then(Value::as_str))
                    .and_then(normalize_type)
                {
                    entry
                        .types
                        .entry(kind.to_owned())
                        .or_default()
                        .insert(location);
                }
            }

            for (name, child) in table {
                let child_path = format!("{path}.{name}");
                collect_runtime_entries(child, &child_path, source, entries, per_file);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                collect_runtime_entries(
                    child,
                    &format!("{path}[{index}]"),
                    source,
                    entries,
                    per_file,
                );
            }
        }
        _ => {}
    }
}

fn env_name_from_table(table: &toml::map::Map<String, Value>, path: &str) -> Option<String> {
    for name in ["env", "env_var", "envVar"] {
        if let Some(key) = table
            .get(name)
            .and_then(Value::as_str)
            .filter(|key| valid_env_key(key))
        {
            return Some(key.to_owned());
        }
    }
    if path.to_ascii_lowercase().contains("env") {
        for name in ["key", "name"] {
            if let Some(key) = table
                .get(name)
                .and_then(Value::as_str)
                .filter(|key| valid_env_key(key))
            {
                return Some(key.to_owned());
            }
        }
    }
    None
}

fn read_bounded_toml(path: &Path) -> Option<Value> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES
    {
        return None;
    }
    fs::read_to_string(path).ok()?.parse::<Value>().ok()
}

fn normalize_type(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "string" => Some("string"),
        "url" => Some("url"),
        "bool" | "boolean" => Some("bool"),
        "int" | "integer" => Some("integer"),
        "float" | "double" | "number" => Some("double"),
        "json" => Some("json"),
        "array" | "string[]" => Some("array"),
        "map" | "object" => Some("map"),
        _ => None,
    }
}

fn incompatible_types(types: &BTreeMap<String, BTreeSet<String>>) -> bool {
    if types.len() <= 1 {
        return false;
    }
    types.keys().any(|kind| kind != "string" && kind != "url")
}

fn valid_env_key(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_uppercase() || byte == b'_')
        && value.len() <= 128
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::augment_runtime_env_contract_audit;
    use crate::audit::RepositoryAuditOptions;
    use crate::model::CommandReport;

    fn audit(flags: &str, runtime: &[(&str, &str)]) -> CommandReport {
        let root = tempdir().expect("temporary repository");
        if !flags.is_empty() {
            fs::write(root.path().join(".cli-flags.toml"), flags).expect("CLI contract");
        }
        for (name, contents) in runtime {
            fs::write(root.path().join(name), contents).expect("runtime TOML");
        }
        augment_runtime_env_contract_audit(
            &RepositoryAuditOptions {
                path: root.path().to_path_buf(),
                profile: "baseline".to_owned(),
                additional_required_paths: Vec::new(),
            },
            CommandReport::new("runtime env contract fixture"),
        )
    }

    fn has(report: &CommandReport, code: &str) -> bool {
        report.findings.iter().any(|finding| finding.code == code)
    }

    #[test]
    fn derives_required_union_without_promoting_secret_to_cli() {
        let report = audit(
            "[flags.port]\nenv='PORT'\ntype='integer'\ndefault=8080\n[commands.serve]\nenv='ORES_SERVE'\n[parse]\nerrors_env='FLAGS2ENV_ERRORS'\n",
            &[
                (
                    ".ores-otel.toml",
                    "[[env]]\nkey='PORT'\nkind='integer'\nrequired=true\nsecret=false\n",
                ),
                (
                    ".shared-auth.toml",
                    "[[env]]\nkey='AUTH_SIGNING_KEY'\nkind='string'\nrequired=true\nsecret=true\n",
                ),
            ],
        );
        assert_eq!(report.metadata["runtimeEnvContractKeyCount"], 4);
        assert_eq!(report.metadata["runtimeEnvRequiredKeyCount"], 2);
        assert_eq!(report.metadata["runtimeEnvSecretKeyCount"], 1);
        assert_eq!(report.metadata["runtimeEnvValuesRead"], false);
        let required = report.metadata["runtimeEnvRequiredKeys"]
            .as_array()
            .expect("required array");
        assert!(required.iter().any(|value| value == "AUTH_SIGNING_KEY"));
        assert!(required.iter().any(|value| value == "PORT"));
    }

    #[test]
    fn required_optional_disagreement_is_evidence_not_a_conflict() {
        let report = audit(
            "",
            &[
                (
                    ".ores-otel.toml",
                    "[[env]]\nkey='PORT'\nkind='integer'\nrequired=true\nsecret=false\n",
                ),
                (
                    ".ores-mw.toml",
                    "[[env]]\nkey='PORT'\nkind='integer'\nrequired=false\nsecret=false\n",
                ),
            ],
        );
        assert!(!has(&report, "runtime-env-type-conflict"));
        assert!(!has(&report, "runtime-env-secret-conflict"));
        assert_eq!(report.metadata["runtimeEnvRequiredKeyCount"], 1);
    }

    #[test]
    fn rejects_public_flag_and_command_control_collision() {
        let report = audit(
            "[flags.mode]\nenv='APP_MODE'\ntype='string'\n[commands.run]\nenv='APP_MODE'\n",
            &[],
        );
        assert!(has(&report, "runtime-env-cli-role-collision"));
    }

    #[test]
    fn rejects_runtime_secret_and_type_conflicts() {
        let report = audit(
            "",
            &[
                (
                    ".ores-chat.toml",
                    "[[env]]\nkey='SHARED_KEY'\nkind='integer'\nrequired=true\nsecret=true\n",
                ),
                (
                    ".ores-rpc.toml",
                    "[[env]]\nenv='SHARED_KEY'\nvalueType='boolean'\nrequired=false\nsecret=false\n",
                ),
            ],
        );
        assert!(has(&report, "runtime-env-type-conflict"));
        assert!(has(&report, "runtime-env-secret-conflict"));
    }

    #[test]
    fn accepts_string_url_process_boundary_compatibility() {
        let report = audit(
            "[flags.endpoint]\nenv='SERVICE_URL'\ntype='string'\n",
            &[(
                ".ores-rpc.toml",
                "[[env]]\nenv='SERVICE_URL'\nvalueType='url'\nrequired=true\nsecret=false\n",
            )],
        );
        assert!(!has(&report, "runtime-env-type-conflict"));
    }

    #[test]
    fn rejects_duplicate_runtime_key_within_one_authority() {
        let report = audit(
            "",
            &[(
                ".ores-mw.toml",
                "[[env]]\nkey='PORT'\nkind='integer'\nrequired=true\n[[env]]\nkey='PORT'\nkind='integer'\nrequired=true\n",
            )],
        );
        assert!(has(&report, "runtime-env-duplicate-declaration"));
    }

    #[test]
    fn never_reflects_literal_defaults_or_environment_values() {
        let secret = "do-not-reflect-this-value";
        let report = audit(
            "[flags.port]\nenv='PORT'\ntype='integer'\ndefault=9000\n",
            &[(
                ".ores-chat.toml",
                &format!(
                    "[[env]]\nkey='CHAT_TOKEN'\nkind='string'\nrequired=true\nsecret=true\ndefault='{secret}'\n"
                ),
            )],
        );
        let rendered = serde_json::to_string(&report.metadata).expect("metadata JSON");
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains("9000"));
        assert_eq!(report.metadata["runtimeEnvLiteralDefaultsRead"], false);
    }
}
