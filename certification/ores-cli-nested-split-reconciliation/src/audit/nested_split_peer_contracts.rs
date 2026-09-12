use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Value as JsonValue, json};
use walkdir::{DirEntry, WalkDir};

use super::RepositoryAuditOptions;
use crate::model::{CommandReport, Finding};

const CONTRACTS_DIRECTORY: &str = "contracts";
const TYPESPEC_DIRECTORY: &str = "typespec";
const JSON_SCHEMA_DIRECTORY: &str = "json-schema";
const TYPESPEC_FILE: &str = "main.tsp";
const JSON_SCHEMA_SUFFIX: &str = ".schema.json";
const JSON_SCHEMA_DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";
const MAX_CONTRACT_ROOTS: usize = 256;
const MAX_CONTRACT_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_WALK_DEPTH: usize = 16;
const CONFLICT_MARKERS: [&str; 3] = ["<<<<<<<", "=======", ">>>>>>>"];

#[derive(Debug, Default)]
struct NestedSplitCandidate {
    typespec: Option<PathBuf>,
    schemas: Vec<PathBuf>,
}

/// Audit nested split peer-authority layouts such as:
///
/// `contracts/graph-analysis/typespec/main.tsp`
/// `contracts/graph-analysis/json-schema/graph-analysis.schema.json`
///
/// TypeSpec and the independently authored Draft 2020-12 JSON Schema are equal
/// source authorities. A TypeSpec-generated JSON Schema is comparison evidence
/// only and is explicitly excluded from authored-schema discovery here. Semantic
/// parity and generated Schema B remain the responsibility of TJSV.
pub(super) fn augment_nested_split_peer_contract_audit(
    options: &RepositoryAuditOptions,
    mut report: CommandReport,
) -> CommandReport {
    let contracts_root = options.path.join(CONTRACTS_DIRECTORY);
    let metadata = match fs::symlink_metadata(&contracts_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return report.finalize(),
        Err(_) => return report.finalize(),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return report.finalize();
    }

    let mut candidates = BTreeMap::<PathBuf, NestedSplitCandidate>::new();
    let mut overflow_reported = false;
    let walker = WalkDir::new(&contracts_root)
        .follow_links(false)
        .max_depth(MAX_WALK_DEPTH)
        .into_iter()
        .filter_entry(should_descend);

    for result in walker {
        let entry = match result {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };

        if entry.file_type().is_symlink()
            && matches!(name, TYPESPEC_DIRECTORY | JSON_SCHEMA_DIRECTORY)
        {
            report.push(
                Finding::error(
                    "nested-split-authority-lane-symlink",
                    "nested split authority lane must not be a symbolic link",
                )
                .with_target(relative_display(&options.path, path)),
            );
            continue;
        }

        let Some(parent) = path.parent() else {
            continue;
        };
        let Some(parent_name) = parent.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let is_typespec = parent_name == TYPESPEC_DIRECTORY && name == TYPESPEC_FILE;
        let is_schema = parent_name == JSON_SCHEMA_DIRECTORY
            && name.ends_with(JSON_SCHEMA_SUFFIX)
            && !is_generated_schema(name);
        if !is_typespec && !is_schema {
            continue;
        }

        let Some(contract_root) = parent.parent() else {
            continue;
        };
        if contract_root == contracts_root {
            // `contracts/typespec/main.tsp` belongs to a different supported
            // split layout and is handled by `split_peer_contracts`.
            continue;
        }
        let relative_root = contract_root
            .strip_prefix(&options.path)
            .unwrap_or(contract_root)
            .to_path_buf();
        if !candidates.contains_key(&relative_root) && candidates.len() >= MAX_CONTRACT_ROOTS {
            if !overflow_reported {
                report.push(
                    Finding::error(
                        "nested-split-contract-pair-limit",
                        format!(
                            "more than {MAX_CONTRACT_ROOTS} nested split contract roots were discovered"
                        ),
                    )
                    .with_target(CONTRACTS_DIRECTORY),
                );
                overflow_reported = true;
            }
            continue;
        }

        let candidate = candidates.entry(relative_root).or_default();
        if is_typespec {
            if candidate.typespec.replace(path.to_path_buf()).is_some() {
                report.push(
                    Finding::error(
                        "nested-split-duplicate-typespec",
                        "nested split contract root resolved more than one TypeSpec entry",
                    )
                    .with_target(relative_display(&options.path, path)),
                );
            }
        } else {
            candidate.schemas.push(path.to_path_buf());
        }
    }

    report.insert_metadata(
        "nestedSplitPeerContractCandidateCount",
        json!(candidates.len()),
    );

    let mut valid_pairs = 0usize;
    let mut valid_typespec_dirs = BTreeSet::<String>::new();
    let mut valid_schema_dirs = BTreeSet::<String>::new();

    for (contract_root, mut candidate) in candidates {
        candidate.schemas.sort();
        let target = relative_display(&options.path, &options.path.join(&contract_root));
        match (candidate.typespec, candidate.schemas.as_slice()) {
            (Some(typespec), [schema]) => {
                let before = report.issue_count();
                audit_typespec(&options.path, &typespec, &mut report);
                audit_json_schema(&options.path, schema, &mut report);
                if report.issue_count() == before {
                    valid_pairs += 1;
                    if let Some(typespec_dir) = typespec.parent() {
                        valid_typespec_dirs.insert(relative_display(&options.path, typespec_dir));
                    }
                    if let Some(schema_dir) = schema.parent() {
                        valid_schema_dirs.insert(relative_display(&options.path, schema_dir));
                    }
                }
            }
            (Some(_), []) => report.push(
                Finding::error(
                    "nested-split-authored-json-schema-missing",
                    format!(
                        "{TYPESPEC_DIRECTORY}/{TYPESPEC_FILE} exists without one independently authored {JSON_SCHEMA_DIRECTORY}/*{JSON_SCHEMA_SUFFIX} peer"
                    ),
                )
                .with_target(target),
            ),
            (None, [_]) => report.push(
                Finding::error(
                    "nested-split-typespec-source-missing",
                    format!(
                        "{JSON_SCHEMA_DIRECTORY}/*{JSON_SCHEMA_SUFFIX} exists without the independently authored {TYPESPEC_DIRECTORY}/{TYPESPEC_FILE} peer"
                    ),
                )
                .with_target(target),
            ),
            (_, schemas) if schemas.len() > 1 => report.push(
                Finding::error(
                    "nested-split-authored-json-schema-ambiguous",
                    format!(
                        "nested split contract root contains {} authored JSON Schema candidates; exactly one is required",
                        schemas.len()
                    ),
                )
                .with_target(target)
                .with_detail("schemaCount", JsonValue::from(schemas.len())),
            ),
            (None, []) => {}
            _ => {}
        }
    }

    // `nested_peer_contracts` predates the split layout and sees
    // `typespec/main.tsp` as an incomplete co-located pair. Reconcile only its
    // specific legacy missing-peer finding after a complete split pair passes
    // every structural check above. Likewise, if the authored schema happens to
    // be named `authored.schema.json`, remove the mirror legacy finding for the
    // JSON-Schema lane. Invalid or ambiguous split pairs remain fail closed.
    if !valid_typespec_dirs.is_empty() || !valid_schema_dirs.is_empty() {
        report.findings.retain(|finding| {
            let target = finding.target.as_deref();
            let legacy_typespec_false_positive = finding.code == "nested-authored-json-schema-missing"
                && target.is_some_and(|value| valid_typespec_dirs.contains(value));
            let legacy_schema_false_positive = finding.code == "nested-typespec-source-missing"
                && target.is_some_and(|value| valid_schema_dirs.contains(value));
            !legacy_typespec_false_positive && !legacy_schema_false_positive
        });
    }

    report.insert_metadata("nestedSplitPeerContractValidPairCount", json!(valid_pairs));
    if valid_pairs > 0 {
        report.push(
            Finding::info(
                "nested-split-peer-contracts-inspected",
                format!(
                    "inspected {valid_pairs} nested split TypeSpec/JSON Schema peer-authority pair{}",
                    if valid_pairs == 1 { "" } else { "s" }
                ),
            )
            .with_target(CONTRACTS_DIRECTORY),
        );
    }

    report.finalize()
}

fn is_generated_schema(file_name: &str) -> bool {
    file_name == "typespec.generated.schema.json" || file_name.contains(".generated.")
}

fn should_descend(entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    let name = entry.file_name().to_string_lossy();
    !matches!(
        name.as_ref(),
        ".git" | "target" | "node_modules" | ".dart_tool" | ".typespec-json-schema-validator"
    )
}

fn audit_typespec(root: &Path, path: &Path, report: &mut CommandReport) {
    let target = relative_display(root, path);
    let Some(text) = read_regular_bounded_file(root, path, "TypeSpec", report) else {
        return;
    };
    if text.trim().is_empty() {
        report.push(
            Finding::error(
                "nested-split-typespec-empty",
                "TypeSpec peer authority must not be empty",
            )
            .with_target(target),
        );
        return;
    }
    audit_conflict_markers(
        &text,
        "nested-split-typespec-conflict-marker",
        &target,
        report,
    );
}

fn audit_json_schema(root: &Path, path: &Path, report: &mut CommandReport) {
    let target = relative_display(root, path);
    let Some(text) = read_regular_bounded_file(root, path, "JSON Schema", report) else {
        return;
    };
    audit_conflict_markers(
        &text,
        "nested-split-json-schema-conflict-marker",
        &target,
        report,
    );

    let document = match serde_json::from_str::<JsonValue>(&text) {
        Ok(document) => document,
        Err(error) => {
            report.push(
                Finding::error(
                    "nested-split-json-schema-invalid",
                    format!("authored JSON Schema is not valid JSON: {error}"),
                )
                .with_target(target),
            );
            return;
        }
    };
    let Some(object) = document.as_object() else {
        report.push(
            Finding::error(
                "nested-split-json-schema-root-shape",
                "authored JSON Schema root must be an object",
            )
            .with_target(target),
        );
        return;
    };
    if object.get("$schema").and_then(JsonValue::as_str) != Some(JSON_SCHEMA_DRAFT) {
        report.push(
            Finding::error(
                "nested-split-json-schema-draft",
                format!("authored JSON Schema must declare {JSON_SCHEMA_DRAFT}"),
            )
            .with_target(target.clone()),
        );
    }
    if object
        .get("$id")
        .is_some_and(|value| value.as_str().is_none_or(str::is_empty))
    {
        report.push(
            Finding::error(
                "nested-split-json-schema-id-shape",
                "$id must be a non-empty string when present",
            )
            .with_target(target.clone()),
        );
    }
    if object.get("$defs").is_some_and(|value| !value.is_object()) {
        report.push(
            Finding::error(
                "nested-split-json-schema-defs-shape",
                "$defs must be an object when present",
            )
            .with_target(target),
        );
    }
}

fn read_regular_bounded_file(
    root: &Path,
    path: &Path,
    authority: &str,
    report: &mut CommandReport,
) -> Option<String> {
    let target = relative_display(root, path);
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            report.push(
                Finding::error(
                    "nested-split-contract-file-unreadable",
                    format!("{authority} authority metadata could not be read: {error}"),
                )
                .with_target(target),
            );
            return None;
        }
    };
    if metadata.file_type().is_symlink() {
        report.push(
            Finding::error(
                "nested-split-contract-file-symlink",
                format!("{authority} authority must not be a symbolic link"),
            )
            .with_target(target),
        );
        return None;
    }
    if !metadata.is_file() {
        report.push(
            Finding::error(
                "nested-split-contract-file-not-regular",
                format!("{authority} authority must be a regular file"),
            )
            .with_target(target),
        );
        return None;
    }
    if metadata.len() > MAX_CONTRACT_FILE_BYTES {
        report.push(
            Finding::error(
                "nested-split-contract-file-too-large",
                format!(
                    "{authority} authority exceeds the {MAX_CONTRACT_FILE_BYTES}-byte audit bound"
                ),
            )
            .with_target(target),
        );
        return None;
    }
    match fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(error) => {
            report.push(
                Finding::error(
                    "nested-split-contract-file-not-utf8",
                    format!("{authority} authority could not be read as UTF-8: {error}"),
                )
                .with_target(target),
            );
            None
        }
    }
}

fn audit_conflict_markers(text: &str, code: &str, target: &str, report: &mut CommandReport) {
    let markers = text
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            CONFLICT_MARKERS
                .iter()
                .find(|marker| line.starts_with(*marker))
                .copied()
        })
        .collect::<BTreeSet<_>>();
    if !markers.is_empty() {
        report.push(
            Finding::error(
                code,
                format!(
                    "authored authority contains unresolved conflict marker{}: {}",
                    if markers.len() == 1 { "" } else { "s" },
                    markers.into_iter().collect::<Vec<_>>().join(", ")
                ),
            )
            .with_target(target.to_owned()),
        );
    }
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::Value as JsonValue;
    use tempfile::tempdir;

    use super::augment_nested_split_peer_contract_audit;
    use crate::audit::{RepositoryAuditOptions, nested_peer_contracts};
    use crate::model::CommandReport;

    fn audit(setup: impl FnOnce(&std::path::Path)) -> CommandReport {
        let root = tempdir().expect("temporary repository");
        setup(root.path());
        let options = RepositoryAuditOptions {
            path: root.path().to_path_buf(),
            profile: "baseline".to_owned(),
            additional_required_paths: Vec::new(),
        };
        let report = nested_peer_contracts::augment_nested_peer_contract_audit(
            &options,
            CommandReport::new("audit repo"),
        );
        augment_nested_split_peer_contract_audit(&options, report)
    }

    fn write_pair(root: &std::path::Path, contract_name: &str, schema_name: &str) {
        let contract = root.join("contracts").join(contract_name);
        fs::create_dir_all(contract.join("typespec")).expect("TypeSpec lane");
        fs::create_dir_all(contract.join("json-schema")).expect("JSON Schema lane");
        fs::write(
            contract.join("typespec/main.tsp"),
            "namespace Example;\nmodel Packet { value: string; }\n",
        )
        .expect("TypeSpec authority");
        fs::write(
            contract.join("json-schema").join(schema_name),
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://example.test/packet.schema.json","type":"object","properties":{"value":{"type":"string"}},"required":["value"],"unevaluatedProperties":false}"#,
        )
        .expect("JSON Schema authority");
    }

    #[test]
    fn accepts_claritas_style_nested_split_pair_and_reconciles_legacy_lint() {
        let report = audit(|root| write_pair(root, "graph-analysis", "graph-analysis.schema.json"));
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
        assert!(report.findings.iter().any(|finding| {
            finding.code == "nested-split-peer-contracts-inspected"
        }));
        assert!(!report.findings.iter().any(|finding| {
            finding.code == "nested-authored-json-schema-missing"
        }));
        assert_eq!(
            report.metadata.get("nestedSplitPeerContractValidPairCount"),
            Some(&JsonValue::from(1))
        );
    }

    #[test]
    fn generated_schema_is_evidence_not_an_authored_peer() {
        let report = audit(|root| {
            let contract = root.join("contracts/graph-analysis");
            fs::create_dir_all(contract.join("typespec")).expect("TypeSpec lane");
            fs::create_dir_all(contract.join("json-schema")).expect("JSON Schema lane");
            fs::write(contract.join("typespec/main.tsp"), "model Packet {}\n")
                .expect("TypeSpec authority");
            fs::write(
                contract.join("json-schema/typespec.generated.schema.json"),
                r#"{"$schema":"https://json-schema.org/draft/2020-12/schema"}"#,
            )
            .expect("generated comparison schema");
        });
        assert!(report.findings.iter().any(|finding| {
            finding.code == "nested-split-authored-json-schema-missing"
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.code == "nested-authored-json-schema-missing"
        }));
    }

    #[test]
    fn rejects_ambiguous_authored_schema_candidates() {
        let report = audit(|root| {
            write_pair(root, "graph-analysis", "graph-analysis.schema.json");
            fs::write(
                root.join("contracts/graph-analysis/json-schema/alternate.schema.json"),
                r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#,
            )
            .expect("alternate schema");
        });
        assert!(report.findings.iter().any(|finding| {
            finding.code == "nested-split-authored-json-schema-ambiguous"
        }));
    }

    #[test]
    fn rejects_schema_without_typespec_peer() {
        let report = audit(|root| {
            let schema = root.join("contracts/query/json-schema");
            fs::create_dir_all(&schema).expect("JSON Schema lane");
            fs::write(
                schema.join("query.schema.json"),
                r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#,
            )
            .expect("JSON Schema authority");
        });
        assert!(report.findings.iter().any(|finding| {
            finding.code == "nested-split-typespec-source-missing"
        }));
    }

    #[test]
    fn invalid_schema_draft_keeps_legacy_fail_closed_finding() {
        let report = audit(|root| {
            write_pair(root, "graph-analysis", "graph-analysis.schema.json");
            fs::write(
                root.join("contracts/graph-analysis/json-schema/graph-analysis.schema.json"),
                r#"{"$schema":"http://json-schema.org/draft-07/schema#","type":"object"}"#,
            )
            .expect("drifted schema");
        });
        assert!(report.findings.iter().any(|finding| {
            finding.code == "nested-split-json-schema-draft"
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.code == "nested-authored-json-schema-missing"
        }));
    }

    #[test]
    fn authored_dot_schema_name_reconciles_both_legacy_lane_findings() {
        let report = audit(|root| write_pair(root, "query", "authored.schema.json"));
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
        assert!(!report.findings.iter().any(|finding| {
            matches!(
                finding.code.as_str(),
                "nested-authored-json-schema-missing" | "nested-typespec-source-missing"
            )
        }));
    }
}
