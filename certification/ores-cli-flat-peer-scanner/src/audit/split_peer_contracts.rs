use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Value as JsonValue, json};

use super::RepositoryAuditOptions;
use crate::model::{CommandReport, Finding};

const TYPESPEC_DIRECTORY: &str = "contracts/typespec";
const JSON_SCHEMA_DIRECTORY: &str = "contracts/json-schema";
const TYPESPEC_SUFFIX: &str = ".tsp";
const JSON_SCHEMA_SUFFIX: &str = ".schema.json";
const JSON_SCHEMA_DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";
const MAX_SPLIT_CONTRACT_SLICES: usize = 256;
const MAX_CONTRACT_FILE_BYTES: u64 = 2 * 1024 * 1024;
const TYPESPEC_SUPPORT_FILES: [&str; 2] = ["main.tsp", "ores.tsp"];
const CONFLICT_MARKERS: [&str; 3] = ["<<<<<<<", "=======", ">>>>>>>"];

#[derive(Debug, Default)]
struct SlicePair {
    typespec: Option<PathBuf>,
    schema: Option<PathBuf>,
}

/// Audit the split peer-authority layout used by interface repositories:
///
/// - `contracts/typespec/<slice>.tsp`; and
/// - `contracts/json-schema/<slice>.schema.json`.
///
/// The two files are independent authored peers. This pass deliberately does
/// not transpile, compare, or choose an authority: compiler-backed TJSV remains
/// responsible for emitting TypeSpec's comparison-only Schema B and comparing
/// it with authored Schema A. Repository audit only proves that both source
/// lanes are present, bounded, independently editable, and structurally sane.
pub(super) fn augment_split_peer_contract_audit(
    options: &RepositoryAuditOptions,
    mut report: CommandReport,
) -> CommandReport {
    let typespec_root = options.path.join(TYPESPEC_DIRECTORY);
    let schema_root = options.path.join(JSON_SCHEMA_DIRECTORY);
    let typespec_present = audit_lane_root(
        &typespec_root,
        TYPESPEC_DIRECTORY,
        "split-typespec-root",
        &mut report,
    );
    let schema_present = audit_lane_root(
        &schema_root,
        JSON_SCHEMA_DIRECTORY,
        "split-json-schema-root",
        &mut report,
    );

    if !typespec_present && !schema_present {
        return report.finalize();
    }

    let mut slices = BTreeMap::<String, SlicePair>::new();
    let mut overflow_reported = false;

    if typespec_present {
        match fs::read_dir(&typespec_root) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if TYPESPEC_SUPPORT_FILES.contains(&name.as_str()) {
                        continue;
                    }
                    let Some(slice) = name.strip_suffix(TYPESPEC_SUFFIX) else {
                        continue;
                    };
                    if slice.is_empty() {
                        continue;
                    }
                    if !insert_candidate(&mut slices, slice, &mut overflow_reported, &mut report) {
                        continue;
                    }
                    slices.entry(slice.to_owned()).or_default().typespec = Some(entry.path());
                }
            }
            Err(error) => report.push(
                Finding::error(
                    "split-typespec-root-unreadable",
                    format!("could not enumerate split TypeSpec authority lane: {error}"),
                )
                .with_target(TYPESPEC_DIRECTORY),
            ),
        }
    }

    if schema_present {
        match fs::read_dir(&schema_root) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    let Some(slice) = name.strip_suffix(JSON_SCHEMA_SUFFIX) else {
                        continue;
                    };
                    if slice.is_empty() {
                        continue;
                    }
                    if !insert_candidate(&mut slices, slice, &mut overflow_reported, &mut report) {
                        continue;
                    }
                    slices.entry(slice.to_owned()).or_default().schema = Some(entry.path());
                }
            }
            Err(error) => report.push(
                Finding::error(
                    "split-json-schema-root-unreadable",
                    format!("could not enumerate split JSON Schema authority lane: {error}"),
                )
                .with_target(JSON_SCHEMA_DIRECTORY),
            ),
        }
    }

    report.insert_metadata("splitContractCandidateCount", json!(slices.len()));

    let mut valid_pairs = 0usize;
    for (slice, pair) in slices {
        match (pair.typespec, pair.schema) {
            (Some(typespec), Some(schema)) => {
                let before = report.issue_count();
                audit_typespec(&options.path, &typespec, &mut report);
                audit_json_schema(&options.path, &schema, &mut report);
                if report.issue_count() == before {
                    valid_pairs += 1;
                }
            }
            (Some(typespec), None) => report.push(
                Finding::error(
                    "split-authored-json-schema-missing",
                    format!(
                        "TypeSpec slice `{slice}` exists without independently authored JSON Schema peer `contracts/json-schema/{slice}.schema.json`"
                    ),
                )
                .with_target(relative_display(&options.path, &typespec)),
            ),
            (None, Some(schema)) => report.push(
                Finding::error(
                    "split-typespec-source-missing",
                    format!(
                        "JSON Schema slice `{slice}` exists without independently authored TypeSpec peer `contracts/typespec/{slice}.tsp`"
                    ),
                )
                .with_target(relative_display(&options.path, &schema)),
            ),
            (None, None) => {}
        }
    }

    report.insert_metadata("splitContractValidPairCount", json!(valid_pairs));
    if valid_pairs > 0 {
        report.push(
            Finding::info(
                "split-peer-contracts-inspected",
                format!(
                    "inspected {valid_pairs} split TypeSpec/JSON Schema peer-authority pair{}",
                    if valid_pairs == 1 { "" } else { "s" }
                ),
            )
            .with_target("contracts"),
        );
    }

    report.finalize()
}

fn audit_lane_root(
    path: &Path,
    target: &str,
    code_prefix: &str,
    report: &mut CommandReport,
) -> bool {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return false,
        Err(error) => {
            report.push(
                Finding::error(
                    format!("{code_prefix}-unreadable"),
                    format!("authority lane metadata could not be read: {error}"),
                )
                .with_target(target),
            );
            return false;
        }
    };
    if metadata.file_type().is_symlink() {
        report.push(
            Finding::error(
                format!("{code_prefix}-symlink"),
                "authority lane must not be a symbolic link",
            )
            .with_target(target),
        );
        return false;
    }
    if !metadata.is_dir() {
        report.push(
            Finding::error(
                format!("{code_prefix}-not-directory"),
                "authority lane must be a directory when present",
            )
            .with_target(target),
        );
        return false;
    }
    true
}

fn insert_candidate(
    slices: &mut BTreeMap<String, SlicePair>,
    slice: &str,
    overflow_reported: &mut bool,
    report: &mut CommandReport,
) -> bool {
    if slices.contains_key(slice) {
        return true;
    }
    if slices.len() < MAX_SPLIT_CONTRACT_SLICES {
        slices.insert(slice.to_owned(), SlicePair::default());
        return true;
    }
    if !*overflow_reported {
        report.push(
            Finding::error(
                "split-contract-pair-limit",
                format!(
                    "more than {MAX_SPLIT_CONTRACT_SLICES} split contract slices were discovered"
                ),
            )
            .with_target("contracts"),
        );
        *overflow_reported = true;
    }
    false
}

fn audit_typespec(root: &Path, path: &Path, report: &mut CommandReport) {
    let target = relative_display(root, path);
    let Some(text) = read_regular_bounded_file(root, path, "TypeSpec", report) else {
        return;
    };
    if text.trim().is_empty() {
        report.push(
            Finding::error(
                "split-typespec-empty",
                "TypeSpec peer authority must not be empty",
            )
            .with_target(target),
        );
        return;
    }
    audit_conflict_markers(&text, "split-typespec-conflict-marker", &target, report);
}

fn audit_json_schema(root: &Path, path: &Path, report: &mut CommandReport) {
    let target = relative_display(root, path);
    let Some(text) = read_regular_bounded_file(root, path, "JSON Schema", report) else {
        return;
    };
    audit_conflict_markers(&text, "split-json-schema-conflict-marker", &target, report);

    let document = match serde_json::from_str::<JsonValue>(&text) {
        Ok(document) => document,
        Err(error) => {
            report.push(
                Finding::error(
                    "split-json-schema-invalid",
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
                "split-json-schema-root-shape",
                "authored JSON Schema root must be an object",
            )
            .with_target(target),
        );
        return;
    };
    if object.get("$schema").and_then(JsonValue::as_str) != Some(JSON_SCHEMA_DRAFT) {
        report.push(
            Finding::error(
                "split-json-schema-draft",
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
                "split-json-schema-id-shape",
                "$id must be a non-empty string when present",
            )
            .with_target(target.clone()),
        );
    }
    if object.get("$defs").is_some_and(|value| !value.is_object()) {
        report.push(
            Finding::error(
                "split-json-schema-defs-shape",
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
                    "split-contract-file-unreadable",
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
                "split-contract-file-symlink",
                format!("{authority} authority must not be a symbolic link"),
            )
            .with_target(target),
        );
        return None;
    }
    if !metadata.is_file() {
        report.push(
            Finding::error(
                "split-contract-file-not-regular",
                format!("{authority} authority must be a regular file"),
            )
            .with_target(target),
        );
        return None;
    }
    if metadata.len() > MAX_CONTRACT_FILE_BYTES {
        report.push(
            Finding::error(
                "split-contract-file-too-large",
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
                    "split-contract-file-not-utf8",
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
        .collect::<Vec<_>>();
    if !markers.is_empty() {
        report.push(
            Finding::error(
                code,
                format!(
                    "authored authority contains unresolved conflict marker{}: {}",
                    if markers.len() == 1 { "" } else { "s" },
                    markers.join(", ")
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

    use super::augment_split_peer_contract_audit;
    use crate::audit::RepositoryAuditOptions;
    use crate::model::CommandReport;

    fn audit(setup: impl FnOnce(&std::path::Path)) -> CommandReport {
        let root = tempdir().expect("temporary repository");
        setup(root.path());
        augment_split_peer_contract_audit(
            &RepositoryAuditOptions {
                path: root.path().to_path_buf(),
                profile: "baseline".to_owned(),
                additional_required_paths: Vec::new(),
            },
            CommandReport::new("audit repo"),
        )
    }

    fn write_split_pair(root: &std::path::Path, slice: &str) {
        let typespec = root.join("contracts/typespec");
        let schema = root.join("contracts/json-schema");
        fs::create_dir_all(&typespec).expect("TypeSpec lane");
        fs::create_dir_all(&schema).expect("JSON Schema lane");
        fs::write(
            typespec.join(format!("{slice}.tsp")),
            format!("namespace Example;\nmodel {slice} {{ value: string; }}\n"),
        )
        .expect("TypeSpec authority");
        fs::write(
            schema.join(format!("{slice}.schema.json")),
            format!(
                r#"{{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://example.test/{slice}.schema.json","type":"object","properties":{{"value":{{"type":"string"}}}},"required":["value"],"unevaluatedProperties":false}}"#
            ),
        )
        .expect("JSON Schema authority");
    }

    #[test]
    fn accepts_multiple_split_peer_pairs_and_ignores_typespec_support_files() {
        let report = audit(|root| {
            write_split_pair(root, "identity");
            write_split_pair(root, "workers");
            let typespec = root.join("contracts/typespec");
            fs::write(typespec.join("main.tsp"), "import \"./identity.tsp\";\n")
                .expect("aggregate TypeSpec");
            fs::write(typespec.join("ores.tsp"), "namespace Ores;\n").expect("support TypeSpec");
            fs::write(
                typespec.join("ores-decorators.js"),
                "export function noop() {}\n",
            )
            .expect("decorator runtime");
        });
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
        assert_eq!(
            report.metadata.get("splitContractCandidateCount"),
            Some(&JsonValue::from(2))
        );
        assert_eq!(
            report.metadata.get("splitContractValidPairCount"),
            Some(&JsonValue::from(2))
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "split-peer-contracts-inspected")
        );
    }

    #[test]
    fn rejects_one_sided_split_slices_in_both_directions() {
        let report = audit(|root| {
            let typespec = root.join("contracts/typespec");
            let schema = root.join("contracts/json-schema");
            fs::create_dir_all(&typespec).expect("TypeSpec lane");
            fs::create_dir_all(&schema).expect("JSON Schema lane");
            fs::write(typespec.join("workers.tsp"), "model Worker {}\n").expect("TypeSpec");
            fs::write(
                schema.join("runs.schema.json"),
                r#"{"$schema":"https://json-schema.org/draft/2020-12/schema"}"#,
            )
            .expect("schema");
        });
        for code in [
            "split-authored-json-schema-missing",
            "split-typespec-source-missing",
        ] {
            assert!(report.findings.iter().any(|finding| finding.code == code));
        }
    }

    #[test]
    fn rejects_wrong_draft_invalid_json_and_empty_typespec() {
        let report = audit(|root| {
            let typespec = root.join("contracts/typespec");
            let schema = root.join("contracts/json-schema");
            fs::create_dir_all(&typespec).expect("TypeSpec lane");
            fs::create_dir_all(&schema).expect("JSON Schema lane");

            fs::write(typespec.join("wrong.tsp"), "model Wrong {}\n").expect("TypeSpec");
            fs::write(
                schema.join("wrong.schema.json"),
                r#"{"$schema":"http://json-schema.org/draft-07/schema#"}"#,
            )
            .expect("wrong draft");

            fs::write(typespec.join("invalid.tsp"), "model Invalid {}\n").expect("TypeSpec");
            fs::write(schema.join("invalid.schema.json"), "{not-json").expect("invalid JSON");

            fs::write(typespec.join("empty.tsp"), " \n").expect("empty TypeSpec");
            fs::write(
                schema.join("empty.schema.json"),
                r#"{"$schema":"https://json-schema.org/draft/2020-12/schema"}"#,
            )
            .expect("schema");
        });
        for code in [
            "split-json-schema-draft",
            "split-json-schema-invalid",
            "split-typespec-empty",
        ] {
            assert!(report.findings.iter().any(|finding| finding.code == code));
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_split_lane_and_authority_file() {
        use std::os::unix::fs::symlink;

        let lane = audit(|root| {
            fs::create_dir_all(root.join("outside")).expect("outside");
            fs::create_dir_all(root.join("contracts")).expect("contracts");
            symlink(root.join("outside"), root.join("contracts/typespec")).expect("lane symlink");
        });
        assert!(
            lane.findings
                .iter()
                .any(|finding| finding.code == "split-typespec-root-symlink")
        );

        let file = audit(|root| {
            let typespec = root.join("contracts/typespec");
            let schema = root.join("contracts/json-schema");
            fs::create_dir_all(&typespec).expect("TypeSpec lane");
            fs::create_dir_all(&schema).expect("JSON Schema lane");
            let outside = root.join("outside.tsp");
            fs::write(&outside, "model Worker {}\n").expect("outside");
            symlink(&outside, typespec.join("workers.tsp")).expect("TypeSpec symlink");
            fs::write(
                schema.join("workers.schema.json"),
                r#"{"$schema":"https://json-schema.org/draft/2020-12/schema"}"#,
            )
            .expect("schema");
        });
        assert!(
            file.findings
                .iter()
                .any(|finding| finding.code == "split-contract-file-symlink")
        );
    }
}
