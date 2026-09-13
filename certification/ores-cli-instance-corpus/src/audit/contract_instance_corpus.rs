use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::json;
use walkdir::{DirEntry, WalkDir};

use super::RepositoryAuditOptions;
use crate::model::{CommandReport, Finding};

const CONTRACTS_DIRECTORY: &str = "contracts";
const TYPESPEC_FILE: &str = "main.tsp";
const JSON_SCHEMA_FILE: &str = "authored.schema.json";
const INSTANCES_DIRECTORY: &str = "instances";
const VALID_DIRECTORY: &str = "valid";
const INVALID_DIRECTORY: &str = "invalid";
const MAX_CORPORA: usize = 256;
const MAX_MODEL_DIRECTORIES: usize = 256;
const MAX_FIXTURES_PER_CLASS: usize = 512;
const MAX_FIXTURE_BYTES: u64 = 1024 * 1024;
const MAX_WALK_DEPTH: usize = 16;
const MAX_FIXTURE_DEPTH: usize = 4;

/// Extend repository admission with bounded checks for TJSV-style instance corpora.
///
/// This lane intentionally does not decide whether a fixture should satisfy or
/// violate an authored schema. TJSV owns semantic instance admission. `ores-cli`
/// only verifies that an opted-in `instances/<Model>/{valid,invalid}` corpus is
/// structurally reviewable, JSON-decodable, bounded, non-symlinked, and contains
/// both positive and negative evidence classes.
pub(super) fn augment_contract_instance_corpus_audit(
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
        // The nested peer-authority lane owns root-shape diagnostics.
        return report.finalize();
    }

    let mut corpus_count = 0usize;
    let mut model_count = 0usize;
    let mut valid_fixture_count = 0usize;
    let mut invalid_fixture_count = 0usize;
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
        if entry.depth() == 0 || entry.file_name() != INSTANCES_DIRECTORY {
            continue;
        }

        let Some(contract_home) = entry.path().parent() else {
            continue;
        };
        if !has_peer_authorities(contract_home) {
            continue;
        }

        if corpus_count >= MAX_CORPORA {
            if !overflow_reported {
                report.push(
                    Finding::error(
                        "contract-instance-corpus-limit",
                        format!(
                            "more than {MAX_CORPORA} contract instance corpora were discovered; split or narrow the contracts tree"
                        ),
                    )
                    .with_target(CONTRACTS_DIRECTORY),
                );
                overflow_reported = true;
            }
            continue;
        }
        corpus_count += 1;

        let instances = entry.path();
        let target = relative_display(&options.path, instances);
        let instances_metadata = match fs::symlink_metadata(instances) {
            Ok(metadata) => metadata,
            Err(_) => {
                report.push(
                    Finding::error(
                        "contract-instance-corpus-unreadable",
                        "instance corpus metadata could not be read",
                    )
                    .with_target(target),
                );
                continue;
            }
        };
        if instances_metadata.file_type().is_symlink() {
            report.push(
                Finding::error(
                    "contract-instance-corpus-symlink",
                    "instance corpus must not be a symbolic link",
                )
                .with_target(target),
            );
            continue;
        }
        if !instances_metadata.is_dir() {
            report.push(
                Finding::error(
                    "contract-instance-corpus-not-directory",
                    "instances must be a directory when present",
                )
                .with_target(target),
            );
            continue;
        }

        let models = match fs::read_dir(instances) {
            Ok(models) => models,
            Err(_) => {
                report.push(
                    Finding::error(
                        "contract-instance-corpus-unreadable",
                        "instance corpus directory could not be read",
                    )
                    .with_target(relative_display(&options.path, instances)),
                );
                continue;
            }
        };

        let mut corpus_models = 0usize;
        for model in models {
            let Ok(model) = model else {
                continue;
            };
            let path = model.path();
            let model_target = relative_display(&options.path, &path);
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            if metadata.file_type().is_symlink() {
                report.push(
                    Finding::error(
                        "contract-instance-model-symlink",
                        "instance model directory must not be a symbolic link",
                    )
                    .with_target(model_target),
                );
                continue;
            }
            if !metadata.is_dir() {
                // README/manifest files at the instances root are permitted.
                continue;
            }
            if corpus_models >= MAX_MODEL_DIRECTORIES {
                report.push(
                    Finding::error(
                        "contract-instance-model-limit",
                        format!(
                            "instance corpus exceeds the {MAX_MODEL_DIRECTORIES}-model audit bound"
                        ),
                    )
                    .with_target(relative_display(&options.path, instances)),
                );
                break;
            }
            corpus_models += 1;
            model_count += 1;

            let valid = path.join(VALID_DIRECTORY);
            let invalid = path.join(INVALID_DIRECTORY);
            let valid_state = class_state(&options.path, &valid, &mut report);
            let invalid_state = class_state(&options.path, &invalid, &mut report);

            if !valid_state.present && !invalid_state.present {
                // Preserve compatibility with older direct-fixture layouts. The
                // paired-class policy activates only once either class exists.
                continue;
            }
            if !valid_state.present || !invalid_state.present {
                let missing = if valid_state.present {
                    INVALID_DIRECTORY
                } else {
                    VALID_DIRECTORY
                };
                report.push(
                    Finding::error(
                        "contract-instance-fixture-class-missing",
                        format!(
                            "paired TJSV corpus is missing its {missing} fixture directory"
                        ),
                    )
                    .with_target(model_target),
                );
            }

            if valid_state.auditable {
                valid_fixture_count += audit_fixture_class(
                    &options.path,
                    &valid,
                    VALID_DIRECTORY,
                    &mut report,
                );
            }
            if invalid_state.auditable {
                invalid_fixture_count += audit_fixture_class(
                    &options.path,
                    &invalid,
                    INVALID_DIRECTORY,
                    &mut report,
                );
            }
        }
    }

    report.insert_metadata("contractInstanceCorpusCount", json!(corpus_count));
    report.insert_metadata("contractInstanceModelCount", json!(model_count));
    report.insert_metadata("contractValidFixtureCount", json!(valid_fixture_count));
    report.insert_metadata("contractInvalidFixtureCount", json!(invalid_fixture_count));
    if corpus_count > 0 {
        report.push(
            Finding::info(
                "contract-instance-corpora-inspected",
                format!(
                    "inspected {corpus_count} contract instance corpus{} with {valid_fixture_count} valid and {invalid_fixture_count} invalid JSON fixture{}",
                    if corpus_count == 1 { "" } else { "a" },
                    if valid_fixture_count + invalid_fixture_count == 1 {
                        ""
                    } else {
                        "s"
                    }
                ),
            )
            .with_target(CONTRACTS_DIRECTORY),
        );
    }

    report.finalize()
}

#[derive(Debug, Clone, Copy)]
struct ClassState {
    present: bool,
    auditable: bool,
}

fn class_state(root: &Path, path: &Path, report: &mut CommandReport) -> ClassState {
    let target = relative_display(root, path);
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return ClassState {
                present: false,
                auditable: false,
            };
        }
        Err(_) => {
            report.push(
                Finding::error(
                    "contract-instance-fixture-class-unreadable",
                    "fixture-class metadata could not be read",
                )
                .with_target(target),
            );
            return ClassState {
                present: true,
                auditable: false,
            };
        }
    };
    if metadata.file_type().is_symlink() {
        report.push(
            Finding::error(
                "contract-instance-fixture-class-symlink",
                "fixture-class directory must not be a symbolic link",
            )
            .with_target(target),
        );
        return ClassState {
            present: true,
            auditable: false,
        };
    }
    if !metadata.is_dir() {
        report.push(
            Finding::error(
                "contract-instance-fixture-class-not-directory",
                "fixture class must be a directory",
            )
            .with_target(target),
        );
        return ClassState {
            present: true,
            auditable: false,
        };
    }
    ClassState {
        present: true,
        auditable: true,
    }
}

fn audit_fixture_class(
    root: &Path,
    directory: &Path,
    class: &str,
    report: &mut CommandReport,
) -> usize {
    let mut count = 0usize;
    let mut overflow_reported = false;
    let walker = WalkDir::new(directory)
        .follow_links(false)
        .max_depth(MAX_FIXTURE_DEPTH)
        .into_iter();

    for result in walker {
        let entry = match result {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        if entry.depth() == 0 {
            continue;
        }
        let path = entry.path();
        let target = relative_display(root, path);
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.file_type().is_symlink() {
            report.push(
                Finding::error(
                    "contract-instance-fixture-symlink",
                    "contract instance fixture tree must not contain symbolic links",
                )
                .with_target(target),
            );
            continue;
        }
        if metadata.is_dir() {
            continue;
        }
        if !metadata.is_file() {
            report.push(
                Finding::error(
                    "contract-instance-fixture-not-regular",
                    "contract instance fixture must be a regular file",
                )
                .with_target(target),
            );
            continue;
        }
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        if count >= MAX_FIXTURES_PER_CLASS {
            if !overflow_reported {
                report.push(
                    Finding::error(
                        "contract-instance-fixture-limit",
                        format!(
                            "{class} fixture class exceeds the {MAX_FIXTURES_PER_CLASS}-file audit bound"
                        ),
                    )
                    .with_target(relative_display(root, directory)),
                );
                overflow_reported = true;
            }
            continue;
        }
        count += 1;
        if metadata.len() > MAX_FIXTURE_BYTES {
            report.push(
                Finding::error(
                    "contract-instance-fixture-too-large",
                    format!(
                        "contract instance fixture exceeds the {MAX_FIXTURE_BYTES}-byte audit bound"
                    ),
                )
                .with_target(target),
            );
            continue;
        }
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(_) => {
                report.push(
                    Finding::error(
                        "contract-instance-fixture-not-utf8",
                        "contract instance fixture must be UTF-8 JSON",
                    )
                    .with_target(target),
                );
                continue;
            }
        };
        if serde_json::from_str::<serde_json::Value>(&text).is_err() {
            report.push(
                Finding::error(
                    "contract-instance-fixture-invalid-json",
                    "contract instance fixture is not valid JSON",
                )
                .with_target(target),
            );
        }
    }

    if count == 0 {
        report.push(
            Finding::error(
                "contract-instance-fixture-class-empty",
                format!("{class} fixture class must contain at least one JSON fixture"),
            )
            .with_target(relative_display(root, directory)),
        );
    }
    count
}

fn has_peer_authorities(contract_home: &Path) -> bool {
    is_regular_file(&contract_home.join(TYPESPEC_FILE))
        && is_regular_file(&contract_home.join(JSON_SCHEMA_FILE))
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
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

    use super::{MAX_FIXTURE_BYTES, augment_contract_instance_corpus_audit};
    use crate::audit::RepositoryAuditOptions;
    use crate::model::CommandReport;

    fn audit(setup: impl FnOnce(&std::path::Path)) -> CommandReport {
        let root = tempdir().expect("temporary repository");
        setup(root.path());
        augment_contract_instance_corpus_audit(
            &RepositoryAuditOptions {
                path: root.path().to_path_buf(),
                profile: "baseline".to_owned(),
                additional_required_paths: Vec::new(),
            },
            CommandReport::new("audit repo"),
        )
    }

    fn write_peer_contract(root: &std::path::Path, relative: &str) -> std::path::PathBuf {
        let contract = root.join(relative);
        fs::create_dir_all(&contract).expect("contract directory");
        fs::write(
            contract.join("main.tsp"),
            "namespace Example;\nmodel Packet { value: string; }\n",
        )
        .expect("TypeSpec authority");
        fs::write(
            contract.join("authored.schema.json"),
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}"#,
        )
        .expect("JSON Schema authority");
        contract
    }

    fn write_fixture(path: &std::path::Path, name: &str, content: &str) {
        fs::create_dir_all(path).expect("fixture directory");
        fs::write(path.join(name), content).expect("fixture");
    }

    #[test]
    fn accepts_people_style_positive_and_negative_corpus() {
        let report = audit(|root| {
            let contract = write_peer_contract(root, "contracts/people/v1");
            let model = contract.join("instances/PeopleDirectory");
            write_fixture(
                &model.join("valid"),
                "canonical.json",
                r#"{"schemaVersion":"people/v1","people":[{"name":"Eugene Li","role":"business/legal counsel"}]}"#,
            );
            write_fixture(
                &model.join("invalid"),
                "missing-role.json",
                r#"{"schemaVersion":"people/v1","people":[{"name":"Eugene Li"}]}"#,
            );
        });
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
        assert_eq!(
            report.metadata.get("contractValidFixtureCount"),
            Some(&JsonValue::from(1))
        );
        assert_eq!(
            report.metadata.get("contractInvalidFixtureCount"),
            Some(&JsonValue::from(1))
        );
    }

    #[test]
    fn rejects_one_sided_fixture_classes() {
        let report = audit(|root| {
            let contract = write_peer_contract(root, "contracts/readiness-offerings");
            let model = contract.join("instances/ReadinessOfferingCatalog");
            write_fixture(&model.join("valid"), "catalog.json", r#"{"tiers":[]}"#);
        });
        assert!(report.findings.iter().any(|finding| {
            finding.code == "contract-instance-fixture-class-missing"
        }));
    }

    #[test]
    fn rejects_empty_and_malformed_json_fixture_classes() {
        let report = audit(|root| {
            let contract = write_peer_contract(root, "contracts/example");
            let model = contract.join("instances/Example");
            write_fixture(&model.join("valid"), "broken.json", "{not-json");
            fs::create_dir_all(model.join("invalid")).expect("invalid fixture class");
        });
        for code in [
            "contract-instance-fixture-invalid-json",
            "contract-instance-fixture-class-empty",
        ] {
            assert!(report.findings.iter().any(|finding| finding.code == code));
        }
    }

    #[test]
    fn direct_fixture_layout_and_missing_instances_remain_compatible() {
        let report = audit(|root| {
            let direct = write_peer_contract(root, "contracts/direct");
            write_fixture(
                &direct.join("instances/DirectModel"),
                "canonical.json",
                r#"{"value":"legacy direct fixture"}"#,
            );
            write_peer_contract(root, "contracts/no-instances");
        });
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
    }

    #[test]
    fn rejects_oversized_fixture_without_decoding_it() {
        let report = audit(|root| {
            let contract = write_peer_contract(root, "contracts/oversized");
            let model = contract.join("instances/Example");
            fs::create_dir_all(model.join("valid")).expect("valid class");
            fs::write(
                model.join("valid/large.json"),
                vec![b' '; MAX_FIXTURE_BYTES as usize + 1],
            )
            .expect("oversized fixture");
            write_fixture(&model.join("invalid"), "negative.json", r#"{"bad":true}"#);
        });
        assert!(report.findings.iter().any(|finding| {
            finding.code == "contract-instance-fixture-too-large"
        }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks_inside_fixture_evidence() {
        use std::os::unix::fs::symlink;

        let report = audit(|root| {
            let contract = write_peer_contract(root, "contracts/symlinked");
            let model = contract.join("instances/Example");
            let valid = model.join("valid");
            write_fixture(&valid, "canonical.json", r#"{"ok":true}"#);
            write_fixture(&model.join("invalid"), "negative.json", r#"{"bad":true}"#);
            symlink(valid.join("canonical.json"), valid.join("alias.json"))
                .expect("fixture symlink");
        });
        assert!(report.findings.iter().any(|finding| {
            finding.code == "contract-instance-fixture-symlink"
        }));
    }
}
