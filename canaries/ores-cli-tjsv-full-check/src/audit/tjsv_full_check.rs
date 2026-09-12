use std::collections::{BTreeMap, BTreeSet};
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
const MAX_CONTRACT_DIRECTORIES: usize = 256;
const MAX_EXECUTION_FILES: usize = 256;
const MAX_EXECUTION_FILE_BYTES: u64 = 1024 * 1024;
const MAX_WALK_DEPTH: usize = 16;

#[derive(Debug, Default)]
struct PairCandidate {
    typespec: bool,
    schema: bool,
}

#[derive(Debug)]
struct ExecutionFile {
    path: String,
    text: String,
}

/// Require every complete TypeSpec + independently authored JSON Schema pair
/// to have repository-owned evidence that executes the full compiler-backed
/// TJSV `check` lane.
///
/// `tjsv check` compiles TypeSpec with the official JSON Schema emitter,
/// creates a generated JSON Schema witness outside both authored authorities,
/// compares normalized generated/authored declarations, and executes both
/// schemas over the differential instance corpus. This audit does not recreate
/// those semantics; it proves that a repository invokes the authority that does.
pub(super) fn augment_tjsv_full_check_audit(
    options: &RepositoryAuditOptions,
    mut report: CommandReport,
) -> CommandReport {
    let pairs = discover_complete_pairs(&options.path, &mut report);
    if pairs.is_empty() {
        report.insert_metadata("tjsvDualAuthorityPairCount", json!(0));
        report.insert_metadata("tjsvFullCheckCoveredPairCount", json!(0));
        return report.finalize();
    }

    let execution_files = discover_execution_files(&options.path, &mut report);
    report.insert_metadata("tjsvDualAuthorityPairCount", json!(pairs.len()));
    report.insert_metadata("tjsvExecutionFileCount", json!(execution_files.len()));

    let mut covered = 0usize;
    for directory in pairs {
        let typespec = format!("{directory}/{TYPESPEC_FILE}");
        let schema = format!("{directory}/{JSON_SCHEMA_FILE}");
        let covering = execution_files
            .iter()
            .filter(|file| invocation_covers_pair(&file.text, &typespec, &schema))
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>();

        if covering.is_empty() {
            report.push(
                Finding::error(
                    "tjsv-full-check-missing",
                    format!(
                        "peer authorities {typespec} and {schema} require a fail-closed full `tjsv check` invocation that names both authored inputs"
                    ),
                )
                .with_target(directory),
            );
        } else {
            covered += 1;
            report.push(
                Finding::info(
                    "tjsv-full-check-covered",
                    format!(
                        "full compiler/emitter/normalized-JSON/differential admission is declared in {}",
                        covering.join(", ")
                    ),
                )
                .with_target(directory),
            );
        }
    }

    report.insert_metadata("tjsvFullCheckCoveredPairCount", json!(covered));
    report.finalize()
}

fn discover_complete_pairs(root: &Path, report: &mut CommandReport) -> Vec<String> {
    let contracts = root.join(CONTRACTS_DIRECTORY);
    let metadata = match fs::symlink_metadata(&contracts) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(_) => return Vec::new(),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Vec::new();
    }

    let mut candidates = BTreeMap::<PathBuf, PairCandidate>::new();
    let walker = WalkDir::new(&contracts)
        .follow_links(false)
        .max_depth(MAX_WALK_DEPTH)
        .into_iter()
        .filter_entry(should_descend);

    for entry in walker.flatten() {
        let name = entry.file_name().to_string_lossy();
        if name != TYPESPEC_FILE && name != JSON_SCHEMA_FILE {
            continue;
        }
        if entry.file_type().is_symlink() || !entry.file_type().is_file() {
            continue;
        }
        let Some(parent) = entry.path().parent() else {
            continue;
        };
        let Ok(relative) = parent.strip_prefix(root) else {
            continue;
        };
        if !candidates.contains_key(relative) && candidates.len() >= MAX_CONTRACT_DIRECTORIES {
            report.push(
                Finding::error(
                    "tjsv-full-check-pair-limit",
                    format!(
                        "more than {MAX_CONTRACT_DIRECTORIES} contract homes were discovered while checking TJSV execution coverage"
                    ),
                )
                .with_target(CONTRACTS_DIRECTORY),
            );
            break;
        }
        let candidate = candidates.entry(relative.to_path_buf()).or_default();
        if name == TYPESPEC_FILE {
            candidate.typespec = true;
        } else {
            candidate.schema = true;
        }
    }

    candidates
        .into_iter()
        .filter_map(|(directory, candidate)| {
            (candidate.typespec && candidate.schema).then(|| normalize_path(&directory))
        })
        .collect()
}

fn discover_execution_files(root: &Path, report: &mut CommandReport) -> Vec<ExecutionFile> {
    let mut paths = BTreeSet::<PathBuf>::new();
    for relative in [".github/workflows", "scripts"] {
        let directory = root.join(relative);
        let Ok(metadata) = fs::symlink_metadata(&directory) else {
            continue;
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        for entry in WalkDir::new(&directory)
            .follow_links(false)
            .max_depth(8)
            .into_iter()
            .filter_entry(should_descend)
            .flatten()
        {
            if entry.file_type().is_file() && !entry.file_type().is_symlink() {
                paths.insert(entry.path().to_path_buf());
            }
        }
    }
    for relative in ["Makefile", "justfile", "Taskfile.yml", "Taskfile.yaml", "package.json"] {
        let path = root.join(relative);
        if fs::symlink_metadata(&path)
            .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        {
            paths.insert(path);
        }
    }

    if paths.len() > MAX_EXECUTION_FILES {
        report.push(
            Finding::error(
                "tjsv-execution-file-limit",
                format!(
                    "more than {MAX_EXECUTION_FILES} workflow/script files were discovered while checking TJSV execution coverage"
                ),
            )
            .with_target(".github/workflows"),
        );
        paths = paths.into_iter().take(MAX_EXECUTION_FILES).collect();
    }

    paths
        .into_iter()
        .filter_map(|path| {
            let metadata = fs::symlink_metadata(&path).ok()?;
            if metadata.len() > MAX_EXECUTION_FILE_BYTES {
                report.push(
                    Finding::error(
                        "tjsv-execution-file-too-large",
                        format!(
                            "TJSV execution evidence file exceeds {MAX_EXECUTION_FILE_BYTES} bytes"
                        ),
                    )
                    .with_target(relative_display(root, &path)),
                );
                return None;
            }
            let text = match fs::read_to_string(&path) {
                Ok(text) => text,
                Err(_) => {
                    report.push(
                        Finding::error(
                            "tjsv-execution-file-unreadable",
                            "TJSV execution evidence file must be readable UTF-8",
                        )
                        .with_target(relative_display(root, &path)),
                    );
                    return None;
                }
            };
            Some(ExecutionFile {
                path: relative_display(root, &path),
                text,
            })
        })
        .collect()
}

fn invocation_covers_pair(text: &str, typespec: &str, schema: &str) -> bool {
    let normalized = text.replace('\\', "/");
    let lower = normalized.to_ascii_lowercase();
    let action = lower.contains("uses: oresoftware/typespec-json-schema-validator@");
    let command = lower.contains("tjsv check")
        || lower.contains("typespec-json-schema-validator check")
        || lower.contains("tsjsv check");
    if !action && !command {
        return false;
    }

    path_variants(typespec)
        .iter()
        .any(|path| normalized.contains(path.as_str()))
        && path_variants(schema)
            .iter()
            .any(|path| normalized.contains(path.as_str()))
}

fn path_variants(path: &str) -> [String; 3] {
    [path.to_owned(), format!("./{path}"), format!("$GITHUB_WORKSPACE/{path}")]
}

fn should_descend(entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    !matches!(
        entry.file_name().to_string_lossy().as_ref(),
        ".git"
            | "target"
            | "node_modules"
            | ".dart_tool"
            | ".typespec-json-schema-validator"
            | "generated"
            | "dist"
            | "build"
            | "vendor"
            | "tmp"
            | "temp"
    )
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn relative_display(root: &Path, path: &Path) -> String {
    normalize_path(path.strip_prefix(root).unwrap_or(path))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::augment_tjsv_full_check_audit;
    use crate::audit::RepositoryAuditOptions;
    use crate::model::CommandReport;

    fn run(workflow: &str) -> CommandReport {
        let root = tempdir().expect("temporary repository");
        let contract = root.path().join("contracts/example");
        fs::create_dir_all(&contract).expect("contract directory");
        fs::write(
            contract.join("main.tsp"),
            "namespace Example;\nmodel Packet { value: string; }\n",
        )
        .expect("TypeSpec authority");
        fs::write(
            contract.join("authored.schema.json"),
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","$defs":{"Packet":{"type":"object"}}}"#,
        )
        .expect("authored JSON Schema");
        let workflows = root.path().join(".github/workflows");
        fs::create_dir_all(&workflows).expect("workflow directory");
        fs::write(workflows.join("contracts.yml"), workflow).expect("workflow");

        augment_tjsv_full_check_audit(
            &RepositoryAuditOptions {
                path: root.path().to_path_buf(),
                profile: "baseline".to_owned(),
                additional_required_paths: Vec::new(),
            },
            CommandReport::new("audit repo"),
        )
    }

    #[test]
    fn accepts_full_check_with_both_independent_authorities() {
        let report = run(
            "run: npx tjsv check --typespec=contracts/example/main.tsp --schema=contracts/example/authored.schema.json --report=artifacts/parity.json\n",
        );
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "tjsv-full-check-covered")
        );
    }

    #[test]
    fn accepts_pinned_action_with_both_independent_authorities() {
        let report = run(
            "- uses: ORESoftware/typespec-json-schema-validator@0123456789012345678901234567890123456789\n  with:\n    typespec: contracts/example/main.tsp\n    schema: contracts/example/authored.schema.json\n",
        );
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "tjsv-full-check-covered")
        );
    }

    #[test]
    fn rejects_inventory_without_compiler_emitter_compare_lane() {
        let report = run("run: npx tjsv inventory --typespec=contracts/example/main.tsp\n");
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "tjsv-full-check-missing")
        );
    }

    #[test]
    fn rejects_compare_only_evidence() {
        let report = run(
            "run: npx tjsv compare --typespec=contracts/example/main.tsp --generated-schema=tmp/generated.json --schema=contracts/example/authored.schema.json\n",
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "tjsv-full-check-missing")
        );
    }

    #[test]
    fn rejects_check_that_names_only_one_authority() {
        let report = run("run: npx tjsv check --typespec=contracts/example/main.tsp\n");
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "tjsv-full-check-missing")
        );
    }

    #[test]
    fn one_invocation_does_not_cover_a_different_contract_home() {
        let root = tempdir().expect("temporary repository");
        for name in ["one", "two"] {
            let contract = root.path().join(format!("contracts/{name}"));
            fs::create_dir_all(&contract).expect("contract directory");
            fs::write(contract.join("main.tsp"), "model Packet {}\n").expect("TypeSpec");
            fs::write(
                contract.join("authored.schema.json"),
                r#"{"$schema":"https://json-schema.org/draft/2020-12/schema"}"#,
            )
            .expect("schema");
        }
        let workflows = root.path().join(".github/workflows");
        fs::create_dir_all(&workflows).expect("workflows");
        fs::write(
            workflows.join("contracts.yml"),
            "run: npx tjsv check --typespec=contracts/one/main.tsp --schema=contracts/one/authored.schema.json\n",
        )
        .expect("workflow");

        let report = augment_tjsv_full_check_audit(
            &RepositoryAuditOptions {
                path: root.path().to_path_buf(),
                profile: "baseline".to_owned(),
                additional_required_paths: Vec::new(),
            },
            CommandReport::new("audit repo"),
        );
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|finding| finding.code == "tjsv-full-check-covered")
                .count(),
            1
        );
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|finding| finding.code == "tjsv-full-check-missing")
                .count(),
            1
        );
    }
}
