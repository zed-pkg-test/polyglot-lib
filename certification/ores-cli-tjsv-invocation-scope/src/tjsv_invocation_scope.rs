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
const TJSV_ACTION_PREFIX: &str = "oresoftware/typespec-json-schema-validator@";

#[derive(Debug, Default)]
struct PairCandidate {
    typespec: bool,
    schema: bool,
}

#[derive(Debug)]
struct ExecutionFile {
    path: String,
    text: String,
    workflow: bool,
}

/// Reject peer-authority coverage that is assembled from unrelated workflow
/// steps instead of one executable TJSV admission step.
///
/// TypeSpec and Draft 2020-12 JSON Schema remain independent, first-class
/// authored authorities. TJSV transpiles TypeSpec through the official emitter
/// to generated Schema B and compares that evidence with independently authored
/// Schema A. This audit only strengthens the repository-owned wiring proof: the
/// command/action, both authored paths, parity receipt destination, and generated
/// Schema-B destination must coexist in one workflow step. Non-workflow scripts
/// keep their existing file-level interpretation.
pub(super) fn augment_tjsv_invocation_scope_audit(
    options: &RepositoryAuditOptions,
    mut report: CommandReport,
) -> CommandReport {
    let pairs = discover_complete_pairs(&options.path, &mut report);
    if pairs.is_empty() {
        report.insert_metadata("tjsvInvocationScopePairCount", json!(0));
        report.insert_metadata("tjsvInvocationScopedPairCount", json!(0));
        report.insert_metadata("tjsvInvocationStitchedPairCount", json!(0));
        return report.finalize();
    }

    let execution_files = discover_execution_files(&options.path, &mut report);
    report.insert_metadata("tjsvInvocationScopePairCount", json!(pairs.len()));
    report.insert_metadata(
        "tjsvInvocationScopeExecutionFileCount",
        json!(execution_files.len()),
    );

    let mut scoped_pair_count = 0usize;
    let mut stitched_pair_count = 0usize;

    for directory in pairs {
        let typespec = format!("{directory}/{TYPESPEC_FILE}");
        let schema = format!("{directory}/{JSON_SCHEMA_FILE}");
        let mut scoped_files = Vec::<&str>::new();
        let mut stitched_files = Vec::<&str>::new();

        for file in &execution_files {
            if !invocation_covers_pair(&file.text, &typespec, &schema) {
                continue;
            }

            let scoped = if file.workflow {
                yaml_step_blocks(&file.text)
                    .iter()
                    .any(|block| invocation_covers_pair(block, &typespec, &schema))
            } else {
                true
            };

            if scoped {
                scoped_files.push(file.path.as_str());
            } else {
                stitched_files.push(file.path.as_str());
            }
        }

        if !scoped_files.is_empty() {
            scoped_pair_count += 1;
        } else if !stitched_files.is_empty() {
            stitched_pair_count += 1;
            report.push(
                Finding::error(
                    "tjsv-full-check-cross-step-stitching",
                    format!(
                        "peer authorities {typespec} and {schema} appear covered only because TJSV command/action and authority/evidence tokens are distributed across separate workflow steps in {}; one step must contain the full fail-closed admission wiring",
                        stitched_files.join(", ")
                    ),
                )
                .with_target(directory),
            );
        }
    }

    report.insert_metadata("tjsvInvocationScopedPairCount", json!(scoped_pair_count));
    report.insert_metadata("tjsvInvocationStitchedPairCount", json!(stitched_pair_count));
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
    for entry in WalkDir::new(&contracts)
        .follow_links(false)
        .max_depth(MAX_WALK_DEPTH)
        .into_iter()
        .filter_entry(should_descend)
        .flatten()
    {
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
                    "tjsv-invocation-scope-pair-limit",
                    format!(
                        "more than {MAX_CONTRACT_DIRECTORIES} contract homes were discovered while checking scoped TJSV invocation evidence"
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
    for relative in [
        "Makefile",
        "justfile",
        "Taskfile.yml",
        "Taskfile.yaml",
        "package.json",
    ] {
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
                "tjsv-invocation-scope-execution-file-limit",
                format!(
                    "more than {MAX_EXECUTION_FILES} workflow/script files were discovered while checking scoped TJSV invocation evidence"
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
                        "tjsv-invocation-scope-file-too-large",
                        format!(
                            "TJSV invocation evidence file exceeds {MAX_EXECUTION_FILE_BYTES} bytes"
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
                            "tjsv-invocation-scope-file-unreadable",
                            "TJSV invocation evidence file must be readable UTF-8",
                        )
                        .with_target(relative_display(root, &path)),
                    );
                    return None;
                }
            };
            let display = relative_display(root, &path);
            let workflow = display.starts_with(".github/workflows/")
                && matches!(
                    path.extension().and_then(|extension| extension.to_str()),
                    Some("yml") | Some("yaml")
                );
            Some(ExecutionFile {
                path: display,
                text,
                workflow,
            })
        })
        .collect()
}

fn yaml_step_blocks(text: &str) -> Vec<String> {
    let mut blocks = Vec::<String>::new();
    let mut current = Vec::<&str>::new();
    let mut current_indent = None::<usize>;

    for line in text.lines() {
        let trimmed = line.trim_start();
        let indent = line.len().saturating_sub(trimmed.len());
        let starts_step = trimmed.starts_with("- name:")
            || trimmed.starts_with("- uses:")
            || trimmed.starts_with("- run:");
        let starts_peer_step = starts_step
            && current_indent.is_none_or(|existing_indent| indent <= existing_indent);

        if starts_peer_step {
            if !current.is_empty() {
                blocks.push(current.join("\n"));
                current.clear();
            }
            current_indent = Some(indent);
        }

        if current_indent.is_some() {
            current.push(line);
        }
    }

    if !current.is_empty() {
        blocks.push(current.join("\n"));
    }

    blocks
}

fn invocation_covers_pair(text: &str, typespec: &str, schema: &str) -> bool {
    let normalized = executable_text(text).replace('\\', "/");
    let lower = normalized.to_ascii_lowercase();
    let action = contains_immutably_pinned_tjsv_action(&lower);
    let command = contains_full_check_command(&lower);
    if !action && !command {
        return false;
    }

    let names_both_authorities = path_variants(typespec)
        .iter()
        .any(|path| normalized.contains(path.as_str()))
        && path_variants(schema)
            .iter()
            .any(|path| normalized.contains(path.as_str()));
    let declares_report = contains_cli_option(&lower, "report")
        || contains_yaml_input(&lower, "report")
        || contains_yaml_input(&lower, "parity_report");
    let declares_generated_schema = contains_cli_option(&lower, "output-dir")
        || contains_yaml_input(&lower, "output_dir")
        || contains_yaml_input(&lower, "output-dir");
    let differential_disabled = [
        "--probes=false",
        "--probes=0",
        "--max-probes=0",
        "probes: false",
        "probes: \"false\"",
        "probes: 'false'",
        "max_probes: 0",
        "max-probes: 0",
    ]
    .iter()
    .any(|needle| lower.contains(needle));

    names_both_authorities && declares_report && declares_generated_schema && !differential_disabled
}

fn executable_text(text: &str) -> String {
    text.lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with('#') && !trimmed.starts_with("//")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn contains_immutably_pinned_tjsv_action(lower: &str) -> bool {
    lower.lines().any(|line| {
        let trimmed = line.trim_start().trim_start_matches('-').trim_start();
        let Some(value) = trimmed.strip_prefix("uses:") else {
            return false;
        };
        let value = value
            .trim()
            .trim_matches(|character| character == '\'' || character == '"');
        let Some(revision) = value.strip_prefix(TJSV_ACTION_PREFIX) else {
            return false;
        };
        revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn contains_full_check_command(lower: &str) -> bool {
    [
        "tjsv check",
        "tsjsv check",
        "typespec-json-schema-validator check",
        "typespec-json-schema-validator.mjs check",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn contains_cli_option(lower: &str, option: &str) -> bool {
    lower.contains(&format!("--{option}="))
        || lower.contains(&format!("--{option} "))
        || lower.contains(&format!("--{option}\n"))
}

fn contains_yaml_input(lower: &str, input: &str) -> bool {
    lower
        .lines()
        .map(str::trim_start)
        .any(|line| line.starts_with(&format!("{input}:")))
}

fn path_variants(path: &str) -> [String; 3] {
    [
        path.to_owned(),
        format!("./{path}"),
        format!("$GITHUB_WORKSPACE/{path}"),
    ]
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

    use super::augment_tjsv_invocation_scope_audit;
    use crate::audit::RepositoryAuditOptions;
    use crate::model::CommandReport;

    fn run(workflow: &str) -> CommandReport {
        let root = tempdir().expect("temporary repository");
        let contract = root.path().join("contracts/example");
        fs::create_dir_all(&contract).expect("contract directory");
        fs::write(contract.join("main.tsp"), "model Packet { value: string; }\n")
            .expect("TypeSpec authority");
        fs::write(
            contract.join("authored.schema.json"),
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema"}"#,
        )
        .expect("JSON Schema authority");
        let workflows = root.path().join(".github/workflows");
        fs::create_dir_all(&workflows).expect("workflow directory");
        fs::write(workflows.join("contracts.yml"), workflow).expect("workflow");

        augment_tjsv_invocation_scope_audit(
            &RepositoryAuditOptions {
                path: root.path().to_path_buf(),
                profile: "baseline".to_owned(),
                additional_required_paths: Vec::new(),
            },
            CommandReport::new("audit repo"),
        )
    }

    fn has_stitching_error(report: &CommandReport) -> bool {
        report
            .findings
            .iter()
            .any(|finding| finding.code == "tjsv-full-check-cross-step-stitching")
    }

    #[test]
    fn accepts_one_run_step_with_complete_peer_authority_wiring() {
        let report = run(
            r#"jobs:
  parity:
    steps:
      - name: full peer check
        run: |
          npx tjsv check \
            --typespec=contracts/example/main.tsp \
            --schema=contracts/example/authored.schema.json \
            --report=artifacts/parity.json \
            --output-dir=artifacts/generated
"#,
        );
        assert!(!has_stitching_error(&report), "{:#?}", report.findings);
    }

    #[test]
    fn accepts_one_pinned_action_step_with_complete_peer_authority_wiring() {
        let report = run(
            r#"jobs:
  parity:
    steps:
      - name: full peer check
        uses: ORESoftware/typespec-json-schema-validator@0123456789012345678901234567890123456789
        with:
          typespec: contracts/example/main.tsp
          schema: contracts/example/authored.schema.json
          report: artifacts/parity.json
          output_dir: artifacts/generated
"#,
        );
        assert!(!has_stitching_error(&report), "{:#?}", report.findings);
    }

    #[test]
    fn rejects_command_and_authority_tokens_stitched_across_steps() {
        let report = run(
            r#"jobs:
  parity:
    steps:
      - name: incomplete check
        run: npx tjsv check
      - name: unrelated token dump
        run: echo contracts/example/main.tsp contracts/example/authored.schema.json --report=artifacts/parity.json --output-dir=artifacts/generated
"#,
        );
        assert!(has_stitching_error(&report), "{:#?}", report.findings);
    }

    #[test]
    fn rejects_action_and_inputs_stitched_across_steps() {
        let report = run(
            r#"jobs:
  parity:
    steps:
      - name: incomplete action
        uses: ORESoftware/typespec-json-schema-validator@0123456789012345678901234567890123456789
      - name: unrelated token dump
        run: echo contracts/example/main.tsp contracts/example/authored.schema.json --report=artifacts/parity.json --output-dir=artifacts/generated
"#,
        );
        assert!(has_stitching_error(&report), "{:#?}", report.findings);
    }

    #[test]
    fn a_real_scoped_step_prevents_a_decoy_from_creating_a_false_error() {
        let report = run(
            r#"jobs:
  parity:
    steps:
      - name: decoy command
        run: npx tjsv check
      - name: full peer check
        run: npx tjsv check --typespec=contracts/example/main.tsp --schema=contracts/example/authored.schema.json --report=artifacts/parity.json --output-dir=artifacts/generated
"#,
        );
        assert!(!has_stitching_error(&report), "{:#?}", report.findings);
    }

    #[test]
    fn comment_only_paths_do_not_complete_an_incomplete_step() {
        let report = run(
            r#"jobs:
  parity:
    steps:
      - name: incomplete check
        run: npx tjsv check
      # contracts/example/main.tsp contracts/example/authored.schema.json --report=x --output-dir=y
"#,
        );
        assert!(!has_stitching_error(&report), "{:#?}", report.findings);
    }
}
