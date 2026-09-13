use std::fs;
use std::path::{Path, PathBuf};

use walkdir::{DirEntry, WalkDir};

use super::RepositoryAuditOptions;
use crate::model::{CommandReport, Finding};

const MAX_FILES: usize = 1_024;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_DEPTH: usize = 12;
const SCAN_ROOTS: [&str; 3] = [".github/workflows", "scripts", "tools"];
const SOURCE_EXTENSIONS: [&str; 8] = ["yml", "yaml", "sh", "bash", "mjs", "js", "ts", "py"];

/// Reject repository automation that writes directly to either independently
/// authored contract authority. TypeSpec and authored Draft 2020-12 JSON Schema
/// are source inputs; generated JSON Schema B, reports, IR and other evidence
/// must be written to distinct generated/evidence paths instead.
pub(super) fn augment_authority_write_protection_audit(
    options: &RepositoryAuditOptions,
    mut report: CommandReport,
) -> CommandReport {
    let mut files = Vec::<PathBuf>::new();

    for relative_root in SCAN_ROOTS {
        let root = options.path.join(relative_root);
        if !root.is_dir() {
            continue;
        }
        let walker = WalkDir::new(&root)
            .follow_links(false)
            .max_depth(MAX_DEPTH)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(should_descend);
        for entry in walker {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    report.push(
                        Finding::error(
                            "peer-authority-write-scan-failed",
                            format!("automation tree could not be inspected: {error}"),
                        )
                        .with_target(relative_root),
                    );
                    continue;
                }
            };
            if entry.file_type().is_symlink() || !entry.file_type().is_file() {
                continue;
            }
            if !is_source_file(entry.path()) {
                continue;
            }
            if files.len() >= MAX_FILES {
                report.push(
                    Finding::error(
                        "peer-authority-write-file-limit",
                        format!("more than {MAX_FILES} automation source files were discovered"),
                    )
                    .with_target(relative_root),
                );
                break;
            }
            files.push(entry.into_path());
        }
    }

    files.sort();
    files.dedup();
    let mut rejected = 0usize;
    for path in &files {
        rejected += audit_file(&options.path, path, &mut report);
    }
    report.insert_metadata(
        "peerAuthorityWriteProtectionFileCount",
        serde_json::json!(files.len()),
    );
    report.insert_metadata(
        "peerAuthorityWriteProtectionViolationCount",
        serde_json::json!(rejected),
    );
    report.finalize()
}

fn audit_file(root: &Path, path: &Path, report: &mut CommandReport) -> usize {
    let target = relative_display(root, path);
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            report.push(
                Finding::error(
                    "peer-authority-write-file-unreadable",
                    format!("automation source metadata could not be read: {error}"),
                )
                .with_target(target),
            );
            return 0;
        }
    };
    if metadata.len() > MAX_FILE_BYTES {
        report.push(
            Finding::error(
                "peer-authority-write-file-too-large",
                "automation source exceeds the 2 MiB authority-write audit bound",
            )
            .with_target(target),
        );
        return 0;
    }
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            report.push(
                Finding::error(
                    "peer-authority-write-file-not-utf8",
                    format!("automation source could not be read as UTF-8: {error}"),
                )
                .with_target(target),
            );
            return 0;
        }
    };

    let mut rejected = 0usize;
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        let Some(authority) = authority_literal(&lower) else {
            continue;
        };
        if !looks_like_write(&lower) {
            continue;
        }

        rejected += 1;
        report.push(
            Finding::error(
                "peer-authority-direct-write",
                format!(
                    "automation must not overwrite the independently authored {authority}; write generated comparison evidence to a distinct path"
                ),
            )
            .with_target(format!("{target}:{}", index + 1)),
        );
    }
    rejected
}

fn authority_literal(line: &str) -> Option<&'static str> {
    if line.contains("authored.schema.json") {
        Some("JSON Schema Draft 2020-12 authority")
    } else if line.contains("main.tsp") {
        Some("TypeSpec authority")
    } else {
        None
    }
}

fn looks_like_write(line: &str) -> bool {
    let shell_copy_or_move = shell_transfer_may_write_authority(line.trim_start());
    let redirect =
        line.contains(">>") || line.contains(" > ") || line.contains(">\"") || line.contains(">' ");
    let output_flag = line.contains("--output=") || line.contains("--output ");
    let write_api = [
        "writefilesync(",
        "writefile(",
        "write_file(",
        "write_text(",
        "fs.write",
        "std::fs::write",
        "file.write",
    ]
    .iter()
    .any(|needle| line.contains(needle));

    shell_copy_or_move || redirect || output_flag || write_api
}

/// Decide whether a `cp`/`mv`/`install` command may write an authored peer.
///
/// Copying an authored peer *out* to a distinct file (for example a TJSV
/// negative-control fixture under `$RUNNER_TEMP`) only reads the authority and
/// is allowed. Everything else stays fail-closed: `mv` of any authority, an
/// explicit `-t`/`--target-directory`, more than one source, a destination
/// that names an authority, or a destination that may be a directory (and so
/// could receive a file named like an authority).
fn shell_transfer_may_write_authority(line: &str) -> bool {
    let mut tokens = line.split_whitespace();
    let Some(command) = tokens.next() else {
        return false;
    };
    if !matches!(command, "cp" | "mv" | "install") {
        return false;
    }

    let mut operands = Vec::<&str>::new();
    for token in tokens {
        if matches!(token, "&&" | "||" | ";" | "|" | "&") {
            break;
        }
        if token == "-t" || token.starts_with("--target-directory") {
            return true;
        }
        if token.starts_with('-') {
            continue;
        }
        operands.push(token.trim_matches(|character| character == '"' || character == '\''));
    }

    if command == "mv" || operands.len() != 2 {
        return true;
    }
    let destination = operands[1];
    if authority_literal(destination).is_some() {
        return true;
    }
    !names_distinct_file(destination)
}

fn names_distinct_file(destination: &str) -> bool {
    if destination.ends_with('/') {
        return false;
    }
    let file_name = destination.rsplit('/').next().unwrap_or(destination);
    !matches!(file_name, "" | "." | "..") && file_name.contains('.')
}

fn should_descend(entry: &DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return true;
    }
    let name = entry.file_name().to_string_lossy();
    !matches!(
        name.as_ref(),
        ".git" | "node_modules" | "target" | "dist" | "build" | "generated" | "vendor"
    )
}

fn is_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| SOURCE_EXTENSIONS.contains(&extension))
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

    use tempfile::tempdir;

    use super::augment_authority_write_protection_audit;
    use crate::audit::RepositoryAuditOptions;
    use crate::model::CommandReport;

    fn audit(path: &str, content: &str) -> CommandReport {
        let root = tempdir().expect("temporary repository");
        let file = root.path().join(path);
        fs::create_dir_all(file.parent().expect("fixture parent")).expect("fixture directory");
        fs::write(file, content).expect("fixture source");
        augment_authority_write_protection_audit(
            &RepositoryAuditOptions {
                path: root.path().to_path_buf(),
                profile: "baseline".to_owned(),
                additional_required_paths: Vec::new(),
            },
            CommandReport::new("audit repo"),
        )
    }

    #[test]
    fn rejects_shell_overwrite_of_authored_json_schema() {
        let report = audit(
            "scripts/generate.sh",
            "cp generated/schema.json contracts/account/authored.schema.json\n",
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "peer-authority-direct-write")
        );
    }

    #[test]
    fn rejects_shell_overwrite_of_authored_typespec() {
        let report = audit(
            ".github/workflows/ci.yml",
            "run: cat generated.tsp > contracts/account/main.tsp\n",
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "peer-authority-direct-write")
        );
    }

    #[test]
    fn rejects_programmatic_write_to_authored_peer() {
        let report = audit(
            "tools/generate.mjs",
            "fs.writeFileSync('contracts/account/authored.schema.json', body);\n",
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "peer-authority-direct-write")
        );
    }

    #[test]
    fn allows_tjsv_reads_and_generated_json_output() {
        let report = audit(
            ".github/workflows/contracts.yml",
            "run: tjsv check --typespec=contracts/account/main.tsp --schema=contracts/account/authored.schema.json --output-dir=.typespec-json-schema-validator/account/generated\n",
        );
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
    }

    #[test]
    fn allows_hash_and_compare_of_both_authored_peers() {
        let report = audit(
            "scripts/check.sh",
            "sha256sum contracts/account/main.tsp contracts/account/authored.schema.json\ncmp contracts/account/authored.schema.json evidence/authored.before.json\n",
        );
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
    }

    #[test]
    fn allows_copying_authored_peers_into_negative_control_fixtures() {
        let report = audit(
            ".github/workflows/ci.yml",
            "          cp contracts/infra-gitops/main.tsp \"$RUNNER_TEMP/infra-gitops-typespec-drift.tsp\"\n          cp contracts/infra-gitops/authored.schema.json \"$RUNNER_TEMP/infra-gitops-drift.schema.json\"\n",
        );
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
    }

    #[test]
    fn still_rejects_copy_move_and_install_that_can_replace_authored_peers() {
        for line in [
            "cp -f \"$RUNNER_TEMP/drift.tsp\" contracts/account/main.tsp",
            "install -m 0644 generated/schema.json contracts/account/authored.schema.json",
            "mv contracts/account/authored.schema.json \"$RUNNER_TEMP/moved.json\"",
            "cp generated/main.tsp contracts/account/",
            "cp generated/main.tsp \"$RUNNER_TEMP\"",
            "cp -t contracts/account generated/main.tsp",
            "cp generated/main.tsp generated/authored.schema.json contracts/account",
        ] {
            let report = audit("scripts/generate.sh", &format!("{line}\n"));
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.code == "peer-authority-direct-write"),
                "expected rejection for {line}"
            );
        }
    }

    #[test]
    fn ignores_commented_write_examples() {
        let report = audit(
            "scripts/check.sh",
            "# cp generated/schema.json contracts/account/authored.schema.json\n// fs.writeFileSync('contracts/account/main.tsp', body);\n",
        );
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
    }
}
