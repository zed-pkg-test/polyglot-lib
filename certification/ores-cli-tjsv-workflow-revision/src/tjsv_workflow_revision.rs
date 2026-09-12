use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::json;

use super::RepositoryAuditOptions;
use crate::model::{CommandReport, Finding};

const WORKFLOW_DIRECTORY: &str = ".github/workflows";
const TJSV_REPOSITORY: &str = "oresoftware/typespec-json-schema-validator";
const MAX_WORKFLOW_FILES: usize = 256;
const MAX_WORKFLOW_BYTES: u64 = 1024 * 1024;
const COMMIT_HEX_LENGTH: usize = 40;

/// Require one immutable TJSV revision inside each workflow that participates in
/// peer-authority admission.
///
/// TypeSpec and independently authored Draft 2020-12 JSON Schema remain equal
/// source authorities. Canonical TJSV transpiles TypeSpec to generated JSON
/// Schema B as comparison-only evidence, compares B with authored Schema A, and
/// may then verify Contract IR/receipts. A workflow must not run those producer,
/// verifier, or negative-control lanes at different validator revisions because
/// that would make the evidence internally non-reproducible.
///
/// Distinct workflow files may intentionally pin distinct immutable revisions;
/// this audit only rejects revision drift inside one executable workflow.
pub(super) fn augment_tjsv_workflow_revision_audit(
    options: &RepositoryAuditOptions,
    mut report: CommandReport,
) -> CommandReport {
    let root = options.path.join(WORKFLOW_DIRECTORY);
    let metadata = match fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return report.finalize(),
        Err(error) => {
            report.push(
                Finding::error(
                    "tjsv-workflow-directory-unreadable",
                    format!("workflow directory metadata could not be read: {error}"),
                )
                .with_target(WORKFLOW_DIRECTORY),
            );
            return report.finalize();
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        report.push(
            Finding::error(
                "tjsv-workflow-directory-unsafe",
                "workflow directory must be a regular directory, not a symlink or file",
            )
            .with_target(WORKFLOW_DIRECTORY),
        );
        return report.finalize();
    }

    let entries = match fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) => {
            report.push(
                Finding::error(
                    "tjsv-workflow-directory-unreadable",
                    format!("workflow directory could not be enumerated: {error}"),
                )
                .with_target(WORKFLOW_DIRECTORY),
            );
            return report.finalize();
        }
    };

    let mut workflows = Vec::<PathBuf>::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                report.push(
                    Finding::warning(
                        "tjsv-workflow-entry-unreadable",
                        format!("workflow directory entry could not be read: {error}"),
                    )
                    .with_target(WORKFLOW_DIRECTORY),
                );
                continue;
            }
        };
        let path = entry.path();
        if !is_workflow_path(&path) {
            continue;
        }
        if workflows.len() >= MAX_WORKFLOW_FILES {
            report.push(
                Finding::error(
                    "tjsv-workflow-file-limit",
                    format!(
                        "more than {MAX_WORKFLOW_FILES} workflow files were discovered; split or narrow the workflow surface"
                    ),
                )
                .with_target(WORKFLOW_DIRECTORY),
            );
            break;
        }
        workflows.push(path);
    }
    workflows.sort();

    let mut tjsv_workflow_count = 0usize;
    let mut tjsv_reference_count = 0usize;
    for path in workflows {
        let (references, had_tjsv) = audit_workflow_file(&options.path, &path, &mut report);
        tjsv_reference_count += references;
        if had_tjsv {
            tjsv_workflow_count += 1;
        }
    }

    report.insert_metadata("tjsvWorkflowCount", json!(tjsv_workflow_count));
    report.insert_metadata("tjsvWorkflowReferenceCount", json!(tjsv_reference_count));
    if tjsv_workflow_count > 0 {
        report.push(
            Finding::info(
                "tjsv-workflow-revisions-inspected",
                format!(
                    "inspected {tjsv_reference_count} TJSV action reference{} across {tjsv_workflow_count} workflow{}",
                    if tjsv_reference_count == 1 { "" } else { "s" },
                    if tjsv_workflow_count == 1 { "" } else { "s" }
                ),
            )
            .with_target(WORKFLOW_DIRECTORY),
        );
    }

    report.finalize()
}

fn audit_workflow_file(root: &Path, path: &Path, report: &mut CommandReport) -> (usize, bool) {
    let target = relative_display(root, path);
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            report.push(
                Finding::error(
                    "tjsv-workflow-file-unreadable",
                    format!("workflow metadata could not be read: {error}"),
                )
                .with_target(target),
            );
            return (0, false);
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        report.push(
            Finding::error(
                "tjsv-workflow-file-unsafe",
                "workflow must be a regular non-symlink file",
            )
            .with_target(target),
        );
        return (0, false);
    }
    if metadata.len() > MAX_WORKFLOW_BYTES {
        report.push(
            Finding::error(
                "tjsv-workflow-file-too-large",
                format!("workflow exceeds the {MAX_WORKFLOW_BYTES}-byte audit bound"),
            )
            .with_target(target),
        );
        return (0, false);
    }
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            report.push(
                Finding::error(
                    "tjsv-workflow-file-not-utf8",
                    format!("workflow could not be read as UTF-8: {error}"),
                )
                .with_target(target),
            );
            return (0, false);
        }
    };

    let mut revisions = BTreeSet::<String>::new();
    let mut reference_count = 0usize;
    for (index, line) in text.lines().enumerate() {
        let Some(reference) = parse_uses_reference(line) else {
            continue;
        };
        let Some(revision) = tjsv_revision(reference) else {
            continue;
        };
        reference_count += 1;
        let line_target = format!("{target}:{}", index + 1);
        if !is_lower_hex(revision, COMMIT_HEX_LENGTH) {
            report.push(
                Finding::error(
                    "tjsv-workflow-ref-not-immutable",
                    "TJSV producer, verifier, and negative-control actions must use an exact 40-character commit SHA",
                )
                .with_target(line_target)
                .with_detail("reference", json!(reference)),
            );
            continue;
        }
        revisions.insert(revision.to_owned());
    }

    if revisions.len() > 1 {
        report.push(
            Finding::error(
                "tjsv-workflow-revision-drift",
                "one workflow invokes TJSV at multiple immutable revisions; producer, verifier, and adversarial lanes must share one exact validator revision",
            )
            .with_target(target)
            .with_detail("revisions", json!(revisions.into_iter().collect::<Vec<_>>())),
        );
    }

    (reference_count, reference_count > 0)
}

fn parse_uses_reference(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return None;
    }
    let trimmed = trimmed.strip_prefix('-').map_or(trimmed, str::trim_start);
    let value = trimmed.strip_prefix("uses:")?.trim();
    if value.is_empty() {
        return Some(value);
    }
    if let Some(quoted) = strip_balanced_quotes(value) {
        return Some(quoted);
    }
    Some(
        value
            .split_once(" #")
            .map_or(value, |(head, _)| head.trim_end()),
    )
}

fn strip_balanced_quotes(value: &str) -> Option<&str> {
    let bytes = value.as_bytes();
    if bytes.len() < 2 {
        return None;
    }
    let quote = bytes[0];
    if !matches!(quote, b'\'' | b'"') || *bytes.last()? != quote {
        return None;
    }
    Some(&value[1..value.len() - 1])
}

fn tjsv_revision(reference: &str) -> Option<&str> {
    let (source, revision) = reference.rsplit_once('@')?;
    let source = source.to_ascii_lowercase();
    if source == TJSV_REPOSITORY || source.starts_with(&format!("{TJSV_REPOSITORY}/")) {
        Some(revision)
    } else {
        None
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_workflow_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "yml" | "yaml"))
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

    use super::augment_tjsv_workflow_revision_audit;
    use crate::audit::RepositoryAuditOptions;
    use crate::model::CommandReport;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn audit(files: &[(&str, String)]) -> CommandReport {
        let root = tempdir().expect("temporary repository");
        let workflows = root.path().join(".github/workflows");
        fs::create_dir_all(&workflows).expect("workflow directory");
        for (name, content) in files {
            fs::write(workflows.join(name), content).expect("workflow");
        }
        augment_tjsv_workflow_revision_audit(
            &RepositoryAuditOptions {
                path: root.path().to_path_buf(),
                profile: "baseline".to_owned(),
                additional_required_paths: Vec::new(),
            },
            CommandReport::new("audit repo"),
        )
    }

    #[test]
    fn accepts_one_revision_across_producer_and_verifier_actions() {
        let workflow = format!(
            "jobs:\n  parity:\n    steps:\n      - uses: ORESoftware/typespec-json-schema-validator@{A}\n      - uses: ORESoftware/typespec-json-schema-validator/actions/verify-contract-ir@{A}\n      - uses: ORESoftware/typespec-json-schema-validator/actions/test-consumer-admission@{A}\n"
        );
        let report = audit(&[("peer.yml", workflow)]);
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
        assert_eq!(
            report.metadata.get("tjsvWorkflowReferenceCount"),
            Some(&JsonValue::from(3))
        );
    }

    #[test]
    fn rejects_revision_drift_between_producer_and_verifier() {
        let workflow = format!(
            "jobs:\n  parity:\n    steps:\n      - uses: ORESoftware/typespec-json-schema-validator@{A}\n      - uses: ORESoftware/typespec-json-schema-validator/actions/verify-contract-ir@{B}\n"
        );
        let report = audit(&[("peer.yml", workflow)]);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "tjsv-workflow-revision-drift")
        );
    }

    #[test]
    fn rejects_mutable_tjsv_revision() {
        let report = audit(&[(
            "peer.yml",
            "jobs:\n  parity:\n    steps:\n      - uses: ORESoftware/typespec-json-schema-validator@main\n"
                .to_owned(),
        )]);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "tjsv-workflow-ref-not-immutable")
        );
    }

    #[test]
    fn permits_distinct_profiles_in_distinct_workflow_files() {
        let first = format!(
            "jobs:\n  parity:\n    steps:\n      - uses: ORESoftware/typespec-json-schema-validator@{A}\n"
        );
        let second = format!(
            "jobs:\n  parity:\n    steps:\n      - uses: ORESoftware/typespec-json-schema-validator/actions/verify-contract-ir@{B}\n"
        );
        let report = audit(&[("legacy.yml", first), ("current.yml", second)]);
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
        assert_eq!(
            report.metadata.get("tjsvWorkflowCount"),
            Some(&JsonValue::from(2))
        );
    }

    #[test]
    fn ignores_comments_and_unrelated_actions() {
        let report = audit(&[(
            "other.yml",
            format!(
                "jobs:\n  test:\n    steps:\n      # - uses: ORESoftware/typespec-json-schema-validator@{A}\n      - uses: actions/checkout@{A}\n"
            ),
        )]);
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
        assert_eq!(
            report.metadata.get("tjsvWorkflowReferenceCount"),
            Some(&JsonValue::from(0))
        );
    }
}