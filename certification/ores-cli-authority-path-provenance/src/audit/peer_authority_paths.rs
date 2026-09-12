use std::collections::BTreeSet;
use std::path::{Component, Path};

use walkdir::{DirEntry, WalkDir};

use super::RepositoryAuditOptions;
use crate::model::{CommandReport, Finding};

const MAX_WALK_DEPTH: usize = 16;
const MAX_AUTHORITIES: usize = 512;
const AUTHORITY_FILES: [&str; 2] = ["main.tsp", "authored.schema.json"];
const NON_AUTHORED_COMPONENTS: [&str; 8] = [
    "generated",
    "evidence",
    ".canary-evidence",
    ".typespec-json-schema-validator",
    "target",
    "dist",
    "build",
    "artifacts",
];

/// Reject repository-discovered peer authorities from generated/evidence/build
/// locations. TypeSpec and authored Draft 2020-12 JSON Schema must both remain
/// human-editable source authorities; generated Schema B and other receipts are
/// evidence only and must not be able to masquerade as either authored peer.
pub(super) fn augment_peer_authority_path_audit(
    options: &RepositoryAuditOptions,
    mut report: CommandReport,
) -> CommandReport {
    let contracts = options.path.join("contracts");
    if !contracts.is_dir() {
        return report.finalize();
    }

    let mut inspected = 0usize;
    let mut rejected = 0usize;
    let mut rejected_paths = BTreeSet::new();

    let walker = WalkDir::new(&contracts)
        .follow_links(false)
        .max_depth(MAX_WALK_DEPTH)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(should_descend);

    for entry in walker {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                report.push(
                    Finding::error(
                        "peer-authority-path-walk-failed",
                        format!("could not inspect peer-authority paths: {error}"),
                    )
                    .with_target("contracts"),
                );
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy();
        if !AUTHORITY_FILES.contains(&name.as_ref()) {
            continue;
        }

        inspected += 1;
        if inspected > MAX_AUTHORITIES {
            report.push(
                Finding::error(
                    "peer-authority-path-limit",
                    format!(
                        "more than {MAX_AUTHORITIES} authored peer-authority files were discovered"
                    ),
                )
                .with_target("contracts"),
            );
            break;
        }

        let relative = entry
            .path()
            .strip_prefix(&options.path)
            .unwrap_or(entry.path());
        if first_non_authored_component(relative).is_some() {
            let target = relative.to_string_lossy().replace('\\', "/");
            if rejected_paths.insert(target.clone()) {
                rejected += 1;
                let authority = if name == "main.tsp" {
                    "TypeSpec"
                } else {
                    "JSON Schema Draft 2020-12"
                };
                report.push(
                    Finding::error(
                        "peer-authority-generated-path",
                        format!(
                            "{authority} must remain an independently authored source and may not live under a generated/evidence/build path"
                        ),
                    )
                    .with_target(target),
                );
            }
        }
    }

    report.insert_metadata(
        "peerAuthorityPathInspectedCount",
        serde_json::json!(inspected.min(MAX_AUTHORITIES)),
    );
    report.insert_metadata(
        "peerAuthorityGeneratedPathCount",
        serde_json::json!(rejected),
    );
    report.finalize()
}

fn should_descend(entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    let name = entry.file_name().to_string_lossy();
    !matches!(name.as_ref(), ".git" | "node_modules" | ".dart_tool")
}

fn first_non_authored_component(path: &Path) -> Option<&str> {
    path.components().find_map(|component| match component {
        Component::Normal(value) => value
            .to_str()
            .filter(|value| NON_AUTHORED_COMPONENTS.contains(value)),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::augment_peer_authority_path_audit;
    use crate::audit::RepositoryAuditOptions;
    use crate::model::CommandReport;

    fn audit(setup: impl FnOnce(&std::path::Path)) -> CommandReport {
        let root = tempdir().expect("temporary repository");
        setup(root.path());
        augment_peer_authority_path_audit(
            &RepositoryAuditOptions {
                path: root.path().to_path_buf(),
                profile: "baseline".to_owned(),
                additional_required_paths: Vec::new(),
            },
            CommandReport::new("audit repo"),
        )
    }

    fn write_authority(path: &std::path::Path, name: &str) {
        fs::create_dir_all(path).expect("authority directory");
        fs::write(path.join(name), "authority\n").expect("authority file");
    }

    #[test]
    fn accepts_independently_authored_peer_locations() {
        let report = audit(|root| {
            write_authority(&root.join("contracts/account"), "main.tsp");
            write_authority(&root.join("contracts/account"), "authored.schema.json");
        });
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
    }

    #[test]
    fn rejects_generated_typespec_authority() {
        let report = audit(|root| {
            write_authority(&root.join("contracts/account/generated"), "main.tsp");
        });
        assert!(report.findings.iter().any(|finding| {
            finding.code == "peer-authority-generated-path"
                && finding.target.as_deref() == Some("contracts/account/generated/main.tsp")
        }));
    }

    #[test]
    fn rejects_generated_json_schema_authority() {
        let report = audit(|root| {
            write_authority(
                &root.join("contracts/account/.canary-evidence"),
                "authored.schema.json",
            );
        });
        assert!(report.findings.iter().any(|finding| {
            finding.code == "peer-authority-generated-path"
                && finding.target.as_deref()
                    == Some("contracts/account/.canary-evidence/authored.schema.json")
        }));
    }

    #[test]
    fn rejects_build_and_tjsv_evidence_locations() {
        let report = audit(|root| {
            write_authority(&root.join("contracts/build/example"), "main.tsp");
            write_authority(
                &root.join("contracts/.typespec-json-schema-validator/example"),
                "authored.schema.json",
            );
        });
        assert_eq!(report.issue_count(), 2, "{:#?}", report.findings);
    }

    #[test]
    fn generated_witness_filename_is_not_misclassified_as_authored_schema() {
        let report = audit(|root| {
            let evidence = root.join("contracts/account/generated");
            fs::create_dir_all(&evidence).expect("evidence directory");
            fs::write(evidence.join("typespec.generated.schema.json"), "{}\n")
                .expect("generated witness");
        });
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
    }
}
