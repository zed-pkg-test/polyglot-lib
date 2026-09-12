use std::collections::BTreeMap;

use walkdir::WalkDir;

use super::RepositoryAuditOptions;
use crate::model::{CommandReport, Finding};

#[derive(Default)]
struct Candidate {
    typespec: bool,
    schema: bool,
}

pub(crate) fn augment_nested_peer_contract_audit(
    options: &RepositoryAuditOptions,
    mut report: CommandReport,
) -> CommandReport {
    let root = options.path.join("contracts");
    if !root.is_dir() {
        return report.finalize();
    }

    let mut candidates = BTreeMap::<String, Candidate>::new();
    for entry in WalkDir::new(&root)
        .follow_links(false)
        .max_depth(16)
        .into_iter()
        .flatten()
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy();
        if name != "main.tsp" && name != "authored.schema.json" {
            continue;
        }
        let Some(parent) = entry.path().parent() else {
            continue;
        };
        let target = parent
            .strip_prefix(&options.path)
            .unwrap_or(parent)
            .to_string_lossy()
            .replace('\\', "/");
        let candidate = candidates.entry(target).or_default();
        if name == "main.tsp" {
            candidate.typespec = true;
        } else {
            candidate.schema = true;
        }
    }

    for (target, candidate) in candidates {
        match (candidate.typespec, candidate.schema) {
            (true, false) => report.push(
                Finding::error(
                    "nested-authored-json-schema-missing",
                    "main.tsp exists without the independently authored authored.schema.json peer",
                )
                .with_target(target),
            ),
            (false, true) => report.push(
                Finding::error(
                    "nested-typespec-source-missing",
                    "authored.schema.json exists without the independently authored main.tsp peer",
                )
                .with_target(target),
            ),
            _ => {}
        }
    }

    report.finalize()
}
