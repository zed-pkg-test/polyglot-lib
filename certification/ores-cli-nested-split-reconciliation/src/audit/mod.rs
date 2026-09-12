use std::path::PathBuf;

use crate::model::CommandReport;

pub(crate) mod nested_peer_contracts;
mod nested_split_peer_contracts;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryAuditOptions {
    pub path: PathBuf,
    pub profile: String,
    pub additional_required_paths: Vec<String>,
}

#[must_use]
pub fn audit_repository(options: &RepositoryAuditOptions) -> CommandReport {
    let report = nested_peer_contracts::augment_nested_peer_contract_audit(
        options,
        CommandReport::new("audit repo"),
    );
    nested_split_peer_contracts::augment_nested_split_peer_contract_audit(options, report)
}
