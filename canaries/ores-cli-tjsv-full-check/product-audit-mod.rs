mod alignment;
mod cargo_git_pins;
mod cli_secret_flag_hygiene;
mod contract;
mod contract_consumer;
#[cfg(test)]
mod contract_consumer_tests;
mod contract_evidence;
#[cfg(test)]
mod contract_evidence_tests;
mod docker_base_pins;
mod flags2env_source_hygiene;
mod flags2env_submodule_source_hygiene;
mod infra_policy;
mod infra_provider_state;
mod nested_peer_contracts;
mod org;
mod package;
mod repository;
mod runtime_toml_indiebuild;
mod runtime_toml_otel;
mod runtime_toml_rate_limit;
mod runtime_toml_registry;
#[cfg(test)]
mod runtime_toml_registry_tests;
mod runtime_toml_sidecar;
mod tjsv_full_check;
mod workflow_action_pins;
mod workflow_permissions;

use std::path::PathBuf;

pub use contract::audit_contract;
pub use org::audit_github_org;
pub use package::audit_package;

use crate::model::CommandReport;

/// Audit one local repository tree, recursively inspect independently authored
/// TypeSpec/JSON Schema peers, require the full compiler/emitter/comparison TJSV
/// lane for each complete peer pair, reject mutable GitHub Actions dependencies,
/// require explicit workflow-token posture and immutable Docker/Cargo Git
/// identities, fail closed on unknown ORES runtime TOML names, enforce
/// credential/public-argv separation plus canonical flags2env provenance,
/// apply bounded peer-authority runtime configuration checks, and harden
/// provider IaC when the infra profile is explicitly selected.
#[must_use]
pub fn audit_repository(options: &RepositoryAuditOptions) -> CommandReport {
    let report = nested_peer_contracts::augment_nested_peer_contract_audit(
        options,
        repository::audit_repository(options),
    );
    let report = tjsv_full_check::augment_tjsv_full_check_audit(options, report);
    let report = workflow_action_pins::augment_workflow_action_pin_audit(options, report);
    let report = workflow_permissions::augment_workflow_permissions_audit(options, report);
    let report = docker_base_pins::augment_docker_base_pin_audit(options, report);
    let report = cargo_git_pins::augment_cargo_git_pin_audit(options, report);
    let report = runtime_toml_registry::augment_runtime_toml_registry_audit(options, report);
    let report = runtime_toml_rate_limit::augment_rate_limit_runtime_toml_audit(options, report);
    let report = runtime_toml_otel::augment_otel_runtime_toml_audit(options, report);
    let report = runtime_toml_indiebuild::augment_indiebuild_runtime_toml_audit(options, report);
    let mut report = runtime_toml_sidecar::augment_sidecar_runtime_toml_audit(options, report);
    cli_secret_flag_hygiene::audit_cli_secret_flag_hygiene(&options.path, &mut report);
    flags2env_source_hygiene::audit_flags2env_source_hygiene(&options.path, &mut report);
    flags2env_submodule_source_hygiene::audit_flags2env_submodule_source_hygiene(
        &options.path,
        &mut report,
    );
    let report = report.finalize();
    if options.profile.trim() == "infra" {
        let report = infra_policy::augment_infra_policy_audit(options, report);
        infra_provider_state::augment_infra_provider_state_audit(options, report)
    } else {
        report
    }
}

/// Options for a GitHub organization audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubOrgAuditOptions {
    /// GitHub account or organization login.
    pub owner: String,
    /// Maximum repositories requested from `gh`.
    pub repo_limit: usize,
    /// Exact additional repository names that must exist.
    pub expected_repositories: Vec<String>,
    /// Optional standard family prefix.
    pub family_prefix: Option<String>,
    /// Standard family suffixes required with the prefix.
    pub family_members: Vec<String>,
    /// Require a `docs` or `*-docs` repository.
    pub require_docs_repository: bool,
    /// Inspect top-level entries for active repositories.
    pub check_layout: bool,
    /// Required top-level entries.
    pub required_root_entries: Vec<String>,
    /// Maximum repositories inspected for layout.
    pub max_layout_repositories: usize,
    /// Whether archived repositories receive layout checks.
    pub include_archived: bool,
}

/// Options for a local repository audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryAuditOptions {
    /// Local repository root.
    pub path: PathBuf,
    /// Structural profile.
    pub profile: String,
    /// Additional required paths.
    pub additional_required_paths: Vec<String>,
}

/// Options for Cargo/zed-pkg metadata parity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageAuditOptions {
    /// Local package root.
    pub path: PathBuf,
    /// Whether Cargo.lock must exist.
    pub require_cargo_lock: bool,
}

/// Options for TypeSpec/JSON Schema parity validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractAuditOptions {
    /// TypeSpec source entry.
    pub typespec: PathBuf,
    /// Independently authored JSON Schema source.
    pub schema: PathBuf,
    /// Machine-readable validator report path.
    pub report: PathBuf,
    /// Validator executable.
    pub validator: String,
}
