use std::path::PathBuf;

pub mod model {
    use std::collections::BTreeMap;

    use serde_json::Value;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Severity {
        Info,
        Error,
    }

    #[derive(Debug, Clone)]
    pub struct Finding {
        pub code: String,
        pub message: String,
        pub target: Option<String>,
        pub severity: Severity,
        pub details: BTreeMap<String, Value>,
    }

    impl Finding {
        #[must_use]
        pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
            Self {
                code: code.into(),
                message: message.into(),
                target: None,
                severity: Severity::Error,
                details: BTreeMap::new(),
            }
        }

        #[must_use]
        pub fn info(code: impl Into<String>, message: impl Into<String>) -> Self {
            Self {
                code: code.into(),
                message: message.into(),
                target: None,
                severity: Severity::Info,
                details: BTreeMap::new(),
            }
        }

        #[must_use]
        pub fn with_target(mut self, target: impl Into<String>) -> Self {
            self.target = Some(target.into());
            self
        }

        #[must_use]
        pub fn with_detail(mut self, key: impl Into<String>, value: Value) -> Self {
            self.details.insert(key.into(), value);
            self
        }
    }

    #[derive(Debug, Clone)]
    pub struct CommandReport {
        pub command: String,
        pub findings: Vec<Finding>,
        pub metadata: BTreeMap<String, Value>,
    }

    impl CommandReport {
        #[must_use]
        pub fn new(command: impl Into<String>) -> Self {
            Self {
                command: command.into(),
                findings: Vec::new(),
                metadata: BTreeMap::new(),
            }
        }

        pub fn push(&mut self, finding: Finding) {
            self.findings.push(finding);
        }

        pub fn insert_metadata(&mut self, key: impl Into<String>, value: Value) {
            self.metadata.insert(key.into(), value);
        }

        #[must_use]
        pub fn finalize(self) -> Self {
            self
        }
    }
}

pub mod audit {
    use super::PathBuf;
    use crate::model::CommandReport;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RepositoryAuditOptions {
        pub path: PathBuf,
        pub profile: String,
        pub additional_required_paths: Vec<String>,
    }

    pub(super) mod runtime_toml_registry {
        pub(super) const REGISTERED_RUNTIME_CONFIGS: &[&str] = &[
            ".ores-otel.toml",
            ".ores-chat.toml",
            ".ores-forms.toml",
            ".opto-sync.toml",
            ".fanwaave-cfg.toml",
            ".ores-mw.toml",
            ".ores-rl.toml",
            ".ores-lru.toml",
            ".shared-auth.toml",
            ".auth-shared.toml",
            ".ores-rpc.toml",
            ".ores-legal.toml",
            ".ores-wasm.toml",
            ".ores-sidecar.toml",
            ".indiebuild.toml",
        ];
    }

    mod runtime_env_contract {
        include!("runtime_env_contract.rs");
    }

    /// Execute the exact mirrored production runtime environment inventory lint.
    #[must_use]
    pub fn certify_repository(path: PathBuf) -> CommandReport {
        runtime_env_contract::augment_runtime_env_contract_audit(
            &RepositoryAuditOptions {
                path,
                profile: "baseline".to_owned(),
                additional_required_paths: Vec::new(),
            },
            CommandReport::new("certify ores-cli runtime env contract"),
        )
    }
}
