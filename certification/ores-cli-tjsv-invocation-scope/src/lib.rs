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
    }

    impl Finding {
        #[must_use]
        pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
            Self {
                code: code.into(),
                message: message.into(),
                target: None,
                severity: Severity::Error,
            }
        }

        #[must_use]
        pub fn info(code: impl Into<String>, message: impl Into<String>) -> Self {
            Self {
                code: code.into(),
                message: message.into(),
                target: None,
                severity: Severity::Info,
            }
        }

        #[must_use]
        pub fn with_target(mut self, target: impl Into<String>) -> Self {
            self.target = Some(target.into());
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

        #[must_use]
        pub fn issue_count(&self) -> usize {
            self.findings
                .iter()
                .filter(|finding| finding.severity == Severity::Error)
                .count()
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

    mod tjsv_invocation_scope {
        include!("tjsv_invocation_scope.rs");
    }

    /// Execute the exact mirrored production scoped-invocation guard.
    #[must_use]
    pub fn certify_repository(path: PathBuf) -> CommandReport {
        tjsv_invocation_scope::augment_tjsv_invocation_scope_audit(
            &RepositoryAuditOptions {
                path,
                profile: "baseline".to_owned(),
                additional_required_paths: Vec::new(),
            },
            CommandReport::new("certify ores-cli scoped TJSV invocation lint"),
        )
    }
}
