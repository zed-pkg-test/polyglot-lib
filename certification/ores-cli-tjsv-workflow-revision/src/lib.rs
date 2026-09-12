use std::path::PathBuf;

pub mod model {
    use std::collections::BTreeMap;

    use serde_json::Value;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Severity {
        Info,
        Warning,
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
            Self::new(Severity::Error, code, message)
        }

        #[must_use]
        pub fn warning(code: impl Into<String>, message: impl Into<String>) -> Self {
            Self::new(Severity::Warning, code, message)
        }

        #[must_use]
        pub fn info(code: impl Into<String>, message: impl Into<String>) -> Self {
            Self::new(Severity::Info, code, message)
        }

        fn new(
            severity: Severity,
            code: impl Into<String>,
            message: impl Into<String>,
        ) -> Self {
            Self {
                code: code.into(),
                message: message.into(),
                target: None,
                severity,
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

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RepositoryAuditOptions {
        pub path: PathBuf,
        pub profile: String,
        pub additional_required_paths: Vec<String>,
    }

    mod tjsv_workflow_revision {
        include!("tjsv_workflow_revision.rs");
    }
}
