use std::path::PathBuf;

pub mod model {
    use serde_json::Value;
    use std::collections::BTreeMap;

    #[derive(Debug, Clone)]
    pub struct Finding {
        pub code: String,
        pub target: Option<String>,
        pub severity: &'static str,
        pub message: String,
    }

    impl Finding {
        pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
            Self {
                code: code.into(),
                target: None,
                severity: "error",
                message: message.into(),
            }
        }

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

        pub fn finalize(self) -> Self {
            self
        }

        pub fn issue_count(&self) -> usize {
            self.findings
                .iter()
                .filter(|finding| finding.severity == "error")
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

    mod authority_write_protection;

    pub use authority_write_protection::augment_authority_write_protection_audit;
}
