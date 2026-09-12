pub mod model {
    use std::collections::BTreeMap;

    use serde_json::Value;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Finding {
        pub code: String,
        pub severity: Severity,
        pub message: String,
        pub target: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Severity {
        Error,
        Info,
    }

    impl Finding {
        pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
            Self {
                code: code.into(),
                severity: Severity::Error,
                message: message.into(),
                target: None,
            }
        }

        pub fn info(code: impl Into<String>, message: impl Into<String>) -> Self {
            Self {
                code: code.into(),
                severity: Severity::Info,
                message: message.into(),
                target: None,
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
        pub fn new(command: impl Into<String>) -> Self {
            Self {
                command: command.into(),
                findings: Vec::new(),
                metadata: BTreeMap::new(),
            }
        }

        pub fn insert_metadata(&mut self, key: impl Into<String>, value: Value) {
            self.metadata.insert(key.into(), value);
        }

        pub fn push(&mut self, finding: Finding) {
            self.findings.push(finding);
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
    use std::path::{Path, PathBuf};

    use crate::model::CommandReport;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RepositoryAuditOptions {
        pub path: PathBuf,
        pub profile: String,
        pub additional_required_paths: Vec<String>,
    }

    mod tjsv_full_check;

    /// Exercise the exact production augmentation through the same module
    /// boundary that owns it in ores-cli. This keeps the public canary honest:
    /// strict Clippy sees the production path as reachable instead of treating
    /// the snapshot as test-only/dead code.
    #[must_use]
    pub fn exercise_tjsv_full_check(root: &Path) -> CommandReport {
        let options = RepositoryAuditOptions {
            path: root.to_path_buf(),
            profile: "standards".to_owned(),
            additional_required_paths: Vec::new(),
        };
        tjsv_full_check::augment_tjsv_full_check_audit(
            &options,
            CommandReport::new("canary tjsv full check"),
        )
    }
}

#[cfg(test)]
mod canary_tests {
    use tempfile::tempdir;

    use crate::audit::exercise_tjsv_full_check;

    #[test]
    fn production_augmentation_is_reachable_from_the_canary_boundary() {
        let root = tempdir().expect("temporary repository root");
        let report = exercise_tjsv_full_check(root.path());
        assert_eq!(report.command, "canary tjsv full check");
    }
}
