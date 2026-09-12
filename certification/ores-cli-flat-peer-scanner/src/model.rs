use std::collections::BTreeMap;

use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub code: String,
    pub message: String,
    pub target: Option<String>,
    severity: Severity,
}

impl Finding {
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            target: None,
            severity: Severity::Error,
        }
    }

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
    pub fn issue_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.severity == Severity::Error)
            .count()
    }

    #[must_use]
    pub fn finalize(self) -> Self {
        self
    }
}
