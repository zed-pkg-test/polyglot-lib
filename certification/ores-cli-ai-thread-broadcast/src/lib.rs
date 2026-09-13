#![forbid(unsafe_code)]

pub mod error {
    #[derive(Debug, thiserror::Error)]
    pub enum RuntimeError {
        #[error("usage: {0}")]
        Usage(String),
        #[error("invariant: {0}")]
        Invariant(String),
        #[error("dependency {command}: {message}")]
        Dependency {
            command: String,
            exit_code: Option<i32>,
            message: String,
        },
        #[error(transparent)]
        Json(#[from] serde_json::Error),
    }
}

pub mod model {
    use std::collections::BTreeMap;
    use serde_json::Value;

    #[derive(Debug, Clone)]
    pub struct Finding {
        pub code: String,
        pub message: String,
        pub target: Option<String>,
        pub details: BTreeMap<String, Value>,
        pub error: bool,
    }

    impl Finding {
        pub fn info(code: impl Into<String>, message: impl Into<String>) -> Self {
            Self { code: code.into(), message: message.into(), target: None, details: BTreeMap::new(), error: false }
        }
        pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
            Self { code: code.into(), message: message.into(), target: None, details: BTreeMap::new(), error: true }
        }
        pub fn with_target(mut self, target: impl Into<String>) -> Self {
            self.target = Some(target.into());
            self
        }
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
        pub fn new(command: impl Into<String>) -> Self {
            Self { command: command.into(), findings: Vec::new(), metadata: BTreeMap::new() }
        }
        pub fn push(&mut self, finding: Finding) { self.findings.push(finding); }
        pub fn insert_metadata(&mut self, key: impl Into<String>, value: Value) { self.metadata.insert(key.into(), value); }
        pub fn finalize(self) -> Self { self }
    }
}

pub mod process {
    use std::process::ExitStatus;
    use std::time::Duration;
    use tokio::process::Command;
    use crate::error::RuntimeError;

    #[derive(Debug, Clone, Copy)]
    pub struct CaptureLimits;
    impl CaptureLimits {
        pub const fn new(_: Duration, _: usize, _: usize) -> Self { Self }
    }

    #[derive(Debug)]
    pub struct CapturedOutput {
        pub status: ExitStatus,
        pub stdout: String,
        pub stderr: String,
    }

    pub async fn run_bounded_with_input(
        _: Command,
        _: impl Into<String>,
        _: CaptureLimits,
        _: &[u8],
    ) -> Result<CapturedOutput, RuntimeError> {
        Err(RuntimeError::Invariant("transport stub must not execute in certificate tests".to_owned()))
    }
}

pub mod ai;
