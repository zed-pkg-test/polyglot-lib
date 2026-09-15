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
    use serde_json::Value;
    use std::collections::BTreeMap;

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
            Self {
                code: code.into(),
                message: message.into(),
                target: None,
                details: BTreeMap::new(),
                error: false,
            }
        }
        pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
            Self {
                code: code.into(),
                message: message.into(),
                target: None,
                details: BTreeMap::new(),
                error: true,
            }
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
        pub fn exit_code(&self) -> u8 {
            u8::from(self.findings.iter().any(|finding| finding.error))
        }
    }
}

pub mod process {
    use crate::error::RuntimeError;
    use std::process::ExitStatus;
    use std::time::Duration;
    use tokio::process::Command;

    #[derive(Debug, Clone, Copy)]
    pub struct CaptureLimits;
    impl CaptureLimits {
        pub const fn new(_: Duration, _: usize, _: usize) -> Self {
            Self
        }
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
        Err(RuntimeError::Invariant(
            "transport stub must not execute in certificate tests".to_owned(),
        ))
    }
}

pub mod flags {
    use crate::error::RuntimeError;

    pub fn active_flag_contract_path() -> Result<String, RuntimeError> {
        Ok("/tmp/ores-cli-ai-cert-contract.toml".to_owned())
    }
}

pub mod output {
    use crate::error::RuntimeError;
    use crate::model::CommandReport;

    pub fn emit_report(_: &CommandReport, _: bool) -> Result<(), RuntimeError> {
        Ok(())
    }
}

pub mod ai;
pub mod ai_cli;
