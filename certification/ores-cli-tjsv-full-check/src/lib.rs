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

    #[derive(Debug, Clone)]
    pub struct RepositoryAuditOptions {
        pub path: PathBuf,
        pub profile: String,
        pub additional_required_paths: Vec<String>,
    }

    #[path = "../tjsv_full_check.rs"]
    mod tjsv_full_check;

    #[cfg(test)]
    mod certification_tests {
        use std::fs;

        use tempfile::tempdir;

        use super::RepositoryAuditOptions;
        use super::tjsv_full_check::augment_tjsv_full_check_audit;
        use crate::model::CommandReport;

        fn audit(workflow: &str) -> CommandReport {
            let root = tempdir().expect("temporary repository");
            let contract = root.path().join("contracts/example");
            fs::create_dir_all(&contract).expect("contract directory");
            fs::write(
                contract.join("main.tsp"),
                "namespace Example;\nmodel Packet { value: string; }\n",
            )
            .expect("TypeSpec authority");
            fs::write(
                contract.join("authored.schema.json"),
                r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","$defs":{"Packet":{"type":"object"}}}"#,
            )
            .expect("authored JSON Schema");
            let workflows = root.path().join(".github/workflows");
            fs::create_dir_all(&workflows).expect("workflow directory");
            fs::write(workflows.join("contracts.yml"), workflow).expect("workflow");

            augment_tjsv_full_check_audit(
                &RepositoryAuditOptions {
                    path: root.path().to_path_buf(),
                    profile: "baseline".to_owned(),
                    additional_required_paths: Vec::new(),
                },
                CommandReport::new("audit repo"),
            )
        }

        #[test]
        fn accepts_real_compiler_entrypoint_with_explicit_comparison_evidence() {
            let report = audit(
                r#"run: |
  node tmp/tjsv/bin/typespec-json-schema-validator.mjs check \
    --typespec=contracts/example/main.tsp \
    --schema=contracts/example/authored.schema.json \
    --report=tmp/evidence/report.json \
    --contract-ir=tmp/evidence/contract-ir.json \
    --output-dir=tmp/evidence/generated
"#,
            );
            assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
        }

        #[test]
        fn rejects_mutable_action_reference() {
            let report = audit(
                r#"- uses: ORESoftware/typespec-json-schema-validator@main
  with:
    typespec: contracts/example/main.tsp
    schema: contracts/example/authored.schema.json
    report: tmp/evidence/report.json
    output_dir: tmp/evidence/generated
"#,
            );
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.code == "tjsv-full-check-missing"),
                "{:#?}",
                report.findings
            );
        }

        #[test]
        fn rejects_check_without_generated_schema_and_report_destinations() {
            let report = audit(
                "run: npx tjsv check --typespec=contracts/example/main.tsp --schema=contracts/example/authored.schema.json\n",
            );
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.code == "tjsv-full-check-missing"),
                "{:#?}",
                report.findings
            );
        }

        #[test]
        fn rejects_comment_only_decoy() {
            let report = audit(
                r#"# uses: ORESoftware/typespec-json-schema-validator@0123456789012345678901234567890123456789
# typespec: contracts/example/main.tsp
# schema: contracts/example/authored.schema.json
# report: tmp/evidence/report.json
# output_dir: tmp/evidence/generated
run: echo no-contract-admission
"#,
            );
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.code == "tjsv-full-check-missing"),
                "{:#?}",
                report.findings
            );
        }

        #[test]
        fn rejects_explicitly_disabled_differential_probes() {
            let report = audit(
                r#"- uses: ORESoftware/typespec-json-schema-validator@0123456789012345678901234567890123456789
  with:
    typespec: contracts/example/main.tsp
    schema: contracts/example/authored.schema.json
    report: tmp/evidence/report.json
    output_dir: tmp/evidence/generated
    probes: "false"
"#,
            );
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.code == "tjsv-full-check-missing"),
                "{:#?}",
                report.findings
            );
        }
    }
}
