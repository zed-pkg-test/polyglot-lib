use std::fs;

use tempfile::tempdir;

use super::{RepositoryAuditOptions, tjsv_full_check::augment_tjsv_full_check_audit};
use crate::model::CommandReport;

fn run(workflow: &str) -> CommandReport {
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
    .expect("authored JSON Schema authority");
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

fn has_missing(report: &CommandReport) -> bool {
    report
        .findings
        .iter()
        .any(|finding| finding.code == "tjsv-full-check-missing")
}

#[test]
fn accepts_real_compiler_entrypoint_with_explicit_schema_b_and_report() {
    let report = run(
        r#"run: |
  node tmp/tjsv/bin/typespec-json-schema-validator.mjs check \
    --typespec=contracts/example/main.tsp \
    --schema=contracts/example/authored.schema.json \
    --report=artifacts/parity.json \
    --output-dir=artifacts/generated
"#,
    );
    assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
}

#[test]
fn rejects_mutable_action_reference() {
    let report = run(
        "- uses: ORESoftware/typespec-json-schema-validator@main\n  with:\n    typespec: contracts/example/main.tsp\n    schema: contracts/example/authored.schema.json\n    report: artifacts/parity.json\n    output_dir: artifacts/generated\n",
    );
    assert!(has_missing(&report), "{:#?}", report.findings);
}

#[test]
fn rejects_check_without_comparison_destinations() {
    let report = run(
        "run: npx tjsv check --typespec=contracts/example/main.tsp --schema=contracts/example/authored.schema.json\n",
    );
    assert!(has_missing(&report), "{:#?}", report.findings);
}

#[test]
fn rejects_comment_only_decoy() {
    let report = run(
        "# uses: ORESoftware/typespec-json-schema-validator@0123456789012345678901234567890123456789\n# typespec: contracts/example/main.tsp\n# schema: contracts/example/authored.schema.json\n# report: artifacts/parity.json\n# output_dir: artifacts/generated\nrun: echo no-admission\n",
    );
    assert!(has_missing(&report), "{:#?}", report.findings);
}

#[test]
fn rejects_explicitly_disabled_differential_probes() {
    let report = run(
        "- uses: ORESoftware/typespec-json-schema-validator@0123456789012345678901234567890123456789\n  with:\n    typespec: contracts/example/main.tsp\n    schema: contracts/example/authored.schema.json\n    report: artifacts/parity.json\n    output_dir: artifacts/generated\n    probes: false\n",
    );
    assert!(has_missing(&report), "{:#?}", report.findings);
}

#[test]
fn one_invocation_does_not_cover_a_different_contract_home() {
    let root = tempdir().expect("temporary repository");
    for name in ["one", "two"] {
        let contract = root.path().join(format!("contracts/{name}"));
        fs::create_dir_all(&contract).expect("contract directory");
        fs::write(contract.join("main.tsp"), "model Packet {}\n").expect("TypeSpec");
        fs::write(
            contract.join("authored.schema.json"),
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema"}"#,
        )
        .expect("schema");
    }
    let workflows = root.path().join(".github/workflows");
    fs::create_dir_all(&workflows).expect("workflows");
    fs::write(
        workflows.join("contracts.yml"),
        "run: npx tjsv check --typespec=contracts/one/main.tsp --schema=contracts/one/authored.schema.json --report=artifacts/parity.json --output-dir=artifacts/generated\n",
    )
    .expect("workflow");

    let report = augment_tjsv_full_check_audit(
        &RepositoryAuditOptions {
            path: root.path().to_path_buf(),
            profile: "baseline".to_owned(),
            additional_required_paths: Vec::new(),
        },
        CommandReport::new("audit repo"),
    );
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|finding| finding.code == "tjsv-full-check-covered")
            .count(),
        1
    );
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|finding| finding.code == "tjsv-full-check-missing")
            .count(),
        1
    );
}
