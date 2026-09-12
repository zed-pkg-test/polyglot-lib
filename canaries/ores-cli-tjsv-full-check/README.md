# ORES CLI TJSV full-check canary

This public `*-test` canary certifies the exact source slice from `ORESoftware/ores-cli#177` without treating this repository as a schema authority.

The copied `src/audit/tjsv_full_check.rs` must retain Git blob `41b5fc7ace31717fbb4980e728225d7b656ad979`. The copied production dispatcher snapshot must retain Git blob `6174f65a07145bd0f2b0624a94a5f578a45a3de1` and prove that the audited module is actually called from `audit_repository`.

The product lint enforces the fleet's peer-authority model: human-authored TypeSpec and independently human-authored JSON Schema Draft 2020-12 are equal first-class inputs; full TJSV admission must transpile TypeSpec through the official emitter into generated JSON Schema comparison evidence, compare that generated JSON with the independently authored JSON Schema, and fail closed on unexplained divergence. Generated schema, reports, SARIF, and Contract IR remain evidence rather than a third authority.

The canary's Rust harness supplies only the surrounding report/options types needed to execute the exact product module and its embedded positive/negative regressions. It does not reimplement the lint.
