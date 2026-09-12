# TJSV command-atomicity certificate

This certificate binds `ORESoftware/ores-cli#244` and distinguishes two admission failures:

- **cross-step stitching**: required TJSV command/action and peer-authority evidence are distributed across unrelated GitHub Actions steps;
- **cross-command stitching**: one `run:` step contains the right aggregate tokens, but no single logical shell command contains the complete fail-closed TJSV admission.

Accepted shell forms include one complete command split by backslash continuation and one complete YAML folded `run: >` scalar. Setup and cleanup commands may surround the complete TJSV command, but cannot contribute missing TypeSpec, authored JSON Schema A, parity-report, or generated-Schema-B evidence tokens to it.

The authority model is unchanged: TypeSpec and authored Draft 2020-12 JSON Schema A are independent first-class peers with no precedence. TypeSpec-generated Schema B is comparison evidence only and must be compared with authored Schema A.
