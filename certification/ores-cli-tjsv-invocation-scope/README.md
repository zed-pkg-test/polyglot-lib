# ORES CLI TJSV invocation-scope certificate

This public `zed-pkg-test` certificate mirrors the exact production `src/audit/tjsv_invocation_scope.rs` source for `ORESoftware/ores-cli#244` at candidate `3105f76a2d91316128808216aaab7619d214d932`.

The authority contract is unchanged: authored TypeSpec and authored JSON Schema Draft 2020-12 are independent first-class peers with no precedence. Canonical TJSV transpiles TypeSpec to generated JSON Schema B; B is comparison evidence only and is compared with independently authored Schema A.

The lint now proves admission wiring at three nested boundaries:

1. a repository file cannot stitch evidence from unrelated files;
2. a workflow cannot stitch evidence from unrelated steps;
3. a `run:` step cannot stitch an incomplete TJSV invocation with unrelated shell commands.

Backslash continuations and YAML folded run scalars remain one logical command. The source lock binds both the exact mirrored module blob and the product audit dispatcher so adjacent OAuth/OIDC, full-check, and TJSV revision-consistency audits remain part of the certified composition.
