# polyglot-lib

One repository, four languages, **four independently installable zed packages**.

This is the fixture for zed-pkg's multi-language model (see
[zed-docs doc 16](https://github.com/zed-pkg/zed-docs/blob/main/docs/16-zed-pkg-test-ci.md)).
A single `[targets]` table in [`.zpkg.toml`](.zpkg.toml) declares one language
subtree each; `zed publish` fans that out:

| Target | Source | Published package | Ecosystem |
| --- | --- | --- | --- |
| `nodejs` | [`node/`](node/) | `zedtest/polyglot-lib-nodejs` | npm |
| `python` | [`python/`](python/) | `zedtest/polyglot-lib-python` | pypi |
| `golang` | [`go/`](go/) | `zedtest/polyglot-lib-golang` | gomod |
| `rust` | [`rust/`](rust/) | `zedtest/polyglot-lib-rust` | cargo |

One version in the repo, four packages on the wire. Each artifact is re-rooted at
its own subtree and carries none of the others.

## Two-source consumer matrix

DEN-1514 combines this language-specific source repository with the universal
`zedtest/shared-schema` package. Three heterogeneous projects install both:

- [`polyglot-node-app`](https://github.com/zed-pkg-test/polyglot-node-app) — Node CLI-style consumer
- [`polyglot-go-app`](https://github.com/zed-pkg-test/polyglot-go-app) — Go worker/service-style consumer
- [`python-app`](https://github.com/zed-pkg-test/python-app) — Python API/application-style consumer

Each consumer executes its native `polyglot-lib` slice and validates the same
installed JSON Schema bytes. CI publishes both sources to a hermetic `file://`
registry, so there are no public registry writes, credentials, or mutable tags.

## Ecosystem isolation

Each published artifact's derived manifest declares its language/ecosystem. A
consumer therefore refuses the wrong slice unless the caller explicitly opts
into an ecosystem mismatch.

## License

MIT
