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
its own subtree and carries none of the others, so a Go consumer downloads Go
bytes only:

```console
$ zed pack
packed zedtest/polyglot-lib-golang@0.1.0 (target golang)
  sha256 06d8407f…   size 613 B (4 files)
packed zedtest/polyglot-lib-nodejs@0.1.0 (target nodejs)
  sha256 ac5af270…   size 733 B (4 files)
…
```

Each published artifact's derived manifest declares what it is for
(`language = "golang"`, `ecosystem = "gomod"`), which is what lets a consumer's
`zed install` refuse the wrong one:

```console
$ zed install    # in an npm project, having asked for the golang package
error: `zedtest/polyglot-lib-golang` targets the `gomod` ecosystem, but this project looks like `npm`
  try instead: zedtest/polyglot-lib-nodejs
  if this is deliberate, re-run with --allow-ecosystem-mismatch
```

## Consumers

- [`polyglot-node-app`](https://github.com/zed-pkg-test/polyglot-node-app) — takes `-nodejs` alongside npm
- [`polyglot-go-app`](https://github.com/zed-pkg-test/polyglot-go-app) — takes `-golang` via a `go.mod` replace

Both run the whole loop in GitHub Actions against a hermetic `file://` registry:
no server, no secrets.

## License

MIT
