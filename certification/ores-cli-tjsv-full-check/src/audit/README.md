# Canary module anchor

The certification harness declares the same `audit` module boundary as `ores-cli` and explicitly includes the byte-locked production mirror from `../tjsv_full_check.rs`.

This directory remains as a visible module-layout anchor and as evidence that no second implementation lives under `src/audit/`. The mirrored `tjsv_full_check.rs` bytes, its recorded upstream Git blob, and the adversarial tests remain the executable authority for this certificate.

This directory is harness-only. It is not a contract source, generated Schema B, runtime implementation, or additional authority.
