# Canary module anchor

This directory exists so Rust can resolve the certification harness's inline `audit` module path to the byte-identical production mirror at `../tjsv_full_check.rs`.

The mirrored `tjsv_full_check.rs` bytes and their recorded upstream Git blob remain unchanged. This directory is harness-only and is not an additional contract or implementation authority.
