#!/usr/bin/env python3
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: reconstruct-product-source.py <tjsv_invocation_scope.rs>")

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
before = """            return (!folded.trim().is_empty())
                .then(|| vec![folded])
                .unwrap_or_default();"""
after = """            return if folded.trim().is_empty() {
                Vec::new()
            } else {
                vec![folded]
            };"""

if text.count(before) != 1:
    raise SystemExit("expected exactly one Rust 1.95 obfuscated-if-else source anchor")

path.write_text(text.replace(before, after, 1), encoding="utf-8")
