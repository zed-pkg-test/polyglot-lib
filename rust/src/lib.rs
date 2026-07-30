//! Rust slice of polyglot-lib, published as zedtest/polyglot-lib-rust.

pub const LANGUAGE: &str = "rust";

pub fn greet(who: &str) -> String {
    format!("hello {who} from polyglot-lib/rust")
}
