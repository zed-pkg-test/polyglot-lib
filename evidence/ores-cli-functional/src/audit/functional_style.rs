use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;
use walkdir::{DirEntry, WalkDir};

use crate::model::{CommandReport, Finding};

const MAX_SOURCE_FILES: usize = 1024;
const MAX_SOURCE_BYTES: u64 = 1024 * 1024;
const HOT_PATH_MARKER: &str = "ores-functional: hot-path reason=";
const SKIPPED_DIRECTORIES: &[&str] = &[
    ".git",
    ".dart_tool",
    ".typespec-json-schema-validator",
    ".vendor",
    "build",
    "dist",
    "generated",
    "node_modules",
    "target",
    "vendor",
];

/// Inspect mutable caller-owned parameters in languages used by the ORES fleet.
///
/// The rule is intentionally opt-in through the `functional` repository profile
/// while the fleet migrates. It favors factory/transform functions returning new
/// values. Mutation remains admissible on measured hot paths when an adjacent
/// `ores-functional: hot-path reason=...` comment gives a meaningful rationale.
pub(super) fn audit_functional_style(root: &Path, report: &mut CommandReport) {
    let issues_before = report.issue_count();
    let mut scanned = 0usize;
    let mut candidates = 0usize;
    let mut exemptions = 0usize;

    for entry in WalkDir::new(root)
        .max_depth(14)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !skip_entry(entry))
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() || !supported_source(entry.path()) {
            continue;
        }
        if scanned >= MAX_SOURCE_FILES {
            report.push(
                Finding::warning(
                    "functional-style-file-limit",
                    format!(
                        "functional audit stopped after {MAX_SOURCE_FILES} source files; split or narrow the repository surface"
                    ),
                )
                .with_target(relative_display(root, entry.path())),
            );
            break;
        }
        scanned += 1;

        let metadata = match fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(error) => {
                report.push(
                    Finding::warning(
                        "functional-style-source-unreadable",
                        format!("source metadata could not be read: {error}"),
                    )
                    .with_target(relative_display(root, entry.path())),
                );
                continue;
            }
        };
        if metadata.file_type().is_symlink() || metadata.len() > MAX_SOURCE_BYTES {
            continue;
        }
        let text = match fs::read_to_string(entry.path()) {
            Ok(text) => text,
            Err(error) => {
                report.push(
                    Finding::warning(
                        "functional-style-source-unreadable",
                        format!("source could not be read as UTF-8: {error}"),
                    )
                    .with_target(relative_display(root, entry.path())),
                );
                continue;
            }
        };
        let extension = entry
            .path()
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        let (file_candidates, file_exemptions) = match extension {
            "rs" => audit_rust(root, entry.path(), &text, report),
            "go" => audit_go(root, entry.path(), &text, report),
            "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" | "dart" => {
                audit_property_mutation(root, entry.path(), &text, extension, report)
            }
            _ => (0, 0),
        };
        candidates += file_candidates;
        exemptions += file_exemptions;
    }

    report.insert_metadata("functionalStyleFilesScanned", json!(scanned));
    report.insert_metadata("functionalStyleCandidates", json!(candidates));
    report.insert_metadata("functionalStyleHotPathExemptions", json!(exemptions));
    if scanned > 0 && report.issue_count() == issues_before {
        report.push(Finding::info(
            "functional-style-ready",
            "functional profile found no undocumented caller-owned mutation candidates",
        ));
    }
}

fn audit_rust(root: &Path, path: &Path, text: &str, report: &mut CommandReport) -> (usize, usize) {
    let lines = text.lines().collect::<Vec<_>>();
    let mut index = 0usize;
    let mut candidates = 0usize;
    let mut exemptions = 0usize;
    while index < lines.len() {
        let line = lines[index].trim_start();
        if line.starts_with("//") || !line.contains("fn ") {
            index += 1;
            continue;
        }
        let (signature, end) = signature_window(&lines, index);
        if !signature.contains("&mut ") {
            index = end + 1;
            continue;
        }
        let function = rust_function_name(&signature).unwrap_or("function");
        let target = format!("{}:{}", relative_display(root, path), index + 1);
        let exemption = hot_path_exemption(&lines, index);

        if signature.contains("&mut self") {
            candidates += 1;
            exemptions += emit_candidate(
                report,
                exemption.as_ref(),
                "functional-style-mutable-receiver",
                format!(
                    "`{function}` mutates `self`; prefer a consuming/immutable transform such as `with_*` or a factory returning a new value"
                ),
                &target,
            );
        }

        let non_self = signature.replace("&mut self", "");
        if non_self.contains("&mut ") && !only_stateful_sink(&non_self) {
            candidates += 1;
            exemptions += emit_candidate(
                report,
                exemption.as_ref(),
                "functional-style-mutable-parameter",
                format!(
                    "`{function}` accepts a mutable caller-owned parameter; prefer returning a new value/struct instead of output-parameter mutation"
                ),
                &target,
            );
        }
        index = end + 1;
    }
    (candidates, exemptions)
}

fn audit_go(root: &Path, path: &Path, text: &str, report: &mut CommandReport) -> (usize, usize) {
    let lines = text.lines().collect::<Vec<_>>();
    let mut candidates = 0usize;
    let mut exemptions = 0usize;
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("func ") || trimmed.starts_with("func (") {
            continue;
        }
        let Some(open) = trimmed.find('(') else {
            continue;
        };
        let Some(close_offset) = trimmed[open + 1..].find(')') else {
            continue;
        };
        let close = open + 1 + close_offset;
        let params = &trimmed[open + 1..close];
        for segment in params.split(',') {
            let segment = segment.trim();
            if !segment.contains('*') {
                continue;
            }
            let name = segment.split_whitespace().next().unwrap_or_default().trim();
            if !identifier(name) || !body_mutates(&lines, index + 1, name, "go") {
                continue;
            }
            candidates += 1;
            let target = format!("{}:{}", relative_display(root, path), index + 1);
            exemptions += emit_candidate(
                report,
                hot_path_exemption(&lines, index).as_ref(),
                "functional-style-go-pointer-mutation",
                format!(
                    "Go function mutates pointer parameter `{name}`; prefer returning a newly constructed value when allocation/copy cost is acceptable"
                ),
                &target,
            );
        }
    }
    (candidates, exemptions)
}

fn audit_property_mutation(
    root: &Path,
    path: &Path,
    text: &str,
    extension: &str,
    report: &mut CommandReport,
) -> (usize, usize) {
    let lines = text.lines().collect::<Vec<_>>();
    let mut candidates = 0usize;
    let mut exemptions = 0usize;
    for (index, line) in lines.iter().enumerate() {
        let Some(params) = function_parameters(line, extension) else {
            continue;
        };
        for name in params {
            if !body_mutates(&lines, index + 1, &name, extension) {
                continue;
            }
            candidates += 1;
            let target = format!("{}:{}", relative_display(root, path), index + 1);
            exemptions += emit_candidate(
                report,
                hot_path_exemption(&lines, index).as_ref(),
                "functional-style-object-parameter-mutation",
                format!(
                    "function mutates caller-owned parameter `{name}`; prefer object spread/copyWith/factory construction returning a new value"
                ),
                &target,
            );
        }
    }
    (candidates, exemptions)
}

fn emit_candidate(
    report: &mut CommandReport,
    exemption: Option<&Result<String, ()>>,
    code: &str,
    message: String,
    target: &str,
) -> usize {
    match exemption {
        Some(Ok(reason)) => {
            report.push(
                Finding::info(
                    "functional-style-hot-path-exemption",
                    format!("mutation retained for documented hot path: {reason}"),
                )
                .with_target(target),
            );
            1
        }
        Some(Err(())) => {
            report.push(
                Finding::warning(
                    "functional-style-hot-path-missing-rationale",
                    "hot-path mutation exemption must include a concrete performance rationale after `reason=`",
                )
                .with_target(target),
            );
            0
        }
        None => {
            report.push(Finding::warning(code, message).with_target(target));
            0
        }
    }
}

fn hot_path_exemption(lines: &[&str], index: usize) -> Option<Result<String, ()>> {
    let start = index.saturating_sub(3);
    for line in &lines[start..=index] {
        let Some((_, reason)) = line.split_once(HOT_PATH_MARKER) else {
            continue;
        };
        let reason = reason.trim().trim_end_matches("*/").trim();
        return if reason.len() >= 12 && reason.split_whitespace().count() >= 2 {
            Some(Ok(reason.to_owned()))
        } else {
            Some(Err(()))
        };
    }
    None
}

fn signature_window(lines: &[&str], start: usize) -> (String, usize) {
    let mut signature = String::new();
    let mut end = start;
    for (offset, line) in lines[start..].iter().take(8).enumerate() {
        if !signature.is_empty() {
            signature.push(' ');
        }
        signature.push_str(line.trim());
        end = start + offset;
        if line.contains('{') || line.trim_end().ends_with(';') {
            break;
        }
    }
    (signature, end)
}

fn rust_function_name(signature: &str) -> Option<&str> {
    let (_, rest) = signature.split_once("fn ")?;
    let length = rest
        .char_indices()
        .take_while(|(_, value)| value.is_ascii_alphanumeric() || *value == '_')
        .map(|(index, value)| index + value.len_utf8())
        .last()?;
    Some(&rest[..length])
}

fn only_stateful_sink(signature: &str) -> bool {
    let count = signature.matches("&mut ").count();
    count == 1
        && [
            "Connection",
            "Transaction",
            "Formatter",
            "Hasher",
            "Writer",
            "BufWriter",
            "std::io::Write",
        ]
        .iter()
        .any(|sink| signature.contains(sink))
}

fn function_parameters(line: &str, extension: &str) -> Option<Vec<String>> {
    let trimmed = line.trim();
    if trimmed.starts_with("//")
        || trimmed.starts_with("if ")
        || trimmed.starts_with("for ")
        || trimmed.starts_with("while ")
        || trimmed.starts_with("switch ")
        || trimmed.starts_with("catch ")
    {
        return None;
    }
    let open = trimmed.find('(')?;
    let close = trimmed[open + 1..].find(')')? + open + 1;
    if extension != "dart"
        && !trimmed.contains("function ")
        && !trimmed.contains("=>")
        && !trimmed[close + 1..].contains('{')
    {
        return None;
    }
    if extension == "dart" && !trimmed[close + 1..].contains('{') && !trimmed.contains("=>") {
        return None;
    }
    let mut result = Vec::new();
    for raw in trimmed[open + 1..close].split(',') {
        let raw = raw.trim();
        if raw.is_empty() || raw.starts_with('{') || raw.starts_with('[') {
            continue;
        }
        let without_default = raw.split('=').next().unwrap_or(raw).trim();
        let candidate = if matches!(extension, "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs") {
            without_default
                .split(':')
                .next()
                .unwrap_or(without_default)
                .split_whitespace()
                .last()
                .unwrap_or_default()
        } else {
            without_default
                .split_whitespace()
                .last()
                .unwrap_or_default()
        };
        let candidate = candidate.trim_matches(|ch: char| ch == '?' || ch == '{' || ch == '}');
        if identifier(candidate) {
            result.push(candidate.to_owned());
        }
    }
    (!result.is_empty()).then_some(result)
}

fn body_mutates(lines: &[&str], start: usize, name: &str, extension: &str) -> bool {
    let end = (start + 48).min(lines.len());
    let property = format!("{name}.");
    let dereference = format!("*{name}");
    for line in &lines[start..end] {
        let compact = line.trim();
        if compact.contains(&format!("Object.assign({name},")) {
            return true;
        }
        if compact.starts_with(&dereference) && assignment_operator(compact) {
            return true;
        }
        if let Some(position) = compact.find(&property) {
            let tail = &compact[position + property.len()..];
            if assignment_operator(tail)
                || tail.contains(".push(")
                || tail.starts_with("push(")
                || tail.contains(".splice(")
                || tail.starts_with("add(")
                || tail.starts_with("addAll(")
                || (extension == "go" && tail.contains(" ="))
            {
                return true;
            }
        }
    }
    false
}

fn assignment_operator(text: &str) -> bool {
    [
        " = ", " += ", " -= ", " *= ", " /= ", " ??= ", " ||= ", " &&= ",
    ]
    .iter()
    .any(|operator| text.contains(operator))
        || (text.contains(" =") && !text.contains(" =="))
}

fn skip_entry(entry: &DirEntry) -> bool {
    if entry.depth() == 0 || !entry.file_type().is_dir() {
        return false;
    }
    entry
        .file_name()
        .to_str()
        .is_some_and(|name| SKIPPED_DIRECTORIES.contains(&name))
}

fn supported_source(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|value| value.to_str()),
        Some("rs" | "go" | "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" | "dart")
    )
}

fn identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|value| value.is_ascii_alphanumeric() || value == '_')
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::audit_functional_style;
    use crate::model::{CommandReport, Severity};

    fn audit(path: &str, source: &str) -> CommandReport {
        let root = tempdir().expect("temp repo");
        let file = root.path().join(path);
        fs::create_dir_all(file.parent().expect("parent")).expect("create parent");
        fs::write(&file, source).expect("write source");
        let mut report = CommandReport::new("audit repo");
        audit_functional_style(root.path(), &mut report);
        report.finalize()
    }

    fn has(report: &CommandReport, code: &str) -> bool {
        report.findings.iter().any(|finding| finding.code == code)
    }

    #[test]
    fn rust_factory_is_not_flagged() {
        let report = audit(
            "src/lib.rs",
            "fn create_foo() -> Foo { Foo { value: 1 } }\n",
        );
        assert!(!has(&report, "functional-style-mutable-parameter"));
    }

    #[test]
    fn rust_output_parameter_is_flagged() {
        let report = audit(
            "src/lib.rs",
            "fn mutate_stuff(value: &mut Foo) { value.count += 1; }\n",
        );
        assert!(has(&report, "functional-style-mutable-parameter"));
    }

    #[test]
    fn documented_hot_path_is_admitted_as_evidence() {
        let report = audit(
            "src/lib.rs",
            "// ores-functional: hot-path reason=reuses a preallocated packet buffer\nfn fill_packet(value: &mut Vec<u8>) { value.push(1); }\n",
        );
        assert!(has(&report, "functional-style-hot-path-exemption"));
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.severity != Severity::Info)
        );
    }

    #[test]
    fn empty_hot_path_reason_fails_closed() {
        let report = audit(
            "src/lib.rs",
            "// ores-functional: hot-path reason=fast\nfn fill_packet(value: &mut Vec<u8>) { value.push(1); }\n",
        );
        assert!(has(&report, "functional-style-hot-path-missing-rationale"));
    }

    #[test]
    fn go_pointer_output_mutation_is_flagged() {
        let report = audit("worker.go", "func Mutate(foo *Foo) {\n  foo.Count = 2\n}\n");
        assert!(has(&report, "functional-style-go-pointer-mutation"));
    }

    #[test]
    fn typescript_parameter_mutation_is_flagged() {
        let report = audit(
            "client.ts",
            "function enrich(foo: Foo) {\n  foo.count = 2;\n}\n",
        );
        assert!(has(&report, "functional-style-object-parameter-mutation"));
    }

    #[test]
    fn dart_parameter_mutation_is_flagged() {
        let report = audit(
            "client.dart",
            "Foo enrich(Foo foo) {\n  foo.count = 2;\n  return foo;\n}\n",
        );
        assert!(has(&report, "functional-style-object-parameter-mutation"));
    }

    #[test]
    fn generated_directories_are_ignored() {
        let report = audit(
            "generated/client.ts",
            "function enrich(foo: Foo) {\n  foo.count = 2;\n}\n",
        );
        assert!(!has(&report, "functional-style-object-parameter-mutation"));
    }
}
