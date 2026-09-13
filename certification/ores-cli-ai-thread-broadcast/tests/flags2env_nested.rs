use flags2env::BundledFlags2Env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

const CONTRACT: &str = r#"
[parse]
command_env = "ORES_CLI_COMMAND"
positionals_env = "ORES_CLI_POSITIONALS"
unknown_options_env = "ORES_CLI_UNKNOWN_OPTIONS"
errors_env = "ORES_CLI_PARSE_ERRORS"
allow_unknown = false

[flags.json]
env = "ORES_CLI_JSON"
aliases = ["json"]
type = "bool"
default = "true"

[commands.ai]
env = "ORES_CLI_COMMAND_AI"

[commands.ai.flags.provider]
env = "ORES_CLI_AI_PROVIDER"
aliases = ["provider"]
type = "string"
default = "all"

[commands.ai.flags.older-than-days]
env = "ORES_CLI_AI_OLDER_THAN_DAYS"
aliases = ["older-than-days"]
type = "integer"
default = 7

[commands.ai.flags.inactive-days]
env = "ORES_CLI_AI_INACTIVE_DAYS"
aliases = ["inactive-days"]
type = "integer"
default = 5

[commands.ai.flags.max-threads]
env = "ORES_CLI_AI_MAX_THREADS"
aliases = ["max-threads"]
type = "integer"
default = 20

[commands.ai.flags.concurrency]
env = "ORES_CLI_AI_CONCURRENCY"
aliases = ["concurrency"]
type = "integer"
default = 20

[commands.ai.commands.threads]
env = "ORES_CLI_COMMAND_AI_THREADS"

[commands.ai.commands.threads.commands.prompt]
env = "ORES_CLI_COMMAND_AI_THREADS_PROMPT"

[commands.ai.commands.threads.commands.prompt.flags.prompt]
env = "ORES_CLI_AI_PROMPT"
aliases = ["prompt"]
type = "string"
"#;

fn contract_path() -> String {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "ores-cli-ai-flags2env-{}-{stamp}.toml",
        std::process::id()
    ));
    fs::write(&path, CONTRACT).unwrap();
    path.to_string_lossy().into_owned()
}

#[test]
fn three_level_prompt_path_and_inherited_flags_resolve() {
    let path = contract_path();
    let parser = BundledFlags2Env::new();
    parser.audit_config(Some(&path)).unwrap();
    let argv = vec![
        "oresc".to_owned(),
        "ai".to_owned(),
        "threads".to_owned(),
        "prompt".to_owned(),
        "--no-json".to_owned(),
        "--provider=all".to_owned(),
        "--older-than-days=7".to_owned(),
        "--inactive-days=5".to_owned(),
        "--max-threads=20".to_owned(),
        "--concurrency=20".to_owned(),
        "--prompt=continue the unfinished work".to_owned(),
    ];

    let structured = parser.parse_structured(&argv, Some(&path)).unwrap();
    assert!(structured.errors.is_empty(), "{:?}", structured.errors);
    assert!(
        structured.unknown_options.is_empty(),
        "{:?}",
        structured.unknown_options
    );
    assert!(structured.extras.is_empty(), "{:?}", structured.extras);

    let resolved = parser.resolve_commands(&argv, Some(&path)).unwrap();
    assert_eq!(resolved.path, vec!["ai", "threads", "prompt"]);
    assert_eq!(
        structured.provided_flags.get("ORES_CLI_AI_PROVIDER"),
        Some(&"all".to_owned())
    );
    assert_eq!(
        structured.provided_flags.get("ORES_CLI_AI_MAX_THREADS"),
        Some(&"20".to_owned())
    );
    assert_eq!(
        structured.provided_flags.get("ORES_CLI_AI_PROMPT"),
        Some(&"continue the unfinished work".to_owned())
    );
    assert_eq!(
        structured.provided_flags.get("ORES_CLI_JSON"),
        Some(&"false".to_owned())
    );

    fs::remove_file(path).unwrap();
}
