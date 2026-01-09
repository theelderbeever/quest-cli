// Integration tests for CLI - tests external usage via command execution
// These tests verify the CLI works correctly as an external tool

use assert_cmd::Command;
use predicates::prelude::*;
use std::env;
use std::fs;
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

// Helper to create a test quest file
fn create_temp_quest_file(content: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("test-quest.yaml");
    fs::write(&file_path, content).unwrap();
    (dir, file_path)
}

// Helper to get quest command using the recommended macro
fn quest_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("quest"))
}

#[test]
fn test_cli_help_flag() {
    let mut cmd = quest_cmd();
    cmd.arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Cli for all the http fetch"));
}

#[test]
fn test_list_command_with_valid_file() {
    let quest_file = fixture_path("test-quests.yaml");

    let mut cmd = quest_cmd();
    cmd.arg("list").arg("--file").arg(quest_file);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("simple-get"))
        .stdout(predicate::str::contains("post-with-json"))
        .stdout(predicate::str::contains("composed-url"));
}

#[test]
fn test_list_command_with_nonexistent_file() {
    let mut cmd = quest_cmd();
    cmd.arg("list").arg("--file").arg("nonexistent-file.yaml");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Failed to load quest file"));
}

#[test]
fn test_go_command_with_valid_quest() {
    let quest_file = fixture_path("test-quests.yaml");

    let mut cmd = quest_cmd();
    cmd.arg("go")
        .arg("simple-get")
        .arg("--file")
        .arg(quest_file);

    // This will actually make an HTTP request to httpbin.org
    // In a real CI environment, you might want to mock this
    cmd.assert().success();
}

#[test]
fn test_go_command_with_nonexistent_quest() {
    let quest_file = fixture_path("test-quests.yaml");

    let mut cmd = quest_cmd();
    cmd.arg("go")
        .arg("nonexistent-quest")
        .arg("--file")
        .arg(quest_file);

    cmd.assert().failure().stderr(predicate::str::contains(
        "Quest 'nonexistent-quest' not found",
    ));
}

#[test]
fn test_malformed_header_error() {
    let mut cmd = quest_cmd();
    cmd.arg("get")
        .arg("https://httpbin.org/get")
        .arg("--header")
        .arg("InvalidHeader");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Invalid header format"))
        .stderr(predicate::str::contains("must contain a colon"));
}

#[test]
fn test_malformed_param_error() {
    let mut cmd = quest_cmd();
    cmd.arg("get")
        .arg("https://httpbin.org/get")
        .arg("--param")
        .arg("invalidparam");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Invalid parameter format"))
        .stderr(predicate::str::contains("must contain an equals sign"));
}

#[test]
fn test_malformed_auth_error() {
    let mut cmd = quest_cmd();
    cmd.arg("get")
        .arg("https://httpbin.org/get")
        .arg("--auth")
        .arg("invalidauth");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Invalid auth format"))
        .stderr(predicate::str::contains("must contain a colon"));
}

#[test]
fn test_empty_header_name_error() {
    let mut cmd = quest_cmd();
    cmd.arg("get")
        .arg("https://httpbin.org/get")
        .arg("--header")
        .arg(": value");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Header name cannot be empty"));
}

#[test]
fn test_empty_param_name_error() {
    let mut cmd = quest_cmd();
    cmd.arg("get")
        .arg("https://httpbin.org/get")
        .arg("--param")
        .arg("=value");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Parameter name cannot be empty"));
}

#[test]
fn test_empty_auth_username_error() {
    let mut cmd = quest_cmd();
    cmd.arg("get")
        .arg("https://httpbin.org/get")
        .arg("--auth")
        .arg(":password");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Username cannot be empty"));
}

#[test]
fn test_valid_header_with_empty_value() {
    let mut cmd = quest_cmd();
    cmd.arg("get")
        .arg("https://httpbin.org/get")
        .arg("--header")
        .arg("X-Custom:");

    cmd.assert().success();
}

#[test]
fn test_valid_param_with_empty_value() {
    let mut cmd = quest_cmd();
    cmd.arg("get")
        .arg("https://httpbin.org/get")
        .arg("--param")
        .arg("key=");

    cmd.assert().success();
}

#[test]
fn test_cli_option_override_quest_file() {
    let quest_content = r#"
quests:
  test-override:
    method: get
    url: https://httpbin.org/get
    headers:
      - "X-Quest-Header: from-file"
    user_agent: QuestAgent/1.0
"#;

    let (_temp_dir, quest_file) = create_temp_quest_file(quest_content);

    let mut cmd = quest_cmd();
    cmd.arg("go")
        .arg("test-override")
        .arg("--file")
        .arg(&quest_file)
        .arg("--header")
        .arg("X-CLI-Header: from-cli")
        .arg("--user-agent")
        .arg("CliAgent/2.0");

    // Should succeed - CLI options override quest file options
    cmd.assert().success();
}

#[test]
fn test_get_command_with_headers() {
    let mut cmd = quest_cmd();
    cmd.arg("get")
        .arg("https://httpbin.org/get")
        .arg("--header")
        .arg("X-Test: value1")
        .arg("--header")
        .arg("X-Another: value2");

    cmd.assert().success();
}

#[test]
fn test_get_command_with_params() {
    let mut cmd = quest_cmd();
    cmd.arg("get")
        .arg("https://httpbin.org/get")
        .arg("--param")
        .arg("foo=bar")
        .arg("--param")
        .arg("baz=qux");

    cmd.assert().success();
}

#[test]
fn test_post_command_with_json() {
    let json_file = fixture_path("create-user.json");

    let mut cmd = quest_cmd();
    cmd.arg("post")
        .arg("https://httpbin.org/post")
        .arg("--json")
        .arg(format!("@{}", json_file.display()));

    cmd.assert().success();
}

#[test]
fn test_post_command_with_inline_json() {
    let mut cmd = quest_cmd();
    cmd.arg("post")
        .arg("https://httpbin.org/post")
        .arg("--json")
        .arg(r#"{"name": "test", "value": 123}"#);

    cmd.assert().success();
}

#[test]
fn test_put_command() {
    let mut cmd = quest_cmd();
    cmd.arg("put")
        .arg("https://httpbin.org/put")
        .arg("--raw")
        .arg("updated content");

    cmd.assert().success();
}

#[test]
fn test_patch_command() {
    let mut cmd = quest_cmd();
    cmd.arg("patch")
        .arg("https://httpbin.org/patch")
        .arg("--json")
        .arg(r#"{"updated": true}"#);

    cmd.assert().success();
}

#[test]
fn test_delete_command() {
    let mut cmd = quest_cmd();
    cmd.arg("delete").arg("https://httpbin.org/delete");

    cmd.assert().success();
}

#[test]
fn test_verbose_mode_output() {
    let mut cmd = quest_cmd();
    cmd.arg("get")
        .arg("https://httpbin.org/get")
        .arg("--verbose");

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("GET"))
        .stderr(predicate::str::contains("HTTP/1.1"));
}

#[test]
fn test_verbose_mode_redacts_bearer_token() {
    let mut cmd = quest_cmd();
    cmd.arg("get")
        .arg("https://httpbin.org/bearer")
        .arg("--bearer")
        .arg("secret-token-12345")
        .arg("--verbose");

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Authorization: Bearer [REDACTED]"))
        .stderr(predicate::str::contains("secret-token-12345").not());
}

#[test]
fn test_verbose_mode_redacts_basic_auth() {
    let mut cmd = quest_cmd();
    cmd.arg("get")
        .arg("https://httpbin.org/basic-auth/user/pass")
        .arg("--auth")
        .arg("user:secretpassword")
        .arg("--verbose");

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Authorization: Basic [REDACTED]"))
        .stderr(predicate::str::contains("secretpassword").not());
}

#[test]
fn test_verbose_mode_shows_referer() {
    let mut cmd = quest_cmd();
    cmd.arg("get")
        .arg("https://httpbin.org/get")
        .arg("--referer")
        .arg("https://example.com")
        .arg("--verbose");

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Referer: https://example.com"));
}

#[test]
fn test_user_agent_header() {
    let mut cmd = quest_cmd();
    cmd.arg("get")
        .arg("https://httpbin.org/user-agent")
        .arg("--user-agent")
        .arg("CustomAgent/3.0");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("CustomAgent/3.0"));
}

#[test]
fn test_accept_header() {
    let mut cmd = quest_cmd();
    cmd.arg("get")
        .arg("https://httpbin.org/headers")
        .arg("--accept")
        .arg("application/xml");

    cmd.assert().success();
}

#[test]
fn test_simple_output_mode() {
    let mut cmd = quest_cmd();
    cmd.arg("get")
        .arg("https://httpbin.org/json")
        .arg("--simple");

    // Simple mode should not colorize JSON
    cmd.assert().success();
}

#[test]
fn test_output_to_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let output_file = temp_dir.path().join("response.txt");

    let mut cmd = quest_cmd();
    cmd.arg("get")
        .arg("https://httpbin.org/get")
        .arg("--output")
        .arg(&output_file);

    cmd.assert().success();

    // Verify file was created and has content
    assert!(output_file.exists());
    let content = fs::read_to_string(&output_file).unwrap();
    assert!(!content.is_empty());
}

#[test]
fn test_env_file_loading() {
    let temp_dir = tempfile::tempdir().unwrap();
    let env_file = temp_dir.path().join(".env");
    fs::write(&env_file, "TEST_VAR=test_value\n").unwrap();

    let mut cmd = quest_cmd();
    cmd.arg("get")
        .arg("https://httpbin.org/get")
        .arg("--env")
        .arg(&env_file);

    cmd.assert().success();
}

// ============================================================================
// Parameter Handling Tests - Added to fix duplicate parameter bug
// ============================================================================

#[test]
fn test_quest_go_with_cli_params() {
    let quest_content = r#"
quests:
  test-params:
    method: get
    url: https://httpbin.org/get
    params:
      - foo=bar
      - baz=qux
"#;

    let (_temp_dir, quest_file) = create_temp_quest_file(quest_content);

    let mut cmd = quest_cmd();
    cmd.arg("go")
        .arg("test-params")
        .arg("--file")
        .arg(&quest_file)
        .arg("--param")
        .arg("hello=world");

    let output = cmd.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    // Parse the JSON response from httpbin
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    // Check the args field directly - httpbin returns query params here
    let args = json["args"].as_object().unwrap();

    // Each param should appear exactly once as a key in args
    assert_eq!(args.get("foo").unwrap().as_str().unwrap(), "bar");
    assert_eq!(args.get("baz").unwrap().as_str().unwrap(), "qux");
    assert_eq!(args.get("hello").unwrap().as_str().unwrap(), "world");

    // Verify exactly 3 params (no duplicates)
    assert_eq!(args.len(), 3, "Should have exactly 3 parameters");
}

#[test]
fn test_quest_go_with_multiple_cli_params() {
    let quest_content = r#"
quests:
  test-multi-params:
    method: get
    url: https://httpbin.org/get
    params:
      - foo=bar
"#;

    let (_temp_dir, quest_file) = create_temp_quest_file(quest_content);

    let mut cmd = quest_cmd();
    cmd.arg("go")
        .arg("test-multi-params")
        .arg("--file")
        .arg(&quest_file)
        .arg("--param")
        .arg("a=1")
        .arg("--param")
        .arg("b=2");

    let output = cmd.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    // Parse the JSON response from httpbin
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let args = json["args"].as_object().unwrap();

    // Each param should appear exactly once
    assert_eq!(args.get("foo").unwrap().as_str().unwrap(), "bar");
    assert_eq!(args.get("a").unwrap().as_str().unwrap(), "1");
    assert_eq!(args.get("b").unwrap().as_str().unwrap(), "2");

    // Verify exactly 3 params
    assert_eq!(args.len(), 3, "Should have exactly 3 parameters");
}

#[test]
fn test_direct_get_with_params() {
    let mut cmd = quest_cmd();
    cmd.arg("get")
        .arg("https://httpbin.org/get")
        .arg("--param")
        .arg("test=value");

    let output = cmd.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    // Parse the JSON response from httpbin
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let args = json["args"].as_object().unwrap();

    // Verify test=value appears exactly once
    assert_eq!(args.get("test").unwrap().as_str().unwrap(), "value");
    assert_eq!(args.len(), 1, "Should have exactly 1 parameter");
}

#[test]
fn test_intentional_duplicate_params() {
    let quest_content = r#"
quests:
  test-duplicate:
    method: get
    url: https://httpbin.org/get
"#;

    let (_temp_dir, quest_file) = create_temp_quest_file(quest_content);

    let mut cmd = quest_cmd();
    cmd.arg("go")
        .arg("test-duplicate")
        .arg("--file")
        .arg(&quest_file)
        .arg("--param")
        .arg("tag=foo")
        .arg("--param")
        .arg("tag=bar");

    let output = cmd.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    // When user explicitly passes -p tag=foo -p tag=bar, both should be present
    assert!(stdout.contains("\"tag\""));

    // httpbin returns arrays when same key appears multiple times
    // We expect both "foo" and "bar" to appear
    assert!(stdout.contains("\"foo\""));
    assert!(stdout.contains("\"bar\""));
}
