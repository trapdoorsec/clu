use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

fn make_yara_config(dir: &tempfile::TempDir) -> clu::config::YaraConfig {
    clu::config::YaraConfig {
        rules_dir: dir.path().to_string_lossy().into_owned(),
        max_file_size: None,
        timeout_secs: None,
    }
}

fn write_rule(dir: &PathBuf, subdir: &str, name: &str, content: &str) {
    let rule_dir = dir.join(subdir);
    fs::create_dir_all(&rule_dir).unwrap();
    fs::write(rule_dir.join(format!("{}.yar", name)), content).unwrap();
}

#[test]
fn test_yara_engine_new_empty_dir() {
    let dir = tempfile::tempdir().unwrap();
    let config = make_yara_config(&dir);
    let engine = clu::analysis::yara::YaraEngine::new(&config);
    assert!(engine.is_ok(), "YaraEngine should initialize with empty rules dir");
    let engine = engine.unwrap();
    let rules = engine.list_rules();
    assert!(rules.is_empty(), "Empty rules dir should have no rules");
}

#[test]
fn test_yara_engine_loads_builtin_rules() {
    let dir = tempfile::tempdir().unwrap();
    write_rule(
        &dir.path().to_path_buf(),
        "builtin",
        "test_builtin",
        r#"
rule test_builtin
{
    meta:
        severity = "high"
        description = "Built-in test rule"
        ecosystem = "pypi"
        risk_score = 75
    strings:
        $s = "evil_string"
    condition:
        $s
}
"#,
    );
    let config = make_yara_config(&dir);
    let engine = clu::analysis::yara::YaraEngine::new(&config).unwrap();
    let rules = engine.list_rules();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "test_builtin");
    assert_eq!(rules[0].severity, "high");
    assert_eq!(rules[0].ecosystem, "pypi");
    assert_eq!(rules[0].risk_score, 75);
    assert_eq!(rules[0].source, "builtin");
    assert!(rules[0].enabled);
}

#[test]
fn test_yara_engine_loads_custom_rules() {
    let dir = tempfile::tempdir().unwrap();
    write_rule(
        &dir.path().to_path_buf(),
        "custom",
        "my_custom_rule",
        r#"
rule my_custom_rule
{
    meta:
        severity = "medium"
        description = "My custom detection"
    strings:
        $a = "suspicious"
    condition:
        $a
}
"#,
    );
    let config = make_yara_config(&dir);
    let engine = clu::analysis::yara::YaraEngine::new(&config).unwrap();
    let rules = engine.list_rules();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "my_custom_rule");
    assert_eq!(rules[0].source, "custom");
}

#[test]
fn test_yara_scan_match() {
    let dir = tempfile::tempdir().unwrap();
    write_rule(
        &dir.path().to_path_buf(),
        "builtin",
        "detect_evil",
        r#"
rule detect_evil
{
    meta:
        severity = "critical"
        description = "Detects evil patterns"
        risk_score = 90
    strings:
        $evil = "EVIL_CODE"
    condition:
        $evil
}
"#,
    );
    let config = make_yara_config(&dir);
    let engine = clu::analysis::yara::YaraEngine::new(&config).unwrap();

    let files = vec![
        ("main.py".to_string(), "import os\nEVIL_CODE\nprint('hello')".to_string()),
    ];
    let result = engine
        .scan_package(&files, clu::feed::ecosystem::Ecosystem::PyPI, &config)
        .unwrap();

    assert!(result.is_malicious, "Should detect evil pattern");
    assert!(result.risk_score > 0, "Risk score should be positive");
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_name, "detect_evil");
    assert_eq!(result.findings[0].severity, "critical");
}

#[test]
fn test_yara_scan_no_match() {
    let dir = tempfile::tempdir().unwrap();
    write_rule(
        &dir.path().to_path_buf(),
        "builtin",
        "detect_evil",
        r#"
rule detect_evil
{
    meta:
        severity = "critical"
        description = "Detects evil patterns"
    strings:
        $evil = "EVIL_CODE"
    condition:
        $evil
}
"#,
    );
    let config = make_yara_config(&dir);
    let engine = clu::analysis::yara::YaraEngine::new(&config).unwrap();

    let files = vec![
        ("main.py".to_string(), "import os\nprint('hello')".to_string()),
    ];
    let result = engine
        .scan_package(&files, clu::feed::ecosystem::Ecosystem::PyPI, &config)
        .unwrap();

    assert!(!result.is_malicious);
    assert_eq!(result.risk_score, 0);
    assert!(result.findings.is_empty());
}

#[test]
fn test_yara_ecosystem_filtering() {
    let dir = tempfile::tempdir().unwrap();
    write_rule(
        &dir.path().to_path_buf(),
        "builtin",
        "pypi_only",
        r#"
rule pypi_only
{
    meta:
        severity = "high"
        description = "Only for PyPI"
        ecosystem = "pypi"
    strings:
        $s = "dangerous"
    condition:
        $s
}
"#,
    );
    write_rule(
        &dir.path().to_path_buf(),
        "builtin",
        "all_ecosystems",
        r#"
rule all_ecosystems
{
    meta:
        severity = "medium"
        description = "All ecosystems"
        ecosystem = "all"
    strings:
        $s = "dangerous"
    condition:
        $s
}
"#,
    );
    let config = make_yara_config(&dir);
    let engine = clu::analysis::yara::YaraEngine::new(&config).unwrap();

    // Scan with PyPI: should match both rules
    let files = vec![("main.py".to_string(), "dangerous code".to_string())];
    let result_pypi = engine
        .scan_package(&files, clu::feed::ecosystem::Ecosystem::PyPI, &config)
        .unwrap();
    assert_eq!(result_pypi.findings.len(), 2);

    // Scan with npm: should only match the "all" rule
    let result_npm = engine
        .scan_package(&files, clu::feed::ecosystem::Ecosystem::Npm, &config)
        .unwrap();
    assert_eq!(result_npm.findings.len(), 1);
    assert_eq!(result_npm.findings[0].rule_name, "all_ecosystems");
}

#[test]
fn test_yara_create_and_delete_custom_rule() {
    let dir = tempfile::tempdir().unwrap();
    let config = make_yara_config(&dir);
    let mut engine = clu::analysis::yara::YaraEngine::new(&config).unwrap();
    assert!(engine.list_rules().is_empty());

    let rule_content = r#"
rule custom_detection
{
    meta:
        severity = "high"
        description = "Custom rule"
    strings:
        $s = "bad_stuff"
    condition:
        $s
}
"#;
    engine.create_rule("custom_detection", rule_content).unwrap();
    let rules = engine.list_rules();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "custom_detection");
    assert_eq!(rules[0].source, "custom");

    // Created rule should be scannable
    let files = vec![("main.py".to_string(), "bad_stuff here".to_string())];
    let result = engine
        .scan_package(&files, clu::feed::ecosystem::Ecosystem::PyPI, &config)
        .unwrap();
    assert_eq!(result.findings.len(), 1);

    // Delete the rule
    engine.delete_rule("custom_detection").unwrap();
    assert!(engine.list_rules().is_empty());
}

#[test]
fn test_yara_cannot_delete_builtin_rule() {
    let dir = tempfile::tempdir().unwrap();
    write_rule(
        &dir.path().to_path_buf(),
        "builtin",
        "builtin_rule",
        r#"
rule builtin_rule
{
    meta:
        severity = "low"
        description = "Built-in"
    strings:
        $s = "test"
    condition:
        $s
}
"#,
    );
    let config = make_yara_config(&dir);
    let mut engine = clu::analysis::yara::YaraEngine::new(&config).unwrap();
    let result = engine.delete_rule("builtin_rule");
    assert!(result.is_err(), "Should not be able to delete built-in rules");
}

#[test]
fn test_yara_enable_disable_rule() {
    let dir = tempfile::tempdir().unwrap();
    write_rule(
        &dir.path().to_path_buf(),
        "builtin",
        "toggle_rule",
        r#"
rule toggle_rule
{
    meta:
        severity = "medium"
        description = "Toggle me"
    strings:
        $s = "target"
    condition:
        $s
}
"#,
    );
    let config = make_yara_config(&dir);
    let mut engine = clu::analysis::yara::YaraEngine::new(&config).unwrap();

    // Initially enabled
    let rule = engine.get_rule("toggle_rule").unwrap();
    assert!(rule.enabled);

    // Disable
    engine.set_rule_enabled("toggle_rule", false).unwrap();
    let rule = engine.get_rule("toggle_rule").unwrap();
    assert!(!rule.enabled);

    // Scan should not match disabled rule
    let files = vec![("main.py".to_string(), "target found".to_string())];
    let result = engine
        .scan_package(&files, clu::feed::ecosystem::Ecosystem::PyPI, &config)
        .unwrap();
    assert!(result.findings.is_empty(), "Disabled rule should not match");

    // Re-enable
    engine.set_rule_enabled("toggle_rule", true).unwrap();
    let result = engine
        .scan_package(&files, clu::feed::ecosystem::Ecosystem::PyPI, &config)
        .unwrap();
    assert_eq!(result.findings.len(), 1, "Re-enabled rule should match");
}

#[test]
fn test_yara_test_rule() {
    let dir = tempfile::tempdir().unwrap();
    let config = make_yara_config(&dir);
    let engine = clu::analysis::yara::YaraEngine::new(&config).unwrap();

    let rule_content = r#"
rule test_match
{
    meta:
        severity = "medium"
        description = "Test rule"
    strings:
        $hello = "hello world"
    condition:
        $hello
}
"#;

    // Positive test
    let matched = engine.test_rule(rule_content, "hello world is great").unwrap();
    assert_eq!(matched, vec!["test_match"]);

    // Negative test
    let no_match = engine.test_rule(rule_content, "no match here").unwrap();
    assert!(no_match.is_empty());
}

#[test]
fn test_yara_test_rule_compilation_error() {
    let dir = tempfile::tempdir().unwrap();
    let config = make_yara_config(&dir);
    let engine = clu::analysis::yara::YaraEngine::new(&config).unwrap();

    let bad_rule = "rule bad { condition: nonexistent_thing }";
    let result = engine.test_rule(bad_rule, "test data");
    assert!(result.is_err(), "Invalid YARA rule should fail compilation");
}

#[test]
fn test_yara_create_rule_compilation_error() {
    let dir = tempfile::tempdir().unwrap();
    let config = make_yara_config(&dir);
    let mut engine = clu::analysis::yara::YaraEngine::new(&config).unwrap();

    let bad_rule = "rule bad { condition: nonexistent }";
    let result = engine.create_rule("bad_rule", bad_rule);
    assert!(result.is_err(), "Invalid YARA rule should fail creation");
}

#[test]
fn test_yara_risk_score_malicious_threshold() {
    let dir = tempfile::tempdir().unwrap();
    write_rule(
        &dir.path().to_path_buf(),
        "builtin",
        "critical_rule",
        r#"
rule critical_rule
{
    meta:
        severity = "critical"
        description = "Critical detection"
        risk_score = 75
    strings:
        $s = "payload"
    condition:
        $s
}
"#,
    );
    let config = make_yara_config(&dir);
    let engine = clu::analysis::yara::YaraEngine::new(&config).unwrap();

    let files = vec![("main.py".to_string(), "payload detected".to_string())];
    let result = engine
        .scan_package(&files, clu::feed::ecosystem::Ecosystem::PyPI, &config)
        .unwrap();

    assert!(result.is_malicious, "risk_score=75 >= 70 should be malicious");
    assert!(result.findings.iter().any(|f| f.severity == "critical"));
}

#[test]
fn test_yara_max_file_size() {
    let dir = tempfile::tempdir().unwrap();
    write_rule(
        &dir.path().to_path_buf(),
        "builtin",
        "big_target",
        r#"
rule big_target
{
    meta:
        severity = "low"
        description = "Matches anything"
    strings:
        $s = "x"
    condition:
        $s
}
"#,
    );
    let mut config = make_yara_config(&dir);
    config.max_file_size = Some(10); // 10 bytes max
    let engine = clu::analysis::yara::YaraEngine::new(&config).unwrap();

    // File larger than max_file_size should be skipped
    let big_file = ("big.py".to_string(), "a".repeat(100));
    let result = engine
        .scan_package(&[big_file], clu::feed::ecosystem::Ecosystem::PyPI, &config)
        .unwrap();
    assert!(result.findings.is_empty(), "Oversized file should be skipped");

    // Small file should match
    let small_file = ("small.py".to_string(), "x".to_string());
    let result = engine
        .scan_package(&[small_file], clu::feed::ecosystem::Ecosystem::PyPI, &config)
        .unwrap();
    assert_eq!(result.findings.len(), 1, "Small file should match");
}

#[test]
fn test_yara_rules_state_persistence() {
    let dir = tempfile::tempdir().unwrap();
    write_rule(
        &dir.path().to_path_buf(),
        "builtin",
        "persist_rule",
        r#"
rule persist_rule
{
    meta:
        severity = "medium"
        description = "Persistence test"
    strings:
        $s = "match"
    condition:
        $s
}
"#,
    );
    let config = make_yara_config(&dir);
    let mut engine = clu::analysis::yara::YaraEngine::new(&config).unwrap();

    // Disable the rule
    engine.set_rule_enabled("persist_rule", false).unwrap();

    // Verify state file was created
    let state_path = dir.path().join("rules_state.json");
    assert!(state_path.exists(), "State file should be created");

    // Create a new engine instance to verify state is loaded
    let engine2 = clu::analysis::yara::YaraEngine::new(&config).unwrap();
    let rule = engine2.get_rule("persist_rule").unwrap();
    assert!(!rule.enabled, "Disabled state should persist across restarts");
}