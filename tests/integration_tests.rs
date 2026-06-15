use clu::config::{PipelineConfig, YaraConfig};
use std::fs;

#[test]
fn test_pipeline_config_default() {
    let config = PipelineConfig::default();
    assert!(config.heuristics);
    assert!(config.typosquat);
    assert!(!config.yara);
    assert!(!config.llm);
    assert!(!config.guarddog);
}

#[test]
fn test_pipeline_config_yara_from_toml() {
    let toml = r#"
heuristics = true
typosquat = true
yara = true
llm = false
"#;
    let config: PipelineConfig = toml::from_str(toml).unwrap();
    assert!(config.yara);
    assert!(!config.llm);
}

#[test]
fn test_pipeline_config_guarddog_backward_compat() {
    let toml = r#"
heuristics = true
typosquat = true
guarddog = true
llm = false
"#;
    let mut config: PipelineConfig = toml::from_str(toml).unwrap();
    assert!(config.guarddog, "guarddog field should parse");
    assert!(!config.yara, "yara should be false initially");

    // Apply backward compat logic (mirrors Config::load)
    if config.guarddog && !config.yara {
        config.yara = true;
    }
    assert!(config.yara, "guarddog=true should enable yara");
}

#[test]
fn test_config_load_guarddog_backward_compat() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
[feed]
endpoint = "https://pypi.org/rss/packages.xml"
popular_packages_endpoint = "https://example.com/popular.json"
poll_interval = "30s"
check_updates = false

[llm]
endpoint = "http://localhost:11434"
model = "qwen2.5-coder:7b"
request_timeout = 30

[output]
log_level = "info"
enable_tui = true

[analysis]
typosquat_distance_threshold = 2
min_package_length = 4

[pipeline]
guarddog = true
"#,
    )
    .unwrap();

    let path_str = config_path.to_string_lossy().to_string();
    let config = clu::config::Config::load(&path_str).unwrap();
    assert!(config.pipeline.yara, "Config::load should apply guarddog->yara compat");
}

#[test]
fn test_yara_config_default() {
    let config = YaraConfig::default();
    assert_eq!(config.rules_dir, "config/yara_rules");
    assert!(config.max_file_size.is_none());
    assert!(config.timeout_secs.is_none());
}

#[test]
fn test_yara_config_from_toml() {
    let toml = r#"
rules_dir = "/custom/rules"
max_file_size = 10485760
timeout_secs = 30
"#;
    let config: YaraConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.rules_dir, "/custom/rules");
    assert_eq!(config.max_file_size, Some(10485760));
    assert_eq!(config.timeout_secs, Some(30));
}

#[test]
fn test_yara_config_full_load() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
[feed]
endpoint = "https://pypi.org/rss/packages.xml"
popular_packages_endpoint = "https://example.com/popular.json"
poll_interval = "30s"
check_updates = false

[llm]
endpoint = "http://localhost:11434"
model = "qwen2.5-coder:7b"
request_timeout = 30

[output]
log_level = "info"
enable_tui = true

[analysis]
typosquat_distance_threshold = 2
min_package_length = 4

[yara]
rules_dir = "/opt/clu/rules"
max_file_size = 20971520
timeout_secs = 15
"#,
    )
    .unwrap();

    let path_str = config_path.to_string_lossy().to_string();
    let config = clu::config::Config::load(&path_str).unwrap();
    assert_eq!(config.yara.rules_dir, "/opt/clu/rules");
    assert_eq!(config.yara.max_file_size, Some(20971520));
    assert_eq!(config.yara.timeout_secs, Some(15));
}

#[test]
fn test_compute_static_severity_with_yara() {
    let (sev, malicious, risk) = clu::analysis::compute_static_severity(0, 0, 70);
    assert_eq!(sev, 7);
    assert!(malicious);
    assert_eq!(risk, 70);

    let (sev, malicious, _risk) = clu::analysis::compute_static_severity(0, 0, 30);
    assert_eq!(sev, 3);
    assert!(!malicious);

    let (sev, malicious, _risk) = clu::analysis::compute_static_severity(30, 90, 30);
    assert_eq!(sev, 15);
    assert!(malicious);
}

#[test]
fn test_package_status_yara_variant() {
    use clu::db::PackageStatus;

    assert_eq!(PackageStatus::Yara.as_str(), "yara");
    assert_eq!(
        PackageStatus::from_str("yara").unwrap(),
        PackageStatus::Yara
    );
    assert_eq!(
        PackageStatus::from_str("guarddog").unwrap(),
        PackageStatus::Yara
    );
}

#[test]
fn test_db_migration_guarddog_to_yara() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let db = clu::db::Database::new("sqlite::memory:").await.unwrap();

        let report = clu::output::AnalysisReport {
            package_name: "migration-test".to_string(),
            package_version: Some("1.0.0".to_string()),
            timestamp: chrono::Utc::now().to_rfc3339(),
            ecosystem: clu::feed::ecosystem::Ecosystem::PyPI,
            sha256: "abc123".to_string(),
            heuristic_matches: vec![],
            typosquat_matches: vec![],
            yara_result: Some(clu::output::YaraScanResult {
                is_malicious: true,
                risk_score: 80,
                findings: vec![clu::output::YaraMatch {
                    rule_name: "test_rule".to_string(),
                    severity: "critical".to_string(),
                    description: "Test finding".to_string(),
                    risk_score: 80,
                    strings_matched: vec!["$s at offset 0".to_string()],
                }],
            }),
            injection_detection: None,
            llm_analysis: None,
            severity: 10,
            is_malicious: true,
            recommendation: "INSPECT".to_string(),
        };

        let id = db.insert_report(&report).await.unwrap();
        assert!(id > 0);

        let retrieved = db.get_report("migration-test").await.unwrap().unwrap();
        assert_eq!(retrieved.package_name, "migration-test");
        assert!(retrieved.yara_result.is_some());
        let yr = retrieved.yara_result.unwrap();
        assert_eq!(yr.findings.len(), 1);
        assert_eq!(yr.findings[0].rule_name, "test_rule");
        assert_eq!(yr.risk_score, 80);
    });
}