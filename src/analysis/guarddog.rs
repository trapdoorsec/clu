#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::error::Error;
use std::process::Command;
use std::time::Duration;
use tokio::time::timeout;

/// Result from GuardDog analysis
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GuardDogResult {
    pub is_malicious: bool,
    pub risk_score: u8,
    pub findings: Vec<GuardDogFinding>,
}

/// Individual finding from GuardDog
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GuardDogFinding {
    pub rule_name: String,
    pub severity: String,
    pub description: String,
}

/// GuardDog JSON output structure (internal)
/// Handles multiple formats that GuardDog can return
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum GuardDogJson {
    // New format: results is a map of rule_name -> issue_description
    ModernFormat {
        #[serde(default)]
        package: String,
        #[serde(default)]
        issues: u32,
        results: serde_json::Map<String, serde_json::Value>,
        #[serde(default)]
        #[allow(dead_code)]
        errors: serde_json::Map<String, serde_json::Value>,
    },
    // Legacy format: results is array of findings
    LegacyFormat {
        #[serde(default)]
        results: Vec<JsonFinding>,
        #[serde(default)]
        #[allow(dead_code)]
        errors: Vec<String>,
    },
    // Direct array format
    Array(Vec<JsonFinding>),
}

#[derive(Debug, Deserialize)]
struct JsonFinding {
    #[serde(default)]
    rule: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    message: String,
}

/// Analyze package using GuardDog (Tier 3 analysis)
///
/// Executes GuardDog CLI as a subprocess to scan the package
/// Timeout set to 60 seconds to prevent hanging
pub async fn analyze_with_guarddog(
    package_name: &str,
    package_version: Option<&str>,
) -> Result<GuardDogResult, Box<dyn Error>> {
    log::debug!("GuardDog: Starting analysis for {}", package_name);

    // Sanitize inputs to prevent command injection
    let safe_package = sanitize_package_name(package_name);

    // Get cache directory from environment or use default
    let cache_dir = std::env::var("PIP_CACHE_DIR").unwrap_or_else(|_| "/tmp/pip-cache".to_string());

    // Build command with shared cache directory for package reuse
    let mut cmd = Command::new("guarddog");

    // Set environment variables to use shared cache
    cmd.env("PIP_CACHE_DIR", &cache_dir);

    cmd.arg("pypi");
    cmd.arg("scan");

    // Add package with optional version specifier
    if let Some(version) = package_version {
        let safe_version = sanitize_version(version);
        cmd.arg(format!("{}=={}", safe_package, safe_version));
    } else {
        cmd.arg(&safe_package);
    }

    cmd.arg("--output-format");
    cmd.arg("json");

    // Execute with timeout to prevent hanging
    let output = timeout(Duration::from_secs(60), async {
        tokio::task::spawn_blocking(move || cmd.output()).await?
    })
    .await??;

    // Parse output
    let result = parse_guarddog_output(&output.stdout)?;

    Ok(result)
}

/// Parse GuardDog JSON output
fn parse_guarddog_output(stdout: &[u8]) -> Result<GuardDogResult, Box<dyn Error>> {
    let output_str = String::from_utf8_lossy(stdout);

    // Try to parse as JSON
    let parsed: GuardDogJson = match serde_json::from_str(&output_str) {
        Ok(p) => p,
        Err(e) => {
            // If JSON parsing fails, log both error and actual output for debugging
            log::error!("GuardDog: Failed to parse JSON output");
            log::error!("GuardDog: Parse error: {}", e);
            log::error!(
                "GuardDog: Raw output (first 2000 chars): {}",
                if output_str.len() > 2000 {
                    format!("{}...[truncated]", &output_str[..2000])
                } else {
                    output_str.to_string()
                }
            );
            log::error!("GuardDog: Full output length: {} bytes", output_str.len());
            return Ok(GuardDogResult {
                is_malicious: false,
                risk_score: 0,
                findings: vec![],
            });
        }
    };

    // Extract results based on format (object or array)
    let findings: Vec<GuardDogFinding> = match parsed {
        GuardDogJson::ModernFormat { results, .. } => {
            // New format: results is a map of rule_name -> issue_value
            results
                .iter()
                .filter_map(|(rule_name, value)| {
                    // Only include rules with actual string descriptions (issues found)
                    // null and {} both mean "no issue found for this rule"
                    match value {
                        serde_json::Value::String(description) if !description.is_empty() => {
                            Some(GuardDogFinding {
                                rule_name: rule_name.clone(),
                                severity: categorize_rule_severity(rule_name),
                                description: description.clone(),
                            })
                        }
                        _ => None, // Null, empty objects {}, or other values = no issue
                    }
                })
                .collect()
        }
        GuardDogJson::LegacyFormat { results, .. } => {
            // Legacy format: results is array of findings
            results
                .iter()
                .map(|issue| GuardDogFinding {
                    rule_name: issue.rule.clone(),
                    severity: issue.severity.clone(),
                    description: issue.message.clone(),
                })
                .collect()
        }
        GuardDogJson::Array(array) => {
            // Direct array format
            array
                .iter()
                .map(|issue| GuardDogFinding {
                    rule_name: issue.rule.clone(),
                    severity: issue.severity.clone(),
                    description: issue.message.clone(),
                })
                .collect()
        }
    };

    // Calculate risk score based on severity and number of findings
    let risk_score = calculate_risk_score(&findings);
    let is_malicious = risk_score >= 70 || findings.iter().any(|f| f.severity == "critical");

    Ok(GuardDogResult {
        is_malicious,
        risk_score,
        findings,
    })
}

/// Categorize rule severity based on rule name
/// Used when GuardDog output doesn't include explicit severity levels
fn categorize_rule_severity(rule_name: &str) -> String {
    match rule_name {
        // Critical severity rules
        "code-execution" | "exec-base64" | "download-executable" => "critical".to_string(),

        // High severity rules
        "exfiltrate-sensitive-data"
        | "silent-process-execution"
        | "dll-hijacking"
        | "clipboard-access"
        | "cmd-overwrite"
        | "steganography"
        | "api-obfuscation"
        | "shady-links"
        | "bundled_binary"
        | "deceptive_author"
        | "potentially_compromised_email_domain" => "high".to_string(),

        // Medium severity rules
        "obfuscation"
        | "unicode"
        | "single_python_file"
        | "release_zero"
        | "empty_information"
        | "repository_integrity_mismatch" => "medium".to_string(),

        // Low severity rules
        "unclaimed_maintainer_email_domain" | "typosquatting" => "low".to_string(),

        // Default to medium for unknown rules
        _ => "medium".to_string(),
    }
}

/// Calculate risk score from GuardDog findings
fn calculate_risk_score(findings: &[GuardDogFinding]) -> u8 {
    if findings.is_empty() {
        return 0;
    }

    let mut score = 0u8;

    for finding in findings {
        let severity_score = match finding.severity.to_lowercase().as_str() {
            "critical" => 30,
            "high" => 20,
            "medium" => 10,
            "low" => 5,
            _ => 5,
        };
        score = score.saturating_add(severity_score);
    }

    // Cap at 100
    score.min(100)
}

/// Sanitize package name to prevent command injection
fn sanitize_package_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .take(100)
        .collect()
}

/// Sanitize version string
fn sanitize_version(version: &str) -> String {
    version
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '.')
        .take(20)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_package_name() {
        assert_eq!(sanitize_package_name("requests"), "requests");
        assert_eq!(sanitize_package_name("my-package_2.0"), "my-package_2.0");
        assert_eq!(sanitize_package_name("evil; rm -rf /"), "evilrm-rf");
        assert_eq!(sanitize_package_name("$(whoami)"), "whoami");
    }

    #[test]
    fn test_sanitize_version() {
        assert_eq!(sanitize_version("1.2.3"), "1.2.3");
        assert_eq!(sanitize_version("2.0.0rc1"), "2.0.0rc1");
        assert_eq!(sanitize_version("1.0; cat /etc/passwd"), "1.0catetcpasswd");
    }

    #[test]
    fn test_calculate_risk_score() {
        let findings = vec![
            GuardDogFinding {
                rule_name: "exec-base64".to_string(),
                severity: "critical".to_string(),
                description: "Executes base64 encoded code".to_string(),
            },
            GuardDogFinding {
                rule_name: "exfiltrate-sensitive-data".to_string(),
                severity: "high".to_string(),
                description: "May exfiltrate data".to_string(),
            },
        ];

        let score = calculate_risk_score(&findings);
        assert_eq!(score, 50); // 30 (critical) + 20 (high)
    }

    #[test]
    fn test_empty_findings() {
        let findings = vec![];
        let score = calculate_risk_score(&findings);
        assert_eq!(score, 0);
    }

    #[test]
    fn test_parse_empty_json() {
        // Test object format
        let json = r#"{"results": [], "errors": []}"#;
        let result = parse_guarddog_output(json.as_bytes()).unwrap();
        assert!(!result.is_malicious);
        assert_eq!(result.risk_score, 0);
        assert_eq!(result.findings.len(), 0);

        // Test array format
        let json_array = r#"[]"#;
        let result_array = parse_guarddog_output(json_array.as_bytes()).unwrap();
        assert!(!result_array.is_malicious);
        assert_eq!(result_array.risk_score, 0);
        assert_eq!(result_array.findings.len(), 0);
    }

    #[test]
    fn test_parse_with_findings() {
        let json = r#"{
            "results": [
                {
                    "rule": "exec-base64",
                    "severity": "critical",
                    "message": "Executes base64 encoded code"
                }
            ],
            "errors": []
        }"#;
        let result = parse_guarddog_output(json.as_bytes()).unwrap();
        assert!(result.is_malicious); // critical severity triggers malicious flag
        assert_eq!(result.risk_score, 30);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].rule_name, "exec-base64");
    }

    #[test]
    fn test_parse_modern_format_with_map() {
        // Modern GuardDog format: results is a map of rule_name -> issue_value
        let json = r#"{
            "package": "cdef-pil",
            "issues": 2,
            "errors": {},
            "results": {
                "unclaimed_maintainer_email_domain": null,
                "single_python_file": "This package has 1 or fewer Python source files",
                "bundled_binary": "Binary file/s detected",
                "silent-process-execution": {},
                "code-execution": null
            },
            "path": "/tmp/test"
        }"#;
        let result = parse_guarddog_output(json.as_bytes()).unwrap();
        // Should find: single_python_file (medium), bundled_binary (high)
        // null and {} values are ignored (no issue)
        assert_eq!(result.findings.len(), 2);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.rule_name == "bundled_binary")
        );
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.rule_name == "single_python_file")
        );
        // Verify that rules with null or {} are NOT included
        assert!(
            !result
                .findings
                .iter()
                .any(|f| f.rule_name == "code-execution")
        );
        assert!(
            !result
                .findings
                .iter()
                .any(|f| f.rule_name == "silent-process-execution")
        );
    }
}
