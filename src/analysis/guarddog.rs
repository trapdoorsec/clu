#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::error::Error;
use std::process::Command;
use std::time::Duration;
use tokio::time::timeout;

/// Result from GuardDog analysis
#[derive(Debug, Serialize, Clone)]
pub struct GuardDogResult {
    pub is_malicious: bool,
    pub risk_score: u8,
    pub findings: Vec<GuardDogFinding>,
}

/// Individual finding from GuardDog
#[derive(Debug, Serialize, Clone)]
pub struct GuardDogFinding {
    pub rule_name: String,
    pub severity: String,
    pub description: String,
}

/// GuardDog JSON output structure (internal)
#[derive(Debug, Deserialize)]
struct GuardDogJson {
    #[serde(default)]
    results: Vec<JsonFinding>,
    #[serde(default)]
    #[allow(dead_code)]
    errors: Vec<String>,
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
    // Sanitize inputs to prevent command injection
    let safe_package = sanitize_package_name(package_name);

    // Build command
    let mut cmd = Command::new("guarddog");
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
            // If JSON parsing fails, return empty result
            eprintln!("Failed to parse GuardDog output: {}", e);
            return Ok(GuardDogResult {
                is_malicious: false,
                risk_score: 0,
                findings: vec![],
            });
        }
    };

    // Convert GuardDog issues to our findings format
    let findings: Vec<GuardDogFinding> = parsed
        .results
        .iter()
        .map(|issue| GuardDogFinding {
            rule_name: issue.rule.clone(),
            severity: issue.severity.clone(),
            description: issue.message.clone(),
        })
        .collect();

    // Calculate risk score based on severity and number of findings
    let risk_score = calculate_risk_score(&findings);
    let is_malicious = risk_score >= 70 || findings.iter().any(|f| f.severity == "critical");

    Ok(GuardDogResult {
        is_malicious,
        risk_score,
        findings,
    })
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
        let json = r#"{"results": [], "errors": []}"#;
        let result = parse_guarddog_output(json.as_bytes()).unwrap();
        assert!(!result.is_malicious);
        assert_eq!(result.risk_score, 0);
        assert_eq!(result.findings.len(), 0);
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
}
