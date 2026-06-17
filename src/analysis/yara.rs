#![allow(dead_code)]

use crate::config::YaraConfig;
use crate::feed::ecosystem::Ecosystem;
use crate::output::YaraScanResult;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

const SEVERITY_CRITICAL: u8 = 30;
const SEVERITY_HIGH: u8 = 20;
const SEVERITY_MEDIUM: u8 = 10;
const SEVERITY_LOW: u8 = 5;
const MALICIOUS_RISK_THRESHOLD: u8 = 70;
const DEFAULT_MAX_FILE_SIZE: usize = 5 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleInfo {
    pub name: String,
    pub severity: String,
    pub description: String,
    pub ecosystem: String,
    pub risk_score: u8,
    pub enabled: bool,
    pub source: String,
    pub file_path: PathBuf,
}

pub struct YaraEngine {
    rules: Arc<RwLock<Option<yara_x::Rules>>>,
    rule_metadata: Arc<RwLock<HashMap<String, YaraRuleInfo>>>,
    rules_dir: PathBuf,
    rules_state_path: PathBuf,
}

impl YaraEngine {
    pub fn new(config: &YaraConfig) -> Result<Self, Box<dyn Error>> {
        let rules_dir = PathBuf::from(&config.rules_dir);
        let rules_state_path = rules_dir.join("rules_state.json");

        let mut engine = YaraEngine {
            rules: Arc::new(RwLock::new(None)),
            rule_metadata: Arc::new(RwLock::new(HashMap::new())),
            rules_dir,
            rules_state_path,
        };

        engine.compile_rules()?;
        Ok(engine)
    }

    fn compile_rules(&mut self) -> Result<(), Box<dyn Error>> {
        let mut compiler = yara_x::Compiler::new();
        let mut metadata = HashMap::new();

        let builtin_dir = self.rules_dir.join("builtin");
        let custom_dir = self.rules_dir.join("custom");

        for dir in [&builtin_dir, &custom_dir] {
            if !dir.exists() {
                fs::create_dir_all(dir)?;
                continue;
            }

            let source = if dir == &builtin_dir {
                "builtin"
            } else {
                "custom"
            };

            let entries = fs::read_dir(dir)?;
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("yar")
                    || path.extension().and_then(|e| e.to_str()) == Some("yara")
                {
                    let content = fs::read_to_string(&path)?;
                    let rule_name = path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("unknown")
                        .to_string();

                    if let Err(e) = compiler.add_source(content.as_str()) {
                        log::error!("YARA: Failed to compile rule {}: {}", rule_name, e);
                        continue;
                    }

                    let info = parse_rule_metadata(&content, &rule_name, source, &path);
                    metadata.insert(rule_name, info);
                }
            }
        }

        let rules = compiler.build();

        let enabled_state = self.load_rules_state()?;
        for (name, info) in metadata.iter_mut() {
            if let Some(enabled) = enabled_state.get(name) {
                info.enabled = *enabled;
            }
        }

        *self.rules.write() = Some(rules);
        *self.rule_metadata.write() = metadata;

        log::info!("YARA: Compiled {} rules", self.rule_metadata.read().len());
        Ok(())
    }

    fn load_rules_state(&self) -> Result<HashMap<String, bool>, Box<dyn Error>> {
        if self.rules_state_path.exists() {
            let content = fs::read_to_string(&self.rules_state_path)?;
            let state: HashMap<String, bool> = serde_json::from_str(&content)?;
            Ok(state)
        } else {
            Ok(HashMap::new())
        }
    }

    fn save_rules_state(&self) -> Result<(), Box<dyn Error>> {
        let state: HashMap<String, bool> = self
            .rule_metadata
            .read()
            .iter()
            .filter(|(_, info)| !info.enabled)
            .map(|(k, _)| (k.clone(), false))
            .collect();

        let content = serde_json::to_string_pretty(&state)?;
        fs::write(&self.rules_state_path, content)?;
        Ok(())
    }

    pub fn reload_rules(&mut self) -> Result<(), Box<dyn Error>> {
        log::info!("YARA: Reloading rules from {}", self.rules_dir.display());
        self.compile_rules()?;
        Ok(())
    }

    pub fn scan_package(
        &self,
        files: &[(String, String)],
        ecosystem: Ecosystem,
        config: &YaraConfig,
    ) -> Result<YaraScanResult, Box<dyn Error>> {
        let start = Instant::now();
        let ecosystem_str = match ecosystem {
            Ecosystem::PyPI => "pypi",
            Ecosystem::Npm => "npm",
        };

        let max_file_size = config.max_file_size.unwrap_or(DEFAULT_MAX_FILE_SIZE);
        let rules_guard = self.rules.read();
        let rules = rules_guard.as_ref().ok_or("YARA: No rules compiled")?;
        let metadata = self.rule_metadata.read();

        let mut all_findings = Vec::new();

        for (file_path, file_content) in files {
            let content_bytes = file_content.as_bytes();
            if content_bytes.len() > max_file_size {
                log::debug!(
                    "YARA: Skipping {} ({} bytes exceeds limit)",
                    file_path,
                    content_bytes.len()
                );
                continue;
            }

            let mut scanner = yara_x::Scanner::new(rules);
            if let Some(timeout) = config.timeout_secs {
                scanner.set_timeout(std::time::Duration::from_secs(timeout));
            }
            scanner.max_scan_size(max_file_size);

            let scan_result = match scanner.scan(content_bytes) {
                Ok(result) => result,
                Err(e) => {
                    log::warn!("YARA: Scan error for {}: {}", file_path, e);
                    continue;
                }
            };

            for rule in scan_result.matching_rules() {
                let rule_name = rule.identifier().to_string();

                let info = metadata.get(&rule_name);
                let enabled = info.as_ref().map(|i| i.enabled).unwrap_or(true);
                if !enabled {
                    continue;
                }

                let ecosystem_filter = info.as_ref().map(|i| i.ecosystem.as_str()).unwrap_or("all");
                if ecosystem_filter != "all" && ecosystem_filter != ecosystem_str {
                    continue;
                }

                let severity = info
                    .as_ref()
                    .map(|i| i.severity.clone())
                    .unwrap_or_else(|| "medium".to_string());

                let description = info
                    .as_ref()
                    .map(|i| i.description.clone())
                    .unwrap_or_else(|| rule_name.clone());

                let risk_score = info
                    .as_ref()
                    .map(|i| i.risk_score)
                    .unwrap_or_else(|| severity_to_risk_score(&severity));

                let strings_matched: Vec<String> = rule
                    .patterns()
                    .flat_map(|p| {
                        p.matches()
                            .map(|m| {
                                let line = byte_offset_to_line(file_content, m.range().start);
                                match line {
                                    Some(ln) => format!("{} at line {}", p.identifier(), ln),
                                    None => format!("{} at offset {}", p.identifier(), m.range().start),
                                }
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect();

                all_findings.push(crate::output::YaraMatch {
                    rule_name: rule_name.clone(),
                    file: file_path.clone(),
                    severity: severity.clone(),
                    description: description.clone(),
                    risk_score,
                    strings_matched,
                });
            }
        }

        let risk_score = calculate_yara_risk_score(&all_findings);
        let is_malicious = risk_score >= MALICIOUS_RISK_THRESHOLD
            || all_findings.iter().any(|f| f.severity == "critical");

        let elapsed = start.elapsed();
        log::debug!(
            "YARA: Scanned {} files, found {} matches in {:?}",
            files.len(),
            all_findings.len(),
            elapsed
        );

        Ok(YaraScanResult {
            is_malicious,
            risk_score,
            findings: all_findings,
        })
    }

    pub fn list_rules(&self) -> Vec<YaraRuleInfo> {
        self.rule_metadata.read().values().cloned().collect()
    }

    pub fn get_rule(&self, name: &str) -> Option<YaraRuleInfo> {
        self.rule_metadata.read().get(name).cloned()
    }

    pub fn create_rule(&mut self, name: &str, content: &str) -> Result<(), Box<dyn Error>> {
        let custom_dir = self.rules_dir.join("custom");
        fs::create_dir_all(&custom_dir)?;

        let mut test_compiler = yara_x::Compiler::new();
        if let Err(e) = test_compiler.add_source(content) {
            return Err(format!("Rule compilation failed: {}", e).into());
        }
        test_compiler.build();

        // Sanitize rule name to prevent path traversal (e.g. "../../etc/passwd")
        let safe_name = name.chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
            .collect::<String>();
        if safe_name.is_empty() {
            return Err("Rule name must contain alphanumeric characters, hyphens, or underscores".into());
        }
        if safe_name != name {
            return Err(format!(
                "Rule name '{}' contains invalid characters. Only alphanumeric, hyphens, and underscores are allowed.",
                name
            ).into());
        }

        let file_path = custom_dir.join(format!("{}.yar", safe_name));
        fs::write(&file_path, content)?;

        let info = parse_rule_metadata(content, name, "custom", &file_path);
        self.rule_metadata.write().insert(name.to_string(), info);

        self.reload_rules()?;
        Ok(())
    }

    pub fn delete_rule(&mut self, name: &str) -> Result<(), Box<dyn Error>> {
        let info = self
            .rule_metadata
            .read()
            .get(name)
            .cloned()
            .ok_or("Rule not found")?;

        if info.source == "builtin" {
            return Err("Cannot delete built-in rules".into());
        }

        if info.file_path.exists() {
            fs::remove_file(&info.file_path)?;
        }

        self.rule_metadata.write().remove(name);
        self.reload_rules()?;
        Ok(())
    }

    pub fn set_rule_enabled(&mut self, name: &str, enabled: bool) -> Result<(), Box<dyn Error>> {
        {
            let mut metadata = self.rule_metadata.write();
            let info = metadata.get_mut(name).ok_or("Rule not found")?;
            info.enabled = enabled;
        }
        self.save_rules_state()?;
        Ok(())
    }

    pub fn test_rule(&self, content: &str, test_data: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let rules = yara_x::compile(content).map_err(|e| format!("Compilation error: {}", e))?;

        let mut scanner = yara_x::Scanner::new(&rules);
        let result = scanner
            .scan(test_data.as_bytes())
            .map_err(|e| format!("Scan error: {}", e))?;

        let matched: Vec<String> = result
            .matching_rules()
            .map(|r| r.identifier().to_string())
            .collect();
        Ok(matched)
    }
}

fn parse_rule_metadata(
    content: &str,
    rule_name: &str,
    source: &str,
    file_path: &Path,
) -> YaraRuleInfo {
    let mut severity = "medium".to_string();
    let mut description = rule_name.to_string();
    let mut ecosystem = "all".to_string();
    let mut risk_score = SEVERITY_MEDIUM;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("condition:") {
            break;
        }

        if let Some(rest) = trimmed.strip_prefix("severity") {
            let value = rest.trim_start_matches(['=', ' ', '\t', '"']);
            let value = value.trim_end_matches(['"', ',']);
            severity = value.to_string();
            risk_score = severity_to_risk_score(&severity);
        } else if let Some(rest) = trimmed.strip_prefix("description") {
            let value = rest.trim_start_matches(['=', ' ', '\t', '"']);
            let value = value.trim_end_matches(['"', ',']);
            description = value.to_string();
        } else if let Some(rest) = trimmed.strip_prefix("ecosystem") {
            let value = rest.trim_start_matches(['=', ' ', '\t', '"']);
            let value = value.trim_end_matches(['"', ',']);
            ecosystem = value.to_string();
        } else if let Some(rest) = trimmed.strip_prefix("risk_score") {
            let value = rest.trim_start_matches(['=', ' ', '\t']);
            let value = value.trim_end_matches([',']);
            if let Ok(score) = value.parse::<u8>() {
                risk_score = score;
            }
        }
    }

    YaraRuleInfo {
        name: rule_name.to_string(),
        severity,
        description,
        ecosystem,
        risk_score,
        enabled: true,
        source: source.to_string(),
        file_path: file_path.to_path_buf(),
    }
}

fn severity_to_risk_score(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "critical" => SEVERITY_CRITICAL,
        "high" => SEVERITY_HIGH,
        "medium" => SEVERITY_MEDIUM,
        "low" => SEVERITY_LOW,
        _ => SEVERITY_MEDIUM,
    }
}

fn calculate_yara_risk_score(findings: &[crate::output::YaraMatch]) -> u8 {
    let mut score: u8 = 0;
    for finding in findings {
        score = score.saturating_add(severity_to_risk_score(&finding.severity));
    }
    score.min(100)
}

/// Convert a byte offset in a string to a 1-based line number.
fn byte_offset_to_line(content: &str, byte_offset: usize) -> Option<u32> {
    if byte_offset > content.len() {
        return None;
    }
    let line_num = content[..byte_offset].chars().filter(|&c| c == '\n').count() as u32 + 1;
    Some(line_num)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_to_risk_score() {
        assert_eq!(severity_to_risk_score("critical"), 30);
        assert_eq!(severity_to_risk_score("high"), 20);
        assert_eq!(severity_to_risk_score("medium"), 10);
        assert_eq!(severity_to_risk_score("low"), 5);
        assert_eq!(severity_to_risk_score("unknown"), 10);
    }

    #[test]
    fn test_calculate_yara_risk_score_empty() {
        let findings = vec![];
        assert_eq!(calculate_yara_risk_score(&findings), 0);
    }

    #[test]
    fn test_calculate_yara_risk_score_single_critical() {
        let findings = vec![crate::output::YaraMatch {
            rule_name: "exec_base64".to_string(),
            file: "setup.py".to_string(),
            severity: "critical".to_string(),
            description: "test".to_string(),
            risk_score: 95,
            strings_matched: vec![],
        }];
        assert_eq!(calculate_yara_risk_score(&findings), 30);
    }

    #[test]
    fn test_calculate_yara_risk_score_multiple() {
        let findings = vec![
            crate::output::YaraMatch {
                rule_name: "exec_base64".to_string(),
                file: "setup.py".to_string(),
                severity: "critical".to_string(),
                description: "test".to_string(),
                risk_score: 30,
                strings_matched: vec![],
            },
            crate::output::YaraMatch {
                rule_name: "obfuscation".to_string(),
                file: "utils.py".to_string(),
                severity: "high".to_string(),
                description: "test".to_string(),
                risk_score: 20,
                strings_matched: vec![],
            },
        ];
        assert_eq!(calculate_yara_risk_score(&findings), 50);
    }

    #[test]
    fn test_calculate_yara_risk_score_capped() {
        let findings: Vec<crate::output::YaraMatch> = (0..5)
            .map(|_| crate::output::YaraMatch {
                rule_name: "test".to_string(),
                file: "test.py".to_string(),
                severity: "critical".to_string(),
                description: "test".to_string(),
                risk_score: 30,
                strings_matched: vec![],
            })
            .collect();
        assert_eq!(calculate_yara_risk_score(&findings), 100);
    }

    #[test]
    fn test_parse_rule_metadata() {
        let content = r#"
rule test_rule
{
    meta:
        severity = "high"
        description = "A test rule"
        ecosystem = "pypi"
        risk_score = 85
    strings:
        $test = "hello"
    condition:
        $test
}
"#;
        let info = parse_rule_metadata(content, "test_rule", "builtin", Path::new("/tmp/test.yar"));
        assert_eq!(info.name, "test_rule");
        assert_eq!(info.severity, "high");
        assert_eq!(info.description, "A test rule");
        assert_eq!(info.ecosystem, "pypi");
        assert_eq!(info.risk_score, 85);
        assert_eq!(info.source, "builtin");
        assert!(info.enabled);
    }

    #[test]
    fn test_parse_rule_metadata_defaults() {
        let content = r#"
rule minimal_rule
{
    meta:
        description = "Minimal"
    strings:
        $a = "test"
    condition:
        $a
}
"#;
        let info = parse_rule_metadata(
            content,
            "minimal_rule",
            "custom",
            Path::new("/tmp/minimal.yar"),
        );
        assert_eq!(info.severity, "medium");
        assert_eq!(info.ecosystem, "all");
        assert_eq!(info.risk_score, 10);
    }

    #[test]
    fn test_byte_offset_to_line() {
        let content = "line1\nline2\nline3\nline4";
        assert_eq!(byte_offset_to_line(content, 0), Some(1)); // start of line 1
        assert_eq!(byte_offset_to_line(content, 6), Some(2)); // start of line 2
        assert_eq!(byte_offset_to_line(content, 12), Some(3)); // start of line 3
        assert_eq!(byte_offset_to_line(content, 18), Some(4)); // start of line 4
        assert_eq!(byte_offset_to_line(content, 3), Some(1)); // mid-line 1
        assert_eq!(byte_offset_to_line(content, 100), None); // past end
    }

    #[test]
    fn test_byte_offset_to_line_single_line() {
        let content = "hello world";
        assert_eq!(byte_offset_to_line(content, 0), Some(1));
        assert_eq!(byte_offset_to_line(content, 5), Some(1));
    }

    #[test]
    fn test_byte_offset_to_line_empty() {
        assert_eq!(byte_offset_to_line("", 0), Some(1));
        assert_eq!(byte_offset_to_line("", 1), None);
    }
}
