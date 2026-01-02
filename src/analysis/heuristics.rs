use crate::feed;
use feed::pypi::PythonPackage;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Debug, Serialize)]
pub struct HeuristicMatch {
    pub rule_name: String,
    pub risk_score: u8,
    pub evidence: String,
    pub description: String,
    pub location: String,
}

#[derive(Debug, Deserialize)]
pub struct HeuristicRule {
    pub name: String,
    #[serde(rename = "type")]
    pub rule_type: String,
    pub field: Option<String>,
    pub keywords: Option<Vec<String>>,
    pub pattern: Option<String>,
    pub check: Option<String>,
    pub risk_score: u8,
    pub description: String,
}
#[derive(Debug, Deserialize)]
pub struct HeuristicRules {
    pub rules: Vec<HeuristicRule>,
}

impl HeuristicRules {
    pub fn load(path: &str) -> Result<HeuristicRules, Box<dyn Error>> {
        let content = std::fs::read_to_string(path)?;
        let rules: HeuristicRules = toml::from_str(&content)?;
        Ok(rules)
    }
}

/// Sanitizes a string for safe display in error messages
/// Removes/escapes characters that could be used for injection attacks
/// Also prevents information disclosure from path traversal attempts
fn sanitize_error_string(s: &str) -> String {
    let filtered: String = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\t' || *c == ' ') // Remove control chars except tab/space
        .map(|c| match c {
            ';' | '|' | '&' | '$' | '`' | '\'' | '"' | '\\' => ' ', // Replace shell metacharacters
            c => c,
        })
        .collect();

    // Collapse multiple path traversal sequences to prevent information disclosure
    let sanitized = if filtered.matches("../").count() > 2 || filtered.matches("..\\").count() > 2 {
        "[path-traversal-attempt]".to_string()
    } else {
        filtered
    };

    sanitized
        .chars()
        .take(200) // Limit length to prevent log flooding
        .collect()
}

/// Validates a heuristics rule file for correctness before loading
/// Returns Ok(()) if valid, or Err with detailed validation errors
/// All error messages are sanitized to prevent injection attacks
pub fn validate_heuristics_file(path: &str) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // Sanitize the path for error messages
    let safe_path = sanitize_error_string(path);

    // Check if file exists
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            errors.push(format!("Failed to read file [{}]: {}", safe_path, e));
            return Err(errors);
        }
    };

    // Parse TOML
    let parsed: toml::Value = match toml::from_str(&content) {
        Ok(p) => p,
        Err(e) => {
            // Sanitize TOML error message to prevent reflection attacks
            let error_msg = sanitize_error_string(&e.to_string());
            errors.push(format!("Invalid TOML syntax: {}", error_msg));
            return Err(errors);
        }
    };

    // Get rules array
    let rules = match parsed.get("rules") {
        Some(r) => match r.as_array() {
            Some(arr) => arr,
            None => {
                errors.push("'rules' must be an array".to_string());
                return Err(errors);
            }
        },
        None => {
            errors.push("Missing 'rules' array in TOML".to_string());
            return Err(errors);
        }
    };

    if rules.is_empty() {
        errors.push("Rules array is empty - no rules defined".to_string());
    }

    // Validate each rule
    let valid_fields = ["description", "title", "link", "author", "published_date"];
    let valid_checks = ["is_some", "is_none"];

    for (idx, rule) in rules.iter().enumerate() {
        let rule_table = match rule.as_table() {
            Some(t) => t,
            None => {
                errors.push(format!("Rule {} is not a valid table", idx));
                continue;
            }
        };

        // Sanitize rule name to prevent injection in error messages
        let rule_name = rule_table
            .get("name")
            .and_then(|n| n.as_str())
            .map(|s| sanitize_error_string(s))
            .unwrap_or_else(|| format!("#{}", idx));

        // Check required fields for all rules
        if !rule_table.contains_key("name") {
            errors.push(format!("Rule {} missing 'name'", idx));
        }
        if !rule_table.contains_key("type") {
            errors.push(format!("Rule '{}' missing 'type'", rule_name));
        }
        if !rule_table.contains_key("risk_score") {
            errors.push(format!("Rule '{}' missing 'risk_score'", rule_name));
        }
        if !rule_table.contains_key("description") {
            errors.push(format!("Rule '{}' missing 'description'", rule_name));
        }

        // Validate risk_score range
        if let Some(score) = rule_table.get("risk_score") {
            if let Some(score_int) = score.as_integer() {
                if !(0..=100).contains(&score_int) {
                    errors.push(format!(
                        "Rule '{}' has invalid risk_score {}, must be 0-100",
                        rule_name, score_int
                    ));
                }
            } else {
                errors.push(format!(
                    "Rule '{}' risk_score must be an integer",
                    rule_name
                ));
            }
        }

        // Type-specific validation
        let rule_type = rule_table
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("");

        match rule_type {
            "keyword" => {
                if !rule_table.contains_key("field") {
                    errors.push(format!("Keyword rule '{}' missing 'field'", rule_name));
                }
                if !rule_table.contains_key("keywords") {
                    errors.push(format!(
                        "Keyword rule '{}' missing 'keywords' array",
                        rule_name
                    ));
                }
            }
            "regex" => {
                if !rule_table.contains_key("field") {
                    errors.push(format!("Regex rule '{}' missing 'field'", rule_name));
                }
                if !rule_table.contains_key("pattern") {
                    errors.push(format!("Regex rule '{}' missing 'pattern'", rule_name));
                } else if let Some(pattern) = rule_table.get("pattern").and_then(|p| p.as_str()) {
                    // Validate regex compiles
                    if let Err(e) = Regex::new(pattern) {
                        let safe_pattern = sanitize_error_string(pattern);
                        let safe_err = sanitize_error_string(&e.to_string());
                        errors.push(format!(
                            "Regex rule '{}' has invalid pattern [{}]: {}",
                            rule_name, safe_pattern, safe_err
                        ));
                    }
                }
            }
            "metadata" => {
                if !rule_table.contains_key("field") {
                    errors.push(format!("Metadata rule '{}' missing 'field'", rule_name));
                }
                if !rule_table.contains_key("check") {
                    errors.push(format!("Metadata rule '{}' missing 'check'", rule_name));
                } else if let Some(check) = rule_table.get("check").and_then(|c| c.as_str()) {
                    if !valid_checks.contains(&check) {
                        let safe_check = sanitize_error_string(check);
                        errors.push(format!(
                            "Metadata rule '{}' has invalid check [{}], must be one of: {:?}",
                            rule_name, safe_check, valid_checks
                        ));
                    }
                }
            }
            "" => {
                errors.push(format!("Rule '{}' has empty type", rule_name));
            }
            other => {
                let safe_type = sanitize_error_string(other);
                errors.push(format!(
                    "Rule '{}' has unknown type [{}], must be 'keyword', 'regex', or 'metadata'",
                    rule_name, safe_type
                ));
            }
        }

        // Validate field name if present
        if let Some(field) = rule_table.get("field").and_then(|f| f.as_str()) {
            if !valid_fields.contains(&field) {
                let safe_field = sanitize_error_string(field);
                errors.push(format!(
                    "Rule '{}' has invalid field [{}], must be one of: {:?}",
                    rule_name, safe_field, valid_fields
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
fn heuristic_check(_pkg: PythonPackage) -> Result<HeuristicMatch, Box<dyn Error>> {
    let h_match = HeuristicMatch {
        rule_name: "".to_string(),
        risk_score: 0,
        evidence: "".to_string(),
        description: "".to_string(),
        location: "".to_string(),
    };
    Ok(h_match)
}

pub fn apply_rule(rule: HeuristicRule, pkg: &PythonPackage) -> Option<HeuristicMatch> {
    match rule.rule_type.as_str() {
        "keyword" => check_keywords(rule, pkg),
        "regex" => check_regex(rule, pkg),
        "metadata" => check_metadata(rule, pkg),
        _ => None,
    }
}

fn check_metadata(rule: HeuristicRule, pkg: &PythonPackage) -> Option<HeuristicMatch> {
    let field = rule.field.as_deref()?;
    let check = rule.check.as_deref()?;

    let field_value = match field {
        "description" => &pkg.description,
        "title" => &pkg.title,
        "link" => &pkg.link,
        "published_date" => &pkg.published_date,
        "author" => &pkg.author,
        _ => return None,
    };

    let cond = match check {
        "is_some" => field_value.is_some(),
        "is_none" => field_value.is_none(),
        _ => false,
    };

    if cond {
        Some(HeuristicMatch {
            rule_name: rule.name,
            risk_score: rule.risk_score,
            evidence: format!("{} {}", field, check),
            description: rule.description,
            location: field.to_string(),
        })
    } else {
        None
    }
}

fn check_regex(rule: HeuristicRule, pkg: &PythonPackage) -> Option<HeuristicMatch> {
    let pattern = rule.pattern.as_deref()?;
    let field = rule.field.as_deref()?;

    // Get the text to check from the specified field
    let text = match field {
        "description" => pkg.description.as_deref()?,
        "title" => pkg.title.as_deref()?,
        "link" => pkg.link.as_deref()?,
        "author" => pkg.author.as_deref()?,
        _ => return None,
    };

    // Compile the regex (return None if invalid pattern)
    let re = Regex::new(pattern).ok()?;

    // Check if the regex matches
    if let Some(matched) = re.find(text) {
        Some(HeuristicMatch {
            rule_name: rule.name,
            risk_score: rule.risk_score,
            evidence: matched.as_str().to_string(),
            description: rule.description,
            location: field.to_string(),
        })
    } else {
        None
    }
}

fn check_keywords(rule: HeuristicRule, pkg: &PythonPackage) -> Option<HeuristicMatch> {
    let keywords = rule.keywords.as_ref()?;
    let field = rule.field.as_deref()?;

    let text = match field {
        "description" => pkg.description.as_deref()?,
        "title" => pkg.title.as_deref()?,
        "link" => pkg.link.as_deref()?,
        "author" => pkg.author.as_deref()?,
        _ => return None,
    };

    for keyword in keywords {
        if text
            .to_lowercase()
            .contains(keyword.to_lowercase().as_str())
        {
            return Some(HeuristicMatch {
                rule_name: rule.name,
                risk_score: rule.risk_score,
                evidence: keyword.clone(),
                description: rule.description,
                location: field.to_string(),
            });
        }
    }
    None
}
