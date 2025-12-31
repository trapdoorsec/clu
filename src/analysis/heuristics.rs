use serde::Deserialize;
use regex::Regex;
use std::error::Error;
use std::fmt::DebugSet;
use feed::pypi::PythonPackage;
use crate::feed;
struct HeuristicMatch {
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
    pub location: Option<String>,
    pub keywords: Option<Vec<String>>,
    pub pattern: Option<String>,
    pub field: Option<String>,
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
        let rules: HeuristicRules = serde_json::from_str(&content)?;
        Ok(rules)
    }
}
fn heuristic_check(pkg: PythonPackage) -> Result<HeuristicMatch, Box<dyn Error>> {
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
        Some (HeuristicMatch {
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

fn check_regex(heuristic_rule: HeuristicRule, python_package: &PythonPackage) -> Option<HeuristicMatch> {
    unimplemented!()
}

fn check_keywords(rule: HeuristicRule, pkg: &PythonPackage) -> Option<HeuristicMatch> {
    let keywords = rule.keywords.as_ref()?;
    let text = match rule.location.as_deref() {
        Some("description") => pkg.description.as_deref()?,
        Some("title") => pkg.title.as_deref()?,
        _ => return None,
    };

    for keyword in keywords {
        if text.to_lowercase().contains(&keyword.to_lowercase().as_str()) {
            return Some(HeuristicMatch {
                rule_name: rule.name.clone(),
                risk_score: rule.risk_score,
                evidence: keyword.clone(),
                description: rule.description.clone(),
                location: rule.location.clone().unwrap_or_default(),
            });
        }
    }
    None
}