#![allow(dead_code)]

pub use crate::analysis::heuristics::HeuristicMatch;
pub use crate::analysis::llm::{LlmAnalysisResult, PromptInjectionDetection};
pub use crate::analysis::typosquat::TypoSquatterMatch;
pub use crate::analysis::yara::{YaraEngine, YaraRuleInfo};
pub use crate::feed::ecosystem::Ecosystem;
use serde::{Deserialize, Serialize};

pub mod formatters;
pub mod notify;
pub mod tui;
pub mod webhook;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub severity: String,
    pub description: String,
    pub risk_score: u8,
    pub strings_matched: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraScanResult {
    pub is_malicious: bool,
    pub risk_score: u8,
    pub findings: Vec<YaraMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub package_name: String,
    pub package_version: Option<String>,
    pub timestamp: String,
    pub ecosystem: Ecosystem,
    pub sha256: String,

    pub heuristic_matches: Vec<HeuristicMatch>,
    pub typosquat_matches: Vec<TypoSquatterMatch>,

    pub yara_result: Option<YaraScanResult>,

    pub injection_detection: Option<PromptInjectionDetection>,
    pub llm_analysis: Option<LlmAnalysisResult>,

    pub severity: u8,
    pub is_malicious: bool,
    pub recommendation: String,
}

pub trait Formatter {
    fn format_report(&self, report: &AnalysisReport) -> String;
}
