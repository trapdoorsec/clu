#![allow(dead_code)]

use serde::Serialize;
pub use crate::analysis::guarddog::GuardDogResult;
pub use crate::analysis::heuristics::HeuristicMatch;
pub use crate::analysis::llm::{LlmAnalysisResult, PromptInjectionDetection};
pub use crate::analysis::typosquat::TypoSquatterMatch;

pub mod formatters;
pub mod webhook;
pub mod tui;

#[derive(Serialize)]
pub struct AnalysisReport {
    pub package_name: String,
    pub package_version: Option<String>,
    pub timestamp: String,

    // Tier 1: Heuristics
    pub heuristic_matches: Vec<HeuristicMatch>,
    pub typosquat_matches: Vec<TypoSquatterMatch>,

    // Tier 2: LLM
    pub injection_detection: Option<PromptInjectionDetection>,
    pub llm_analysis: Option<LlmAnalysisResult>,

    // Tier 3: GuardDog
    pub guarddog_result: Option<GuardDogResult>,

    // Summary
    pub overall_risk_score: u8,
    pub is_malicious: bool,
    pub recommendation: String, // "BLOCK", "REVIEW", "SAFE"
}


pub trait Formatter {
    fn format_report(&self, report: &AnalysisReport) -> String;
}