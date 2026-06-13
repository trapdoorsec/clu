#![allow(dead_code)]

pub use crate::analysis::guarddog::GuardDogResult;
pub use crate::analysis::heuristics::HeuristicMatch;
pub use crate::analysis::llm::{LlmAnalysisResult, PromptInjectionDetection};
pub use crate::analysis::typosquat::TypoSquatterMatch;
pub use crate::feed::ecosystem::Ecosystem;
use serde::{Deserialize, Serialize};

pub mod formatters;
pub mod notify;
pub mod tui;
pub mod webhook;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub package_name: String,
    pub package_version: Option<String>,
    pub timestamp: String,
    pub ecosystem: Ecosystem,
    pub sha256: String,

    // Tier 1: Initial findings
    pub heuristic_matches: Vec<HeuristicMatch>,
    pub typosquat_matches: Vec<TypoSquatterMatch>,

    // Tier 2: GuardDog
    pub guarddog_result: Option<GuardDogResult>,

    // Tier 3: LLM Assessment (final scoring based on all findings)
    pub injection_detection: Option<PromptInjectionDetection>,
    pub llm_analysis: Option<LlmAnalysisResult>,

    // Final Assessment (derived from LLM or fallback)
    pub severity: u8, // 1-25 scale (impact * likelihood)
    pub is_malicious: bool,
    pub recommendation: String, // "IGNORE", "INSPECT"
}

pub trait Formatter {
    fn format_report(&self, report: &AnalysisReport) -> String;
}
