#![allow(dead_code)]

use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub feed: FeedConfig,
    pub llm: LlmConfig,
    pub analysis: AnalysisConfig,
    pub output: OutputConfig,
    #[serde(default)]
    pub pipeline: PipelineConfig,
}

#[derive(Debug, Deserialize)]
pub struct FeedConfig {
    pub poll_interval: String, // supports 5s, 5m, 5h etc
    pub endpoint: String,      //e.g. https://pypi.org/
    pub popular_packages_endpoint: String,
    pub check_updates: bool,
}

#[derive(Debug, Deserialize)]
pub struct LlmConfig {
    pub endpoint: String,
    pub model: String,
}

impl LlmConfig {
    /// Parse endpoint URL to extract host and port
    /// Example: "http://ollama:11434" -> ("ollama", 11434)
    pub fn parse_endpoint(&self) -> Result<(String, u16), Box<dyn std::error::Error>> {
        let url = url::Url::parse(&self.endpoint)?;
        let host = url.host_str().unwrap_or("localhost").to_string();
        let port = url.port().unwrap_or(11434);
        Ok((host, port))
    }
}

#[derive(Debug, Deserialize)]
pub struct AnalysisConfig {
    /// Maximum Levenshtein distance to consider as potential typosquat
    /// 1 = very strict (only 1 char difference), 2 = moderate, 3+ = lenient
    #[serde(default = "default_typosquat_threshold")]
    pub typosquat_distance_threshold: usize,

    /// Minimum length of package name to check for typosquatting
    /// Short names have more false positives
    #[serde(default = "default_min_package_length")]
    pub min_package_length: usize,
}

fn default_typosquat_threshold() -> usize {
    2
}

fn default_min_package_length() -> usize {
    4
}

#[derive(Debug, Deserialize)]
pub struct OutputConfig {
    #[serde(default)]
    pub webhook: Option<String>,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_enable_tui")]
    pub enable_tui: bool,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_enable_tui() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct PipelineConfig {
    /// Enable heuristic-based metadata analysis (fast, low false positives)
    #[serde(default = "default_heuristics")]
    pub heuristics: bool,

    /// Enable typosquat detection based on Levenshtein distance
    #[serde(default = "default_typosquat")]
    pub typosquat: bool,

    /// Enable GuardDog pattern-based code analysis (requires download)
    #[serde(default = "default_guarddog")]
    pub guarddog: bool,

    /// Enable LLM semantic code analysis (requires download, slower)
    #[serde(default = "default_llm")]
    pub llm: bool,
}

fn default_heuristics() -> bool {
    true
}

fn default_typosquat() -> bool {
    true
}

fn default_guarddog() -> bool {
    false
}

fn default_llm() -> bool {
    false
}

impl Default for PipelineConfig {
    fn default() -> Self {
        PipelineConfig {
            heuristics: true,
            typosquat: true,
            guarddog: false,
            llm: false,
        }
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}
