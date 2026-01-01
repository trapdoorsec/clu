use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub feed: FeedConfig,
    pub llm: LlmConfig,
    pub analysis: AnalysisConfig,
    pub output: OutputConfig,
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

impl Config {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}
