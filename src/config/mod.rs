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
    pub cache: CacheConfig,
    #[serde(default)]
    pub pipeline: PipelineConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub extraction: ExtractionConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExtractionConfig {
    #[serde(default = "default_max_total_bytes")]
    pub max_total_bytes: usize,
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: usize,
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
}

fn default_max_total_bytes() -> usize {
    67_108_864 // 64 MiB
}

fn default_max_file_bytes() -> usize {
    2_097_152 // 2 MiB
}

fn default_max_entries() -> usize {
    5000
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        ExtractionConfig {
            max_total_bytes: default_max_total_bytes(),
            max_file_bytes: default_max_file_bytes(),
            max_entries: default_max_entries(),
        }
    }
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
    #[serde(default = "default_request_timeout")]
    pub request_timeout: u64,
}

fn default_request_timeout() -> u64 {
    30
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
pub struct CacheConfig {
    /// Directory for caching pip packages (used by GuardDog and LLM)
    #[serde(default = "default_pip_cache_dir")]
    pub pip_cache_dir: String,
}

fn default_pip_cache_dir() -> String {
    "/tmp/pip-cache".to_string()
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            pip_cache_dir: default_pip_cache_dir(),
        }
    }
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

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    /// Database connection URL (e.g., "sqlite://data/clu.db")
    #[serde(default = "default_database_url")]
    pub url: String,

    /// Enable database persistence (if false, uses in-memory only)
    #[serde(default = "default_enable_database")]
    pub enable: bool,
}

fn default_database_url() -> String {
    "sqlite://config/data/clu.db".to_string()
}

fn default_enable_database() -> bool {
    true
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig {
            url: default_database_url(),
            enable: default_enable_database(),
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
