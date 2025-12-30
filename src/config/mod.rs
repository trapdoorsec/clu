use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub feed: FeedConfig,
    pub llm: LlmConfig,
    pub output: OutputConfig,
}

#[derive(Debug, Deserialize)]
pub struct FeedConfig {
    pub poll_interval: String, // supports 5s, 5m, 5h etc
    pub endpoint: String,      //e.g. https://pypi.org/
    pub checkUpdates: bool,
}

#[derive(Debug, Deserialize)]
pub struct LlmConfig {
    pub endpoint: String,
    pub model: String,
}

#[derive(Debug, Deserialize)]
pub struct OutputConfig {
    #[serde(default)]
    pub webhook: Option<String>,
}

impl Config {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}
