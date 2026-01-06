use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use std::fs;
use std::path::Path;
use std::process::Command;
use crate::glitch::matrix_glitch;

struct ConfigValues {
    feed_endpoint: String,
    popular_packages_endpoint: String,
    poll_interval: String,
    check_updates: bool,
    llm_endpoint: String,
    llm_model: String,
    typosquat_threshold: usize,
    min_package_length: usize,
    webhook: Option<String>,
    log_level: String,
    enable_tui: bool,
    heuristics_enabled: bool,
    typosquat_enabled: bool,
    guarddog_enabled: bool,
    llm_enabled: bool,
}

pub async fn run_init(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let use_color = std::io::IsTerminal::is_terminal(&std::io::stdout());
    matrix_glitch(".:* Configuring CLU with acceptable parameters..\n", 10,use_color);
    // Check if config already exists
    if Path::new(config_path).exists() {
        let overwrite = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!("Configuration file '{}' already exists. Overwrite?", config_path))
            .default(false)
            .interact()?;

        if !overwrite {
            println!("❌ Configuration setup cancelled.");
            return Ok(());
        }
    }

    // === Feed Configuration ===
    matrix_glitch("\n.:* Feed Configuration\n", 10, use_color);
    println!("Configure how CLU monitors the PyPI package feed.\n");

    let feed_endpoint: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("PyPI RSS feed endpoint")
        .default("https://pypi.org/rss/packages.xml".to_string())
        .interact_text()?;

    let popular_packages_endpoint: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Popular packages endpoint (for typosquatting detection)")
        .default("https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json".to_string())
        .interact_text()?;

    let poll_interval_options = ["10s", "30s", "1m", "5m", "15m", "30m", "1h"];
    let poll_selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("How often should CLU check for new packages?")
        .default(1) // 30s
        .items(&poll_interval_options)
        .interact()?;
    let poll_interval = poll_interval_options[poll_selection].to_string();

    let check_updates = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Monitor package updates in addition to new packages?")
        .default(false)
        .interact()?;

    // === LLM Configuration ===
    matrix_glitch("\n.:* LLM Configuration\n", 10, use_color);
    println!("Configure the LLM endpoint for advanced code analysis.\n");

    let llm_endpoint: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("LLM endpoint (e.g., Ollama)")
        .default("http://localhost:11434".to_string())
        .interact_text()?;

    let model_options = [
        ("qwen2.5-coder:7b - Excellent for code analysis (Recommended)", "qwen2.5-coder:7b"),
        ("llama3.2 - Latest Llama model, strong reasoning", "llama3.2"),
        ("deepseek-coder-v2 - Specialized for code understanding", "deepseek-coder-v2"),
        ("codellama - Meta's code-specialized model", "codellama"),
        ("mistral-nemo - Balanced performance", "mistral-nemo"),
        ("Custom model name...", "custom"),
    ];

    let model_selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select LLM model for code analysis")
        .default(0) // qwen2.5-coder:7b
        .items(&model_options.iter().map(|(label, _)| label).collect::<Vec<_>>())
        .interact()?;

    let llm_model = if model_options[model_selection].1 == "custom" {
        Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter custom model name")
            .interact_text()?
    } else {
        model_options[model_selection].1.to_string()
    };

    // Check if model exists on Ollama server
    if let Err(e) = check_and_download_model(&llm_endpoint, &llm_model).await {
        eprintln!("⚠ Warning: {}", e);
        println!("You can download it later with: ollama pull {}", llm_model);
    }

    // === Analysis Configuration ===
    matrix_glitch("\n.:* Analysis Configuration\n", 10, use_color);
    println!("Configure detection sensitivity and thresholds.\n");

    let typosquat_options = [
        ("1 - Very strict (only 1 character difference)", 1),
        ("2 - Moderate (2 character difference) - Recommended", 2),
        ("3 - Lenient (3 character difference)", 3),
    ];
    let typosquat_selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Typosquatting detection sensitivity")
        .default(1) // Moderate
        .items(&typosquat_options.iter().map(|(label, _)| label).collect::<Vec<_>>())
        .interact()?;
    let typosquat_threshold = typosquat_options[typosquat_selection].1;

    let min_package_length: usize = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Minimum package name length to check for typosquatting")
        .default(4)
        .interact_text()?;

    // === Pipeline Configuration ===
    matrix_glitch("\n.:* Analysis Pipeline Configuration\n", 10, use_color);
    println!("Configure which analysis stages are enabled.\n");

    let heuristics_enabled = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Enable Heuristics (metadata analysis)")
        .default(true)
        .interact()?;

    let typosquat_enabled = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Enable Typosquat Detection (package name analysis)")
        .default(true)
        .interact()?;

    let guarddog_enabled = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Enable GuardDog (pattern-based code analysis)")
        .default(false)
        .interact()?;

    let llm_enabled = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Enable LLM Analysis (semantic code analysis)")
        .default(false)
        .interact()?;

    // === Output Configuration ===
    matrix_glitch("\n.:* Output Configuration\n",10, use_color);
    println!("Configure how CLU outputs detection results.\n");

    let enable_webhook = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Enable webhook notifications?")
        .default(false)
        .interact()?;

    let webhook = if enable_webhook {
        let url: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Webhook URL")
            .interact_text()?;
        Some(url)
    } else {
        None
    };

    let log_level_options = ["debug", "info", "warn", "error"];
    let log_level_selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Log level")
        .default(1) // info
        .items(&log_level_options)
        .interact()?;
    let log_level = log_level_options[log_level_selection].to_string();

    let enable_tui = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Enable terminal UI (TUI) for live monitoring?")
        .default(true)
        .interact()?;

    // === Generate TOML ===
    let config_values = ConfigValues {
        feed_endpoint,
        popular_packages_endpoint,
        poll_interval,
        check_updates,
        llm_endpoint,
        llm_model,
        typosquat_threshold,
        min_package_length,
        webhook,
        log_level,
        enable_tui,
        heuristics_enabled,
        typosquat_enabled,
        guarddog_enabled,
        llm_enabled,
    };

    let config_content = generate_toml(&config_values);

    // Write to file
    fs::write(config_path, config_content)?;

    println!("\n.oO0( Configuration saved to '{}'", config_path);
    matrix_glitch(r#"
    .:* Setup complete! You can now run:
       clu watch    - Start monitoring the PyPI feed
       clu scan <package>  - Scan a specific package"#, 10, use_color);
    println!("\nYou can edit '{}' manually to fine-tune your configuration.\n", config_path);

    Ok(())
}

fn generate_toml(config: &ConfigValues) -> String {
    let webhook_line = if let Some(url) = &config.webhook {
        format!("webhook = \"{}\"", url)
    } else {
        "# webhook = \"https://your-webhook-url.com\"".to_string()
    };

    format!(
        r#"# CLU Configuration File
# Generated by: clu init
# Docs: https://github.com/akses/clu

[feed]
# PyPI RSS feed endpoint for monitoring new packages
endpoint = "{}"

# Endpoint for fetching popular packages list (used for typosquatting detection)
popular_packages_endpoint = "{}"

# How often to poll the feed (supports: s=seconds, m=minutes, h=hours)
poll_interval = "{}"

# Whether to also monitor package updates (not just new packages)
check_updates = {}

[llm]
# LLM endpoint for advanced code analysis (e.g., Ollama, OpenAI-compatible API)
endpoint = "{}"

# Model name to use for analysis
model = "{}"

[analysis]
# Maximum Levenshtein distance for typosquatting detection
# 1 = very strict, 2 = moderate (recommended), 3+ = lenient
typosquat_distance_threshold = {}

# Minimum package name length to check for typosquatting
# Shorter names tend to have more false positives
min_package_length = {}

[output]
# Webhook URL for sending alerts (optional)
{}

# Log level: debug, info, warn, error
log_level = "{}"

# Enable terminal UI for live monitoring
enable_tui = {}

[pipeline]
# Enable heuristic-based metadata analysis (fast, low false positives)
heuristics = {}

# Enable typosquat detection based on Levenshtein distance
typosquat = {}

# Enable GuardDog pattern-based code analysis (requires download)
guarddog = {}

# Enable LLM semantic code analysis (requires download, slower)
llm = {}
"#,
        config.feed_endpoint,
        config.popular_packages_endpoint,
        config.poll_interval,
        config.check_updates,
        config.llm_endpoint,
        config.llm_model,
        config.typosquat_threshold,
        config.min_package_length,
        webhook_line,
        config.log_level,
        config.enable_tui,
        config.heuristics_enabled,
        config.typosquat_enabled,
        config.guarddog_enabled,
        config.llm_enabled
    )
}

/// Check if a model exists on Ollama server, and offer to download it if not
async fn check_and_download_model(_endpoint: &str, model_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n.:* Checking if model '{}' is available...", model_name);

    // Check if ollama CLI is available
    let ollama_check = Command::new("ollama")
        .arg("list")
        .output();

    if ollama_check.is_err() {
        return Err("Ollama CLI not found. Please install Ollama from https://ollama.ai".into());
    }

    // Get list of installed models
    let output = ollama_check?;
    let output_str = String::from_utf8_lossy(&output.stdout);

    // Check if model is in the list
    let model_exists = output_str.lines().any(|line| {
        line.to_lowercase().contains(&model_name.to_lowercase())
    });

    if model_exists {
        println!(".oO0( Model '{}' is already installed )", model_name);
        return Ok(());
    }

    // Model not found, ask user if they want to download
    println!("⚠ Model '{}' not found on Ollama server", model_name);

    let should_download = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!("Would you like to download '{}' now? (This may take a while depending on model size)", model_name))
        .default(true)
        .interact()?;

    if !should_download {
        return Err(format!("Model '{}' not installed. You can install it later with: ollama pull {}", model_name, model_name).into());
    }

    // Download the model
    println!(">> Downloading model '{}'... This may take several minutes.", model_name);
    println!("   (You can cancel with Ctrl+C and download later with: ollama pull {})", model_name);

    let pull_result = Command::new("ollama")
        .arg("pull")
        .arg(model_name)
        .status()?;

    if pull_result.success() {
        println!(".oO0( Model '{}' downloaded successfully!)", model_name);
        Ok(())
    } else {
        Err(format!("Failed to download model '{}'. Please try manually: ollama pull {}", model_name, model_name).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_toml_with_webhook() {
        let config = ConfigValues {
            feed_endpoint: "https://pypi.org/rss/packages.xml".to_string(),
            popular_packages_endpoint: "https://example.com/popular.json".to_string(),
            poll_interval: "30s".to_string(),
            check_updates: false,
            llm_endpoint: "http://localhost:11434".to_string(),
            llm_model: "llama2".to_string(),
            typosquat_threshold: 2,
            min_package_length: 4,
            webhook: Some("https://webhook.site/test".to_string()),
            log_level: "info".to_string(),
            enable_tui: true,
            heuristics_enabled: true,
            typosquat_enabled: true,
            guarddog_enabled: true,
            llm_enabled: true,
        };

        let toml = generate_toml(&config);

        assert!(toml.contains("endpoint = \"https://pypi.org/rss/packages.xml\""));
        assert!(toml.contains("webhook = \"https://webhook.site/test\""));
        assert!(toml.contains("log_level = \"info\""));
        assert!(toml.contains("heuristics = true"));
        assert!(toml.contains("typosquat = true"));
        assert!(toml.contains("guarddog = true"));
        assert!(toml.contains("llm = true"));
    }

    #[test]
    fn test_generate_toml_without_webhook() {
        let config = ConfigValues {
            feed_endpoint: "https://pypi.org/rss/packages.xml".to_string(),
            popular_packages_endpoint: "https://example.com/popular.json".to_string(),
            poll_interval: "1m".to_string(),
            check_updates: true,
            llm_endpoint: "http://localhost:11434".to_string(),
            llm_model: "llama2".to_string(),
            typosquat_threshold: 2,
            min_package_length: 4,
            webhook: None,
            log_level: "debug".to_string(),
            enable_tui: false,
            heuristics_enabled: true,
            typosquat_enabled: true,
            guarddog_enabled: false,
            llm_enabled: false,
        };

        let toml = generate_toml(&config);

        assert!(toml.contains("# webhook ="));
        // Should have commented webhook, not active webhook line
        let has_active_webhook = toml.lines()
            .any(|line| line.starts_with("webhook = \"") && !line.starts_with("# webhook"));
        assert!(!has_active_webhook);
        assert!(toml.contains("check_updates = true"));
        assert!(toml.contains("enable_tui = false"));
        assert!(toml.contains("typosquat = true"));
        assert!(toml.contains("guarddog = false"));
        assert!(toml.contains("llm = false"));
    }
}
