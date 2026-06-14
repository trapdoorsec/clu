use crate::glitch::matrix_glitch;
use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};
use std::fs;
use std::path::Path;

struct ConfigValues {
    feed_endpoint: String,
    popular_packages_endpoint: String,
    poll_interval: String,
    check_updates: bool,
    llm_endpoint: String,
    llm_model: String,
    llm_request_timeout: u64,
    pip_cache_dir: String,
    typosquat_threshold: usize,
    min_package_length: usize,
    webhook: Option<String>,
    log_level: String,
    enable_tui: bool,
    heuristics_enabled: bool,
    typosquat_enabled: bool,
    guarddog_enabled: bool,
    llm_enabled: bool,
    quarantine_enabled: bool,
    quarantine_dir: String,
    quarantine_min_severity: u8,
    quarantine_max_age_days: u64,
    quarantine_max_disk_mb: u64,
    quarantine_retain_metadata: bool,
    notifications_enabled: bool,
    discord_webhook: Option<String>,
    slack_webhook: Option<String>,
    generic_webhook: Option<String>,
    notifications_min_severity: u8,
    notifications_timeout_secs: u64,
}

pub async fn run_init(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let use_color = std::io::IsTerminal::is_terminal(&std::io::stdout());
    matrix_glitch(
        ".:* Configuring CLU with acceptable parameters..\n",
        10,
        use_color,
    );
    // Check if config already exists
    if Path::new(config_path).exists() {
        let overwrite = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!(
                "Configuration file '{}' already exists. Overwrite?",
                config_path
            ))
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
        .default(
            "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
                .to_string(),
        )
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
        .default("http://ollama:11434".to_string())
        .interact_text()?;

    let model_options = [
        (
            "qwen2.5-coder:7b - Excellent for code analysis (Recommended)",
            "qwen2.5-coder:7b",
        ),
        (
            "llama3.2 - Latest Llama model, strong reasoning",
            "llama3.2",
        ),
        (
            "deepseek-coder-v2 - Specialized for code understanding",
            "deepseek-coder-v2",
        ),
        ("codellama - Meta's code-specialized model", "codellama"),
        ("mistral-nemo - Balanced performance", "mistral-nemo"),
        ("Custom model name...", "custom"),
    ];

    let model_selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select LLM model for code analysis")
        .default(0) // qwen2.5-coder:7b
        .items(
            &model_options
                .iter()
                .map(|(label, _)| label)
                .collect::<Vec<_>>(),
        )
        .interact()?;

    let llm_model = if model_options[model_selection].1 == "custom" {
        Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter custom model name")
            .interact_text()?
    } else {
        model_options[model_selection].1.to_string()
    };

    let llm_request_timeout: u64 = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("LLM request timeout (seconds)")
        .default(30)
        .interact_text()?;

    // Check if model exists on Ollama server
    if let Err(e) = check_and_download_model(&llm_endpoint, &llm_model).await {
        eprintln!("⚠ Warning: {}", e);
        println!("You can download it later with: ollama pull {}", llm_model);
    }

    // === Cache Configuration ===
    matrix_glitch("\n.:* Cache Configuration\n", 10, use_color);
    println!("Configure caching for package downloads.\n");

    let pip_cache_dir: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Pip package cache directory (used by GuardDog and LLM)")
        .default("/tmp/pip-cache".to_string())
        .interact_text()?;

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
        .items(
            &typosquat_options
                .iter()
                .map(|(label, _)| label)
                .collect::<Vec<_>>(),
        )
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

    // === Quarantine Configuration ===
    matrix_glitch("\n.:* Quarantine Configuration\n", 10, use_color);
    println!("Configure quarantine of suspicious packages for deeper investigation.\n");

    let quarantine_enabled = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Enable package quarantine for suspicious packages?")
        .default(true)
        .interact()?;

    let quarantine_dir: String = if quarantine_enabled {
        Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Quarantine directory (where suspicious packages are saved)")
            .default("/tmp/clu-quarantine".to_string())
            .interact_text()?
    } else {
        "/tmp/clu-quarantine".to_string()
    };

    let quarantine_min_severity_options = [
        ("1 - LOW (quarantine everything)", 1),
        (
            "5 - MEDIUM (quarantine suspicious packages) - Recommended",
            5,
        ),
        ("13 - HIGH (quarantine only high-risk packages)", 13),
        ("20 - CRITICAL (quarantine only critical packages)", 20),
    ];
    let quarantine_min_severity = if quarantine_enabled {
        let sel = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Minimum severity to quarantine a package")
            .default(1)
            .items(
                &quarantine_min_severity_options
                    .iter()
                    .map(|(label, _)| label)
                    .collect::<Vec<_>>(),
            )
            .interact()?;
        quarantine_min_severity_options[sel].1
    } else {
        5
    };

    let quarantine_max_age_days: u64 = if quarantine_enabled {
        Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Maximum quarantine age in days (auto-delete after this)")
            .default(3)
            .interact_text()?
    } else {
        3
    };

    let quarantine_max_disk_mb: u64 = if quarantine_enabled {
        Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Maximum quarantine disk usage in MB (evict oldest when exceeded)")
            .default(1024)
            .interact_text()?
    } else {
        1024
    };

    let quarantine_retain_metadata = if quarantine_enabled {
        Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Save analysis report alongside quarantined archive?")
            .default(true)
            .interact()?
    } else {
        true
    };

    // === Output Configuration ===
    matrix_glitch("\n.:* Output Configuration\n", 10, use_color);
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

    // === Notifications Configuration ===
    matrix_glitch("\n.:* Notifications Configuration\n", 10, use_color);
    println!("Configure webhook notifications for alerts (Discord, Slack, or generic).\n");

    let notifications_enabled = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Enable notification webhooks?")
        .default(false)
        .interact()?;

    let (discord_webhook, slack_webhook, generic_webhook) = if notifications_enabled {
        let enable_discord = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Configure Discord webhook?")
            .default(false)
            .interact()?;
        let discord_webhook: Option<String> = if enable_discord {
            Some(
                Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Discord webhook URL")
                    .interact_text()?,
            )
        } else {
            None
        };

        let enable_slack = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Configure Slack webhook?")
            .default(false)
            .interact()?;
        let slack_webhook: Option<String> = if enable_slack {
            Some(
                Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Slack webhook URL")
                    .interact_text()?,
            )
        } else {
            None
        };

        let enable_generic = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Configure generic webhook?")
            .default(false)
            .interact()?;
        let generic_webhook: Option<String> = if enable_generic {
            Some(
                Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Generic webhook URL")
                    .interact_text()?,
            )
        } else {
            None
        };

        (discord_webhook, slack_webhook, generic_webhook)
    } else {
        (None, None, None)
    };

    let notifications_min_severity_options = [
        ("1 - LOW (notify on all findings)", 1),
        ("5 - MEDIUM (notify on suspicious packages)", 5),
        ("13 - HIGH (notify on high-risk packages) - Recommended", 13),
        ("20 - CRITICAL (notify only on critical packages)", 20),
    ];
    let notifications_min_severity = if notifications_enabled {
        let sel = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Minimum severity to trigger notifications")
            .default(2)
            .items(
                &notifications_min_severity_options
                    .iter()
                    .map(|(label, _)| label)
                    .collect::<Vec<_>>(),
            )
            .interact()?;
        notifications_min_severity_options[sel].1
    } else {
        13
    };

    let notifications_timeout_secs: u64 = if notifications_enabled {
        Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Notification request timeout (seconds)")
            .default(10)
            .interact_text()?
    } else {
        10
    };

    // === Generate TOML ===
    let config_values = ConfigValues {
        feed_endpoint,
        popular_packages_endpoint,
        poll_interval,
        check_updates,
        llm_endpoint,
        llm_model,
        llm_request_timeout,
        pip_cache_dir,
        typosquat_threshold,
        min_package_length,
        webhook,
        log_level,
        enable_tui,
        heuristics_enabled,
        typosquat_enabled,
        guarddog_enabled,
        llm_enabled,
        quarantine_enabled,
        quarantine_dir,
        quarantine_min_severity,
        quarantine_max_age_days,
        quarantine_max_disk_mb,
        quarantine_retain_metadata,
        notifications_enabled,
        discord_webhook,
        slack_webhook,
        generic_webhook,
        notifications_min_severity,
        notifications_timeout_secs,
    };

    let config_content = generate_toml(&config_values);

    // Write to file
    fs::write(config_path, config_content)?;

    println!("\n.oO0( Configuration saved to '{}'", config_path);
    matrix_glitch(
        r#"
    .:* Setup complete! You can now run:
       clu watch    - Start monitoring the PyPI feed
       clu scan <package>  - Scan a specific package"#,
        10,
        use_color,
    );
    println!(
        "\nYou can edit '{}' manually to fine-tune your configuration.\n",
        config_path
    );

    Ok(())
}

fn generate_toml(config: &ConfigValues) -> String {
    let webhook_line = if let Some(url) = &config.webhook {
        format!("webhook = \"{}\"", url)
    } else {
        "# webhook = \"https://your-webhook-url.com\"".to_string()
    };

    let discord_webhook_line = if let Some(url) = &config.discord_webhook {
        format!("discord_webhook = \"{}\"", url)
    } else {
        "# discord_webhook = \"https://discord.com/api/webhooks/...\"".to_string()
    };

    let slack_webhook_line = if let Some(url) = &config.slack_webhook {
        format!("slack_webhook = \"{}\"", url)
    } else {
        "# slack_webhook = \"https://hooks.slack.com/services/...\"".to_string()
    };

    let generic_webhook_line = if let Some(url) = &config.generic_webhook {
        format!("generic_webhook = \"{}\"", url)
    } else {
        "# generic_webhook = \"https://example.com/webhook\"".to_string()
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

# Request timeout in seconds for LLM requests (default: 30)
request_timeout = {}

[cache]
# Directory for caching pip packages (used by GuardDog and LLM)
# Allows reusing packages across analysis stages to avoid redundant downloads
pip_cache_dir = "{}"

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

[quarantine]
# Enable package quarantine for suspicious packages
enabled = {}

# Directory where quarantined packages are saved
directory = "{}"

# Minimum severity to quarantine a package (1=LOW, 5=MEDIUM, 13=HIGH, 20=CRITICAL)
min_severity = {}

# Maximum age in days before auto-deleting quarantined packages
max_age_days = {}

# Maximum disk usage in MB (evicts oldest when exceeded)
max_disk_mb = {}

# Save analysis report (report.json) alongside quarantined archive
retain_metadata = {}

[notifications]
# Enable notification webhooks (Discord, Slack, generic)
enabled = {}

# Discord webhook URL for alerts
{}

# Slack webhook URL for alerts
{}

# Generic webhook URL for alerts
{}

# Minimum severity to trigger notifications (1=LOW, 5=MEDIUM, 13=HIGH, 20=CRITICAL)
min_severity = {}

# Request timeout in seconds for webhook calls
timeout_secs = {}
"#,
        config.feed_endpoint,
        config.popular_packages_endpoint,
        config.poll_interval,
        config.check_updates,
        config.llm_endpoint,
        config.llm_model,
        config.llm_request_timeout,
        config.pip_cache_dir,
        config.typosquat_threshold,
        config.min_package_length,
        webhook_line,
        config.log_level,
        config.enable_tui,
        config.heuristics_enabled,
        config.typosquat_enabled,
        config.guarddog_enabled,
        config.llm_enabled,
        config.quarantine_enabled,
        config.quarantine_dir,
        config.quarantine_min_severity,
        config.quarantine_max_age_days,
        config.quarantine_max_disk_mb,
        config.quarantine_retain_metadata,
        config.notifications_enabled,
        discord_webhook_line,
        slack_webhook_line,
        generic_webhook_line,
        config.notifications_min_severity,
        config.notifications_timeout_secs
    )
}

/// Check if a model exists on Ollama server via HTTP API
async fn check_and_download_model(
    endpoint: &str,
    model_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::analysis;

    println!(
        "\n.:* Checking if model '{}' is available at {}...",
        model_name, endpoint
    );

    // Normalize endpoint URL
    let endpoint_url = if endpoint.contains("://") {
        endpoint.to_string()
    } else {
        format!("http://{}", endpoint)
    };

    // Use shared utility - don't auto-pull during init, just check
    match analysis::ollama_utils::check_model_available(&endpoint_url, model_name, false).await {
        Ok(()) => Ok(()),
        Err(e) => {
            println!("⚠ Model check failed: {}", e);
            Ok(()) // Don't fail - user might have model already
        }
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
            llm_endpoint: "http://ollama:11434".to_string(),
            llm_model: "llama2".to_string(),
            llm_request_timeout: 30,
            pip_cache_dir: "/tmp/pip-cache".to_string(),
            typosquat_threshold: 2,
            min_package_length: 4,
            webhook: Some("https://webhook.site/test".to_string()),
            log_level: "info".to_string(),
            enable_tui: true,
            heuristics_enabled: true,
            typosquat_enabled: true,
            guarddog_enabled: true,
            llm_enabled: true,
            quarantine_enabled: true,
            quarantine_dir: "/tmp/clu-quarantine".to_string(),
            quarantine_min_severity: 5,
            quarantine_max_age_days: 3,
            quarantine_max_disk_mb: 1024,
            quarantine_retain_metadata: true,
            notifications_enabled: true,
            discord_webhook: Some("https://discord.com/api/webhooks/test".to_string()),
            slack_webhook: Some("https://hooks.slack.com/services/test".to_string()),
            generic_webhook: None,
            notifications_min_severity: 13,
            notifications_timeout_secs: 10,
        };

        let toml = generate_toml(&config);

        assert!(toml.contains("endpoint = \"https://pypi.org/rss/packages.xml\""));
        assert!(toml.contains("webhook = \"https://webhook.site/test\""));
        assert!(toml.contains("log_level = \"info\""));
        assert!(toml.contains("heuristics = true"));
        assert!(toml.contains("typosquat = true"));
        assert!(toml.contains("guarddog = true"));
        assert!(toml.contains("llm = true"));
        assert!(toml.contains("[notifications]"));
        assert!(toml.contains("enabled = true"));
        assert!(toml.contains("discord_webhook = \"https://discord.com/api/webhooks/test\""));
        assert!(toml.contains("slack_webhook = \"https://hooks.slack.com/services/test\""));
        assert!(toml.contains("# generic_webhook ="));
        assert!(toml.contains("min_severity = 13"));
        assert!(toml.contains("timeout_secs = 10"));
    }

    #[test]
    fn test_generate_toml_without_webhook() {
        let config = ConfigValues {
            feed_endpoint: "https://pypi.org/rss/packages.xml".to_string(),
            popular_packages_endpoint: "https://example.com/popular.json".to_string(),
            poll_interval: "1m".to_string(),
            check_updates: true,
            llm_endpoint: "http://ollama:11434".to_string(),
            llm_model: "llama2".to_string(),
            llm_request_timeout: 30,
            pip_cache_dir: "/tmp/pip-cache".to_string(),
            typosquat_threshold: 2,
            min_package_length: 4,
            webhook: None,
            log_level: "debug".to_string(),
            enable_tui: false,
            heuristics_enabled: true,
            typosquat_enabled: true,
            guarddog_enabled: false,
            llm_enabled: false,
            quarantine_enabled: false,
            quarantine_dir: "/tmp/clu-quarantine".to_string(),
            quarantine_min_severity: 5,
            quarantine_max_age_days: 3,
            quarantine_max_disk_mb: 1024,
            quarantine_retain_metadata: true,
            notifications_enabled: false,
            discord_webhook: None,
            slack_webhook: None,
            generic_webhook: None,
            notifications_min_severity: 13,
            notifications_timeout_secs: 10,
        };

        let toml = generate_toml(&config);

        assert!(toml.contains("# webhook ="));
        let has_active_webhook = toml
            .lines()
            .any(|line| line.starts_with("webhook = \"") && !line.starts_with("# webhook"));
        assert!(!has_active_webhook);
        assert!(toml.contains("check_updates = true"));
        assert!(toml.contains("enable_tui = false"));
        assert!(toml.contains("typosquat = true"));
        assert!(toml.contains("guarddog = false"));
        assert!(toml.contains("llm = false"));
        assert!(toml.contains("[notifications]"));
        assert!(toml.contains("enabled = false"));
        assert!(toml.contains("# discord_webhook ="));
        assert!(toml.contains("# slack_webhook ="));
        assert!(toml.contains("# generic_webhook ="));
        assert!(toml.contains("min_severity = 13"));
        assert!(toml.contains("timeout_secs = 10"));
    }

    #[test]
    fn test_generate_toml_with_discord_notification() {
        let config = ConfigValues {
            feed_endpoint: "https://pypi.org/rss/packages.xml".to_string(),
            popular_packages_endpoint: "https://example.com/popular.json".to_string(),
            poll_interval: "30s".to_string(),
            check_updates: false,
            llm_endpoint: "http://ollama:11434".to_string(),
            llm_model: "qwen2.5-coder:7b".to_string(),
            llm_request_timeout: 30,
            pip_cache_dir: "/tmp/pip-cache".to_string(),
            typosquat_threshold: 2,
            min_package_length: 4,
            webhook: None,
            log_level: "info".to_string(),
            enable_tui: true,
            heuristics_enabled: true,
            typosquat_enabled: true,
            guarddog_enabled: false,
            llm_enabled: false,
            quarantine_enabled: true,
            quarantine_dir: "/tmp/clu-quarantine".to_string(),
            quarantine_min_severity: 5,
            quarantine_max_age_days: 3,
            quarantine_max_disk_mb: 1024,
            quarantine_retain_metadata: true,
            notifications_enabled: true,
            discord_webhook: Some("https://discord.com/api/webhooks/123456789/abcdef".to_string()),
            slack_webhook: None,
            generic_webhook: None,
            notifications_min_severity: 13,
            notifications_timeout_secs: 15,
        };

        let toml = generate_toml(&config);

        assert!(toml.contains("[notifications]"));
        assert!(toml.contains("enabled = true"));
        assert!(toml.contains("discord_webhook = \"https://discord.com/api/webhooks/123456789/abcdef\""));
        assert!(toml.contains("# slack_webhook ="));
        assert!(toml.contains("# generic_webhook ="));
        assert!(toml.contains("min_severity = 13"));
        assert!(toml.contains("timeout_secs = 15"));

        let has_active_slack = toml
            .lines()
            .any(|line| line.starts_with("slack_webhook = \"") && !line.starts_with("#"));
        let has_active_generic = toml
            .lines()
            .any(|line| line.starts_with("generic_webhook = \"") && !line.starts_with("#"));
        assert!(!has_active_slack);
        assert!(!has_active_generic);
    }
}
