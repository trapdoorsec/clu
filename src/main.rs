//! This file contains the main entry point for the application.
//! It initializes the logging system and handles the command-line arguments.

use clap::ArgMatches;
use clap::{arg, command};

use crate::analysis::heuristics;
use crate::config::Config;
use crate::feed::ecosystem::{Ecosystem, PackageRef, PyPIRegistry};
use crate::feed::ecosystem::NpmRegistry;

// modules
mod analysis;
mod cli;
mod config;
mod db;
mod feed;
mod glitch;
mod init;
mod output;

/// Main entry point for the CLU (Command Line Utility) malware scanner.
///
/// This function orchestrates the application startup sequence:
/// 1. Displays the ASCII art banner with some fun character animations
/// 2. Parses command-line arguments using clap
/// 3. Initializes the logging system based on config.toml settings
/// 4. Routes to the appropriate command handler (init, watch, or scan)
///
/// # Subcommands
/// - `init`: Interactive configuration setup (creates config.toml)
/// - `watch`: Continuously monitor PyPI RSS feed for new packages
/// - `scan`: Analyze a specific package
///
/// If no subcommand is provided, only the banner is shown and the program exits.
fn main() {
    print_banner();
    let cmd = command_builder().get_matches();

    // Initialize logging based on config
    initialize_logging();

    if cmd.subcommand().is_none() {
        // No subcommand provided, just show the banner
        return;
    }
    match cmd.subcommand() {
        Some(("init", primary_command)) => handle_init(primary_command),
        Some(("watch", primary_command)) => handle_watch(primary_command),
        Some(("scan", primary_command)) => handle_scan(primary_command),
        Some(_) => handle_unknown(),
        None => todo!(),
    }
}

/// Initialize logging based on config.toml log_level setting
fn initialize_logging() {
    use log::LevelFilter;

    // Try to load config to get log level
    let log_level = if let Ok(config) = Config::load("config.toml") {
        match config.output.log_level.to_lowercase().as_str() {
            "debug" => LevelFilter::Debug,
            "info" => LevelFilter::Info,
            "warn" => LevelFilter::Warn,
            "error" => LevelFilter::Error,
            _ => LevelFilter::Info,
        }
    } else {
        // Default to Info if config not available
        LevelFilter::Info
    };

    // Build logger with custom format
    env_logger::Builder::from_default_env()
        .filter_level(log_level)
        .format(|buf, record| {
            use std::io::Write;
            writeln!(buf, "[{}] {}", record.level(), record.args())
        })
        .init();
}

fn handle_unknown() {
    unimplemented!()
}

fn handle_scan(args: &ArgMatches) {
    let package_name = match args.get_one::<String>("PACKAGE") {
        Some(name) => name.clone(),
        None => {
            eprintln!("Error: PACKAGE argument is required");
            std::process::exit(1);
        }
    };
    let version = args.get_one::<String>("pkg-version").cloned();
    let format_str = args.get_one::<String>("format").map(|s| s.as_str()).unwrap_or("auto");

    let config = Config::load("config.toml").ok();
    let heuristics = match heuristics::HeuristicRules::load("heuristics.toml") {
        Ok(h) => Some(h),
        Err(e) => {
            log::warn!("Failed to load heuristics: {}", e);
            None
        }
    };

    let package = PackageRef {
        ecosystem: Ecosystem::PyPI,
        name: package_name.clone(),
        version: version.clone(),
        title: Some(package_name.clone()),
        description: None,
        link: None,
        author: None,
        published_date: None,
    };

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let database = if let Some(ref cfg) = config {
            if cfg.database.enable {
                match db::Database::new(&cfg.database.url).await {
                    Ok(db) => Some(db),
                    Err(e) => {
                        eprintln!("Failed to initialize database: {}", e);
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        match analyze_package(&package, config.as_ref(), &heuristics, &database).await {
            Ok(report) => {
                let formatter = get_formatter(format_str);
                let formatted = formatter.format_report(&report);
                println!("{}", formatted);

                persist_and_notify(&report, database.as_ref(), config.as_ref()).await;

                if report.is_malicious {
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("Analysis failed: {}", e);
                std::process::exit(1);
            }
        }
    });
}

fn handle_watch(args: &ArgMatches) {
    use owo_colors::OwoColorize;

    let format_str = args.get_one::<String>("format").map(|s| s.as_str()).unwrap_or("auto");

    let config = Config::load("config.toml").ok();

    if let Some(ref cfg) = config {
        unsafe {
            std::env::set_var("PIP_CACHE_DIR", &cfg.cache.pip_cache_dir);
        }
        log::debug!("Set PIP_CACHE_DIR={}", cfg.cache.pip_cache_dir);
    }

    let url = args
        .get_one::<String>("url")
        .map(|s| s.as_str())
        .or_else(|| config.as_ref().map(|c| c.feed.endpoint.as_str()))
        .unwrap_or("https://pypi.org/rss/packages.xml");

    let poll_interval_str = args
        .get_one::<String>("poll-interval")
        .map(|s| s.as_str())
        .or_else(|| config.as_ref().map(|c| c.feed.poll_interval.as_str()))
        .unwrap_or("30s");

    let poll_interval = match parse_duration(poll_interval_str) {
        Ok(duration) => duration,
        Err(e) => {
            eprintln!("Invalid poll interval '{}': {}", poll_interval_str, e);
            std::process::exit(1);
        }
    };

    let check_updates = if args.get_flag("check-updates") {
        true
    } else {
        config
            .as_ref()
            .map(|c| c.feed.check_updates)
            .unwrap_or(false)
    };

    if config.is_some() {
        println!("{}", ".oO( Loaded configuration from config.toml )".green());
    } else {
        println!(
            "{}",
            "No config.toml found, using defaults. Run 'clu init' to create one.".yellow()
        );
    }

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        if let Err(e) = watch_feed(url, poll_interval, check_updates, config.as_ref(), format_str).await {
            eprintln!("Watch failed: {}", e);
            std::process::exit(1);
        }
    });
}

/// Check if a pipeline stage is enabled
fn is_stage_enabled(enabled: Option<bool>) -> bool {
    enabled.unwrap_or(true)
}

fn get_formatter(format_str: &str) -> Box<dyn output::Formatter> {
    match format_str {
        "json" => Box::new(output::formatters::json::JsonFormatter),
        "text" => Box::new(output::formatters::text::TextFormatter {}),
        "color" => Box::new(output::formatters::coloured_text::ColouredTextFormatter {}),
        "auto" => {
            if std::io::IsTerminal::is_terminal(&std::io::stdout()) {
                Box::new(output::formatters::coloured_text::ColouredTextFormatter {})
            } else {
                Box::new(output::formatters::text::TextFormatter {})
            }
        }
        _ => Box::new(output::formatters::coloured_text::ColouredTextFormatter {}),
    }
}

async fn persist_and_notify(
    report: &output::AnalysisReport,
    database: Option<&db::Database>,
    config: Option<&Config>,
) {
    if let Some(db) = database {
        let package_name = report.package_name.as_str();
        match db.insert_report(report).await {
            Ok(id) => {
                log::debug!("Saved report to database with ID: {}", id);
                let _ = db
                    .update_package_status(package_name, db::PackageStatus::Completed, None)
                    .await;

                if let Some(cfg) = config {
                    let report_clone = report.clone();
                    let sidecar_cfg = cfg.sidecar.clone();
                    tokio::spawn(async move {
                        output::webhook::post_finding_to_sidecar(
                            &report_clone,
                            Some(id),
                            &sidecar_cfg,
                        )
                        .await;
                    });
                }
            }
            Err(e) => {
                log::warn!("Failed to save report to database: {}", e);
            }
        }
    }

    if let Some(cfg) = config
        && cfg.notifications.enabled
    {
        let report_clone = report.clone();
        let notif_cfg = cfg.notifications.clone();
        tokio::spawn(async move {
            output::notify::notify_finding(&report_clone, &notif_cfg).await;
        });
    }
}

async fn watch_feed(
    url: &str,
    poll_interval: std::time::Duration,
    _check_updates: bool,
    config_opt: Option<&Config>,
    format_str: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use owo_colors::OwoColorize;
    use std::collections::HashSet;

    println!("{}", ".:* Starting feed watcher...".bright_cyan().bold());
    println!("{} {}", "Feed URL:".bright_white(), url.yellow());
    println!(
        "{} {:?}",
        "Poll Interval:".bright_white(),
        poll_interval.bright_yellow()
    );
    println!("{}", "━".repeat(60).bright_cyan());

    // Load configuration and heuristics
    let loaded_config = if config_opt.is_none() {
        Config::load("config.toml").ok()
    } else {
        None
    };
    let config = config_opt.or(loaded_config.as_ref());
    let heuristics = match analysis::heuristics::HeuristicRules::load("heuristics.toml") {
        Ok(h) => {
            println!("{}", ".:* Loaded heuristics rules".green());
            Some(h)
        }
        Err(e) => {
            eprintln!("{} Failed to load heuristics: {}", "[!]".yellow(), e);
            None
        }
    };

    // Initialize database if enabled
    let database = if let Some(cfg) = &config {
        if cfg.database.enable {
            match db::Database::new(&cfg.database.url).await {
                Ok(db) => {
                    println!("{}", ".:* Database initialized".green());
                    Some(db)
                }
                Err(e) => {
                    eprintln!("{} Failed to initialize database: {}", "[!]".yellow(), e);
                    eprintln!("{} Continuing without database persistence", "[!]".yellow());
                    None
                }
            }
        } else {
            println!("{}", ".:* Database disabled in config".yellow());
            None
        }
    } else {
        None
    };

    // Send startup health-check notification
    if let Some(cfg) = &config {
        output::notify::notify_startup(&cfg.notifications).await;
    }

    let mut seen_packages: HashSet<(Ecosystem, String)> = HashSet::new();

    loop {
        let mut all_new_packages: Vec<PackageRef> = Vec::new();

        let pypi_enabled = config.map(|c| c.ecosystems.pypi_enabled).unwrap_or(true);
        let npm_enabled = config.map(|c| c.ecosystems.npm_enabled).unwrap_or(false);

        if pypi_enabled {
            let pypi_registry = PyPIRegistry::new(
                url,
                config
                    .map(|c| c.feed.popular_packages_endpoint.as_str())
                    .unwrap_or("https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.json"),
            );
            match pypi_registry.fetch_feed().await {
                Ok(packages) => {
                    let new_pkgs: Vec<_> = packages
                        .into_iter()
                        .filter(|p| {
                            let key = (p.ecosystem, p.name.clone());
                            !seen_packages.contains(&key)
                        })
                        .collect();

                    if new_pkgs.is_empty() {
                        print!(".");
                        use std::io::Write;
                        std::io::stdout().flush()?;
                    } else {
                        for p in &new_pkgs {
                            seen_packages.insert((p.ecosystem, p.name.clone()));
                        }
                        all_new_packages.extend(new_pkgs);
                    }
                }
                Err(e) => {
                    eprintln!("\n{} PyPI feed error: {}", "[!]".yellow(), e);
                }
            }
        }

        if npm_enabled {
            let npm_registry = NpmRegistry::default();
            match npm_registry.fetch_feed().await {
                Ok(packages) => {
                    let new_pkgs: Vec<_> = packages
                        .into_iter()
                        .filter(|p| {
                            let key = (p.ecosystem, p.name.clone());
                            !seen_packages.contains(&key)
                        })
                        .collect();

                    if !new_pkgs.is_empty() {
                        for p in &new_pkgs {
                            seen_packages.insert((p.ecosystem, p.name.clone()));
                        }
                        all_new_packages.extend(new_pkgs);
                    }
                }
                Err(e) => {
                    eprintln!("\n{} npm feed error: {}", "[!]".yellow(), e);
                }
            }
        }

        if !all_new_packages.is_empty() {
            println!(
                "\n{} {} new package(s) found",
                "|+|".bright_green(),
                all_new_packages.len().to_string().bright_yellow().bold()
            );

            for package in &all_new_packages {
                let pkg_name = package.title.as_deref().unwrap_or(&package.name);

                if let Some(ref db) = database {
                    let _ = db
                        .update_package_status(pkg_name, db::PackageStatus::Queued, None)
                        .await;
                }

                match analyze_package(package, config, &heuristics, &database).await {
                    Ok(report) => {
                        let formatter = get_formatter(format_str);
                        let formatted = formatter.format_report(&report);
                        println!("{}", formatted);

                        persist_and_notify(&report, database.as_ref(), config).await;
                    }
                    Err(e) => {
                        eprintln!(
                            "{} Analysis failed for {}: {}",
                            "[!]".red(),
                            pkg_name.yellow(),
                            e
                        );

                        if let Some(ref db) = database {
                            let _ = db
                                .update_package_status(
                                    pkg_name,
                                    db::PackageStatus::Failed,
                                    Some(&e.to_string()),
                                )
                                .await;
                        }
                    }
                }
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

async fn analyze_package(
    package: &PackageRef,
    config: Option<&Config>,
    heuristics: &Option<analysis::heuristics::HeuristicRules>,
    database: &Option<db::Database>,
) -> Result<output::AnalysisReport, Box<dyn std::error::Error>> {
    use chrono::Utc;

    let package_name = package.title.as_deref().unwrap_or("unknown");
    let pipeline_config = config.map(|c| &c.pipeline);

    // Update status: starting heuristics
    if let Some(db) = database {
        let _ = db
            .update_package_status(package_name, db::PackageStatus::Heuristics, None)
            .await;
    }

    // Run Stages 1 & 2 concurrently (these are always fast)
    let (heuristic_matches, typosquat_matches) = tokio::join!(
        run_heuristics_stage(package, heuristics, pipeline_config),
        run_typosquat_stage(package, config, pipeline_config)
    );

    // Update status: typosquat completed
    if let Some(db) = database {
        let _ = db
            .update_package_status(package_name, db::PackageStatus::Typosquat, None)
            .await;
    }

    // Determine if we need to download package for GuardDog and LLM
    let guarddog_enabled = is_stage_enabled(pipeline_config.map(|p| p.guarddog));
    let llm_enabled = is_stage_enabled(pipeline_config.map(|p| p.llm));

    // Try to download package, but don't let failure skip stages
    let package_result = if guarddog_enabled || llm_enabled {
        Some(analysis::package::download_and_extract_package(package_name, None).await)
    } else {
        None
    };

    // Run GuardDog stage
    if guarddog_enabled
        && let Some(db) = database
    {
        let _ = db
            .update_package_status(package_name, db::PackageStatus::GuardDog, None)
            .await;
    }

    let guarddog_result = run_guarddog_stage(package_name, &package_result, guarddog_enabled).await;

    // Run LLM stage last - it aggregates all findings
    let llm_analysis = if llm_enabled {
        if let Some(db) = database {
            let _ = db
                .update_package_status(package_name, db::PackageStatus::Llm, None)
                .await;
        }
        run_llm_stage(
            package_name,
            config,
            &package_result,
            &heuristic_matches,
            &typosquat_matches,
            &guarddog_result,
            llm_enabled,
        )
        .await
    } else {
        None
    };

    // Compute static floor from non-manipulable tiers (heuristics + typosquat + GuardDog).
    // The LLM can escalate but NEVER de-escalate below this floor, because an LLM
    // evaluating attacker-controlled text is inherently injectable.
    let static_finding_count = heuristic_matches.len()
        + typosquat_matches.len()
        + guarddog_result
            .as_ref()
            .map(|g| g.findings.len())
            .unwrap_or(0);

    let static_severity = if static_finding_count == 0 {
        1 // NONE * NONE
    } else if static_finding_count <= 2 {
        6 // MEDIUM * UNLIKELY
    } else {
        12 // HIGH * LIKELY
    };
    let static_is_malicious = static_finding_count > 3;

    // Merge: LLM can escalate but never de-escalate below the static floor.
    // is_malicious = OR of LLM and static (either flag is definitive).
    // severity = MAX of LLM and static (worst case wins).
    let (severity, is_malicious) = if let Some(ref llm) = llm_analysis {
        let merged_severity = llm.severity.max(static_severity);
        let merged_is_malicious = llm.is_malicious || static_is_malicious;
        (merged_severity, merged_is_malicious)
    } else {
        (static_severity, static_is_malicious)
    };

    let recommendation = if severity <= 4 { "IGNORE" } else { "INSPECT" }.to_string();

    Ok(output::AnalysisReport {
        package_name: package_name.to_string(),
        package_version: None,
        timestamp: Utc::now().to_rfc3339(),
        ecosystem: package.ecosystem,
        sha256: package_result
            .as_ref()
            .map(|r| r.as_ref().map(|c| c.sha256.clone()).unwrap_or_default())
            .unwrap_or_default(),
        heuristic_matches,
        typosquat_matches,
        guarddog_result,
        injection_detection: None,
        llm_analysis,
        severity,
        is_malicious,
        recommendation,
    })
}

/// Stage 1: Heuristic Analysis
async fn run_heuristics_stage(
    package: &PackageRef,
    heuristics: &Option<analysis::heuristics::HeuristicRules>,
    pipeline_config: Option<&config::PipelineConfig>,
) -> Vec<output::HeuristicMatch> {
    if !is_stage_enabled(pipeline_config.map(|p| p.heuristics)) {
        return Vec::new();
    }

    let pkg_name = package.title.as_deref().unwrap_or("unknown");
    log::debug!("Stage 1: Starting heuristics analysis for {}", pkg_name);

    let mut matches = Vec::new();
    if let Some(rules) = heuristics {
        for rule in &rules.rules {
            if let Some(heuristic_match) = analysis::heuristics::apply_rule(rule.clone(), package) {
                matches.push(heuristic_match);
            }
        }
    }

    log::debug!(
        "Stage 1: Heuristics analysis completed for {} ({} matches)",
        pkg_name,
        matches.len()
    );
    matches
}

/// Stage 2: Typosquat Detection
async fn run_typosquat_stage(
    package: &PackageRef,
    config: Option<&Config>,
    pipeline_config: Option<&config::PipelineConfig>,
) -> Vec<output::TypoSquatterMatch> {
    use owo_colors::OwoColorize;

    if !is_stage_enabled(pipeline_config.map(|p| p.typosquat)) {
        return Vec::new();
    }

    let pkg_name = package.title.as_deref().unwrap_or("unknown");
    log::debug!("Stage 2: Starting typosquat analysis for {}", pkg_name);

    if let Some(cfg) = config {
        match analysis::typosquat::find_typosquatters(std::slice::from_ref(package), cfg).await {
            Ok(matches) => {
                log::debug!(
                    "Stage 2: Typosquat analysis completed for {} ({} matches)",
                    pkg_name,
                    matches.len()
                );
                matches
            }
            Err(e) => {
                eprintln!(
                    "{} Stage 2: Typosquat analysis failed for {}: {}",
                    "[!]".yellow(),
                    pkg_name.yellow(),
                    e
                );
                Vec::new()
            }
        }
    } else {
        eprintln!(
            "{} Stage 2: Config not found, skipping typosquat analysis",
            "[!]".yellow()
        );
        Vec::new()
    }
}

/// Stage 3: GuardDog Analysis
async fn run_guarddog_stage(
    package_name: &str,
    _package_result: &Option<
        Result<analysis::package::PackageContents, Box<dyn std::error::Error>>,
    >,
    enabled: bool,
) -> Option<output::GuardDogResult> {
    use owo_colors::OwoColorize;

    if !enabled {
        return None;
    }

    log::debug!("Stage 3: Starting GuardDog analysis for {}", package_name);
    match analysis::guarddog::analyze_with_guarddog(package_name, None).await {
        Ok(result) => {
            log::debug!("Stage 3: GuardDog analysis completed for {}", package_name);
            Some(result)
        }
        Err(e) => {
            eprintln!(
                "{} Stage 3: GuardDog analysis failed for {}: {}",
                "[!]".yellow(),
                package_name.yellow(),
                e
            );
            None
        }
    }
}

/// Stage 4: LLM Analysis with Prompt Injection Detection (Aggregates all findings)
async fn run_llm_stage(
    package_name: &str,
    config: Option<&Config>,
    package_result: &Option<Result<analysis::package::PackageContents, Box<dyn std::error::Error>>>,
    heuristic_matches: &[output::HeuristicMatch],
    typosquat_matches: &[output::TypoSquatterMatch],
    guarddog_result: &Option<output::GuardDogResult>,
    enabled: bool,
) -> Option<output::LlmAnalysisResult> {
    use owo_colors::OwoColorize;

    if !enabled {
        return None;
    }

    log::debug!("Stage 4: Starting LLM analysis for {}", package_name);

    if let Some(cfg) = config.map(|c| &c.llm) {
        // Check if package download succeeded
        let package_contents = match package_result {
            Some(Ok(contents)) => contents,
            Some(Err(e)) => {
                eprintln!(
                    "{} Stage 4: Package download failed, cannot run LLM analysis: {}",
                    "[!]".yellow(),
                    e
                );
                return None;
            }
            None => {
                eprintln!(
                    "{} Stage 4: Package download was not attempted, cannot run LLM analysis",
                    "[!]".yellow()
                );
                return None;
            }
        };

        // Extract source code for analysis (in-memory, never writes to disk)
        let bundle = analysis::package::build_source_bundle(package_contents, 15000);
        let source_code = analysis::package::format_source_bundle(&bundle);

        // Aggregate findings for LLM assessment
        let heuristic_findings: Vec<String> = heuristic_matches
            .iter()
            .map(|h| format!("{}: {}", h.rule_name, h.description))
            .collect();

        let typosquat_findings: Vec<String> = typosquat_matches
            .iter()
            .map(|t| t.evidence.clone())
            .collect();

        let guarddog_findings: Vec<String> = guarddog_result
            .as_ref()
            .map(|g| {
                g.findings
                    .iter()
                    .map(|f| format!("{} [{}]: {}", f.rule_name, f.severity, f.description))
                    .collect()
            })
            .unwrap_or_default();

        // Build the single attacker-influenced body that both the sentinel
        // and the main analysis will receive. This eliminates the window-gap
        // injection vulnerability where sentinel and analysis saw different
        // truncations of the same data.
        let body = analysis::llm::build_prompt_body(
            package_name,
            &source_code,
            &heuristic_findings,
            &typosquat_findings,
            &guarddog_findings,
        );

        // Check for prompt injection first (sentinel checks the SAME body)
        match analysis::llm::detect_prompt_injection(&body, cfg).await {
            Ok(injection_result) => {
                if injection_result.injection_detected {
                    eprintln!(
                        "{} Prompt injection detected in {}",
                        "[!]".red(),
                        package_name.yellow()
                    );
                    return None;
                }

                // Safe to proceed with analysis (same body passed to main analysis)
                match analysis::llm::analyze_package_code(&body, cfg).await {
                    Ok(result) => {
                        log::debug!("Stage 4: LLM analysis completed for {}", package_name);
                        Some(result)
                    }
                    Err(e) => {
                        eprintln!(
                            "{} Stage 4: LLM analysis failed for {}: {}",
                            "[!]".yellow(),
                            package_name.yellow(),
                            e
                        );
                        None
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "{} Stage 4: Injection detection failed for {}: {}",
                    "[!]".yellow(),
                    package_name.yellow(),
                    e
                );
                None
            }
        }
    } else {
        eprintln!("{} LLM config not found, skipping Stage 4", "[!]".yellow());
        None
    }
}

fn parse_duration(s: &str) -> Result<std::time::Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("Empty duration string".to_string());
    }

    // Find where the number ends and unit begins
    let mut num_end = 0;
    for (i, ch) in s.chars().enumerate() {
        if ch.is_ascii_digit() {
            num_end = i + 1;
        } else {
            break;
        }
    }

    if num_end == 0 {
        return Err(format!("No number found in '{}'", s));
    }

    let num_str = &s[..num_end];
    let unit = &s[num_end..];

    let num: u64 = num_str
        .parse()
        .map_err(|_| format!("Invalid number: '{}'", num_str))?;

    let duration = match unit {
        "s" | "sec" | "second" | "seconds" => std::time::Duration::from_secs(num),
        "m" | "min" | "minute" | "minutes" => std::time::Duration::from_secs(num * 60),
        "h" | "hour" | "hours" => std::time::Duration::from_secs(num * 3600),
        "" => std::time::Duration::from_secs(num), // Default to seconds
        _ => return Err(format!("Unknown unit: '{}'. Use s, m, or h", unit)),
    };

    Ok(duration)
}

fn handle_init(args: &ArgMatches) {
    let config_path = args
        .get_one::<String>("path")
        .map(|s| s.as_str())
        .unwrap_or("config.toml");

    // Run the async init function
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        match init::run_init(config_path).await {
            Ok(_) => {}
            Err(e) => {
                eprintln!("❌ Configuration setup failed: {}", e);
                std::process::exit(1);
            }
        }
    });
}
fn print_banner() {
    let banner = r#"

    +===================================+\
    |                                   | |
    |    .|'''', '||     '||   ||`      | |
    |    ||       ||      ||   ||       | |
    |    ||       ||      ||   ||       | |
    |    ||       ||      ||   ||       | |
    |    `|....' .||...|  `|...|'       | |
    |                                   | |
    +==================================+| |
    \____________________________________\|

      Find malicious python packages fast
         💕 with love from akses 💕
              version 0.1-alpha

              Features;-
              - heuristic analysis
              - guarddog rules
              - LLM code analysis
    "#;

    // Use teal color if terminal supports it, with glitch animation
    // Check if we're in a TTY (not piped/redirected)
    let use_color = std::io::IsTerminal::is_terminal(&std::io::stdout());
    glitch::matrix_glitch(banner, 33, use_color);
}

fn command_builder() -> clap::Command {
    clap::Command::new("clu")
        .version(env!("CARGO_PKG_VERSION"))
        .bin_name("clu")
        .styles(CLAP_STYLING)
        .subcommand_required(false)
        .subcommand(
            command!("init")
                .about("Initialize CLU configuration with interactive setup")
                .arg(
                    arg!(-p --path <PATH>)
                        .default_value("config.toml")
                        .help("Path where the configuration file will be saved")
                        .required(false)
                )
        )
        .subcommand(
            command!("scan").about("Scan a single package for malicious indicators")
                .arg(
                    arg!([PACKAGE])
                        .required(true)
                        .help("PyPI package name to scan")
                ).arg(
                    arg!(-V --"pkg-version" <VERSION>)
                        .required(false)
                        .help("Package version (defaults to latest)")
                ).arg(
                    arg!(-f --format <FORMAT>)
                        .default_value("auto")
                        .required(false)
                        .help("Output format: auto, color, text, json")
                )
        )
        .subcommand(
            command!("watch").about("Start watching the package feed for new releases")
                .arg(
                    arg!(-u --"url" <URL>)
                        .help("Sets a different location for the package feed. Defaults to config.toml or PyPI RSS feed.")
                        .required(false)
                ).arg(
                    arg!(-p --"poll-interval" <INTERVAL>)
                        .help("Sets a poll interval for checking the package feed. Defaults to config.toml or 30s.")
                        .required(false)
                ).arg(
                    arg!(-c --"check-updates")
                        .help("Optionally check the updates feed instead of the new package feed.")
                        .action(clap::ArgAction::SetTrue)
                        .required(false)
                ).arg(
                    arg!(-f --format <FORMAT>)
                        .default_value("auto")
                        .required(false)
                        .help("Output format: auto, color, text, json")
                )
        )
}
pub const CLAP_STYLING: clap::builder::styling::Styles = clap::builder::styling::Styles::styled()
    .header(clap_cargo::style::HEADER)
    .usage(clap_cargo::style::USAGE)
    .literal(clap_cargo::style::LITERAL)
    .placeholder(clap_cargo::style::PLACEHOLDER)
    .error(clap_cargo::style::ERROR)
    .valid(clap_cargo::style::VALID)
    .invalid(clap_cargo::style::INVALID);
