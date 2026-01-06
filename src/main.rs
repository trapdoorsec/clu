use clap::{ArgMatches, Parser};
use clap::{arg, command};

use crate::analysis::heuristics;
use crate::config::Config;

// modules
mod analysis;
mod cli;
mod config;
mod feed;
mod output;
mod glitch;
mod init;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    file: String,
}

fn main() {
    print_banner();
    let cmd = command_builder().get_matches();
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

fn handle_unknown() {
    unimplemented!()
}

fn handle_scan(_: &ArgMatches) {
    let _config = Config::load("config.toml");
    let _ = heuristics::validate_heuristics_file("heuristics.toml");
    todo!("Implement scan logic")
}

fn handle_watch(args: &ArgMatches) {
    use owo_colors::OwoColorize;

    // Try to load config file
    let config = Config::load("config.toml").ok();

    // Priority: CLI args > config.toml > hardcoded defaults
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
            eprintln!("❌ Invalid poll interval '{}': {}", poll_interval_str, e);
            std::process::exit(1);
        }
    };

    // For boolean flags, check CLI first, then config
    let check_updates = if args.get_flag("check-updates") {
        true
    } else {
        config.as_ref().map(|c| c.feed.check_updates).unwrap_or(false)
    };

    // Show what configuration is being used
    if config.is_some() {
        println!("{}", ".oO( Loaded configuration from config.toml )".green());
    } else {
        println!("{}", "ℹ No config.toml found, using defaults. Run 'clu init' to create one.".yellow());
    }

    // Run the async watch function
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        if let Err(e) = watch_feed(url, poll_interval, check_updates).await {
            eprintln!("❌ Watch failed: {}", e);
            std::process::exit(1);
        }
    });
}

/// Check if a pipeline stage is enabled
fn is_stage_enabled(enabled: Option<bool>) -> bool {
    enabled.unwrap_or(true) // Default to enabled if no config
}

async fn watch_feed(
    url: &str,
    poll_interval: std::time::Duration,
    _check_updates: bool,
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
    let config = Config::load("config.toml").ok();
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

    let mut seen_packages: HashSet<String> = HashSet::new();
    let feed_url = url::Url::parse(url)?;

    loop {
        match feed::fetch_rss(&feed_url).await {
            Ok(channel) => {
                if let Some(packages) = feed::serialize_packages(channel).await {
                    let new_packages: Vec<_> = packages
                        .into_iter()
                        .filter(|p| {
                            if let Some(title) = &p.title {
                                !seen_packages.contains(title)
                            } else {
                                false
                            }
                        })
                        .collect();

                    if !new_packages.is_empty() {
                        println!(
                            "\n{} {} new package(s) found",
                            "|+|".bright_green(),
                            new_packages.len().to_string().bright_yellow().bold()
                        );

                        // Analyze packages
                        for package in &new_packages {
                            if let Some(title) = &package.title {
                                seen_packages.insert(title.clone());

                                // Run analysis
                                match analyze_package(package, &config, &heuristics).await {
                                    Ok(report) => {
                                        use output::Formatter;
                                        let formatter = output::formatters::coloured_text::ColouredTextFormatter {};
                                        let formatted = formatter.format_report(&report);
                                        println!("{}", formatted);
                                    }
                                    Err(e) => {
                                        eprintln!("{} Analysis failed for {}: {}",
                                            "[!]".red(),
                                            title.yellow(),
                                            e
                                        );
                                    }
                                }
                            }
                        }
                    } else {
                        print!(".");
                        use std::io::Write;
                        std::io::stdout().flush()?;
                    }
                }
            }
            Err(e) => {
                eprintln!("\n{} Failed to fetch feed: {}", "[!]".yellow(), e);
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

async fn analyze_package(
    package: &feed::pypi::PythonPackage,
    config: &Option<Config>,
    heuristics: &Option<analysis::heuristics::HeuristicRules>,
) -> Result<output::AnalysisReport, Box<dyn std::error::Error>> {
    use chrono::Utc;
    use owo_colors::OwoColorize;

    let package_name = package.title.as_deref().unwrap_or("unknown");
    let mut heuristic_matches = Vec::new();
    let mut typosquat_matches = Vec::new();

    // Get pipeline config if available, otherwise use defaults
    let pipeline_config = config.as_ref().map(|c| &c.pipeline);

    // Stage 1: Heuristic Analysis
    if is_stage_enabled(pipeline_config.map(|p| p.heuristics)) {
        if let Some(rules) = heuristics {
            for rule in &rules.rules {
                if let Some(heuristic_match) = analysis::heuristics::apply_rule(rule.clone(), package) {
                    heuristic_matches.push(heuristic_match);
                }
            }
        }
    }

    // Stage 2: Typosquat Detection
    if is_stage_enabled(pipeline_config.map(|p| p.typosquat)) {
        if let Some(cfg) = config {
            match analysis::typosquat::find_typosquatters(vec![package.clone()], cfg).await {
                Ok(matches) => typosquat_matches = matches,
                Err(e) => eprintln!("{} Typosquat analysis failed: {}", "[!]".yellow(), e),
            }
        }
    }

    // Calculate risk score based on Tier 1 findings
    let mut risk_score: u8 = 0;
    for h in &heuristic_matches {
        risk_score = risk_score.saturating_add(h.risk_score / 2); // Scale down
    }
    for t in &typosquat_matches {
        risk_score = risk_score.saturating_add(t.risk_score / 2);
    }
    risk_score = risk_score.min(100);

    // Stage 3: GuardDog Analysis
    // Note: GuardDog currently requires package to be installed or available locally
    // Full implementation would require package download first
    let guarddog_result = if is_stage_enabled(pipeline_config.map(|p| p.guarddog)) {
        // TODO: Implement actual GuardDog analysis
        None
    } else {
        None
    };

    // Stage 4: LLM Analysis
    // Note: LLM analysis currently requires extracted Python source code
    // Full implementation would require package download and code extraction first
    let llm_analysis = if is_stage_enabled(pipeline_config.map(|p| p.llm)) {
        // TODO: Implement actual LLM analysis
        None
    } else {
        None
    };

    // Determine recommendation based on risk score
    let (is_malicious, recommendation) = match risk_score {
        0..=30 => (false, "SAFE".to_string()),
        31..=70 => (false, "REVIEW".to_string()),
        _ => (true, "BLOCK".to_string()),
    };

    Ok(output::AnalysisReport {
        package_name: package_name.to_string(),
        package_version: None,
        timestamp: Utc::now().to_rfc3339(),
        heuristic_matches,
        typosquat_matches,
        injection_detection: None,
        llm_analysis,
        guarddog_result,
        overall_risk_score: risk_score,
        is_malicious,
        recommendation,
    })
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
            command!("scan").about("scan a single package")
                .arg(
                    arg!([PACKAGE])
                        .required(true)
                        .help("pypi package name to scan")
                ).arg(
                    arg!(-v --version)
                        .required(false)
                        .help("pypi package version. Uses latest if not specified.")))
        .subcommand(
            command!("watch").about("start watching the pypi feed").arg(
                arg!(-u --"url" <URL>)
                    .help( "Sets a different location for the package feed. Defaults to config.toml or PyPI RSS feed.", )
                    .required(false)
            ).arg(
                arg!(-p --"poll-interval" <INTERVAL>)
                    .help( "Sets a poll interval for checking the package feed. Defaults to config.toml or 30s." )
                    .required(false)
            ).arg(
                arg!(-c --"check-updates")
                    .help("Optionally check the updates feed instead of the new package feed. Defaults to config.toml.")
                    .action(clap::ArgAction::SetTrue)
                    .required(false))
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
