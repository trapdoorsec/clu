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

fn handle_watch(_: &ArgMatches) {
    todo!()
}
fn print_banner() {
    let banner = r#"

        .|'''', '||     '||   ||`
        ||       ||      ||   ||
        ||       ||      ||   ||
        ||       ||      ||   ||
        `|....' .||...|  `|...|'

    CLU - Find malicious python packages fast
    💕 with love from akses 💕
    version 0.1-alpha
    "#;
    println!("{}", banner)
}

fn command_builder() -> clap::Command {
    clap::Command::new("clu")
        .version(env!("CARGO_PKG_VERSION"))
        .bin_name("clu")
        .styles(CLAP_STYLING)
        .subcommand_required(false)
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
                arg!(-u --"url")
                    .default_value("https://pypi.org/rss/packages.xml")
                    .help( "Sets a different location for the package feed. Assumes you know what you're doing with that. default is the pypi feed.", )
                    .required(false)
            ).arg(
                arg!(-p --poll-interval)
                    .default_value("30s")
                    .help( "Sets a poll interval for checking the package feed." )
                    .required(false)
            ).arg(
                arg!(-u --check-updates)
                    .help("Optionally check the updates feed instead of the new package feed")
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
