#![allow(dead_code)]

use crate::output::{AnalysisReport, Formatter};
use owo_colors::OwoColorize;

pub struct ColouredTextFormatter {}

impl Formatter for ColouredTextFormatter {
    fn format_report(&self, report: &AnalysisReport) -> String {
        let mut output = String::new();

        // Recommendation badge at start
        let badge = match report.recommendation.as_str() {
            "IGNORE" => "[ IGNORE ]".green().bold().to_string(),
            "INSPECT" => "[INSPECT]".yellow().bold().to_string(),
            _ => "[?????]".white().bold().to_string(),
        };

        // Severity level indicator (1-25 scale: impact * likelihood)
        let severity_indicator = match report.severity {
            1..=4 => "●".green().to_string(), // Low: NONE/LOW impact or likelihood
            5..=12 => "●".yellow().to_string(), // Medium: MEDIUM impact/likelihood
            _ => "●".red().to_string(),       // High: HIGH/CRITICAL (13-25)
        };

        // Single line header
        output.push_str(&format!(
            "\n{} {} {} (severity: {})\n",
            badge,
            report.package_name.bright_cyan().bold(),
            severity_indicator,
            report.severity
        ));

        // Only show findings if there are any
        let mut findings_count = 0;

        // Heuristic matches - compact
        if !report.heuristic_matches.is_empty() {
            for heuristic in &report.heuristic_matches {
                findings_count += 1;
                output.push_str(&format!(
                    "  {} {} - {}\n",
                    "⚠".yellow(),
                    heuristic.rule_name.bright_white(),
                    heuristic.description.dimmed()
                ));
            }
        }

        // Typosquat matches - compact
        if !report.typosquat_matches.is_empty() {
            for typo in &report.typosquat_matches {
                findings_count += 1;
                output.push_str(&format!(
                    "  {} Typosquat of '{}' ({})\n",
                    "⚠".yellow(),
                    typo.legit_package_name.bright_white(),
                    typo.evidence.dimmed()
                ));
            }
        }

        // GuardDog - compact
        if let Some(guarddog) = &report.guarddog_result {
            if !guarddog.findings.is_empty() {
                for finding in &guarddog.findings {
                    findings_count += 1;
                    let severity_icon = match finding.severity.to_lowercase().as_str() {
                        "critical" => "🔴",
                        "high" => "🟠",
                        "medium" => "🟡",
                        _ => "⚠",
                    };
                    output.push_str(&format!(
                        "  {} {} - {}\n",
                        severity_icon,
                        finding.rule_name.bright_white(),
                        finding.description.dimmed()
                    ));
                }
            }
        }

        // LLM - compact
        if let Some(llm) = &report.llm_analysis {
            if llm.is_malicious {
                findings_count += 1;
                output.push_str(&format!(
                    "  {} LLM flagged as malicious: {}\n",
                    "🤖".yellow(),
                    llm.reasoning.dimmed()
                ));
            }
        }

        // If no findings, say so
        if findings_count == 0 {
            output.push_str(&format!("  {}\n", "No issues detected".green()));
        }

        output
    }
}
