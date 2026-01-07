#![allow(dead_code)]

use crate::output::{AnalysisReport, Formatter};
use owo_colors::OwoColorize;

pub struct ColouredTextFormatter {}

impl Formatter for ColouredTextFormatter {
    fn format_report(&self, report: &AnalysisReport) -> String {
        let mut output = String::new();

        // Header with package info
        output.push_str(&format!(
            "\n{} {} {}\n",
            "━".repeat(60).bright_cyan(),
            "ANALYSIS REPORT".bright_cyan().bold(),
            "━".repeat(60).bright_cyan()
        ));

        output.push_str(&format!(
            "{} {}\n",
            "Package:".bright_white().bold(),
            report.package_name.bright_yellow()
        ));

        if let Some(version) = &report.package_version {
            output.push_str(&format!(
                "{} {}\n",
                "Version:".bright_white().bold(),
                version.bright_yellow()
            ));
        }

        output.push_str(&format!(
            "{} {}\n",
            "Timestamp:".bright_white().bold(),
            report.timestamp
        ));

        // Analysis methods section
        output.push_str(&format!("\n{}\n", "Analysis Methods:".bright_white().bold()));

        let heuristics_status = if !report.heuristic_matches.is_empty() {
            format!("[x] Heuristics ({} rules matched)", report.heuristic_matches.len()).green().to_string()
        } else {
            "[·] Heuristics (no matches)".dimmed().to_string()
        };
        output.push_str(&format!("  {}\n", heuristics_status));

        let typosquat_status = if !report.typosquat_matches.is_empty() {
            format!("[x] Typosquat Detection ({} matches)", report.typosquat_matches.len()).yellow().to_string()
        } else {
            "[·] Typosquat Detection (no matches)".dimmed().to_string()
        };
        output.push_str(&format!("  {}\n", typosquat_status));

        let llm_status = if report.llm_analysis.is_some() {
            "[x] LLM Analysis".green().to_string()
        } else {
            "[·] LLM Analysis (skipped)".dimmed().to_string()
        };
        output.push_str(&format!("  {}\n", llm_status));

        let guarddog_status = if report.guarddog_result.is_some() {
            "[x] GuardDog".green().to_string()
        } else {
            "[·] GuardDog (skipped)".dimmed().to_string()
        };
        output.push_str(&format!("  {}\n", guarddog_status));

        // Risk assessment with categorical levels
        let (_risk_level, risk_colored) = match report.overall_risk_score {
            0..=30 => ("LOW", format!("LOW ({})", report.overall_risk_score).green().to_string()),
            31..=60 => ("MED", format!("MED ({})", report.overall_risk_score).yellow().to_string()),
            61..=85 => ("HIGH", format!("HIGH ({})", report.overall_risk_score).red().to_string()),
            _ => ("CRIT", format!("CRIT ({})", report.overall_risk_score).magenta().bold().to_string()),
        };

        output.push_str(&format!(
            "{} {}\n",
            "Risk Level:".bright_white().bold(),
            risk_colored
        ));

        let recommendation_colored = match report.recommendation.as_str() {
            "SAFE" => report.recommendation.green().bold().to_string(),
            "REVIEW" => report.recommendation.yellow().bold().to_string(),
            "BLOCK" => report.recommendation.red().bold().to_string(),
            "CRITICAL" => report.recommendation.magenta().bold().to_string(),
            _ => report.recommendation.white().bold().to_string(),
        };

        output.push_str(&format!(
            "{} {}\n",
            "Recommendation:".bright_white().bold(),
            recommendation_colored
        ));

        // Heuristic matches
        if !report.heuristic_matches.is_empty() {
            output.push_str(&format!("\n{}\n", "Heuristic Matches:".bright_white().bold()));
            for heuristic in &report.heuristic_matches {
                output.push_str(&format!(
                    "  {} {} (risk: {})\n",
                    "•".red(),
                    heuristic.rule_name.yellow(),
                    heuristic.risk_score.to_string().bright_red()
                ));
                output.push_str(&format!("    {}\n", heuristic.description.dimmed()));
                if !heuristic.evidence.is_empty() {
                    output.push_str(&format!("    Evidence: {}\n", heuristic.evidence.dimmed()));
                }
            }
        }

        // Typosquat matches
        if !report.typosquat_matches.is_empty() {
            output.push_str(&format!("\n{}\n", "Typosquat Matches:".bright_white().bold()));
            for typo in &report.typosquat_matches {
                output.push_str(&format!(
                    "  {} Similar to: {} (confidence: {:.0}%)\n",
                    "•".red(),
                    typo.legit_package_name.yellow(),
                    typo.confidence
                ));
                if !typo.evidence.is_empty() {
                    output.push_str(&format!("    {}\n", typo.evidence.dimmed()));
                }
            }
        }

        // LLM Analysis
        if let Some(llm) = &report.llm_analysis {
            output.push_str(&format!("\n{}\n", "LLM Analysis:".bright_white().bold()));
            let verdict_str = if llm.is_malicious {
                "MALICIOUS".red().bold().to_string()
            } else {
                "CLEAN".green().bold().to_string()
            };
            output.push_str(&format!(
                "  {} {}\n",
                "Verdict:".bright_white(),
                verdict_str
            ));
            if !llm.reasoning.is_empty() {
                output.push_str(&format!("  {} {}\n", "Reasoning:".bright_white(), llm.reasoning));
            }
            output.push_str(&format!(
                "  {} {:.0}%\n",
                "Confidence:".bright_white(),
                llm.confidence
            ));
        }

        // GuardDog Results
        if let Some(guarddog) = &report.guarddog_result {
            output.push_str(&format!("\n{}\n", "GuardDog Analysis:".bright_white().bold()));
            if !guarddog.findings.is_empty() {
                for finding in &guarddog.findings {
                    output.push_str(&format!(
                        "  {} {} [{}]\n",
                        "•".red(),
                        finding.rule_name.yellow(),
                        finding.severity.bright_red()
                    ));
                    output.push_str(&format!("    {}\n", finding.description.dimmed()));
                }
            } else {
                output.push_str(&format!("  {}\n", "No findings".green()));
            }
        }

        output.push_str(&format!("{}\n", "━".repeat(140).bright_cyan()));

        output
    }
}