use crate::output::{AnalysisReport, Formatter};

pub struct TextFormatter {}

impl Formatter for TextFormatter {
    fn format_report(&self, report: &AnalysisReport) -> String {
        let mut output = String::new();

        let severity_label = match report.severity {
            1..=4 => "LOW",
            5..=12 => "MEDIUM",
            13..=20 => "HIGH",
            _ => "CRITICAL",
        };

        output.push_str(&format!(
            "\n[{}] {} {} (severity: {}/{}):\n",
            report.recommendation,
            report.package_name,
            report
                .package_version
                .as_deref()
                .unwrap_or(""),
            severity_label,
            report.severity,
        ));

        let mut findings_count = 0;

        if !report.heuristic_matches.is_empty() {
            for heuristic in &report.heuristic_matches {
                findings_count += 1;
                output.push_str(&format!(
                    "  HEURISTIC: {} - {}\n",
                    heuristic.rule_name, heuristic.description
                ));
            }
        }

        if !report.typosquat_matches.is_empty() {
            for typo in &report.typosquat_matches {
                findings_count += 1;
                output.push_str(&format!(
                    "  TYPOSQUAT: {}\n",
                    typo.evidence
                ));
            }
        }

        if let Some(guarddog) = &report.guarddog_result
            && !guarddog.findings.is_empty()
        {
            for finding in &guarddog.findings {
                findings_count += 1;
                output.push_str(&format!(
                    "  GUARDDOG: {} [{}] - {}\n",
                    finding.rule_name, finding.severity, finding.description
                ));
            }
        }

        if let Some(llm) = &report.llm_analysis
            && llm.is_malicious
        {
            findings_count += 1;
            output.push_str(&format!(
                "  LLM: MALICIOUS - {}\n",
                llm.reasoning
            ));
        }

        if findings_count == 0 {
            output.push_str("  No issues detected\n");
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::heuristics::HeuristicMatch;
    use crate::analysis::typosquat::TypoSquatterMatch;
    use crate::feed::ecosystem::Ecosystem;

    fn make_report(overrides: Option<AnalysisReport>) -> AnalysisReport {
        let base = AnalysisReport {
            package_name: "test-pkg".to_string(),
            package_version: Some("1.0.0".to_string()),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            ecosystem: Ecosystem::PyPI,
            sha256: "abc123".to_string(),
            heuristic_matches: vec![],
            typosquat_matches: vec![],
            guarddog_result: None,
            injection_detection: None,
            llm_analysis: None,
            severity: 5,
            is_malicious: false,
            recommendation: "IGNORE".to_string(),
        };
        if let Some(o) = overrides {
            o
        } else {
            base
        }
    }

    #[test]
    fn test_text_formatter_no_findings() {
        let report = make_report(None);
        let formatter = TextFormatter {};
        let output = formatter.format_report(&report);
        assert!(output.contains("IGNORE"));
        assert!(output.contains("test-pkg"));
        assert!(output.contains("No issues detected"));
    }

    #[test]
    fn test_text_formatter_with_heuristics() {
        let report = AnalysisReport {
            heuristic_matches: vec![HeuristicMatch {
                rule_name: "suspicious_author".to_string(),
                risk_score: 50,
                evidence: "author=test".to_string(),
                description: "Suspicious author name".to_string(),
                location: "author".to_string(),
            }],
            ..make_report(None)
        };
        let formatter = TextFormatter {};
        let output = formatter.format_report(&report);
        assert!(output.contains("HEURISTIC: suspicious_author"));
    }

    #[test]
    fn test_text_formatter_with_typosquat() {
        let report = AnalysisReport {
            typosquat_matches: vec![TypoSquatterMatch {
                rule_name: "typosquat".to_string(),
                risk_score: 75,
                confidence: 0.9,
                evidence: "likely typosquat of requests".to_string(),
                legit_package_name: "requests".to_string(),
            }],
            ..make_report(None)
        };
        let formatter = TextFormatter {};
        let output = formatter.format_report(&report);
        assert!(output.contains("TYPOSQUAT"));
    }

    #[test]
    fn test_text_formatter_severity_labels() {
        let low = TextFormatter {}.format_report(&AnalysisReport {
            severity: 3,
            ..make_report(None)
        });
        assert!(low.contains("LOW"));

        let high = TextFormatter {}.format_report(&AnalysisReport {
            severity: 18,
            ..make_report(None)
        });
        assert!(high.contains("HIGH"));
    }
}