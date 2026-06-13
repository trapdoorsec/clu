use crate::config::NotificationsConfig;
use crate::output::AnalysisReport;

pub async fn notify_finding(report: &AnalysisReport, cfg: &NotificationsConfig) {
    if !cfg.enabled {
        return;
    }
    if report.severity < cfg.min_severity {
        log::debug!(
            "notification skipped: severity {} below threshold {}",
            report.severity,
            cfg.min_severity
        );
        return;
    }

    let message = format_notification(report);

    if let Some(ref url) = cfg.slack_webhook {
        send_slack(url, &message, cfg).await;
    }
    if let Some(ref url) = cfg.discord_webhook {
        send_discord(url, &message, cfg).await;
    }
    if let Some(ref url) = cfg.generic_webhook {
        send_generic(url, &message, report, cfg).await;
    }
}

fn format_notification(report: &AnalysisReport) -> String {
    let severity_label = match report.severity {
        1..=4 => "LOW",
        5..=12 => "MEDIUM",
        13..=20 => "HIGH",
        _ => "CRITICAL",
    };

    let mut lines = Vec::new();
    lines.push(format!(
        "[CLU] {} — {} {} (severity: {}/{})",
        report.recommendation,
        report.package_name,
        report
            .package_version
            .as_deref()
            .unwrap_or("unknown"),
        severity_label,
        report.severity,
    ));

    if !report.heuristic_matches.is_empty() {
        for h in &report.heuristic_matches {
            lines.push(format!("  heuristic: {} — {}", h.rule_name, h.description));
        }
    }
    if !report.typosquat_matches.is_empty() {
        for t in &report.typosquat_matches {
            lines.push(format!("  typosquat: {}", t.evidence));
        }
    }
    if let Some(ref gd) = report.guarddog_result {
        for f in &gd.findings {
            lines.push(format!("  guarddog: {} [{}] — {}", f.rule_name, f.severity, f.description));
        }
    }
    if let Some(ref llm) = report.llm_analysis
        && llm.is_malicious
    {
        lines.push(format!("  llm: MALICIOUS — {}", llm.reasoning));
    }

    lines.join("\n")
}

async fn send_slack(url: &str, message: &str, cfg: &NotificationsConfig) {
    let payload = serde_json::json!({ "text": message });
    match reqwest::Client::new()
        .post(url)
        .timeout(std::time::Duration::from_secs(cfg.timeout_secs))
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                log::info!("slack notification sent for {}", message.lines().next().unwrap_or(""));
            } else {
                log::warn!("slack returned status {} for {}", resp.status(), url);
            }
        }
        Err(e) => {
            log::warn!("slack notification failed: {}", e);
        }
    }
}

async fn send_discord(url: &str, message: &str, cfg: &NotificationsConfig) {
    let payload = serde_json::json!({ "content": message });
    match reqwest::Client::new()
        .post(url)
        .timeout(std::time::Duration::from_secs(cfg.timeout_secs))
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                log::info!("discord notification sent");
            } else {
                log::warn!("discord returned status {} for {}", resp.status(), url);
            }
        }
        Err(e) => {
            log::warn!("discord notification failed: {}", e);
        }
    }
}

async fn send_generic(url: &str, _message: &str, report: &AnalysisReport, cfg: &NotificationsConfig) {
    match reqwest::Client::new()
        .post(url)
        .timeout(std::time::Duration::from_secs(cfg.timeout_secs))
        .json(report)
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                log::info!("generic webhook sent for {}", report.package_name);
            } else {
                log::warn!("generic webhook returned status {} for {}", resp.status(), url);
            }
        }
        Err(e) => {
            log::warn!("generic webhook failed: {}", e);
        }
    }
}