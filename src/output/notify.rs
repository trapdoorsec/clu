use crate::config::NotificationsConfig;
use crate::output::AnalysisReport;

/// Send a startup health-check ping to all configured notification channels.
/// This lets the operator confirm that Discord/Slack/generic webhooks are reachable
/// before the first finding is produced.
pub async fn notify_startup(cfg: &NotificationsConfig) {
    if !cfg.enabled {
        return;
    }

    let message = "🟢 **CLU startup health-check** — notification channel is live.";

    if let Some(ref url) = cfg.slack_webhook {
        send_slack_raw(url, message, cfg).await;
    }
    if let Some(ref url) = cfg.discord_webhook {
        send_discord_raw(url, message, cfg).await;
    }
    if let Some(ref url) = cfg.generic_webhook {
        send_generic_raw(url, message, cfg).await;
    }
}

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
        report.package_version.as_deref().unwrap_or("unknown"),
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
    if let Some(ref yara) = report.yara_result {
        for f in &yara.findings {
            lines.push(format!(
                "  yara: {} [{}] — {}",
                f.rule_name, f.severity, f.description
            ));
        }
    }
    if let Some(ref llm) = report.llm_analysis
        && llm.is_malicious()
    {
        let conflicted_marker = if llm.conflicted { " [CONFLICTED]" } else { "" };
        lines.push(format!(
            "  llm: MALICIOUS{} — {}",
            conflicted_marker, llm.reasoning
        ));
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
                log::info!(
                    "slack notification sent for {}",
                    message.lines().next().unwrap_or("")
                );
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

async fn send_generic(
    url: &str,
    _message: &str,
    report: &AnalysisReport,
    cfg: &NotificationsConfig,
) {
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
                log::warn!(
                    "generic webhook returned status {} for {}",
                    resp.status(),
                    url
                );
            }
        }
        Err(e) => {
            log::warn!("generic webhook failed: {}", e);
        }
    }
}

// ── Raw helpers for startup health-check (no report required) ───────────

async fn send_slack_raw(url: &str, message: &str, cfg: &NotificationsConfig) {
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
                log::info!("slack startup ping sent");
            } else {
                log::warn!("slack startup ping returned status {}", resp.status());
            }
        }
        Err(e) => {
            log::warn!("slack startup ping failed: {}", e);
        }
    }
}

async fn send_discord_raw(url: &str, message: &str, cfg: &NotificationsConfig) {
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
                log::info!("discord startup ping sent");
            } else {
                log::warn!("discord startup ping returned status {}", resp.status());
            }
        }
        Err(e) => {
            log::warn!("discord startup ping failed: {}", e);
        }
    }
}

async fn send_generic_raw(url: &str, message: &str, cfg: &NotificationsConfig) {
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
                log::info!("generic startup ping sent");
            } else {
                log::warn!("generic startup ping returned status {}", resp.status());
            }
        }
        Err(e) => {
            log::warn!("generic startup ping failed: {}", e);
        }
    }
}
