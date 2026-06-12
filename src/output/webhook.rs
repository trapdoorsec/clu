//! Scanner → sidecar POST helper.
//!
//! When `sidecar.endpoint` is configured, the scanner POSTs the `AnalysisReport`
//! (plus the `report_id` from the local DB insert) as JSON to the sidecar's
//! `/findings` endpoint.  Failures are logged and swallowed — the sidecar
//! must never block or fail a scan.

use crate::config::SidecarConfig;
use crate::output::AnalysisReport;

#[derive(serde::Serialize)]
struct FindingPayload {
    report: AnalysisReport,
    report_id: Option<i64>,
}

/// Fire-and-forget POST of the analysis report to the sidecar API.
/// Non-fatal: errors are logged but never propagated.
pub async fn post_finding_to_sidecar(
    report: &AnalysisReport,
    report_id: Option<i64>,
    cfg: &SidecarConfig,
) {
    let endpoint = match &cfg.endpoint {
        Some(e) => e.clone(),
        None => return,
    };

    let url = format!("{}/findings", endpoint.trim_end_matches('/'));

    let payload = FindingPayload {
        report: report.clone(),
        report_id,
    };

    let client = reqwest::Client::new();
    let mut req = client.post(&url).json(&payload);

    if let Some(ref token) = cfg.token {
        req = req.bearer_auth(token);
    }

    match req
        .timeout(std::time::Duration::from_secs(cfg.timeout_secs))
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                log::info!(
                    "sidecar: posted finding for {} (status {})",
                    report.package_name,
                    resp.status()
                );
            } else {
                log::warn!(
                    "sidecar: POST /findings returned {} for {}",
                    resp.status(),
                    report.package_name
                );
            }
        }
        Err(e) => {
            log::warn!(
                "sidecar: failed to POST finding for {}: {}",
                report.package_name,
                e
            );
        }
    }
}
