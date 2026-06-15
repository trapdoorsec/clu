//! Stats aggregation endpoint for the dashboard.

use axum::{Json, extract::State, http::HeaderMap};
use serde::{Deserialize, Serialize};

use crate::api::{AppError, AppState, require_auth};
use crate::db::findings::FindingFilters;
use crate::db::quarantine::QuarantineFilters;

#[derive(Debug, Deserialize)]
pub struct StatsQuery {
    pub since: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub total_findings: i64,
    pub total_reports: i64,
    pub total_quarantined: i64,
    pub findings_by_severity: serde_json::Value,
    pub findings_by_status: serde_json::Value,
    pub findings_by_ecosystem: serde_json::Value,
    pub recent_findings_24h: i64,
}

pub async fn get_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<StatsResponse>, AppError> {
    require_auth(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        &state.token,
        &state.listen_addr,
    )?;

    let db = &state.db;

    let total_findings = db
        .count_findings(&FindingFilters::default())
        .await
        .map_err(AppError::Internal)?;

    let total_reports = db
        .count_report_rows(&crate::db::ReportListFilters::default())
        .await
        .map_err(AppError::Internal)?;

    let total_quarantined = db
        .count_quarantined_packages(&QuarantineFilters::default())
        .await
        .map_err(AppError::Internal)?;

    let findings_low = db
        .count_findings(&FindingFilters {
            min_severity: Some(1),
            ..Default::default()
        })
        .await
        .map_err(AppError::Internal)?;

    let findings_medium = db
        .count_findings(&FindingFilters {
            min_severity: Some(5),
            ..Default::default()
        })
        .await
        .map_err(AppError::Internal)?;

    let findings_high = db
        .count_findings(&FindingFilters {
            min_severity: Some(13),
            ..Default::default()
        })
        .await
        .map_err(AppError::Internal)?;

    let findings_critical = db
        .count_findings(&FindingFilters {
            min_severity: Some(20),
            ..Default::default()
        })
        .await
        .map_err(AppError::Internal)?;

    let findings_new = db
        .count_findings(&FindingFilters {
            status: Some("new".to_string()),
            ..Default::default()
        })
        .await
        .map_err(AppError::Internal)?;

    let findings_triaging = db
        .count_findings(&FindingFilters {
            status: Some("triaging".to_string()),
            ..Default::default()
        })
        .await
        .map_err(AppError::Internal)?;

    let findings_confirmed = db
        .count_findings(&FindingFilters {
            status: Some("confirmed_malicious".to_string()),
            ..Default::default()
        })
        .await
        .map_err(AppError::Internal)?;

    let findings_benign = db
        .count_findings(&FindingFilters {
            status: Some("benign".to_string()),
            ..Default::default()
        })
        .await
        .map_err(AppError::Internal)?;

    let findings_reported = db
        .count_findings(&FindingFilters {
            status: Some("reported".to_string()),
            ..Default::default()
        })
        .await
        .map_err(AppError::Internal)?;

    let findings_duplicate = db
        .count_findings(&FindingFilters {
            status: Some("duplicate".to_string()),
            ..Default::default()
        })
        .await
        .map_err(AppError::Internal)?;

    let findings_pypi = db
        .count_findings(&FindingFilters {
            ecosystem: Some("pypi".to_string()),
            ..Default::default()
        })
        .await
        .map_err(AppError::Internal)?;

    let findings_npm = db
        .count_findings(&FindingFilters {
            ecosystem: Some("npm".to_string()),
            ..Default::default()
        })
        .await
        .map_err(AppError::Internal)?;

    let severity = serde_json::json!({
        "low": findings_low,
        "medium": findings_medium,
        "high": findings_high,
        "critical": findings_critical,
    });

    let status = serde_json::json!({
        "new": findings_new,
        "triaging": findings_triaging,
        "confirmed_malicious": findings_confirmed,
        "benign": findings_benign,
        "reported": findings_reported,
        "duplicate": findings_duplicate,
    });

    let ecosystem = serde_json::json!({
        "pypi": findings_pypi,
        "npm": findings_npm,
    });

    Ok(Json(StatsResponse {
        total_findings,
        total_reports,
        total_quarantined,
        findings_by_severity: severity,
        findings_by_status: status,
        findings_by_ecosystem: ecosystem,
        recent_findings_24h: findings_new,
    }))
}
