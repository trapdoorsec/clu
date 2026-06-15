//! Report handlers: list, count, and detail for analysis reports.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};

use crate::api::{AppError, AppState, ListResponse, require_auth};
use crate::db::ReportListFilters;

#[derive(Debug, Deserialize)]
pub struct ReportListQuery {
    pub package_name: Option<String>,
    pub ecosystem: Option<String>,
    pub min_severity: Option<u8>,
    pub max_severity: Option<u8>,
    pub recommendation: Option<String>,
    pub is_malicious: Option<bool>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ReportSummaryResponse {
    pub id: i64,
    pub package_name: String,
    pub package_version: Option<String>,
    pub ecosystem: Option<String>,
    pub severity: i64,
    pub is_malicious: bool,
    pub recommendation: String,
    pub sha256: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ReportDetailResponse {
    pub id: i64,
    pub package_name: String,
    pub package_version: Option<String>,
    pub timestamp: String,
    pub ecosystem: String,
    pub sha256: String,
    pub heuristic_matches: Vec<crate::output::HeuristicMatch>,
    pub typosquat_matches: Vec<crate::output::TypoSquatterMatch>,
    pub yara_result: Option<crate::output::YaraScanResult>,
    pub injection_detection: Option<crate::output::PromptInjectionDetection>,
    pub llm_analysis: Option<crate::output::LlmAnalysisResult>,
    pub severity: u8,
    pub is_malicious: bool,
    pub recommendation: String,
}

impl From<crate::db::ReportRow> for ReportSummaryResponse {
    fn from(r: crate::db::ReportRow) -> Self {
        ReportSummaryResponse {
            id: r.id,
            package_name: r.package_name,
            package_version: r.package_version,
            ecosystem: r.ecosystem,
            severity: r.severity,
            is_malicious: r.is_malicious,
            recommendation: r.recommendation,
            sha256: r.sha256,
            timestamp: r.timestamp,
        }
    }
}

pub async fn list_reports(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<ReportListQuery>,
) -> Result<Json<ListResponse<ReportSummaryResponse>>, AppError> {
    require_auth(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        &state.token,
        &state.listen_addr,
    )?;

    let limit = params.limit.unwrap_or(50).min(200);
    let offset = params.offset.unwrap_or(0);

    let filters = ReportListFilters {
        package_name: params.package_name,
        ecosystem: params.ecosystem,
        min_severity: params.min_severity,
        max_severity: params.max_severity,
        recommendation: params.recommendation,
        is_malicious: params.is_malicious,
        since: params.since,
        until: params.until,
        sort: params.sort,
        order: params.order,
        limit: Some(limit),
        offset: Some(offset),
    };

    let total = state
        .db
        .count_report_rows(&filters)
        .await
        .map_err(AppError::Internal)?;
    let rows = state
        .db
        .list_report_rows(&filters)
        .await
        .map_err(AppError::Internal)?;

    let items: Vec<ReportSummaryResponse> =
        rows.into_iter().map(ReportSummaryResponse::from).collect();

    Ok(Json(ListResponse {
        items,
        total,
        offset,
        limit,
    }))
}

pub async fn report_count(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<ReportListQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    require_auth(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        &state.token,
        &state.listen_addr,
    )?;

    let filters = ReportListFilters {
        package_name: params.package_name,
        ecosystem: params.ecosystem,
        min_severity: params.min_severity,
        max_severity: params.max_severity,
        recommendation: params.recommendation,
        is_malicious: params.is_malicious,
        since: params.since,
        until: params.until,
        sort: None,
        order: None,
        limit: None,
        offset: None,
    };

    let count = state
        .db
        .count_report_rows(&filters)
        .await
        .map_err(AppError::Internal)?;

    Ok(Json(serde_json::json!({ "count": count })))
}

pub async fn get_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ReportDetailResponse>, AppError> {
    require_auth(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        &state.token,
        &state.listen_addr,
    )?;

    let report = state
        .db
        .get_report_by_id(id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound(format!("report {} not found", id)))?;

    let ecosystem_str = serde_json::to_string(&report.ecosystem)
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_else(|_| "pypi".to_string());

    Ok(Json(ReportDetailResponse {
        id,
        package_name: report.package_name,
        package_version: report.package_version,
        timestamp: report.timestamp,
        ecosystem: ecosystem_str,
        sha256: report.sha256,
        heuristic_matches: report.heuristic_matches,
        typosquat_matches: report.typosquat_matches,
        yara_result: report.yara_result,
        injection_detection: report.injection_detection,
        llm_analysis: report.llm_analysis,
        severity: report.severity,
        is_malicious: report.is_malicious,
        recommendation: report.recommendation,
    }))
}
