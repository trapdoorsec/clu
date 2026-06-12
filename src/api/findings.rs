//! Finding handlers: create, list, get, update, and OSM report export.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};

use crate::api::{AppError, AppState, require_auth};
use crate::db::findings::{Finding, FindingFilters, FindingStatus, FindingUpdate};
use crate::output::AnalysisReport;

// ── Request / Response DTOs ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateFindingRequest {
    pub report: AnalysisReport,
    pub report_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct FindingResponse {
    pub id: i64,
    pub report_id: Option<i64>,
    pub ecosystem: String,
    pub name: String,
    pub version: Option<String>,
    pub sha256: Option<String>,
    pub first_seen: String,
    pub last_updated: String,
    pub status: String,
    pub severity: i64,
    pub classification: Option<String>,
    pub score: i64,
    pub ioc: Option<String>,
    pub payload_excerpt: Option<String>,
    pub analyst_notes: Option<String>,
    pub reported_to: Option<String>,
}

impl From<Finding> for FindingResponse {
    fn from(f: Finding) -> Self {
        FindingResponse {
            id: f.id,
            report_id: f.report_id,
            ecosystem: f.ecosystem,
            name: f.name,
            version: f.version,
            sha256: f.sha256,
            first_seen: f.first_seen,
            last_updated: f.last_updated,
            status: f.status.as_str().to_string(),
            severity: f.severity,
            classification: f.classification,
            score: f.score,
            ioc: f.ioc,
            payload_excerpt: f.payload_excerpt,
            analyst_notes: f.analyst_notes,
            reported_to: f.reported_to,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct PatchFindingRequest {
    pub status: Option<String>,
    pub classification: Option<String>,
    pub analyst_notes: Option<String>,
    pub reported_to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub ecosystem: Option<String>,
    pub status: Option<String>,
    pub min_severity: Option<i64>,
    pub min_score: Option<i64>,
    pub since: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ── Handlers ─────────────────────────────────────────────────────────────

pub async fn create_finding(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateFindingRequest>,
) -> Result<Json<FindingResponse>, AppError> {
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok());
    require_auth(auth, &state.token, &state.listen_addr)?;

    let report = body.report;
    let ecosystem_str = serde_json::to_string(&report.ecosystem)
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_else(|_| "pypi".to_string());

    let sha256_val = if report.sha256.is_empty() {
        None
    } else {
        Some(report.sha256.clone())
    };

    let finding = Finding {
        id: 0,
        report_id: body.report_id,
        ecosystem: ecosystem_str,
        name: report.package_name.clone(),
        version: report.package_version.clone(),
        sha256: sha256_val,
        first_seen: String::new(),
        last_updated: String::new(),
        status: FindingStatus::New,
        severity: report.severity as i64,
        classification: None,
        score: report.severity as i64,
        ioc: None,
        payload_excerpt: None,
        analyst_notes: None,
        reported_to: None,
    };

    let id = state
        .db
        .insert_finding(&finding)
        .await
        .map_err(AppError::Internal)?;
    let stored = state
        .db
        .get_finding(id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound("finding not found after insert".into()))?;

    Ok(Json(FindingResponse::from(stored)))
}

pub async fn list_findings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<ListQuery>,
) -> Result<Json<Vec<FindingResponse>>, AppError> {
    require_auth(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        &state.token,
        &state.listen_addr,
    )?;

    let filters = FindingFilters {
        ecosystem: params.ecosystem,
        status: params.status,
        min_severity: params.min_severity,
        min_score: params.min_score,
        since: params.since,
        limit: params.limit,
        offset: params.offset,
    };

    let findings = state
        .db
        .query_findings(&filters)
        .await
        .map_err(AppError::Internal)?;

    Ok(Json(
        findings.into_iter().map(FindingResponse::from).collect(),
    ))
}

pub async fn get_finding(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<FindingResponse>, AppError> {
    require_auth(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        &state.token,
        &state.listen_addr,
    )?;

    let finding = state
        .db
        .get_finding(id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound(format!("finding {} not found", id)))?;

    Ok(Json(FindingResponse::from(finding)))
}

pub async fn update_finding(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<PatchFindingRequest>,
) -> Result<Json<FindingResponse>, AppError> {
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok());
    require_auth(auth, &state.token, &state.listen_addr)?;

    let status = body
        .status
        .as_deref()
        .map(|s| s.parse::<FindingStatus>())
        .transpose()
        .map_err(AppError::BadRequest)?;

    let update = FindingUpdate {
        status,
        classification: body.classification,
        analyst_notes: body.analyst_notes,
        reported_to: body.reported_to,
    };

    state
        .db
        .update_finding(id, &update)
        .await
        .map_err(AppError::Internal)?;

    let finding = state
        .db
        .get_finding(id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound(format!("finding {} not found after update", id)))?;

    Ok(Json(FindingResponse::from(finding)))
}

pub async fn get_finding_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    require_auth(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        &state.token,
        &state.listen_addr,
    )?;

    let finding = state
        .db
        .get_finding(id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound(format!("finding {} not found", id)))?;

    let report = if let Some(report_id) = finding.report_id {
        state
            .db
            .get_report_by_id(report_id)
            .await
            .map_err(AppError::Internal)?
    } else {
        None
    };

    let osm = super::osm::to_osm_report(&finding, report.as_ref());
    let value = serde_json::to_value(&osm).map_err(|e| AppError::Internal(Box::new(e)))?;
    Ok(Json(value))
}
