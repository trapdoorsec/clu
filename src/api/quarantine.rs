//! Quarantine handlers: list, inspect, delete, and download archived packages.

use axum::{
    Json,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::Response,
};
use serde::{Deserialize, Serialize};
use tokio::fs;

use crate::api::{AppError, AppState, ListResponse, require_auth};
use crate::db::audit::AuditEntry;
use crate::db::quarantine::QuarantineFilters;

#[derive(Debug, Deserialize)]
pub struct QuarantineListQuery {
    pub ecosystem: Option<String>,
    pub package_name: Option<String>,
    pub min_severity: Option<i64>,
    pub since: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct QuarantineResponse {
    pub id: i64,
    pub package_name: String,
    pub package_version: Option<String>,
    pub ecosystem: String,
    pub severity: i64,
    pub recommendation: String,
    pub archive_size: Option<i64>,
    pub quarantined_at: String,
    pub report_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct QuarantineDetailResponse {
    pub id: i64,
    pub package_name: String,
    pub package_version: Option<String>,
    pub ecosystem: String,
    pub severity: i64,
    pub recommendation: String,
    pub archive_path: String,
    pub archive_size: Option<i64>,
    pub metadata_path: Option<String>,
    pub quarantined_at: String,
    pub report_id: Option<i64>,
    pub report: Option<super::reports::ReportDetailResponse>,
}

impl From<crate::db::quarantine::QuarantinedPackage> for QuarantineResponse {
    fn from(qp: crate::db::quarantine::QuarantinedPackage) -> Self {
        QuarantineResponse {
            id: qp.id,
            package_name: qp.package_name,
            package_version: qp.package_version,
            ecosystem: qp.ecosystem,
            severity: qp.severity,
            recommendation: qp.recommendation,
            archive_size: qp.archive_size,
            quarantined_at: qp.quarantined_at,
            report_id: qp.report_id,
        }
    }
}

pub async fn list_quarantine(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<QuarantineListQuery>,
) -> Result<Json<ListResponse<QuarantineResponse>>, AppError> {
    require_auth(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        &state.token,
        &state.listen_addr,
    )?;

    let limit = params.limit.unwrap_or(50).min(200);
    let offset = params.offset.unwrap_or(0);

    let filters = QuarantineFilters {
        ecosystem: params.ecosystem,
        package_name: params.package_name,
        min_severity: params.min_severity,
        since: params.since,
        limit: Some(limit),
        offset: Some(offset),
    };

    let total = state
        .db
        .count_quarantined_packages(&filters)
        .await
        .map_err(AppError::Internal)?;
    let packages = state
        .db
        .query_quarantined_packages(&filters)
        .await
        .map_err(AppError::Internal)?;

    let items: Vec<QuarantineResponse> =
        packages.into_iter().map(QuarantineResponse::from).collect();

    Ok(Json(ListResponse {
        items,
        total,
        offset,
        limit,
    }))
}

pub async fn get_quarantine(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<QuarantineDetailResponse>, AppError> {
    require_auth(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        &state.token,
        &state.listen_addr,
    )?;

    let qp = state
        .db
        .get_quarantined_package(id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound(format!("quarantined package {} not found", id)))?;

    let report_detail = if let Some(report_id) = qp.report_id {
        state
            .db
            .get_report_by_id(report_id)
            .await
            .map_err(AppError::Internal)?
            .map(|report| {
                let ecosystem_str = serde_json::to_string(&report.ecosystem)
                    .map(|s| s.trim_matches('"').to_string())
                    .unwrap_or_else(|_| "pypi".to_string());
                super::reports::ReportDetailResponse {
                    id: report_id,
                    package_name: report.package_name,
                    package_version: report.package_version,
                    timestamp: report.timestamp,
                    ecosystem: ecosystem_str,
                    sha256: report.sha256,
                    heuristic_matches: report.heuristic_matches,
                    typosquat_matches: report.typosquat_matches,
                    guarddog_result: report.guarddog_result,
                    injection_detection: report.injection_detection,
                    llm_analysis: report.llm_analysis,
                    severity: report.severity,
                    is_malicious: report.is_malicious,
                    recommendation: report.recommendation,
                }
            })
    } else {
        None
    };

    Ok(Json(QuarantineDetailResponse {
        id: qp.id,
        package_name: qp.package_name,
        package_version: qp.package_version,
        ecosystem: qp.ecosystem,
        severity: qp.severity,
        recommendation: qp.recommendation,
        archive_path: qp.archive_path,
        archive_size: qp.archive_size,
        metadata_path: qp.metadata_path,
        quarantined_at: qp.quarantined_at,
        report_id: qp.report_id,
        report: report_detail,
    }))
}

pub async fn delete_quarantine(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<StatusCode, AppError> {
    require_auth(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        &state.token,
        &state.listen_addr,
    )?;

    let qp = state
        .db
        .get_quarantined_package(id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound(format!("quarantined package {} not found", id)))?;

    let _ = state
        .db
        .insert_audit_entry(&AuditEntry {
            id: 0,
            timestamp: String::new(),
            action: "delete".to_string(),
            entity_type: "quarantine".to_string(),
            entity_id: id,
            old_value: Some(serde_json::to_string(&qp).unwrap_or_default()),
            new_value: None,
            details: Some(format!("deleted quarantined package {}", qp.package_name)),
            actor: "api".to_string(),
        })
        .await;

    let archive_path = std::path::PathBuf::from(&qp.archive_path);
    if let Some(parent) = archive_path.parent()
        && parent.exists()
    {
        let _ = std::fs::remove_dir_all(parent);
    }

    state
        .db
        .delete_quarantined_package(id)
        .await
        .map_err(AppError::Internal)?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn download_archive(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Response<Body>, AppError> {
    require_auth(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        &state.token,
        &state.listen_addr,
    )?;

    let qp = state
        .db
        .get_quarantined_package(id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound(format!("quarantined package {} not found", id)))?;

    let archive_path = std::path::PathBuf::from(&qp.archive_path);
    let filename = archive_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("archive")
        .to_string();

    let data = fs::read(&archive_path)
        .await
        .map_err(|e| AppError::NotFound(format!("archive file not found: {}", e)))?;

    let content_disposition =
        format!("attachment; filename=\"{}\"", filename);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, content_disposition)
        .header("x-content-type-options", "nosniff")
        .header(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'",
        )
        .body(Body::from(data))
        .map_err(|e| AppError::Internal(Box::new(e)))
}