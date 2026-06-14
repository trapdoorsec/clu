#![allow(dead_code)]

//! Sidecar REST API: findings triage, reports, quarantine, stats, and audit.
//!
//! All API routes are under the `/api/` prefix to separate them from the
//! SPA static file serving that clu-api provides.
//!
//! Endpoints:
//!   POST   /api/findings              — register finding (idempotent)
//!   GET    /api/findings              — list/query findings
//!   GET    /api/findings/{id}         — single finding detail
//!   PATCH  /api/findings/{id}         — update triage status
//!   DELETE /api/findings/{id}         — delete finding
//!   POST   /api/findings/bulk         — bulk update findings
//!   GET    /api/findings/{id}/report  — OSM-shaped export
//!   GET    /api/reports              — list/search analysis reports
//!   GET    /api/reports/count        — report count for pagination
//!   GET    /api/reports/{id}         — full analysis report detail
//!   GET    /api/quarantine           — list quarantined packages
//!   GET    /api/quarantine/{id}      — inspect quarantined package
//!   DELETE /api/quarantine/{id}      — delete quarantined package
//!   GET    /api/quarantine/{id}/archive — download quarantined archive
//!   GET    /api/stats                — dashboard statistics
//!   GET    /api/audit-log            — query audit trail
//!   GET    /healthz                  — liveness (with DB check)
//!   GET    /metrics                  — Prometheus exposition

mod audit;
mod findings;
mod health;
mod metrics;
mod osm;
mod quarantine;
mod reports;
mod stats;

use axum::{
    Router,
    http::StatusCode,
    routing::{get, post},
};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::Serialize;
use subtle::ConstantTimeEq;

pub use self::findings::{BulkUpdateRequest, BulkUpdateResponse, CreateFindingRequest, FindingResponse, PatchFindingRequest};

#[derive(Clone)]
pub struct AppState {
    pub db: crate::db::Database,
    pub token: Option<String>,
    pub listen_addr: String,
    pub prometheus_handle: Option<PrometheusHandle>,
}

/// Paginated list response envelope.
#[derive(Debug, Serialize)]
pub struct ListResponse<T: Serialize> {
    pub items: Vec<T>,
    pub total: i64,
    pub offset: i64,
    pub limit: i64,
}

/// Build the axum router with all API routes (under /api/) and CORS middleware.
pub fn router(
    db: crate::db::Database,
    token: Option<String>,
    listen_addr: String,
    prometheus_handle: Option<PrometheusHandle>,
) -> Router {
    use tower_http::cors::{AllowOrigin, CorsLayer};

    let state = AppState {
        db,
        token,
        listen_addr,
        prometheus_handle,
    };

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::any())
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PATCH,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers(tower_http::cors::Any);

    Router::new()
        .route("/healthz", get(health::healthz))
        .route("/metrics", get(metrics::metrics))
        .route(
            "/api/findings",
            post(findings::create_finding).get(findings::list_findings),
        )
        .route(
            "/api/findings/bulk",
            post(findings::bulk_update_findings),
        )
        .route(
            "/api/findings/{id}",
            get(findings::get_finding)
                .patch(findings::update_finding)
                .delete(findings::delete_finding),
        )
        .route("/api/findings/{id}/report", get(findings::get_finding_report))
        .route(
            "/api/reports",
            get(reports::list_reports),
        )
        .route("/api/reports/count", get(reports::report_count))
        .route("/api/reports/{id}", get(reports::get_report))
        .route(
            "/api/quarantine",
            get(quarantine::list_quarantine),
        )
        .route(
            "/api/quarantine/{id}",
            get(quarantine::get_quarantine).delete(quarantine::delete_quarantine),
        )
        .route(
            "/api/quarantine/{id}/archive",
            get(quarantine::download_archive),
        )
        .route("/api/stats", get(stats::get_stats))
        .route("/api/audit-log", get(audit::list_audit_entries))
        .with_state(state)
        .layer(cors)
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("internal error: {0}")]
    Internal(#[from] Box<dyn std::error::Error>),
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, body) = match &self {
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            AppError::Internal(e) => {
                log::error!("internal error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            }
        };
        (status, body).into_response()
    }
}

/// Returns true if the listen address is a loopback address.
///
/// Parses host:port and checks if the host portion resolves to a loopback
/// interface (127.0.0.0/8, ::1, or "localhost").
pub fn is_loopback(listen_addr: &str) -> bool {
    let host = listen_addr
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(listen_addr);
    if host == "localhost" {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    false
}

/// Fail-closed authentication check.
///
/// - If a token is configured, requires a matching Bearer header (constant-time compare).
/// - If no token is configured AND the bind address is loopback, allows access.
/// - If no token is configured AND the bind address is NOT loopback, rejects access.
///
/// This prevents accidentally exposing the API on public interfaces without auth.
pub fn require_auth(
    auth_header: Option<&str>,
    expected: &Option<String>,
    listen_addr: &str,
) -> Result<(), AppError> {
    match expected {
        Some(secret) => {
            let provided = auth_header
                .and_then(|h| h.strip_prefix("Bearer "))
                .map(|s| s.trim());
            match provided {
                Some(tok) if secret.as_bytes().ct_eq(tok.as_bytes()).into() => Ok(()),
                _ => Err(AppError::Unauthorized),
            }
        }
        None => {
            if is_loopback(listen_addr) {
                Ok(())
            } else {
                log::error!(
                    "Rejecting unauthenticated request: no token configured and bind address {:?} is not loopback",
                    listen_addr
                );
                Err(AppError::Unauthorized)
            }
        }
    }
}