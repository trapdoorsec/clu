#![allow(dead_code)]

//! Sidecar REST API: findings triage service.
//!
//! Endpoints:
//!   POST   /findings              — register (idempotent)
//!   GET    /findings              — list/query
//!   GET    /findings/{id}         — detail
//!   PATCH  /findings/{id}         — update triage status
//!   GET    /findings/{id}/report  — OSM-shaped export
//!   GET    /healthz               — liveness

mod findings;
mod health;
mod osm;

use axum::{
    Router,
    http::StatusCode,
    routing::{get, patch, post},
};

pub use self::findings::{CreateFindingRequest, FindingResponse, PatchFindingRequest};

#[derive(Clone)]
pub struct AppState {
    pub db: crate::db::Database,
    pub token: Option<String>,
}

/// Build the axum router with all API routes.
pub fn router(db: crate::db::Database, token: Option<String>) -> Router {
    let state = AppState { db, token };

    Router::new()
        .route("/healthz", get(health::healthz))
        .route(
            "/findings",
            post(findings::create_finding).get(findings::list_findings),
        )
        .route(
            "/findings/{id}",
            get(findings::get_finding).patch(findings::update_finding),
        )
        .route("/findings/{id}/report", get(findings::get_finding_report))
        .with_state(state)
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

/// Check auth: if token is configured, require a matching Bearer header.
/// Returns Ok(()) if no token is configured or if the token matches.
pub fn require_auth(auth_header: Option<&str>, expected: &Option<String>) -> Result<(), AppError> {
    match expected {
        None => Ok(()),
        Some(secret) => {
            let provided = auth_header
                .and_then(|h| h.strip_prefix("Bearer "))
                .map(|s| s.trim());
            match provided {
                Some(tok) if tok == secret => Ok(()),
                _ => Err(AppError::Unauthorized),
            }
        }
    }
}
