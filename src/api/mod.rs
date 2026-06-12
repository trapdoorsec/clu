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
use subtle::ConstantTimeEq;

pub use self::findings::{CreateFindingRequest, FindingResponse, PatchFindingRequest};

#[derive(Clone)]
pub struct AppState {
    pub db: crate::db::Database,
    pub token: Option<String>,
    pub listen_addr: String,
}

/// Build the axum router with all API routes.
pub fn router(db: crate::db::Database, token: Option<String>, listen_addr: String) -> Router {
    let state = AppState {
        db,
        token,
        listen_addr,
    };

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
