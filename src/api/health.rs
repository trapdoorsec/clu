//! Health check handler.

use crate::api::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub db: String,
}

pub async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(state.db.pool()).await {
        Ok(_) => (
            StatusCode::OK,
            axum::Json(HealthResponse {
                status: "ok".to_string(),
                db: "ok".to_string(),
            }),
        ),
        Err(e) => {
            log::error!("health check DB query failed: {}", e);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(HealthResponse {
                    status: "error".to_string(),
                    db: "unavailable".to_string(),
                }),
            )
        }
    }
}