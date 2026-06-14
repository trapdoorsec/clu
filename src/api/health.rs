//! Health check handler.

use crate::api::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

pub async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(state.db.pool()).await {
        Ok(_) => (StatusCode::OK, "ok"),
        Err(e) => {
            log::error!("health check DB query failed: {}", e);
            (StatusCode::SERVICE_UNAVAILABLE, "database unavailable")
        }
    }
}