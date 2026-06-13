use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::api::AppState;

pub async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    match &state.prometheus_handle {
        Some(handle) => (StatusCode::OK, handle.render()),
        None => (StatusCode::NOT_FOUND, "metrics not available".to_string()),
    }
}