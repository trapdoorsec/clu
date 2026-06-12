//! Health check handler.

use crate::api::AppState;
use axum::extract::State;

pub async fn healthz(State(_state): State<AppState>) -> &'static str {
    "ok"
}
