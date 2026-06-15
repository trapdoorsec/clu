//! Audit log API endpoints for querying analyst actions.

use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};

use crate::api::{AppError, AppState, require_auth};
use crate::db::audit::{AuditEntry, AuditFilters};

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub action: Option<String>,
    pub entity_type: Option<String>,
    pub entity_id: Option<i64>,
    pub since: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl From<AuditQuery> for AuditFilters {
    fn from(q: AuditQuery) -> Self {
        AuditFilters {
            action: q.action,
            entity_type: q.entity_type,
            entity_id: q.entity_id,
            since: q.since,
            limit: q.limit,
            offset: q.offset,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AuditListResponse {
    pub entries: Vec<AuditEntry>,
    pub total: i64,
}

pub async fn list_audit_entries(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditListResponse>, AppError> {
    require_auth(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        &state.token,
        &state.listen_addr,
    )?;

    let filters: AuditFilters = query.into();
    let entries = state
        .db
        .query_audit_entries(&filters)
        .await
        .map_err(AppError::Internal)?;
    let total = state
        .db
        .count_audit_entries(&filters)
        .await
        .map_err(AppError::Internal)?;

    Ok(Json(AuditListResponse { entries, total }))
}
