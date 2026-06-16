use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};

use crate::analysis::yara::{YaraEngine, YaraRuleInfo};
use crate::api::{AppError, AppState, require_auth};
use crate::config::YaraConfig;

#[derive(Debug, Serialize)]
pub struct YaraRuleResponse {
    pub name: String,
    pub severity: String,
    pub description: String,
    pub ecosystem: String,
    pub risk_score: u8,
    pub enabled: bool,
    pub source: String,
}

impl From<YaraRuleInfo> for YaraRuleResponse {
    fn from(info: YaraRuleInfo) -> Self {
        YaraRuleResponse {
            name: info.name,
            severity: info.severity,
            description: info.description,
            ecosystem: info.ecosystem,
            risk_score: info.risk_score,
            enabled: info.enabled,
            source: info.source,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct YaraRulesListResponse {
    pub rules: Vec<YaraRuleResponse>,
    pub total: usize,
}

pub async fn list_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<YaraRulesListResponse>, AppError> {
    require_auth(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        &state.token,
        &state.listen_addr,
    )?;

    let yara_config = YaraConfig::default();
    let engine = YaraEngine::new(&yara_config).map_err(AppError::Internal)?;

    let rules: Vec<YaraRuleResponse> = engine
        .list_rules()
        .into_iter()
        .map(YaraRuleResponse::from)
        .collect();

    let total = rules.len();
    Ok(Json(YaraRulesListResponse { rules, total }))
}

pub async fn get_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Json<YaraRuleResponse>, AppError> {
    require_auth(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        &state.token,
        &state.listen_addr,
    )?;

    let yara_config = YaraConfig::default();
    let engine = YaraEngine::new(&yara_config).map_err(AppError::Internal)?;

    let info = engine
        .get_rule(&name)
        .ok_or_else(|| AppError::NotFound(format!("Rule '{}' not found", name)))?;

    Ok(Json(YaraRuleResponse::from(info)))
}

#[derive(Debug, Deserialize)]
pub struct CreateRuleRequest {
    pub name: String,
    pub content: String,
}

pub async fn create_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateRuleRequest>,
) -> Result<Json<YaraRuleResponse>, AppError> {
    require_auth(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        &state.token,
        &state.listen_addr,
    )?;

    let yara_config = YaraConfig::default();
    let mut engine = YaraEngine::new(&yara_config).map_err(AppError::Internal)?;

    engine
        .create_rule(&body.name, &body.content)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let info = engine
        .get_rule(&body.name)
        .ok_or_else(|| AppError::Internal("Rule created but not found".into()))?;

    Ok(Json(YaraRuleResponse::from(info)))
}

pub async fn delete_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    require_auth(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        &state.token,
        &state.listen_addr,
    )?;

    let yara_config = YaraConfig::default();
    let mut engine = YaraEngine::new(&yara_config).map_err(AppError::Internal)?;

    engine
        .delete_rule(&name)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    Ok(Json(serde_json::json!({ "deleted": name })))
}

#[derive(Debug, Deserialize)]
pub struct SetEnabledRequest {
    pub enabled: bool,
}

pub async fn set_rule_enabled(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<SetEnabledRequest>,
) -> Result<Json<YaraRuleResponse>, AppError> {
    require_auth(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        &state.token,
        &state.listen_addr,
    )?;

    let yara_config = YaraConfig::default();
    let mut engine = YaraEngine::new(&yara_config).map_err(AppError::Internal)?;

    engine
        .set_rule_enabled(&name, body.enabled)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let info = engine
        .get_rule(&name)
        .ok_or_else(|| AppError::Internal("Rule updated but not found".into()))?;

    Ok(Json(YaraRuleResponse::from(info)))
}

#[derive(Debug, Deserialize)]
pub struct TestRuleRequest {
    pub content: String,
    pub test_data: String,
}

#[derive(Debug, Serialize)]
pub struct TestRuleResponse {
    pub matched_rules: Vec<String>,
}

pub async fn test_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TestRuleRequest>,
) -> Result<Json<TestRuleResponse>, AppError> {
    require_auth(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        &state.token,
        &state.listen_addr,
    )?;

    let yara_config = YaraConfig::default();
    let engine = YaraEngine::new(&yara_config).map_err(AppError::Internal)?;

    let matched = engine
        .test_rule(&body.content, &body.test_data)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    Ok(Json(TestRuleResponse {
        matched_rules: matched,
    }))
}
