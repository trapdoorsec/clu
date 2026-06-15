//! Audit log: immutable record of analyst actions for compliance and traceability.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::error::Error;

use super::Database;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub timestamp: String,
    pub action: String,
    pub entity_type: String,
    pub entity_id: i64,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub details: Option<String>,
    pub actor: String,
}

#[derive(Debug, Default)]
pub struct AuditFilters {
    pub action: Option<String>,
    pub entity_type: Option<String>,
    pub entity_id: Option<i64>,
    pub since: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl Database {
    pub async fn insert_audit_entry(&self, entry: &AuditEntry) -> Result<i64, Box<dyn Error>> {
        let now = if entry.timestamp.is_empty() {
            Utc::now().to_rfc3339()
        } else {
            entry.timestamp.clone()
        };
        let result = sqlx::query(
            r#"
            INSERT INTO audit_log
              (timestamp, action, entity_type, entity_id, old_value, new_value, details, actor)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&now)
        .bind(&entry.action)
        .bind(&entry.entity_type)
        .bind(entry.entity_id)
        .bind(&entry.old_value)
        .bind(&entry.new_value)
        .bind(&entry.details)
        .bind(&entry.actor)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn query_audit_entries(
        &self,
        filters: &AuditFilters,
    ) -> Result<Vec<AuditEntry>, Box<dyn Error>> {
        let mut query = String::from(
            "SELECT id, timestamp, action, entity_type, entity_id, \
             old_value, new_value, details, actor \
             FROM audit_log WHERE 1=1",
        );
        let mut bindings: Vec<String> = Vec::new();

        if let Some(ref action) = filters.action {
            query.push_str(" AND action = ?");
            bindings.push(action.clone());
        }
        if let Some(ref et) = filters.entity_type {
            query.push_str(" AND entity_type = ?");
            bindings.push(et.clone());
        }
        if let Some(eid) = filters.entity_id {
            query.push_str(" AND entity_id = ?");
            bindings.push(eid.to_string());
        }
        if let Some(ref since) = filters.since {
            query.push_str(" AND timestamp >= ?");
            bindings.push(since.clone());
        }

        query.push_str(" ORDER BY timestamp DESC");

        if let Some(limit) = filters.limit {
            query.push_str(&format!(" LIMIT {}", limit.min(200)));
        } else {
            query.push_str(" LIMIT 50");
        }
        if let Some(offset) = filters.offset {
            query.push_str(&format!(" OFFSET {}", offset));
        }

        let mut sql_query = sqlx::query(&query);
        for b in &bindings {
            sql_query = sql_query.bind(b);
        }

        let rows = sql_query.fetch_all(&self.pool).await?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row_to_audit_entry(row)?);
        }
        Ok(entries)
    }

    pub async fn count_audit_entries(&self, filters: &AuditFilters) -> Result<i64, Box<dyn Error>> {
        let mut query = String::from("SELECT COUNT(*) as count FROM audit_log WHERE 1=1");
        let mut bindings: Vec<String> = Vec::new();

        if let Some(ref action) = filters.action {
            query.push_str(" AND action = ?");
            bindings.push(action.clone());
        }
        if let Some(ref et) = filters.entity_type {
            query.push_str(" AND entity_type = ?");
            bindings.push(et.clone());
        }
        if let Some(eid) = filters.entity_id {
            query.push_str(" AND entity_id = ?");
            bindings.push(eid.to_string());
        }
        if let Some(ref since) = filters.since {
            query.push_str(" AND timestamp >= ?");
            bindings.push(since.clone());
        }

        let mut sql_query = sqlx::query(&query);
        for b in &bindings {
            sql_query = sql_query.bind(b);
        }

        let row = sql_query.fetch_one(&self.pool).await?;
        let count: i64 = row.try_get("count")?;
        Ok(count)
    }
}

fn row_to_audit_entry(row: sqlx::sqlite::SqliteRow) -> Result<AuditEntry, Box<dyn Error>> {
    Ok(AuditEntry {
        id: row.try_get("id")?,
        timestamp: row.try_get("timestamp")?,
        action: row.try_get("action")?,
        entity_type: row.try_get("entity_type")?,
        entity_id: row.try_get("entity_id")?,
        old_value: row.try_get("old_value")?,
        new_value: row.try_get("new_value")?,
        details: row.try_get("details")?,
        actor: row.try_get("actor")?,
    })
}
