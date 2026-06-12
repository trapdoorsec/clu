#![allow(dead_code)]
//! Findings table: mutable triage state linked to immutable analysis_reports.
//!
//! Each finding references a report via `report_id`. The finding carries the
//! triage workflow (status, classification, analyst notes, etc.) while the
//! report holds the immutable scan evidence.  Future direction (Option B):
//! the API becomes the sole DB writer and the scanner POSTs everything.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::error::Error;
use std::str::FromStr;

use super::Database;

// ── FindingStatus ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    New,
    Triaging,
    ConfirmedMalicious,
    Benign,
    Reported,
    Duplicate,
}

impl FindingStatus {
    pub fn as_str(&self) -> &str {
        match self {
            FindingStatus::New => "new",
            FindingStatus::Triaging => "triaging",
            FindingStatus::ConfirmedMalicious => "confirmed_malicious",
            FindingStatus::Benign => "benign",
            FindingStatus::Reported => "reported",
            FindingStatus::Duplicate => "duplicate",
        }
    }
}

impl FromStr for FindingStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "new" => Ok(FindingStatus::New),
            "triaging" => Ok(FindingStatus::Triaging),
            "confirmed_malicious" => Ok(FindingStatus::ConfirmedMalicious),
            "benign" => Ok(FindingStatus::Benign),
            "reported" => Ok(FindingStatus::Reported),
            "duplicate" => Ok(FindingStatus::Duplicate),
            _ => Err(format!("Unknown finding status: {}", s)),
        }
    }
}

// ── Finding ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: i64,
    pub report_id: Option<i64>,
    pub ecosystem: String,
    pub name: String,
    pub version: Option<String>,
    pub sha256: Option<String>,
    pub first_seen: String,
    pub last_updated: String,
    pub status: FindingStatus,
    pub severity: i64,
    pub classification: Option<String>,
    pub score: i64,
    pub ioc: Option<String>,
    pub payload_excerpt: Option<String>,
    pub analyst_notes: Option<String>,
    pub reported_to: Option<String>,
}

// ── FindingFilters ────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct FindingFilters {
    pub ecosystem: Option<String>,
    pub status: Option<String>,
    pub min_severity: Option<i64>,
    pub min_score: Option<i64>,
    pub since: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ── FindingUpdate ─────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct FindingUpdate {
    pub status: Option<FindingStatus>,
    pub classification: Option<String>,
    pub analyst_notes: Option<String>,
    pub reported_to: Option<String>,
}

// ── Database impl for findings ────────────────────────────────────────────

impl Database {
    /// Insert a finding.  On UNIQUE(ecosystem, name, version, sha256) conflict,
    /// update mutable fields and bump last_updated (idempotent POST).
    pub async fn insert_finding(&self, f: &Finding) -> Result<i64, Box<dyn Error>> {
        let status_str = f.status.as_str();
        let now = Utc::now().to_rfc3339();

        let result = sqlx::query(
            r#"
            INSERT INTO findings
              (report_id, ecosystem, name, version, sha256,
               first_seen, last_updated, status, severity, classification,
               score, ioc, payload_excerpt, analyst_notes, reported_to)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ecosystem, name, version, sha256) DO UPDATE SET
              report_id     = excluded.report_id,
              last_updated  = excluded.last_updated,
              status        = excluded.status,
              severity      = excluded.severity,
              classification= excluded.classification,
              score         = excluded.score,
              ioc           = excluded.ioc,
              payload_excerpt = excluded.payload_excerpt,
              analyst_notes = excluded.analyst_notes,
              reported_to   = excluded.reported_to
            "#,
        )
        .bind(f.report_id)
        .bind(&f.ecosystem)
        .bind(&f.name)
        .bind(&f.version)
        .bind(&f.sha256)
        .bind(&now)
        .bind(&now)
        .bind(status_str)
        .bind(f.severity)
        .bind(&f.classification)
        .bind(f.score)
        .bind(&f.ioc)
        .bind(&f.payload_excerpt)
        .bind(&f.analyst_notes)
        .bind(&f.reported_to)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    /// Get a single finding by id.
    pub async fn get_finding(&self, id: i64) -> Result<Option<Finding>, Box<dyn Error>> {
        let row = sqlx::query(
            r#"
            SELECT id, report_id, ecosystem, name, version, sha256,
                   first_seen, last_updated, status, severity, classification,
                   score, ioc, payload_excerpt, analyst_notes, reported_to
            FROM findings WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(row_to_finding(r)?)),
            None => Ok(None),
        }
    }

    /// Query findings with optional filters.
    pub async fn query_findings(
        &self,
        filters: &FindingFilters,
    ) -> Result<Vec<Finding>, Box<dyn Error>> {
        let mut query = String::from(
            "SELECT id, report_id, ecosystem, name, version, sha256, \
             first_seen, last_updated, status, severity, classification, \
             score, ioc, payload_excerpt, analyst_notes, reported_to \
             FROM findings WHERE 1=1",
        );
        let mut bindings: Vec<String> = Vec::new();

        if let Some(ref eco) = filters.ecosystem {
            query.push_str(" AND ecosystem = ?");
            bindings.push(eco.clone());
        }
        if let Some(ref st) = filters.status {
            query.push_str(" AND status = ?");
            bindings.push(st.clone());
        }
        if let Some(min_sev) = filters.min_severity {
            query.push_str(" AND severity >= ?");
            bindings.push(min_sev.to_string());
        }
        if let Some(min_sc) = filters.min_score {
            query.push_str(" AND score >= ?");
            bindings.push(min_sc.to_string());
        }
        if let Some(ref since) = filters.since {
            query.push_str(" AND first_seen >= ?");
            bindings.push(since.clone());
        }

        query.push_str(" ORDER BY last_updated DESC");

        if let Some(limit) = filters.limit {
            query.push_str(&format!(" LIMIT {}", limit));
        }
        if let Some(offset) = filters.offset {
            query.push_str(&format!(" OFFSET {}", offset));
        }

        let mut sql_query = sqlx::query(&query);
        for b in &bindings {
            sql_query = sql_query.bind(b);
        }

        let rows = sql_query.fetch_all(&self.pool).await?;
        let mut findings = Vec::new();
        for row in rows {
            findings.push(row_to_finding(row)?);
        }
        Ok(findings)
    }

    /// Update triage fields on a finding.
    pub async fn update_finding(
        &self,
        id: i64,
        update: &FindingUpdate,
    ) -> Result<(), Box<dyn Error>> {
        let now = Utc::now().to_rfc3339();
        let mut sets = Vec::new();
        let mut bindings: Vec<String> = Vec::new();

        if let Some(ref st) = update.status {
            sets.push("status = ?".to_string());
            bindings.push(st.as_str().to_string());
        }
        if let Some(ref cls) = update.classification {
            sets.push("classification = ?".to_string());
            bindings.push(cls.clone());
        }
        if let Some(ref notes) = update.analyst_notes {
            sets.push("analyst_notes = ?".to_string());
            bindings.push(notes.clone());
        }
        if let Some(ref rpt) = update.reported_to {
            sets.push("reported_to = ?".to_string());
            bindings.push(rpt.clone());
        }

        if sets.is_empty() {
            return Ok(());
        }

        sets.push("last_updated = ?".to_string());
        bindings.push(now);

        let sql = format!("UPDATE findings SET {} WHERE id = ?", sets.join(", "));
        let mut q = sqlx::query(&sql);
        for b in &bindings {
            q = q.bind(b);
        }
        q = q.bind(id);
        q.execute(&self.pool).await?;

        Ok(())
    }
}

fn row_to_finding(row: sqlx::sqlite::SqliteRow) -> Result<Finding, Box<dyn Error>> {
    let status_str: String = row.try_get("status")?;
    let status = status_str.parse::<FindingStatus>()?;

    Ok(Finding {
        id: row.try_get("id")?,
        report_id: row.try_get("report_id")?,
        ecosystem: row.try_get("ecosystem")?,
        name: row.try_get("name")?,
        version: row.try_get("version")?,
        sha256: row.try_get("sha256")?,
        first_seen: row.try_get("first_seen")?,
        last_updated: row.try_get("last_updated")?,
        status,
        severity: row.try_get("severity")?,
        classification: row.try_get("classification")?,
        score: row.try_get("score")?,
        ioc: row.try_get("ioc")?,
        payload_excerpt: row.try_get("payload_excerpt")?,
        analyst_notes: row.try_get("analyst_notes")?,
        reported_to: row.try_get("reported_to")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> Database {
        Database::new("sqlite::memory:").await.unwrap()
    }

    fn make_finding(name: &str) -> Finding {
        Finding {
            id: 0,
            report_id: None,
            ecosystem: "pypi".to_string(),
            name: name.to_string(),
            version: Some("1.0.0".to_string()),
            sha256: Some("abc123".to_string()),
            first_seen: String::new(),
            last_updated: String::new(),
            status: FindingStatus::New,
            severity: 0,
            classification: None,
            score: 0,
            ioc: None,
            payload_excerpt: None,
            analyst_notes: None,
            reported_to: None,
        }
    }

    #[tokio::test]
    async fn test_insert_and_get_finding() {
        let db = test_db().await;
        let f = make_finding("test-pkg");
        let id = db.insert_finding(&f).await.unwrap();
        assert!(id > 0);

        let got = db.get_finding(id).await.unwrap().unwrap();
        assert_eq!(got.name, "test-pkg");
        assert_eq!(got.ecosystem, "pypi");
        assert_eq!(got.status, FindingStatus::New);
    }

    #[tokio::test]
    async fn test_insert_finding_idempotent() {
        let db = test_db().await;
        let mut f1 = make_finding("dup-pkg");
        f1.sha256 = Some("sha".to_string());
        let _id1 = db.insert_finding(&f1).await.unwrap();

        let mut f2 = make_finding("dup-pkg");
        f2.sha256 = Some("sha".to_string());
        f2.status = FindingStatus::Triaging;
        let _id2 = db.insert_finding(&f2).await.unwrap();

        // Same unique key bumps status; only one row
        let all = db
            .query_findings(&FindingFilters {
                ecosystem: Some("pypi".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].status, FindingStatus::Triaging);
    }

    #[tokio::test]
    async fn test_update_finding() {
        let db = test_db().await;
        let f = make_finding("up-pkg");
        let id = db.insert_finding(&f).await.unwrap();

        let update = FindingUpdate {
            status: Some(FindingStatus::ConfirmedMalicious),
            classification: Some("trojan".to_string()),
            analyst_notes: Some("confirmed by analyst".to_string()),
            reported_to: None,
        };
        db.update_finding(id, &update).await.unwrap();

        let got = db.get_finding(id).await.unwrap().unwrap();
        assert_eq!(got.status, FindingStatus::ConfirmedMalicious);
        assert_eq!(got.classification.unwrap(), "trojan");
    }

    #[tokio::test]
    async fn test_query_findings_with_filters() {
        let db = test_db().await;

        let mut f1 = make_finding("pkg-a");
        f1.severity = 20;
        let _ = db.insert_finding(&f1).await.unwrap();

        let mut f2 = make_finding("pkg-b");
        f2.severity = 5;
        let _ = db.insert_finding(&f2).await.unwrap();

        let high = db
            .query_findings(&FindingFilters {
                min_severity: Some(15),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(high.len(), 1);
        assert_eq!(high[0].name, "pkg-a");
    }

    #[tokio::test]
    async fn test_get_nonexistent_finding() {
        let db = test_db().await;
        let result = db.get_finding(9999).await.unwrap();
        assert!(result.is_none());
    }
}
