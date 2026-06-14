//! Database layer for persisting analysis reports
//!
//! This module provides SQLite-based storage for:
//! - Analysis reports (full results from all pipeline stages)
//! - Package processing status (for live feed tracking)
//! - Query/filtering capabilities for the web service

pub mod findings;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::error::Error;
use std::path::Path;
use std::str::FromStr;

use crate::output::AnalysisReport;

/// Database connection pool
#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

/// Package processing status for live feed tracking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PackageStatus {
    Queued,
    Heuristics,
    Typosquat,
    GuardDog,
    Llm,
    Completed,
    Failed,
}

impl PackageStatus {
    fn as_str(&self) -> &str {
        match self {
            PackageStatus::Queued => "queued",
            PackageStatus::Heuristics => "heuristics",
            PackageStatus::Typosquat => "typosquat",
            PackageStatus::GuardDog => "guarddog",
            PackageStatus::Llm => "llm",
            PackageStatus::Completed => "completed",
            PackageStatus::Failed => "failed",
        }
    }

    #[allow(dead_code)]
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "queued" => Ok(PackageStatus::Queued),
            "heuristics" => Ok(PackageStatus::Heuristics),
            "typosquat" => Ok(PackageStatus::Typosquat),
            "guarddog" => Ok(PackageStatus::GuardDog),
            "llm" => Ok(PackageStatus::Llm),
            "completed" => Ok(PackageStatus::Completed),
            "failed" => Ok(PackageStatus::Failed),
            _ => Err(format!("Unknown package status: {}", s)),
        }
    }
}

/// Query filters for retrieving analysis reports
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct QueryFilters {
    pub min_severity: Option<u8>,
    pub max_severity: Option<u8>,
    pub recommendation: Option<String>, // "IGNORE", "INSPECT"
    pub is_malicious: Option<bool>,
    pub package_name: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl Database {
    /// Create a new database connection pool
    pub async fn new(database_url: &str) -> Result<Self, Box<dyn Error>> {
        // Ensure parent directory exists
        if let Some(parent) = Path::new(database_url.trim_start_matches("sqlite://")).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let options = SqliteConnectOptions::from_str(database_url)?
            .create_if_missing(true)
            .busy_timeout(std::time::Duration::from_secs(5))
            .foreign_keys(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        let db = Database { pool };

        // Run migrations
        db.run_migrations().await?;

        Ok(db)
    }

    /// Run database migrations
    async fn run_migrations(&self) -> Result<(), Box<dyn Error>> {
        // Create analysis_reports table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS analysis_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                package_version TEXT,
                timestamp TEXT NOT NULL,
                ecosystem TEXT,
                sha256 TEXT,
                severity INTEGER NOT NULL,
                is_malicious INTEGER NOT NULL,
                recommendation TEXT NOT NULL,
                report_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(package_name, timestamp)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create indexes for common queries
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_severity
            ON analysis_reports(severity)
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_recommendation
            ON analysis_reports(recommendation)
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_package_name
            ON analysis_reports(package_name)
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_timestamp
            ON analysis_reports(timestamp DESC)
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create package_status table for tracking live feed
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS package_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                current_stage TEXT,
                started_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                error_message TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_status
            ON package_status(status)
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create findings table for sidecar API
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS findings (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id       INTEGER REFERENCES analysis_reports(id),
                ecosystem       TEXT NOT NULL,
                name            TEXT NOT NULL,
                version         TEXT,
                sha256          TEXT,
                first_seen      TEXT NOT NULL,
                last_updated    TEXT NOT NULL,
                status          TEXT NOT NULL DEFAULT 'new',
                severity        INTEGER NOT NULL DEFAULT 0,
                classification  TEXT,
                score           INTEGER NOT NULL DEFAULT 0,
                ioc             TEXT,
                payload_excerpt TEXT,
                analyst_notes   TEXT,
                reported_to     TEXT,
                UNIQUE(ecosystem, name, version, sha256)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_finding_ecosystem
            ON findings(ecosystem)
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_finding_status
            ON findings(status)
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_finding_name
            ON findings(name)
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Insert a new analysis report
    pub async fn insert_report(&self, report: &AnalysisReport) -> Result<i64, Box<dyn Error>> {
        let report_json = serde_json::to_string(report)?;
        let created_at = Utc::now().to_rfc3339();
        let ecosystem_str = serde_json::to_string(&report.ecosystem)
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_else(|_| "pypi".to_string());

        let result = sqlx::query(
            r#"
            INSERT INTO analysis_reports
            (package_name, package_version, timestamp, ecosystem, sha256, severity,
             is_malicious, recommendation, report_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(package_name, timestamp) DO UPDATE SET
                package_version = excluded.package_version,
                ecosystem = excluded.ecosystem,
                sha256 = excluded.sha256,
                severity = excluded.severity,
                is_malicious = excluded.is_malicious,
                recommendation = excluded.recommendation,
                report_json = excluded.report_json
            "#,
        )
        .bind(&report.package_name)
        .bind(&report.package_version)
        .bind(&report.timestamp)
        .bind(&ecosystem_str)
        .bind(&report.sha256)
        .bind(report.severity as i64)
        .bind(if report.is_malicious { 1 } else { 0 })
        .bind(&report.recommendation)
        .bind(&report_json)
        .bind(&created_at)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    /// Get a specific analysis report by package name (latest)
    #[allow(dead_code)]
    pub async fn get_report(
        &self,
        package_name: &str,
    ) -> Result<Option<AnalysisReport>, Box<dyn Error>> {
        let row = sqlx::query(
            r#"
            SELECT report_json
            FROM analysis_reports
            WHERE package_name = ?
            ORDER BY timestamp DESC
            LIMIT 1
            "#,
        )
        .bind(package_name)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let json: String = row.try_get("report_json")?;
            let report: AnalysisReport = serde_json::from_str(&json)?;
            Ok(Some(report))
        } else {
            Ok(None)
        }
    }

    /// Get a specific analysis report by row id
    #[allow(dead_code)]
    pub async fn get_report_by_id(
        &self,
        id: i64,
    ) -> Result<Option<AnalysisReport>, Box<dyn Error>> {
        let row = sqlx::query(
            r#"
            SELECT report_json
            FROM analysis_reports
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let json: String = row.try_get("report_json")?;
            let report: AnalysisReport = serde_json::from_str(&json)?;
            Ok(Some(report))
        } else {
            Ok(None)
        }
    }

    /// Query analysis reports with filters
    #[allow(dead_code)]
    pub async fn query_reports(
        &self,
        filters: &QueryFilters,
    ) -> Result<Vec<AnalysisReport>, Box<dyn Error>> {
        let mut query = String::from("SELECT report_json FROM analysis_reports WHERE 1=1");
        let mut bindings: Vec<String> = Vec::new();

        if let Some(min_sev) = filters.min_severity {
            query.push_str(" AND severity >= ?");
            bindings.push(min_sev.to_string());
        }

        if let Some(max_sev) = filters.max_severity {
            query.push_str(" AND severity <= ?");
            bindings.push(max_sev.to_string());
        }

        if let Some(ref recommendation) = filters.recommendation {
            query.push_str(" AND recommendation = ?");
            bindings.push(recommendation.clone());
        }

        if let Some(is_malicious) = filters.is_malicious {
            query.push_str(" AND is_malicious = ?");
            bindings.push(if is_malicious { "1" } else { "0" }.to_string());
        }

        if let Some(ref package_name) = filters.package_name {
            query.push_str(" AND package_name LIKE ?");
            bindings.push(format!("%{}%", package_name));
        }

        // Order by timestamp descending (newest first)
        query.push_str(" ORDER BY timestamp DESC");

        if let Some(limit) = filters.limit {
            query.push_str(&format!(" LIMIT {}", limit));
        }

        if let Some(offset) = filters.offset {
            query.push_str(&format!(" OFFSET {}", offset));
        }

        // Build the query dynamically
        let mut sql_query = sqlx::query(&query);
        for binding in &bindings {
            sql_query = sql_query.bind(binding);
        }

        let rows = sql_query.fetch_all(&self.pool).await?;

        let mut reports = Vec::new();
        for row in rows {
            let json: String = row.try_get("report_json")?;
            let report: AnalysisReport = serde_json::from_str(&json)?;
            reports.push(report);
        }

        Ok(reports)
    }

    /// Update package processing status
    pub async fn update_package_status(
        &self,
        package_name: &str,
        status: PackageStatus,
        error_message: Option<&str>,
    ) -> Result<(), Box<dyn Error>> {
        let now = Utc::now().to_rfc3339();
        let status_str = status.as_str();
        let current_stage = if status == PackageStatus::Completed || status == PackageStatus::Failed
        {
            None
        } else {
            Some(status_str)
        };

        sqlx::query(
            r#"
            INSERT INTO package_status
            (package_name, status, current_stage, started_at, updated_at, error_message)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(package_name) DO UPDATE SET
                status = excluded.status,
                current_stage = excluded.current_stage,
                updated_at = excluded.updated_at,
                error_message = excluded.error_message
            "#,
        )
        .bind(package_name)
        .bind(status_str)
        .bind(current_stage)
        .bind(&now)
        .bind(&now)
        .bind(error_message)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get current status of a package
    #[allow(dead_code)]
    pub async fn get_package_status(
        &self,
        package_name: &str,
    ) -> Result<Option<(PackageStatus, Option<String>)>, Box<dyn Error>> {
        let row = sqlx::query(
            r#"
            SELECT status, error_message
            FROM package_status
            WHERE package_name = ?
            "#,
        )
        .bind(package_name)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let status_str: String = row.try_get("status")?;
            let error_msg: Option<String> = row.try_get("error_message")?;
            let status = PackageStatus::from_str(&status_str)?;
            Ok(Some((status, error_msg)))
        } else {
            Ok(None)
        }
    }

    /// Get all packages currently being processed
    #[allow(dead_code)]
    pub async fn get_processing_packages(
        &self,
    ) -> Result<Vec<(String, PackageStatus, DateTime<Utc>)>, Box<dyn Error>> {
        let rows = sqlx::query(
            r#"
            SELECT package_name, status, updated_at
            FROM package_status
            WHERE status NOT IN ('completed', 'failed')
            ORDER BY updated_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut packages = Vec::new();
        for row in rows {
            let name: String = row.try_get("package_name")?;
            let status_str: String = row.try_get("status")?;
            let updated_at_str: String = row.try_get("updated_at")?;
            let status = PackageStatus::from_str(&status_str)?;
            let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)?.with_timezone(&Utc);
            packages.push((name, status, updated_at));
        }

        Ok(packages)
    }

    /// Get total count of reports matching filters
    #[allow(dead_code)]
    pub async fn count_reports(&self, filters: &QueryFilters) -> Result<i64, Box<dyn Error>> {
        let mut query = String::from("SELECT COUNT(*) as count FROM analysis_reports WHERE 1=1");
        let mut bindings: Vec<String> = Vec::new();

        if let Some(min_sev) = filters.min_severity {
            query.push_str(" AND severity >= ?");
            bindings.push(min_sev.to_string());
        }

        if let Some(max_sev) = filters.max_severity {
            query.push_str(" AND severity <= ?");
            bindings.push(max_sev.to_string());
        }

        if let Some(ref recommendation) = filters.recommendation {
            query.push_str(" AND recommendation = ?");
            bindings.push(recommendation.clone());
        }

        if let Some(is_malicious) = filters.is_malicious {
            query.push_str(" AND is_malicious = ?");
            bindings.push(if is_malicious { "1" } else { "0" }.to_string());
        }

        if let Some(ref package_name) = filters.package_name {
            query.push_str(" AND package_name LIKE ?");
            bindings.push(format!("%{}%", package_name));
        }

        let mut sql_query = sqlx::query(&query);
        for binding in &bindings {
            sql_query = sql_query.bind(binding);
        }

        let row = sql_query.fetch_one(&self.pool).await?;
        let count: i64 = row.try_get("count")?;

        Ok(count)
    }

    /// Delete old reports (cleanup function)
    #[allow(dead_code)]
    pub async fn delete_old_reports(&self, days: i64) -> Result<u64, Box<dyn Error>> {
        let cutoff = Utc::now() - chrono::Duration::days(days);
        let cutoff_str = cutoff.to_rfc3339();

        let result = sqlx::query(
            r#"
            DELETE FROM analysis_reports
            WHERE created_at < ?
            "#,
        )
        .bind(&cutoff_str)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::ecosystem::Ecosystem;
    use crate::output::AnalysisReport;

    #[tokio::test]
    async fn test_database_creation() {
        let db = Database::new("sqlite::memory:").await.unwrap();
        assert!(db.pool.acquire().await.is_ok());
    }

    #[tokio::test]
    async fn test_insert_and_retrieve_report() {
        let db = Database::new("sqlite::memory:").await.unwrap();

        let report = AnalysisReport {
            package_name: "test-package".to_string(),
            package_version: Some("1.0.0".to_string()),
            timestamp: Utc::now().to_rfc3339(),
            ecosystem: Ecosystem::PyPI,
            sha256: String::new(),
            heuristic_matches: vec![],
            typosquat_matches: vec![],
            guarddog_result: None,
            injection_detection: None,
            llm_analysis: None,
            severity: 12,
            is_malicious: true,
            recommendation: "INSPECT".to_string(),
        };

        // Insert report
        let id = db.insert_report(&report).await.unwrap();
        assert!(id > 0);

        // Retrieve report
        let retrieved = db.get_report("test-package").await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.package_name, "test-package");
        assert_eq!(retrieved.severity, 12);
    }

    #[tokio::test]
    async fn test_query_filters() {
        let db = Database::new("sqlite::memory:").await.unwrap();

        // Insert test reports
        for i in 0..5 {
            let report = AnalysisReport {
                package_name: format!("package-{}", i),
                package_version: None,
                timestamp: Utc::now().to_rfc3339(),
                ecosystem: Ecosystem::PyPI,
                sha256: String::new(),
                heuristic_matches: vec![],
                typosquat_matches: vec![],
                guarddog_result: None,
                injection_detection: None,
                llm_analysis: None,
                severity: (i as u8) * 5,
                is_malicious: i >= 3,
                recommendation: if i >= 4 {
                    "INSPECT"
                } else if i >= 2 {
                    "INSPECT"
                } else {
                    "IGNORE"
                }
                .to_string(),
            };
            db.insert_report(&report).await.unwrap();
        }

        // Query with filters
        let filters = QueryFilters {
            min_severity: Some(10),
            ..Default::default()
        };

        let results = db.query_reports(&filters).await.unwrap();
        assert_eq!(results.len(), 3); // packages 2, 3, 4

        // Query by recommendation
        let filters = QueryFilters {
            recommendation: Some("INSPECT".to_string()),
            ..Default::default()
        };

        let results = db.query_reports(&filters).await.unwrap();
        assert_eq!(results.len(), 3); // packages 2, 3, 4
    }

    #[tokio::test]
    async fn test_package_status_tracking() {
        let db = Database::new("sqlite::memory:").await.unwrap();

        // Update status
        db.update_package_status("test-pkg", PackageStatus::Heuristics, None)
            .await
            .unwrap();

        // Get status
        let status = db.get_package_status("test-pkg").await.unwrap();
        assert!(status.is_some());
        let (status, _) = status.unwrap();
        assert_eq!(status, PackageStatus::Heuristics);

        // Update to completed
        db.update_package_status("test-pkg", PackageStatus::Completed, None)
            .await
            .unwrap();

        let status = db.get_package_status("test-pkg").await.unwrap();
        let (status, _) = status.unwrap();
        assert_eq!(status, PackageStatus::Completed);
    }

    #[tokio::test]
    async fn test_update_existing_report() {
        let db = Database::new("sqlite::memory:").await.unwrap();

        let timestamp = Utc::now().to_rfc3339();

        // Insert initial report
        let report1 = AnalysisReport {
            package_name: "update-test".to_string(),
            package_version: Some("1.0.0".to_string()),
            timestamp: timestamp.clone(),
            ecosystem: Ecosystem::PyPI,
            sha256: String::new(),
            heuristic_matches: vec![],
            typosquat_matches: vec![],
            guarddog_result: None,
            injection_detection: None,
            llm_analysis: None,
            severity: 12,
            is_malicious: false,
            recommendation: "INSPECT".to_string(),
        };

        db.insert_report(&report1).await.unwrap();

        // Update with same package name and timestamp (should upsert)
        let report2 = AnalysisReport {
            package_name: "update-test".to_string(),
            package_version: Some("1.0.1".to_string()),
            timestamp: timestamp.clone(),
            ecosystem: Ecosystem::PyPI,
            sha256: String::new(),
            heuristic_matches: vec![],
            typosquat_matches: vec![],
            guarddog_result: None,
            injection_detection: None,
            llm_analysis: None,
            severity: 22,
            is_malicious: true,
            recommendation: "INSPECT".to_string(),
        };

        db.insert_report(&report2).await.unwrap();

        // Should retrieve updated report
        let retrieved = db.get_report("update-test").await.unwrap().unwrap();
        assert_eq!(retrieved.severity, 22);
        assert_eq!(retrieved.package_version, Some("1.0.1".to_string()));
        assert_eq!(retrieved.recommendation, "INSPECT");
    }

    #[tokio::test]
    async fn test_query_by_malicious_flag() {
        let db = Database::new("sqlite::memory:").await.unwrap();

        // Insert mix of malicious and safe packages
        for i in 0..6 {
            let report = AnalysisReport {
                package_name: format!("pkg-{}", i),
                package_version: None,
                timestamp: Utc::now().to_rfc3339(),
                ecosystem: Ecosystem::PyPI,
                sha256: String::new(),
                heuristic_matches: vec![],
                typosquat_matches: vec![],
                guarddog_result: None,
                injection_detection: None,
                llm_analysis: None,
                severity: (i as u8) * 4,
                is_malicious: i >= 3,
                recommendation: "INSPECT".to_string(),
            };
            db.insert_report(&report).await.unwrap();
        }

        // Query only malicious packages
        let filters = QueryFilters {
            is_malicious: Some(true),
            ..Default::default()
        };

        let results = db.query_reports(&filters).await.unwrap();
        assert_eq!(results.len(), 3); // packages 3, 4, 5
        assert!(results.iter().all(|r| r.is_malicious));

        // Query only safe packages
        let filters = QueryFilters {
            is_malicious: Some(false),
            ..Default::default()
        };

        let results = db.query_reports(&filters).await.unwrap();
        assert_eq!(results.len(), 3); // packages 0, 1, 2
        assert!(results.iter().all(|r| !r.is_malicious));
    }

    #[tokio::test]
    async fn test_query_with_pagination() {
        let db = Database::new("sqlite::memory:").await.unwrap();

        // Insert 10 packages
        for i in 0..10 {
            let report = AnalysisReport {
                package_name: format!("page-pkg-{}", i),
                package_version: None,
                timestamp: Utc::now().to_rfc3339(),
                ecosystem: Ecosystem::PyPI,
                sha256: String::new(),
                heuristic_matches: vec![],
                typosquat_matches: vec![],
                guarddog_result: None,
                injection_detection: None,
                llm_analysis: None,
                severity: 12,
                is_malicious: false,
                recommendation: "IGNORE".to_string(),
            };
            db.insert_report(&report).await.unwrap();
        }

        // Get first page (limit 5)
        let filters = QueryFilters {
            limit: Some(5),
            offset: Some(0),
            ..Default::default()
        };

        let page1 = db.query_reports(&filters).await.unwrap();
        assert_eq!(page1.len(), 5);

        // Get second page
        let filters = QueryFilters {
            limit: Some(5),
            offset: Some(5),
            ..Default::default()
        };

        let page2 = db.query_reports(&filters).await.unwrap();
        assert_eq!(page2.len(), 5);

        // Ensure pages don't overlap
        let page1_names: Vec<_> = page1.iter().map(|r| &r.package_name).collect();
        let page2_names: Vec<_> = page2.iter().map(|r| &r.package_name).collect();
        assert!(page1_names.iter().all(|n| !page2_names.contains(n)));
    }

    #[tokio::test]
    async fn test_query_by_package_name_like() {
        let db = Database::new("sqlite::memory:").await.unwrap();

        // Insert packages with various names
        let names = vec![
            "requests",
            "requests-mock",
            "urllib3",
            "django-requests",
            "flask",
        ];
        for name in names {
            let report = AnalysisReport {
                package_name: name.to_string(),
                package_version: None,
                timestamp: Utc::now().to_rfc3339(),
                ecosystem: Ecosystem::PyPI,
                sha256: String::new(),
                heuristic_matches: vec![],
                typosquat_matches: vec![],
                guarddog_result: None,
                injection_detection: None,
                llm_analysis: None,
                severity: 3,
                is_malicious: false,
                recommendation: "IGNORE".to_string(),
            };
            db.insert_report(&report).await.unwrap();
        }

        // Search for packages containing "request"
        let filters = QueryFilters {
            package_name: Some("request".to_string()),
            ..Default::default()
        };

        let results = db.query_reports(&filters).await.unwrap();
        assert_eq!(results.len(), 3); // requests, requests-mock, django-requests
    }

    #[tokio::test]
    async fn test_query_risk_score_range() {
        let db = Database::new("sqlite::memory:").await.unwrap();

        // Insert packages with different risk scores
        for score in [3, 8, 12, 17, 22] {
            let report = AnalysisReport {
                package_name: format!("pkg-score-{}", score),
                package_version: None,
                timestamp: Utc::now().to_rfc3339(),
                ecosystem: Ecosystem::PyPI,
                sha256: String::new(),
                heuristic_matches: vec![],
                typosquat_matches: vec![],
                guarddog_result: None,
                injection_detection: None,
                llm_analysis: None,
                severity: score,
                is_malicious: score >= 17,
                recommendation: "INSPECT".to_string(),
            };
            db.insert_report(&report).await.unwrap();
        }

        // Query medium-risk packages (8-17)
        let filters = QueryFilters {
            min_severity: Some(8),
            max_severity: Some(17),
            ..Default::default()
        };

        let results = db.query_reports(&filters).await.unwrap();
        assert_eq!(results.len(), 3); // 8, 12, 17
        assert!(results.iter().all(|r| r.severity >= 8 && r.severity <= 17));
    }

    #[tokio::test]
    async fn test_count_reports() {
        let db = Database::new("sqlite::memory:").await.unwrap();

        // Insert 15 packages
        for i in 0..15 {
            let report = AnalysisReport {
                package_name: format!("count-pkg-{}", i),
                package_version: None,
                timestamp: Utc::now().to_rfc3339(),
                ecosystem: Ecosystem::PyPI,
                sha256: String::new(),
                heuristic_matches: vec![],
                typosquat_matches: vec![],
                guarddog_result: None,
                injection_detection: None,
                llm_analysis: None,
                severity: if i < 5 { 5 } else { 20 },
                is_malicious: i >= 5,
                recommendation: if i < 5 { "IGNORE" } else { "INSPECT" }.to_string(),
            };
            db.insert_report(&report).await.unwrap();
        }

        // Count all
        let count = db.count_reports(&QueryFilters::default()).await.unwrap();
        assert_eq!(count, 15);

        // Count INSPECT recommendations
        let filters = QueryFilters {
            recommendation: Some("INSPECT".to_string()),
            ..Default::default()
        };
        let count = db.count_reports(&filters).await.unwrap();
        assert_eq!(count, 10);
    }

    #[tokio::test]
    async fn test_get_nonexistent_report() {
        let db = Database::new("sqlite::memory:").await.unwrap();

        let result = db.get_report("nonexistent-package").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_nonexistent_status() {
        let db = Database::new("sqlite::memory:").await.unwrap();

        let result = db.get_package_status("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_status_with_error_message() {
        let db = Database::new("sqlite::memory:").await.unwrap();

        let error_msg = "Failed to download package: 404 Not Found";

        db.update_package_status("failed-pkg", PackageStatus::Failed, Some(error_msg))
            .await
            .unwrap();

        let (status, error) = db.get_package_status("failed-pkg").await.unwrap().unwrap();
        assert_eq!(status, PackageStatus::Failed);
        assert_eq!(error, Some(error_msg.to_string()));
    }

    #[tokio::test]
    async fn test_get_processing_packages() {
        let db = Database::new("sqlite::memory:").await.unwrap();

        // Add some packages in various states
        db.update_package_status("pkg-1", PackageStatus::Heuristics, None)
            .await
            .unwrap();
        db.update_package_status("pkg-2", PackageStatus::Llm, None)
            .await
            .unwrap();
        db.update_package_status("pkg-3", PackageStatus::Completed, None)
            .await
            .unwrap();
        db.update_package_status("pkg-4", PackageStatus::Failed, None)
            .await
            .unwrap();
        db.update_package_status("pkg-5", PackageStatus::Typosquat, None)
            .await
            .unwrap();

        let processing = db.get_processing_packages().await.unwrap();

        // Should only return packages not in Completed or Failed state
        assert_eq!(processing.len(), 3);
        let names: Vec<_> = processing.iter().map(|(n, _, _)| n.as_str()).collect();
        assert!(names.contains(&"pkg-1"));
        assert!(names.contains(&"pkg-2"));
        assert!(names.contains(&"pkg-5"));
        assert!(!names.contains(&"pkg-3"));
        assert!(!names.contains(&"pkg-4"));
    }

    #[tokio::test]
    async fn test_multiple_versions_same_package() {
        let db = Database::new("sqlite::memory:").await.unwrap();

        let base_time = Utc::now();

        // Insert multiple versions with different timestamps
        for i in 0..3 {
            let report = AnalysisReport {
                package_name: "multi-version".to_string(),
                package_version: Some(format!("1.0.{}", i)),
                timestamp: (base_time + chrono::Duration::seconds(i)).to_rfc3339(),
                ecosystem: Ecosystem::PyPI,
                sha256: String::new(),
                heuristic_matches: vec![],
                typosquat_matches: vec![],
                guarddog_result: None,
                injection_detection: None,
                llm_analysis: None,
                severity: (i as u8) * 7,
                is_malicious: false,
                recommendation: "IGNORE".to_string(),
            };
            db.insert_report(&report).await.unwrap();
        }

        // get_report should return the latest version
        let latest = db.get_report("multi-version").await.unwrap().unwrap();
        assert_eq!(latest.package_version, Some("1.0.2".to_string()));
        assert_eq!(latest.severity, 14);
    }

    #[tokio::test]
    async fn test_status_transitions() {
        let db = Database::new("sqlite::memory:").await.unwrap();

        let pkg = "transition-test";

        // Simulate full pipeline progression
        let transitions = vec![
            PackageStatus::Queued,
            PackageStatus::Heuristics,
            PackageStatus::Typosquat,
            PackageStatus::GuardDog,
            PackageStatus::Llm,
            PackageStatus::Completed,
        ];

        for expected_status in transitions {
            db.update_package_status(pkg, expected_status.clone(), None)
                .await
                .unwrap();

            let (actual_status, _) = db.get_package_status(pkg).await.unwrap().unwrap();
            assert_eq!(actual_status, expected_status);
        }
    }

    #[tokio::test]
    async fn test_empty_database_queries() {
        let db = Database::new("sqlite::memory:").await.unwrap();

        // Query empty database
        let results = db.query_reports(&QueryFilters::default()).await.unwrap();
        assert_eq!(results.len(), 0);

        let count = db.count_reports(&QueryFilters::default()).await.unwrap();
        assert_eq!(count, 0);

        let processing = db.get_processing_packages().await.unwrap();
        assert_eq!(processing.len(), 0);
    }

    #[tokio::test]
    async fn test_combined_filters() {
        let db = Database::new("sqlite::memory:").await.unwrap();

        // Insert diverse set of packages
        let test_data = vec![
            ("dangerous-1", 22, true, "INSPECT"),
            ("dangerous-2", 21, true, "INSPECT"),
            ("suspicious-1", 14, false, "INSPECT"),
            ("safe-1", 4, false, "IGNORE"),
            ("safe-2", 3, false, "IGNORE"),
        ];

        for (name, score, malicious, rec) in test_data {
            let report = AnalysisReport {
                package_name: name.to_string(),
                package_version: None,
                timestamp: Utc::now().to_rfc3339(),
                ecosystem: Ecosystem::PyPI,
                sha256: String::new(),
                heuristic_matches: vec![],
                typosquat_matches: vec![],
                guarddog_result: None,
                injection_detection: None,
                llm_analysis: None,
                severity: score,
                is_malicious: malicious,
                recommendation: rec.to_string(),
            };
            db.insert_report(&report).await.unwrap();
        }

        // Combined filter: malicious AND high risk AND INSPECT
        let filters = QueryFilters {
            is_malicious: Some(true),
            min_severity: Some(20),
            recommendation: Some("INSPECT".to_string()),
            ..Default::default()
        };

        let results = db.query_reports(&filters).await.unwrap();
        assert_eq!(results.len(), 2); // dangerous-1 and dangerous-2
    }

    #[tokio::test]
    async fn test_delete_old_reports() {
        let db = Database::new("sqlite::memory:").await.unwrap();

        // Insert reports with different created_at timestamps
        // We'll manually set them using raw SQL for this test
        let old_time = (Utc::now() - chrono::Duration::days(40)).to_rfc3339();
        let recent_time = (Utc::now() - chrono::Duration::days(10)).to_rfc3339();

        let report_old = AnalysisReport {
            package_name: "old-package".to_string(),
            package_version: None,
            timestamp: Utc::now().to_rfc3339(),
            ecosystem: Ecosystem::PyPI,
            sha256: String::new(),
            heuristic_matches: vec![],
            typosquat_matches: vec![],
            guarddog_result: None,
            injection_detection: None,
            llm_analysis: None,
            severity: 12,
            is_malicious: false,
            recommendation: "IGNORE".to_string(),
        };

        db.insert_report(&report_old).await.unwrap();

        // Manually update created_at to simulate old report
        sqlx::query("UPDATE analysis_reports SET created_at = ? WHERE package_name = ?")
            .bind(&old_time)
            .bind("old-package")
            .execute(&db.pool)
            .await
            .unwrap();

        let report_recent = AnalysisReport {
            package_name: "recent-package".to_string(),
            package_version: None,
            timestamp: Utc::now().to_rfc3339(),
            ecosystem: Ecosystem::PyPI,
            sha256: String::new(),
            heuristic_matches: vec![],
            typosquat_matches: vec![],
            guarddog_result: None,
            injection_detection: None,
            llm_analysis: None,
            severity: 12,
            is_malicious: false,
            recommendation: "IGNORE".to_string(),
        };

        db.insert_report(&report_recent).await.unwrap();

        sqlx::query("UPDATE analysis_reports SET created_at = ? WHERE package_name = ?")
            .bind(&recent_time)
            .bind("recent-package")
            .execute(&db.pool)
            .await
            .unwrap();

        // Delete reports older than 30 days
        let deleted = db.delete_old_reports(30).await.unwrap();
        assert_eq!(deleted, 1);

        // Verify only recent report remains
        let remaining = db.query_reports(&QueryFilters::default()).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].package_name, "recent-package");
    }

    #[tokio::test]
    async fn test_query_ordering_by_timestamp() {
        let db = Database::new("sqlite::memory:").await.unwrap();

        let base_time = Utc::now();

        // Insert packages with different timestamps
        for i in 0..5 {
            let report = AnalysisReport {
                package_name: format!("pkg-{}", i),
                package_version: None,
                timestamp: (base_time + chrono::Duration::seconds(i)).to_rfc3339(),
                ecosystem: Ecosystem::PyPI,
                sha256: String::new(),
                heuristic_matches: vec![],
                typosquat_matches: vec![],
                guarddog_result: None,
                injection_detection: None,
                llm_analysis: None,
                severity: 12,
                is_malicious: false,
                recommendation: "IGNORE".to_string(),
            };
            db.insert_report(&report).await.unwrap();
        }

        let results = db.query_reports(&QueryFilters::default()).await.unwrap();

        // Should be ordered by timestamp DESC (newest first)
        assert_eq!(results[0].package_name, "pkg-4");
        assert_eq!(results[4].package_name, "pkg-0");
    }

    #[tokio::test]
    async fn test_package_status_overwrite() {
        let db = Database::new("sqlite::memory:").await.unwrap();

        // Set initial status
        db.update_package_status("overwrite-test", PackageStatus::Queued, None)
            .await
            .unwrap();

        // Update status multiple times
        db.update_package_status("overwrite-test", PackageStatus::Heuristics, None)
            .await
            .unwrap();
        db.update_package_status("overwrite-test", PackageStatus::Completed, None)
            .await
            .unwrap();

        // Should only have one record (not three)
        let (status, _) = db
            .get_package_status("overwrite-test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status, PackageStatus::Completed);
    }
}
