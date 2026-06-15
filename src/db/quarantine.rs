//! Quarantined packages table: tracks packages saved to disk for investigation.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::error::Error;

use super::Database;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinedPackage {
    pub id: i64,
    pub package_name: String,
    pub package_version: Option<String>,
    pub ecosystem: String,
    pub severity: i64,
    pub recommendation: String,
    pub archive_path: String,
    pub archive_size: Option<i64>,
    pub metadata_path: Option<String>,
    pub quarantined_at: String,
    pub report_id: Option<i64>,
}

#[derive(Debug, Default)]
pub struct QuarantineFilters {
    pub ecosystem: Option<String>,
    pub package_name: Option<String>,
    pub min_severity: Option<i64>,
    pub since: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl Database {
    pub async fn insert_quarantined_package(
        &self,
        qp: &QuarantinedPackage,
    ) -> Result<i64, Box<dyn Error>> {
        let now = Utc::now().to_rfc3339();
        let result = sqlx::query(
            r#"
            INSERT INTO quarantined_packages
              (package_name, package_version, ecosystem, severity, recommendation,
               archive_path, archive_size, metadata_path, quarantined_at, report_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ecosystem, package_name, package_version) DO UPDATE SET
              severity       = excluded.severity,
              recommendation = excluded.recommendation,
              archive_path   = excluded.archive_path,
              archive_size   = excluded.archive_size,
              metadata_path  = excluded.metadata_path,
              report_id      = excluded.report_id
            "#,
        )
        .bind(&qp.package_name)
        .bind(&qp.package_version)
        .bind(&qp.ecosystem)
        .bind(qp.severity)
        .bind(&qp.recommendation)
        .bind(&qp.archive_path)
        .bind(qp.archive_size)
        .bind(&qp.metadata_path)
        .bind(&now)
        .bind(qp.report_id)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn get_quarantined_package(
        &self,
        id: i64,
    ) -> Result<Option<QuarantinedPackage>, Box<dyn Error>> {
        let row = sqlx::query(
            r#"
            SELECT id, package_name, package_version, ecosystem, severity,
                   recommendation, archive_path, archive_size, metadata_path,
                   quarantined_at, report_id
            FROM quarantined_packages WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(row_to_quarantined_package(r)?)),
            None => Ok(None),
        }
    }

    pub async fn query_quarantined_packages(
        &self,
        filters: &QuarantineFilters,
    ) -> Result<Vec<QuarantinedPackage>, Box<dyn Error>> {
        let mut query = String::from(
            "SELECT id, package_name, package_version, ecosystem, severity, \
             recommendation, archive_path, archive_size, metadata_path, \
             quarantined_at, report_id \
             FROM quarantined_packages WHERE 1=1",
        );
        let mut bindings: Vec<String> = Vec::new();

        if let Some(ref eco) = filters.ecosystem {
            query.push_str(" AND ecosystem = ?");
            bindings.push(eco.clone());
        }
        if let Some(ref name) = filters.package_name {
            query.push_str(" AND package_name LIKE ?");
            bindings.push(format!("%{}%", name));
        }
        if let Some(min_sev) = filters.min_severity {
            query.push_str(" AND severity >= ?");
            bindings.push(min_sev.to_string());
        }
        if let Some(ref since) = filters.since {
            query.push_str(" AND quarantined_at >= ?");
            bindings.push(since.clone());
        }

        query.push_str(" ORDER BY quarantined_at DESC");

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
        let mut results = Vec::new();
        for row in rows {
            results.push(row_to_quarantined_package(row)?);
        }
        Ok(results)
    }

    pub async fn count_quarantined_packages(
        &self,
        filters: &QuarantineFilters,
    ) -> Result<i64, Box<dyn Error>> {
        let mut query =
            String::from("SELECT COUNT(*) as count FROM quarantined_packages WHERE 1=1");
        let mut bindings: Vec<String> = Vec::new();

        if let Some(ref eco) = filters.ecosystem {
            query.push_str(" AND ecosystem = ?");
            bindings.push(eco.clone());
        }
        if let Some(ref name) = filters.package_name {
            query.push_str(" AND package_name LIKE ?");
            bindings.push(format!("%{}%", name));
        }
        if let Some(min_sev) = filters.min_severity {
            query.push_str(" AND severity >= ?");
            bindings.push(min_sev.to_string());
        }
        if let Some(ref since) = filters.since {
            query.push_str(" AND quarantined_at >= ?");
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

    pub async fn delete_quarantined_package(&self, id: i64) -> Result<bool, Box<dyn Error>> {
        let result = sqlx::query("DELETE FROM quarantined_packages WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

fn row_to_quarantined_package(
    row: sqlx::sqlite::SqliteRow,
) -> Result<QuarantinedPackage, Box<dyn Error>> {
    Ok(QuarantinedPackage {
        id: row.try_get("id")?,
        package_name: row.try_get("package_name")?,
        package_version: row.try_get("package_version")?,
        ecosystem: row.try_get("ecosystem")?,
        severity: row.try_get("severity")?,
        recommendation: row.try_get("recommendation")?,
        archive_path: row.try_get("archive_path")?,
        archive_size: row.try_get("archive_size")?,
        metadata_path: row.try_get("metadata_path")?,
        quarantined_at: row.try_get("quarantined_at")?,
        report_id: row.try_get("report_id")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    async fn test_db() -> Database {
        Database::new("sqlite::memory:").await.unwrap()
    }

    fn make_qp(name: &str) -> QuarantinedPackage {
        QuarantinedPackage {
            id: 0,
            package_name: name.to_string(),
            package_version: Some("1.0.0".to_string()),
            ecosystem: "pypi".to_string(),
            severity: 15,
            recommendation: "BLOCK".to_string(),
            archive_path: format!("/tmp/quarantine/pypi/{}", name),
            archive_size: Some(2048),
            metadata_path: Some(format!("/tmp/quarantine/pypi/{}/report.json", name)),
            quarantined_at: String::new(),
            report_id: None,
        }
    }

    #[tokio::test]
    async fn test_insert_and_get_quarantined_package() {
        let db = test_db().await;
        let qp = make_qp("evil-pkg");
        let id = db.insert_quarantined_package(&qp).await.unwrap();
        assert!(id > 0);

        let got = db.get_quarantined_package(id).await.unwrap().unwrap();
        assert_eq!(got.package_name, "evil-pkg");
        assert_eq!(got.ecosystem, "pypi");
        assert_eq!(got.severity, 15);
        assert_eq!(got.recommendation, "BLOCK");
        assert_eq!(got.archive_size, Some(2048));
    }

    #[tokio::test]
    async fn test_query_quarantined_packages_by_ecosystem() {
        let db = test_db().await;

        let mut qp1 = make_qp("pkg-a");
        qp1.ecosystem = "pypi".to_string();
        db.insert_quarantined_package(&qp1).await.unwrap();

        let mut qp2 = make_qp("pkg-b");
        qp2.ecosystem = "npm".to_string();
        db.insert_quarantined_package(&qp2).await.unwrap();

        let pypi = db
            .query_quarantined_packages(&QuarantineFilters {
                ecosystem: Some("pypi".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(pypi.len(), 1);
        assert_eq!(pypi[0].package_name, "pkg-a");

        let npm = db
            .query_quarantined_packages(&QuarantineFilters {
                ecosystem: Some("npm".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(npm.len(), 1);
        assert_eq!(npm[0].package_name, "pkg-b");
    }

    #[tokio::test]
    async fn test_query_quarantined_packages_by_name() {
        let db = test_db().await;

        let qp1 = make_qp("requests-evil");
        let qp2 = make_qp("django-copy");
        let qp3 = make_qp("flask");
        db.insert_quarantined_package(&qp1).await.unwrap();
        db.insert_quarantined_package(&qp2).await.unwrap();
        db.insert_quarantined_package(&qp3).await.unwrap();

        let results = db
            .query_quarantined_packages(&QuarantineFilters {
                package_name: Some("request".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].package_name, "requests-evil");
    }

    #[tokio::test]
    async fn test_query_quarantined_packages_by_severity() {
        let db = test_db().await;

        let mut qp1 = make_qp("pkg-low");
        qp1.severity = 5;
        db.insert_quarantined_package(&qp1).await.unwrap();

        let mut qp2 = make_qp("pkg-high");
        qp2.severity = 20;
        db.insert_quarantined_package(&qp2).await.unwrap();

        let high = db
            .query_quarantined_packages(&QuarantineFilters {
                min_severity: Some(15),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(high.len(), 1);
        assert_eq!(high[0].package_name, "pkg-high");
    }

    #[tokio::test]
    async fn test_count_quarantined_packages() {
        let db = test_db().await;

        for i in 0..5 {
            let mut qp = make_qp(&format!("pkg-{}", i));
            qp.severity = if i < 2 { 5 } else { 20 };
            db.insert_quarantined_package(&qp).await.unwrap();
        }

        let total = db
            .count_quarantined_packages(&QuarantineFilters::default())
            .await
            .unwrap();
        assert_eq!(total, 5);

        let high = db
            .count_quarantined_packages(&QuarantineFilters {
                min_severity: Some(15),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(high, 3);
    }

    #[tokio::test]
    async fn test_delete_quarantined_package() {
        let db = test_db().await;
        let qp = make_qp("to-delete");
        let id = db.insert_quarantined_package(&qp).await.unwrap();

        let deleted = db.delete_quarantined_package(id).await.unwrap();
        assert!(deleted);

        let gone = db.get_quarantined_package(id).await.unwrap();
        assert!(gone.is_none());

        let deleted_again = db.delete_quarantined_package(id).await.unwrap();
        assert!(!deleted_again);
    }

    #[tokio::test]
    async fn test_get_nonexistent_quarantined_package() {
        let db = test_db().await;
        let result = db.get_quarantined_package(9999).await.unwrap();
        assert!(result.is_none());
    }
}
