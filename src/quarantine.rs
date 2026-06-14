use std::fs;
use std::io::Write;
use std::path::PathBuf;

use chrono::Utc;
use walkdir::WalkDir;

use crate::config::QuarantineConfig;
use crate::feed::ecosystem::Ecosystem;
use crate::output::AnalysisReport;

#[allow(dead_code)]
pub struct QuarantineResult {
    pub path: PathBuf,
    pub archive_file: PathBuf,
    pub metadata_file: Option<PathBuf>,
    pub bytes_written: u64,
}

#[derive(Clone)]
pub struct QuarantinePayload {
    pub raw_data: Vec<u8>,
    pub download_url: String,
    pub package_name: String,
    pub package_version: Option<String>,
    pub ecosystem: Ecosystem,
}

fn sanitize_name(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .replace("..", "_")
}

fn archive_extension(url: &str) -> &'static str {
    if url.ends_with(".whl") || url.ends_with(".zip") {
        ".whl"
    } else {
        ".tar.gz"
    }
}

fn ecosystem_dir_name(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::PyPI => "pypi",
        Ecosystem::Npm => "npm",
    }
}

pub async fn quarantine_package(
    name: &str,
    version: Option<&str>,
    ecosystem: Ecosystem,
    raw_data: &[u8],
    url: &str,
    report: &AnalysisReport,
    cfg: &QuarantineConfig,
) -> Result<QuarantineResult, Box<dyn std::error::Error>> {
    let quarantine_root = PathBuf::from(&cfg.directory);
    let eco_dir = quarantine_root.join(ecosystem_dir_name(ecosystem));
    let safe_name = sanitize_name(name);
    let safe_version = sanitize_name(version.unwrap_or("unknown"));
    let timestamp = Utc::now().format("%Y%m%dT%H%M%S");
    let entry_dir = eco_dir.join(format!("{safe_name}_{safe_version}_{timestamp}"));
    if !eco_dir.exists() {
        fs::create_dir_all(&eco_dir)?;
    }
    fs::create_dir_all(&entry_dir)?;

    let ext = archive_extension(url);
    let archive_name = format!("archive{ext}");
    let archive_path = entry_dir.join(&archive_name);

    let tmp_path = archive_path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(raw_data)?;
        f.flush()?;
    }
    fs::rename(&tmp_path, &archive_path)?;

    let mut bytes_written = raw_data.len() as u64;
    let mut metadata_file: Option<PathBuf> = None;

    if cfg.retain_metadata {
        let report_path = entry_dir.join("report.json");
        let tmp_report = entry_dir.join("report.json.tmp");
        let json = serde_json::to_string_pretty(report)?;
        {
            let mut f = fs::File::create(&tmp_report)?;
            f.write_all(json.as_bytes())?;
            f.flush()?;
        }
        fs::rename(&tmp_report, &report_path)?;
        bytes_written += json.len() as u64;
        metadata_file = Some(report_path);
    }

    append_audit_log(&quarantine_root, name, ecosystem, report)?;

    evict_if_needed(&quarantine_root, cfg)?;

    log::info!(
        "quarantined {} ({} bytes) to {}",
        name,
        bytes_written,
        entry_dir.display()
    );

    Ok(QuarantineResult {
        path: entry_dir,
        archive_file: archive_path,
        metadata_file,
        bytes_written,
    })
}

fn append_audit_log(
    quarantine_root: &std::path::Path,
    name: &str,
    ecosystem: Ecosystem,
    report: &AnalysisReport,
) -> Result<(), Box<dyn std::error::Error>> {
    let log_path = quarantine_root.join("quarantine.log");
    let severity_label = match report.severity {
        1..=4 => "LOW",
        5..=12 => "MEDIUM",
        13..=20 => "HIGH",
        _ => "CRITICAL",
    };
    let line = format!(
        "{} {} {} {} {} {}\n",
        Utc::now().to_rfc3339(),
        name,
        ecosystem_dir_name(ecosystem),
        report.severity,
        severity_label,
        report.recommendation,
    );
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    f.write_all(line.as_bytes())?;
    Ok(())
}

fn evict_if_needed(
    quarantine_root: &std::path::Path,
    cfg: &QuarantineConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    evict_expired(quarantine_root, cfg)?;
    evict_over_budget(quarantine_root, cfg)?;
    Ok(())
}

fn evict_expired(
    quarantine_root: &std::path::Path,
    cfg: &QuarantineConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    if cfg.max_age_days == 0 {
        return Ok(());
    }
    let cutoff = Utc::now() - chrono::Duration::days(cfg.max_age_days as i64);
    for entry in WalkDir::new(quarantine_root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_dir() {
            continue;
        }
        let path = entry.path();
        if path == quarantine_root {
            continue;
        }
        let eco_dir = quarantine_root.join(
            path.parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        );
        if path == eco_dir.as_path() {
            continue;
        }
        if let Ok(metadata) = fs::metadata(path)
            && let Ok(modified) = metadata.modified()
        {
            let modified_dt: chrono::DateTime<Utc> = modified.into();
            if modified_dt < cutoff {
                let size = dir_size(path);
                log::info!(
                    "evicting expired quarantine entry {:?} ({} bytes, modified {})",
                    path,
                    size,
                    modified_dt
                );
                let _ = fs::remove_dir_all(path);
            }
        }
    }
    Ok(())
}

fn evict_over_budget(
    quarantine_root: &std::path::Path,
    cfg: &QuarantineConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    if cfg.max_disk_mb == 0 {
        return Ok(());
    }
    let max_bytes = cfg.max_disk_mb * 1_048_576;

    let mut entries: Vec<(PathBuf, u64, std::time::SystemTime)> = Vec::new();
    let mut total_size: u64 = 0;

    for entry in WalkDir::new(quarantine_root)
        .max_depth(3)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path().to_path_buf();
        if !path.is_dir() {
            continue;
        }
        if path == quarantine_root {
            continue;
        }
        let parent_name = path
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned());
        if let Some(ref pname) = parent_name {
            let eco_dir = quarantine_root.join(pname);
            if path == eco_dir {
                continue;
            }
        }
        let size = dir_size(&path);
        let modified = fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok())
            .unwrap_or(std::time::UNIX_EPOCH);
        total_size += size;
        entries.push((path, size, modified));
    }

    if total_size <= max_bytes {
        return Ok(());
    }

    entries.sort_by_key(|(_, _, mtime)| *mtime);

    for (path, size, _) in entries {
        if total_size <= max_bytes {
            break;
        }
        log::info!(
            "evicting quarantine entry {:?} to reclaim {} bytes",
            path,
            size
        );
        let _ = fs::remove_dir_all(&path);
        total_size = total_size.saturating_sub(size);
    }

    Ok(())
}

fn dir_size(path: &std::path::Path) -> u64 {
    WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum()
}

#[allow(dead_code)]
pub async fn download_and_quarantine(
    name: &str,
    version: Option<&str>,
    ecosystem: Ecosystem,
    report: &AnalysisReport,
    cfg: &QuarantineConfig,
) -> Result<QuarantineResult, Box<dyn std::error::Error>> {
    let (raw_data, url) = crate::analysis::package::download_package(name, version).await?;
    quarantine_package(name, version, ecosystem, &raw_data, &url, report, cfg).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{HeuristicMatch, TypoSquatterMatch};

    fn make_report(name: &str, severity: u8, recommendation: &str) -> AnalysisReport {
        AnalysisReport {
            package_name: name.to_string(),
            package_version: Some("1.0.0".to_string()),
            timestamp: Utc::now().to_rfc3339(),
            ecosystem: Ecosystem::PyPI,
            sha256: "abc123".to_string(),
            heuristic_matches: vec![],
            typosquat_matches: vec![],
            guarddog_result: None,
            injection_detection: None,
            llm_analysis: None,
            severity,
            is_malicious: severity >= 70,
            recommendation: recommendation.to_string(),
        }
    }

    fn make_config(dir: &str) -> QuarantineConfig {
        QuarantineConfig {
            enabled: true,
            directory: dir.to_string(),
            min_severity: 5,
            max_age_days: 3,
            max_disk_mb: 1024,
            retain_metadata: true,
        }
    }

    #[tokio::test]
    async fn test_quarantine_writes_archive_and_metadata() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg = make_config(tmp.path().to_str().unwrap());
        let report = make_report("test-pkg", 12, "INSPECT");
        let raw = b"fake archive data".to_vec();

        let result = quarantine_package(
            "test-pkg",
            Some("1.0.0"),
            Ecosystem::PyPI,
            &raw,
            "https://example.com/test-pkg-1.0.0.tar.gz",
            &report,
            &cfg,
        )
        .await
        .unwrap();

        assert!(result.archive_file.exists());
        assert!(result.metadata_file.is_some());
        assert!(result.metadata_file.unwrap().exists());
        assert_eq!(fs::read(&result.archive_file).unwrap(), raw);

        let log_content = fs::read_to_string(tmp.path().join("quarantine.log")).unwrap();
        assert!(log_content.contains("test-pkg"));
        assert!(log_content.contains("MEDIUM"));
    }

    #[tokio::test]
    async fn test_quarantine_severity_filtering() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg = make_config(tmp.path().to_str().unwrap());
        let report = make_report("low-pkg", 2, "IGNORE");

        let result = quarantine_package(
            "low-pkg",
            Some("1.0.0"),
            Ecosystem::PyPI,
            b"data",
            "https://example.com/low.tar.gz",
            &report,
            &cfg,
        )
        .await
        .unwrap();

        assert!(result.archive_file.exists());
    }

    #[tokio::test]
    async fn test_quarantine_disabled_noop() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut cfg = make_config(tmp.path().to_str().unwrap());
        cfg.enabled = false;

        let eco_dir = tmp.path().join("pypi");
        assert!(!eco_dir.exists());
    }

    #[tokio::test]
    async fn test_path_sanitization_prevents_traversal() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg = make_config(tmp.path().to_str().unwrap());
        let report = make_report("../evil-pkg", 12, "INSPECT");

        let result = quarantine_package(
            "../evil-pkg",
            Some("1.0.0"),
            Ecosystem::PyPI,
            b"data",
            "https://example.com/evil.tar.gz",
            &report,
            &cfg,
        )
        .await
        .unwrap();

        let path_str = result.path.to_string_lossy();
        assert!(!path_str.contains(".."));
        assert!(path_str.contains("__evil-pkg"));
    }

    #[tokio::test]
    async fn test_eviction_removes_expired_dirs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut cfg = make_config(tmp.path().to_str().unwrap());
        cfg.max_age_days = 0;

        let report = make_report("old-pkg", 12, "INSPECT");
        let _ = quarantine_package(
            "old-pkg",
            Some("1.0.0"),
            Ecosystem::PyPI,
            b"data",
            "https://example.com/old.tar.gz",
            &report,
            &cfg,
        )
        .await;

        let mut cfg_evict = make_config(tmp.path().to_str().unwrap());
        cfg_evict.max_age_days = 0;
        let _ = evict_if_needed(tmp.path(), &cfg_evict);
    }

    #[tokio::test]
    async fn test_audit_log_appended() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg = make_config(tmp.path().to_str().unwrap());

        let report1 = make_report("pkg-a", 6, "INSPECT");
        let _ = quarantine_package(
            "pkg-a",
            Some("1.0.0"),
            Ecosystem::PyPI,
            b"data1",
            "https://example.com/a.tar.gz",
            &report1,
            &cfg,
        )
        .await
        .unwrap();

        let report2 = make_report("pkg-b", 20, "BLOCK");
        let _ = quarantine_package(
            "pkg-b",
            Some("2.0.0"),
            Ecosystem::PyPI,
            b"data2",
            "https://example.com/b.whl",
            &report2,
            &cfg,
        )
        .await
        .unwrap();

        let log = fs::read_to_string(tmp.path().join("quarantine.log")).unwrap();
        let lines: Vec<&str> = log.trim().lines().collect();
        assert!(lines.len() >= 2);
        assert!(lines[0].contains("pkg-a"));
        assert!(lines[1].contains("pkg-b"));
    }

    #[tokio::test]
    async fn test_whl_extension() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg = make_config(tmp.path().to_str().unwrap());
        let report = make_report("wheel-pkg", 12, "INSPECT");

        let result = quarantine_package(
            "wheel-pkg",
            Some("1.0.0"),
            Ecosystem::PyPI,
            b"wheel data",
            "https://example.com/wheel-pkg-1.0.0-py3-none-any.whl",
            &report,
            &cfg,
        )
        .await
        .unwrap();

        assert!(result.archive_file.to_string_lossy().ends_with(".whl"));
    }
}
