//! Package download and extraction utilities
//! Handles downloading packages from registries and extracting source code
//! **entirely in-memory** — no untrusted archive is ever written to disk.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::config::ExtractionConfig;

pub use crate::feed::ecosystem::Ecosystem;

// ── File classification roles ────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FileRole {
    EntryScript = 0,
    Config = 1,
    Script = 2,
    Source = 3,
    Other = 4,
}

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub relative_path: PathBuf,
    pub contents: String,
    pub role: FileRole,
}

// ── Package contents (entirely in-memory, no TempDir) ───────────────────

pub struct PackageContents {
    pub files: Vec<FileEntry>,
    pub ecosystem: Ecosystem,
}

// ── Source bundle for LLM / heuristics consumption ──────────────────────

#[derive(Debug, Clone)]
pub struct BundleEntry {
    pub path: PathBuf,
    pub role_tag: String,
    pub contents: String,
}

#[derive(Debug, Clone)]
pub struct SourceBundle {
    pub entries: Vec<BundleEntry>,
    pub total_bytes: usize,
    pub truncated: bool,
}

// ── Extraction error ────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ExtractionError {
    EntryLimitExceeded {
        limit: usize,
        found: usize,
    },
    TotalSizeExceeded {
        limit: usize,
        actual: usize,
    },
    FileTooLarge {
        path: PathBuf,
        limit: usize,
        actual: usize,
    },
    Io(String),
    InvalidArchive(String),
}

impl std::fmt::Display for ExtractionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtractionError::EntryLimitExceeded { limit, found } => {
                write!(f, "entry count exceeded: found {} (limit {})", found, limit)
            }
            ExtractionError::TotalSizeExceeded { limit, actual } => {
                write!(f, "total size exceeded: {} bytes (limit {})", actual, limit)
            }
            ExtractionError::FileTooLarge {
                path,
                limit,
                actual,
            } => {
                write!(
                    f,
                    "file {:?} too large: {} bytes (limit {})",
                    path, actual, limit
                )
            }
            ExtractionError::Io(msg) => write!(f, "I/O error: {}", msg),
            ExtractionError::InvalidArchive(msg) => write!(f, "invalid archive: {}", msg),
        }
    }
}

impl std::error::Error for ExtractionError {}

// ── In-memory tar.gz extraction ──────────────────────────────────────────

fn is_suspicious_region(content: &str) -> bool {
    let indicators = [
        "eval(",
        "exec(",
        "Function(",
        "child_process",
        "subprocess",
        "os.system",
        "os.popen",
        "base64.b64decode",
        "base64.b64encode",
        "binascii",
        "urllib.request",
        "requests.get",
        "requests.post",
        "fetch(",
        "axios",
    ];
    let lower = content.to_lowercase();
    indicators.iter().any(|ind| lower.contains(ind))
}

fn sanitize_relative_path(path: &str) -> Option<PathBuf> {
    let p = Path::new(path);
    let mut sanitized = PathBuf::new();
    for comp in p.components() {
        match comp {
            std::path::Component::Normal(c) => sanitized.push(c),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir
            | std::path::Component::Prefix(_)
            | std::path::Component::RootDir => {
                log::warn!("skipping path component in archive entry: {:?}", comp);
                return None;
            }
        }
    }
    if sanitized.as_os_str().is_empty() {
        return None;
    }
    Some(sanitized)
}

pub fn extract_tar_gz_in_memory(
    data: &[u8],
    config: &ExtractionConfig,
    ecosystem: Ecosystem,
) -> Result<PackageContents, ExtractionError> {
    let gz = flate2::read::GzDecoder::new(data);
    let mut archive = tar::Archive::new(gz);

    let mut files: Vec<FileEntry> = Vec::new();
    let mut total_bytes: usize = 0;

    let entries = archive
        .entries()
        .map_err(|e| ExtractionError::InvalidArchive(e.to_string()))?;

    for entry_result in entries {
        let mut entry = entry_result.map_err(|e| ExtractionError::Io(e.to_string()))?;

        let header = entry.header();
        let entry_type = header.entry_type();

        if !entry_type.is_file() {
            log::debug!(
                "skipping non-regular tar entry: {:?} (type={:?})",
                entry.path().ok().map(|p| p.display().to_string()),
                entry_type
            );
            continue;
        }

        if files.len() >= config.max_entries {
            log::warn!(
                "entry limit reached: {} (limit {}),
                 skipping remaining entries",
                files.len(),
                config.max_entries
            );
            break;
        }

        let raw_path = entry
            .path()
            .map_err(|e| ExtractionError::Io(e.to_string()))?;
        let relative_path = match sanitize_relative_path(&raw_path.to_string_lossy()) {
            Some(p) => p,
            None => continue,
        };

        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).map_err(|e| {
            ExtractionError::Io(format!(
                "failed to read tar entry {:?}: {}",
                relative_path, e
            ))
        })?;

        if buf.len() > config.max_file_bytes {
            log::warn!(
                "skipping oversized tar entry {:?}: {} bytes (limit {})",
                relative_path,
                buf.len(),
                config.max_file_bytes
            );
            continue;
        }

        if total_bytes + buf.len() > config.max_total_bytes {
            log::warn!(
                "total size limit reached: {} + {} > {}, stopping extraction",
                total_bytes,
                buf.len(),
                config.max_total_bytes
            );
            break;
        }

        total_bytes += buf.len();
        let contents = String::from_utf8_lossy(&buf).into_owned();
        let role = classify_file(&relative_path, ecosystem);

        files.push(FileEntry {
            relative_path,
            contents,
            role,
        });
    }

    Ok(PackageContents { files, ecosystem })
}

// ── In-memory ZIP extraction (wheels / .whl) ────────────────────────────

pub fn extract_zip_in_memory(
    data: &[u8],
    config: &ExtractionConfig,
    ecosystem: Ecosystem,
) -> Result<PackageContents, ExtractionError> {
    let cursor = std::io::Cursor::new(data);
    let mut archive =
        zip::ZipArchive::new(cursor).map_err(|e| ExtractionError::InvalidArchive(e.to_string()))?;

    let mut files: Vec<FileEntry> = Vec::new();
    let mut total_bytes: usize = 0;

    for i in 0..archive.len() {
        if files.len() >= config.max_entries {
            log::warn!(
                "entry limit reached: {} (limit {}), skipping remaining",
                files.len(),
                config.max_entries
            );
            break;
        }

        let mut zip_file = archive
            .by_index(i)
            .map_err(|e| ExtractionError::Io(format!("failed to open zip entry {}: {}", i, e)))?;

        if zip_file.is_dir() {
            continue;
        }

        let raw_path = zip_file.name().to_string();
        let relative_path = match sanitize_relative_path(&raw_path) {
            Some(p) => p,
            None => continue,
        };

        let mut buf = Vec::new();
        let read_limit = config.max_file_bytes + 1;
        let mut limited_reader = std::io::Read::take(&mut zip_file, read_limit as u64);
        limited_reader.read_to_end(&mut buf).map_err(|e| {
            ExtractionError::Io(format!(
                "failed to read zip entry {:?}: {}",
                relative_path, e
            ))
        })?;

        if buf.len() > config.max_file_bytes {
            log::warn!(
                "skipping oversized zip entry {:?}: {} bytes (limit {})",
                relative_path,
                buf.len(),
                config.max_file_bytes
            );
            continue;
        }

        if total_bytes + buf.len() > config.max_total_bytes {
            log::warn!(
                "total size limit reached: {} + {} > {}, stopping extraction",
                total_bytes,
                buf.len(),
                config.max_total_bytes
            );
            break;
        }

        total_bytes += buf.len();
        let contents = String::from_utf8_lossy(&buf).into_owned();
        let role = classify_file(&relative_path, ecosystem);

        files.push(FileEntry {
            relative_path,
            contents,
            role,
        });
    }

    Ok(PackageContents { files, ecosystem })
}

// ── Ecosystem-aware file classification ──────────────────────────────────

pub fn classify_file(path: &Path, ecosystem: Ecosystem) -> FileRole {
    let fname = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let fname_lower = fname.to_lowercase();

    match ecosystem {
        Ecosystem::PyPI => classify_pypi_file(path, &fname, &fname_lower),
        Ecosystem::Npm => classify_npm_file(path, &fname, &fname_lower),
    }
}

fn classify_pypi_file(path: &Path, fname: &str, fname_lower: &str) -> FileRole {
    match fname {
        "setup.py" | "__main__.py" => return FileRole::EntryScript,
        _ => {}
    }
    if fname_lower == "pyproject.toml" {
        return FileRole::EntryScript;
    }
    if fname_lower == "setup.cfg" || fname_lower == "manifest.in" || fname_lower == "pkg-info" {
        return FileRole::Config;
    }
    if path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("py"))
    {
        return FileRole::Source;
    }
    if path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("sh"))
    {
        return FileRole::Script;
    }
    if fname_lower == "pkg-info" {
        return FileRole::Config;
    }
    FileRole::Other
}

fn classify_npm_file(path: &Path, fname: &str, _fname_lower: &str) -> FileRole {
    if fname == "package.json" {
        return FileRole::EntryScript;
    }
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().into_owned())
        .unwrap_or_default();
    match ext.as_str() {
        "js" | "mjs" | "cjs" => return FileRole::Source,
        "ts" => return FileRole::Source,
        _ => {}
    }
    FileRole::Other
}

// ── Source bundle builder (replaces extract_source_for_analysis) ────────

pub fn build_source_bundle(contents: &PackageContents, budget: usize) -> SourceBundle {
    let mut sorted: Vec<&FileEntry> = contents.files.iter().collect();
    sorted.sort_by_key(|e| e.role);

    let mut entries: Vec<BundleEntry> = Vec::new();
    let mut total_bytes: usize = 0;
    let mut truncated = false;

    let role_tag = |role: FileRole| -> &'static str {
        match role {
            FileRole::EntryScript => "entry-script",
            FileRole::Config => "config",
            FileRole::Script => "script",
            FileRole::Source => "source",
            FileRole::Other => "other",
        }
    };

    for entry in sorted {
        let is_high_priority = matches!(entry.role, FileRole::EntryScript | FileRole::Config);
        let content_len = entry.contents.len();

        if is_high_priority {
            entries.push(BundleEntry {
                path: entry.relative_path.clone(),
                role_tag: role_tag(entry.role).to_string(),
                contents: entry.contents.clone(),
            });
            total_bytes += content_len;
        } else {
            if total_bytes + content_len > budget {
                if content_len > 0 && total_bytes < budget {
                    let remaining = budget.saturating_sub(total_bytes);
                    if remaining > 0 {
                        let content = if is_suspicious_region(&entry.contents) {
                            let start = find_suspicious_offset(&entry.contents, remaining);
                            extract_region(&entry.contents, start, remaining)
                        } else {
                            entry.contents.chars().take(remaining).collect()
                        };
                        entries.push(BundleEntry {
                            path: entry.relative_path.clone(),
                            role_tag: role_tag(entry.role).to_string(),
                            contents: format!(
                                "{}... (truncated from {} bytes)",
                                content, content_len
                            ),
                        });
                        total_bytes = budget;
                    }
                }
                truncated = true;
                continue;
            }
            entries.push(BundleEntry {
                path: entry.relative_path.clone(),
                role_tag: role_tag(entry.role).to_string(),
                contents: entry.contents.clone(),
            });
            total_bytes += content_len;
        }
    }

    SourceBundle {
        entries,
        total_bytes,
        truncated,
    }
}

fn find_suspicious_offset(content: &str, window: usize) -> usize {
    let indicators = [
        "eval(",
        "exec(",
        "Function(",
        "base64",
        "subprocess",
        "os.system",
        "os.popen",
        "child_process",
        "require('child_process",
    ];
    let lower = content.to_lowercase();
    for ind in &indicators {
        if let Some(pos) = lower.find(ind) {
            let char_pos = content[..pos]
                .char_indices()
                .last()
                .map(|(i, _)| i)
                .unwrap_or(0);
            let max_start = content.len().saturating_sub(window);
            return char_pos.min(max_start);
        }
    }
    0
}

fn extract_region(content: &str, start: usize, max_len: usize) -> String {
    let mut result = String::new();
    let mut byte_pos = 0;
    let mut char_count = 0;

    for ch in content.chars() {
        if byte_pos >= start {
            if char_count >= max_len {
                break;
            }
            result.push(ch);
            char_count += ch.len_utf8();
        }
        byte_pos += ch.len_utf8();
    }
    result
}

// ── Format source bundle as a string for LLM prompt ─────────────────────

pub fn format_source_bundle(bundle: &SourceBundle) -> String {
    let mut out = String::new();
    for entry in &bundle.entries {
        out.push_str(&format!(
            "\n# File: {} [{}]\n{}\n",
            entry.path.display(),
            entry.role_tag,
            entry.contents
        ));
    }
    out
}

// ── Download and extract (main entry points) ─────────────────────────────

pub async fn download_and_extract_package(
    package_name: &str,
    package_version: Option<&str>,
) -> Result<PackageContents, Box<dyn std::error::Error>> {
    let config = ExtractionConfig::default();
    download_and_extract_package_with_config(package_name, package_version, &config).await
}

pub async fn download_and_extract_package_with_config(
    package_name: &str,
    package_version: Option<&str>,
    config: &ExtractionConfig,
) -> Result<PackageContents, Box<dyn std::error::Error>> {
    let url = if let Some(version) = package_version {
        log::info!(
            "Fetching download URL for '{}' version {}...",
            package_name,
            version
        );
        match fetch_download_url(package_name, version).await {
            Ok(url) => url,
            Err(e) => {
                log::warn!("Could not fetch download URL: {}", e);
                return download_package_fallback_with_config(package_name, config).await;
            }
        }
    } else {
        log::info!("Fetching latest version of '{}' from PyPI...", package_name);
        match fetch_download_url_latest(package_name).await {
            Ok((version, url)) => {
                log::info!("Found version: {}", version);
                url
            }
            Err(e) => {
                log::warn!("Could not fetch download URL from PyPI: {}", e);
                log::info!("Trying fallback URL without version...");
                return download_package_fallback_with_config(package_name, config).await;
            }
        }
    };

    log::info!("Downloading package from: {}", url);
    let package_data = download_bytes(&url).await?;
    extract_archive_in_memory(&package_data, &url, config, Ecosystem::PyPI)
}

async fn download_package_fallback_with_config(
    package_name: &str,
    config: &ExtractionConfig,
) -> Result<PackageContents, Box<dyn std::error::Error>> {
    log::info!("Using fallback: fetching package links from PyPI simple API");
    let simple_url = format!("https://pypi.org/simple/{}/", package_name);

    let response = reqwest::Client::new()
        .get(&simple_url)
        .send()
        .await
        .map_err(|e| format!("Fallback failed - could not access PyPI simple API: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Package '{}' not found on PyPI (HTTP {})",
            package_name,
            response.status()
        )
        .into());
    }

    let html = response.text().await?;
    let distribution_url = html
        .lines()
        .find(|line| line.contains(".tar.gz") && line.contains("href="))
        .and_then(extract_href)
        .or_else(|| {
            html.lines()
                .find(|line| line.contains(".whl") && line.contains("href="))
                .and_then(extract_href)
        });

    if let Some(dist_url) = distribution_url {
        log::info!("Found package at: {}", dist_url);
        let package_data = download_bytes(&dist_url).await?;
        return extract_archive_in_memory(&package_data, &dist_url, config, Ecosystem::PyPI);
    }

    Err(format!(
        "Could not find source distribution (.tar.gz) or wheel (.whl) for '{}' on PyPI",
        package_name
    )
    .into())
}

async fn download_bytes(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let response = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Failed to download package: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Failed to download package - HTTP {}: {}",
            response.status(),
            url
        )
        .into());
    }

    let bytes = response.bytes().await?;
    Ok(bytes.to_vec())
}

fn extract_archive_in_memory(
    data: &[u8],
    url: &str,
    config: &ExtractionConfig,
    ecosystem: Ecosystem,
) -> Result<PackageContents, Box<dyn std::error::Error>> {
    if url.ends_with(".tar.gz") || url.ends_with(".tgz") {
        log::debug!("Extracting tar.gz archive in-memory");
        extract_tar_gz_in_memory(data, config, ecosystem)
            .map_err(|e| format!("tar.gz extraction failed: {}", e).into())
    } else if url.ends_with(".whl") || url.ends_with(".zip") {
        log::debug!("Extracting wheel/zip archive in-memory");
        extract_zip_in_memory(data, config, ecosystem)
            .map_err(|e| format!("zip extraction failed: {}", e).into())
    } else {
        Err("Unsupported distribution format (expected .tar.gz, .tgz, .whl, or .zip)".into())
    }
}

// ── PyPI JSON API helpers ────────────────────────────────────────────────

async fn fetch_download_url(
    package_name: &str,
    version: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let url = format!("https://pypi.org/pypi/{}/json", package_name);
    let response = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch PyPI data for '{}': {}", package_name, e))?;

    if !response.status().is_success() {
        return Err(format!(
            "PyPI API returned status {} for package '{}' - package may not exist",
            response.status(),
            package_name
        )
        .into());
    }

    let json_data: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse PyPI JSON response: {}", e))?;

    if let Some(releases) = json_data["releases"][version].as_array() {
        let mut wheel_url: Option<String> = None;
        for release in releases {
            if let Some(filename) = release["filename"].as_str() {
                if filename.ends_with(".tar.gz") {
                    if let Some(download_url) = release["url"].as_str() {
                        return Ok(download_url.to_string());
                    }
                } else if filename.ends_with(".whl") && wheel_url.is_none() {
                    wheel_url = release["url"].as_str().map(|s| s.to_string());
                }
            }
        }
        if let Some(url) = wheel_url {
            return Ok(url);
        }
    }

    Err(format!(
        "Could not find source distribution (.tar.gz) or wheel (.whl) for '{}' version '{}' on PyPI",
        package_name, version
    )
    .into())
}

async fn fetch_download_url_latest(
    package_name: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let url = format!("https://pypi.org/pypi/{}/json", package_name);
    let response = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch PyPI data for '{}': {}", package_name, e))?;

    if !response.status().is_success() {
        return Err(format!(
            "PyPI API returned status {} for package '{}' - package may not exist",
            response.status(),
            package_name
        )
        .into());
    }

    let json_data: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse PyPI JSON response: {}", e))?;

    let version = json_data["info"]["version"]
        .as_str()
        .ok_or_else(|| format!("Could not extract version from PyPI for '{}'", package_name))?
        .to_string();

    if let Some(releases) = json_data["releases"][&version].as_array() {
        let mut wheel_url: Option<String> = None;
        for release in releases {
            if let Some(filename) = release["filename"].as_str() {
                if filename.ends_with(".tar.gz") {
                    if let Some(download_url) = release["url"].as_str() {
                        return Ok((version, download_url.to_string()));
                    }
                } else if filename.ends_with(".whl") && wheel_url.is_none() {
                    wheel_url = release["url"].as_str().map(|s| s.to_string());
                }
            }
        }
        if let Some(url) = wheel_url {
            return Ok((version, url));
        }
    }

    Err(format!(
        "Could not find source distribution (.tar.gz) or wheel (.whl) for '{}' on PyPI",
        package_name
    )
    .into())
}

/// Extract href value from HTML line
fn extract_href(line: &str) -> Option<String> {
    if let Some(start) = line.find("href=\"")
        && let Some(end) = line[start + 6..].find('"')
    {
        return Some(line[start + 6..start + 6 + end].to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_pypi_entry_script() {
        assert_eq!(
            classify_file(Path::new("pkg/setup.py"), Ecosystem::PyPI),
            FileRole::EntryScript
        );
        assert_eq!(
            classify_file(Path::new("pkg/__main__.py"), Ecosystem::PyPI),
            FileRole::EntryScript
        );
        assert_eq!(
            classify_file(Path::new("pkg/pyproject.toml"), Ecosystem::PyPI),
            FileRole::EntryScript
        );
    }

    #[test]
    fn test_classify_pypi_config() {
        assert_eq!(
            classify_file(Path::new("pkg/setup.cfg"), Ecosystem::PyPI),
            FileRole::Config
        );
        assert_eq!(
            classify_file(Path::new("pkg/PKG-INFO"), Ecosystem::PyPI),
            FileRole::Config
        );
    }

    #[test]
    fn test_classify_pypi_source() {
        assert_eq!(
            classify_file(Path::new("pkg/module.py"), Ecosystem::PyPI),
            FileRole::Source
        );
    }

    #[test]
    fn test_classify_pypi_script() {
        assert_eq!(
            classify_file(Path::new("pkg/scripts/build.sh"), Ecosystem::PyPI),
            FileRole::Script
        );
    }

    #[test]
    fn test_classify_npm_entry() {
        assert_eq!(
            classify_file(Path::new("pkg/package.json"), Ecosystem::Npm),
            FileRole::EntryScript
        );
    }

    #[test]
    fn test_classify_npm_source() {
        assert_eq!(
            classify_file(Path::new("pkg/index.js"), Ecosystem::Npm),
            FileRole::Source
        );
        assert_eq!(
            classify_file(Path::new("pkg/app.ts"), Ecosystem::Npm),
            FileRole::Source
        );
    }

    #[test]
    fn test_sanitize_relative_path_normal() {
        let result = sanitize_relative_path("pkg/module.py");
        assert_eq!(result, Some(PathBuf::from("pkg/module.py")));
    }

    #[test]
    fn test_sanitize_relative_path_traversal() {
        let result = sanitize_relative_path("../../etc/passwd");
        assert!(result.is_none());
    }

    #[test]
    fn test_sanitize_relative_path_absolute() {
        let result = sanitize_relative_path("/etc/passwd");
        assert!(result.is_none());
    }

    #[test]
    fn test_sanitize_relative_path_mix() {
        let result = sanitize_relative_path("pkg/../etc/passwd");
        assert!(result.is_none());
    }

    #[test]
    fn test_build_source_bundle_priority_ordering() {
        let config = ExtractionConfig::default();
        let contents = PackageContents {
            files: vec![
                FileEntry {
                    relative_path: PathBuf::from("pkg/utils.py"),
                    contents: "import os".to_string(),
                    role: FileRole::Source,
                },
                FileEntry {
                    relative_path: PathBuf::from("pkg/setup.py"),
                    contents: "from setuptools import setup".to_string(),
                    role: FileRole::EntryScript,
                },
                FileEntry {
                    relative_path: PathBuf::from("pkg/README"),
                    contents: "readme".to_string(),
                    role: FileRole::Other,
                },
            ],
            ecosystem: Ecosystem::PyPI,
        };

        let bundle = build_source_bundle(&contents, config.max_total_bytes);
        assert_eq!(bundle.entries.len(), 3);
        assert_eq!(bundle.entries[0].role_tag, "entry-script");
        assert_eq!(bundle.entries[1].role_tag, "source");
        assert_eq!(bundle.entries[2].role_tag, "other");
    }

    #[test]
    fn test_build_source_bundle_no_truncation_of_entry_scripts() {
        let config = ExtractionConfig {
            max_total_bytes: 50,
            max_file_bytes: 2_097_152,
            max_entries: 5000,
        };
        let big_content = "x".repeat(100);
        let contents = PackageContents {
            files: vec![FileEntry {
                relative_path: PathBuf::from("setup.py"),
                contents: big_content.clone(),
                role: FileRole::EntryScript,
            }],
            ecosystem: Ecosystem::PyPI,
        };

        let bundle = build_source_bundle(&contents, 50);
        assert_eq!(bundle.entries[0].contents.len(), 100);
        assert!(!bundle.entries[0].contents.contains("truncated"));
    }

    #[test]
    fn test_build_source_bundle_truncates_source_when_over_budget() {
        let config = ExtractionConfig {
            max_total_bytes: 30,
            max_file_bytes: 2_097_152,
            max_entries: 5000,
        };
        let contents = PackageContents {
            files: vec![FileEntry {
                relative_path: PathBuf::from("module.py"),
                contents: "a".repeat(100),
                role: FileRole::Source,
            }],
            ecosystem: Ecosystem::PyPI,
        };

        let bundle = build_source_bundle(&contents, 30);
        assert!(bundle.truncated);
        assert!(bundle.entries[0].contents.contains("truncated"));
    }

    #[test]
    fn test_extraction_config_defaults() {
        let config = ExtractionConfig::default();
        assert_eq!(config.max_total_bytes, 67_108_864);
        assert_eq!(config.max_file_bytes, 2_097_152);
        assert_eq!(config.max_entries, 5000);
    }
}
