//! Package download and extraction utilities
//! Handles downloading Python packages from PyPI and extracting source code

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;
use walkdir::WalkDir;

/// Downloaded and extracted package contents
pub struct PackageContents {
    /// Temporary directory holding extracted package (kept alive while struct exists)
    #[allow(dead_code)]
    pub source_dir: TempDir,
    pub python_files: Vec<PathBuf>,
}

/// Try to find package in pip cache first, to avoid re-downloading
fn try_find_in_pip_cache(package_name: &str, cache_dir: &str) -> Option<Vec<u8>> {
    log::debug!("Checking pip cache at: {}", cache_dir);

    // Pip typically caches packages in http-v2/ or http/ subdirectories
    let cache_paths = vec![
        format!("{}/http-v2", cache_dir),
        format!("{}/http", cache_dir),
    ];

    for cache_path in cache_paths {
        if let Ok(entries) = fs::read_dir(&cache_path) {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata()
                    && metadata.is_dir()
                {
                    // Check inside each hash directory
                    if let Ok(files) = fs::read_dir(entry.path()) {
                        for file in files.flatten() {
                            let file_name = file.file_name();
                            let name_str = file_name.to_string_lossy();

                            // Look for files matching the package name
                            if name_str.contains(package_name)
                                && (name_str.ends_with(".tar.gz") || name_str.ends_with(".whl"))
                            {
                                log::debug!("Found package in cache: {}", name_str);
                                if let Ok(data) = fs::read(file.path()) {
                                    return Some(data);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

/// Download package from PyPI and extract
pub async fn download_and_extract_package(
    package_name: &str,
    package_version: Option<&str>,
) -> Result<PackageContents, Box<dyn Error>> {
    // Get cache directory from environment or use default
    let cache_dir = std::env::var("PIP_CACHE_DIR").unwrap_or_else(|_| "/tmp/pip-cache".to_string());

    // First try to find package in shared pip cache (e.g., from GuardDog)
    if let Some(package_data) = try_find_in_pip_cache(package_name, &cache_dir) {
        log::info!("Found package in cache, extracting...");
        let temp_dir = TempDir::new()?;
        let tar = flate2::read::GzDecoder::new(&package_data[..]);
        let mut archive = tar::Archive::new(tar);
        archive.unpack(temp_dir.path())?;
        let python_files = find_python_files(temp_dir.path())?;
        return Ok(PackageContents {
            source_dir: temp_dir,
            python_files,
        });
    }

    // Cache miss - fetch download URL from PyPI JSON API
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
                return download_package_fallback(package_name).await;
            }
        }
    } else {
        // Fetch latest version and its download URL from PyPI
        log::info!("Fetching latest version of '{}' from PyPI...", package_name);
        match fetch_download_url_latest(package_name).await {
            Ok((version, url)) => {
                log::info!("Found version: {}", version);
                url
            }
            Err(e) => {
                log::warn!("Could not fetch download URL from PyPI: {}", e);
                log::info!("Trying fallback URL without version...");
                // Fallback: try to download from PyPI files without knowing exact version
                return download_package_fallback(package_name).await;
            }
        }
    };

    log::info!("Downloading package from: {}", url);

    // Download package
    let response = reqwest::Client::new()
        .get(&url)
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

    let package_data = response.bytes().await?;
    let temp_dir = TempDir::new()?;

    // Extract based on file type (tar.gz or wheel)
    if url.ends_with(".tar.gz") {
        log::debug!("Extracting tar.gz archive");
        let tar = flate2::read::GzDecoder::new(&package_data[..]);
        let mut archive = tar::Archive::new(tar);
        archive.unpack(temp_dir.path())?;
    } else if url.ends_with(".whl") {
        log::debug!("Extracting wheel archive");
        extract_wheel(&package_data, temp_dir.path())?;
    } else {
        return Err("Unsupported distribution format (expected .tar.gz or .whl)".into());
    }

    // Find all Python files
    let python_files = find_python_files(temp_dir.path())?;

    Ok(PackageContents {
        source_dir: temp_dir,
        python_files,
    })
}

/// Fallback download method using PyPI simple API
/// This is less reliable but doesn't require knowing the exact version
async fn download_package_fallback(package_name: &str) -> Result<PackageContents, Box<dyn Error>> {
    log::info!("Using fallback: fetching package links from PyPI simple API");

    // Try the simple API to get available downloads
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

    // Prefer .tar.gz (source distribution), but fall back to .whl (wheel)
    let distribution_url = html
        .lines()
        .find(|line| line.contains(".tar.gz") && line.contains("href="))
        .and_then(extract_href)
        .or_else(|| {
            // Fall back to wheel file if no source distribution
            html.lines()
                .find(|line| line.contains(".whl") && line.contains("href="))
                .and_then(extract_href)
        });

    if let Some(dist_url) = distribution_url {
        log::info!("Found package at: {}", dist_url);

        let response = reqwest::Client::new().get(&dist_url).send().await?;

        if !response.status().is_success() {
            return Err("Failed to download from fallback URL".to_string().into());
        }

        let package_data = response.bytes().await?;
        let temp_dir = TempDir::new()?;

        // Extract based on file type
        if dist_url.ends_with(".tar.gz") {
            log::debug!("Extracting tar.gz archive");
            let tar = flate2::read::GzDecoder::new(&package_data[..]);
            let mut archive = tar::Archive::new(tar);
            archive.unpack(temp_dir.path())?;
        } else if dist_url.ends_with(".whl") {
            log::debug!("Extracting wheel archive");
            extract_wheel(&package_data, temp_dir.path())?;
        } else {
            return Err("Unsupported distribution format".into());
        }

        let python_files = find_python_files(temp_dir.path())?;

        return Ok(PackageContents {
            source_dir: temp_dir,
            python_files,
        });
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

/// Extract Python files from wheel archive (which is a ZIP file)
fn extract_wheel(data: &[u8], dest_path: &std::path::Path) -> Result<(), Box<dyn Error>> {
    use std::io::Cursor;
    use std::path::Path;
    use zip::ZipArchive;

    let cursor = Cursor::new(data);
    let mut archive = ZipArchive::new(cursor)?;

    // Extract all files to temp directory
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;

        // Get filename without path traversal attacks
        let file_name = file.name();
        let safe_name = Path::new(file_name)
            .components()
            .filter(|c| !matches!(c, std::path::Component::ParentDir))
            .collect::<std::path::PathBuf>();

        let outpath = dest_path.join(&safe_name);

        if file.is_dir() {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(parent) = outpath.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut outfile = fs::File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }
    }

    Ok(())
}

/// Find all .py files in a directory
fn find_python_files(root: &std::path::Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut files = Vec::new();

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "py"))
    {
        files.push(entry.path().to_path_buf());
    }

    Ok(files)
}

/// Extract Python source code for analysis (limited to first N files, max M bytes)
pub fn extract_source_for_analysis(
    package: &PackageContents,
    max_files: usize,
    max_bytes_per_file: usize,
) -> Result<String, Box<dyn Error>> {
    let mut combined_source = String::new();
    let mut file_count = 0;

    for file_path in package.python_files.iter().take(max_files) {
        if file_count >= max_files {
            break;
        }

        match fs::read_to_string(file_path) {
            Ok(content) => {
                // Truncate if too large, respecting UTF-8 character boundaries
                let truncated = if content.len() > max_bytes_per_file {
                    // Safely truncate by taking characters until we exceed byte limit
                    let mut safe_truncated = String::new();
                    for ch in content.chars() {
                        if safe_truncated.len() + ch.len_utf8() > max_bytes_per_file {
                            break;
                        }
                        safe_truncated.push(ch);
                    }
                    format!(
                        "{}\n... (truncated from {} bytes)",
                        safe_truncated,
                        content.len()
                    )
                } else {
                    content
                };

                combined_source.push_str(&format!(
                    "\n# File: {}\n{}\n",
                    file_path.display(),
                    truncated
                ));

                file_count += 1;
            }
            Err(e) => {
                // Log but continue if we can't read a file
                eprintln!("Warning: Could not read {}: {}", file_path.display(), e);
            }
        }
    }

    Ok(combined_source)
}

/// Fetch download URL for a specific package version from PyPI JSON API
async fn fetch_download_url(package_name: &str, version: &str) -> Result<String, Box<dyn Error>> {
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

    // Get the releases for the specific version
    if let Some(releases) = json_data["releases"][version].as_array() {
        // Prefer source distribution (.tar.gz), but accept wheel (.whl) as fallback
        let mut wheel_url: Option<String> = None;

        for release in releases {
            if let Some(filename) = release["filename"].as_str() {
                if filename.ends_with(".tar.gz") {
                    if let Some(download_url) = release["url"].as_str() {
                        return Ok(download_url.to_string());
                    }
                } else if filename.ends_with(".whl") && wheel_url.is_none() {
                    // Keep the first wheel found as fallback
                    wheel_url = release["url"].as_str().map(|s| s.to_string());
                }
            }
        }

        // If no tar.gz found, use wheel if available
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

/// Fetch latest version and its download URL from PyPI JSON API
async fn fetch_download_url_latest(package_name: &str) -> Result<(String, String), Box<dyn Error>> {
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

    // Get the latest version from info
    let version = json_data["info"]["version"]
        .as_str()
        .ok_or_else(|| format!("Could not extract version from PyPI for '{}'", package_name))?
        .to_string();

    // Get the releases for this version
    if let Some(releases) = json_data["releases"][&version].as_array() {
        // Prefer source distribution (.tar.gz), but accept wheel (.whl) as fallback
        let mut wheel_url: Option<String> = None;

        for release in releases {
            if let Some(filename) = release["filename"].as_str() {
                if filename.ends_with(".tar.gz") {
                    if let Some(download_url) = release["url"].as_str() {
                        return Ok((version, download_url.to_string()));
                    }
                } else if filename.ends_with(".whl") && wheel_url.is_none() {
                    // Keep the first wheel found as fallback
                    wheel_url = release["url"].as_str().map(|s| s.to_string());
                }
            }
        }

        // If no tar.gz found, use wheel if available
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_file_detection() {
        // This would require creating temp files
        // For now, just ensure the module compiles
    }
}
