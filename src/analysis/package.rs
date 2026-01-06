/// Package download and extraction utilities
/// Handles downloading Python packages from PyPI and extracting source code

use std::error::Error;
use std::path::PathBuf;
use std::fs;
use tempfile::TempDir;
use walkdir::WalkDir;

/// Downloaded and extracted package contents
pub struct PackageContents {
    /// Temporary directory holding extracted package (kept alive while struct exists)
    #[allow(dead_code)]
    pub source_dir: TempDir,
    pub python_files: Vec<PathBuf>,
}

/// Download package from PyPI and extract
pub async fn download_and_extract_package(
    package_name: &str,
    package_version: Option<&str>,
) -> Result<PackageContents, Box<dyn Error>> {
    // Fetch download URL from PyPI JSON API
    let url = if let Some(version) = package_version {
        eprintln!("[INFO] Fetching download URL for '{}' version {}...", package_name, version);
        match fetch_download_url(package_name, version).await {
            Ok(url) => url,
            Err(e) => {
                eprintln!("[WARN] Could not fetch download URL: {}", e);
                return download_package_fallback(package_name).await;
            }
        }
    } else {
        // Fetch latest version and its download URL from PyPI
        eprintln!("[INFO] Fetching latest version of '{}' from PyPI...", package_name);
        match fetch_download_url_latest(package_name).await {
            Ok((version, url)) => {
                eprintln!("[INFO] Found version: {}", version);
                url
            }
            Err(e) => {
                eprintln!("[WARN] Could not fetch download URL from PyPI: {}", e);
                eprintln!("[INFO] Trying fallback URL without version...");
                // Fallback: try to download from PyPI files without knowing exact version
                return download_package_fallback(package_name).await;
            }
        }
    };

    eprintln!("[INFO] Downloading package from: {}", url);

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

    // Extract to temp directory
    let temp_dir = TempDir::new()?;
    let tar = flate2::read::GzDecoder::new(&package_data[..]);
    let mut archive = tar::Archive::new(tar);
    archive.unpack(temp_dir.path())?;

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
    eprintln!("[INFO] Using fallback: fetching package links from PyPI simple API");

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

    // Look for first .tar.gz link in the HTML
    if let Some(tar_gz_url) = html.lines()
        .find(|line| line.contains(".tar.gz") && line.contains("href="))
        .and_then(|line| {
            // Extract href value
            if let Some(start) = line.find("href=\"") {
                if let Some(end) = line[start + 6..].find('"') {
                    return Some(line[start + 6..start + 6 + end].to_string());
                }
            }
            None
        })
    {
        eprintln!("[INFO] Found package at: {}", tar_gz_url);

        let response = reqwest::Client::new()
            .get(&tar_gz_url)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to download from fallback URL").into());
        }

        let package_data = response.bytes().await?;

        // Extract to temp directory
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

    Err(format!(
        "Could not find .tar.gz distribution for '{}' on PyPI",
        package_name
    )
    .into())
}

/// Find all .py files in a directory
fn find_python_files(root: &std::path::Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut files = Vec::new();

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "py"))
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
                // Truncate if too large
                let truncated = if content.len() > max_bytes_per_file {
                    format!(
                        "{}\n... (truncated from {} bytes)",
                        &content[..max_bytes_per_file],
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
                eprintln!(
                    "Warning: Could not read {}: {}",
                    file_path.display(),
                    e
                );
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
        // Find the source distribution (.tar.gz)
        for release in releases {
            if let Some(filename) = release["filename"].as_str() {
                if filename.ends_with(".tar.gz") {
                    if let Some(download_url) = release["url"].as_str() {
                        return Ok(download_url.to_string());
                    }
                }
            }
        }
    }

    Err(format!(
        "Could not find .tar.gz distribution for '{}' version '{}' on PyPI",
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
        .ok_or_else(|| {
            format!(
                "Could not extract version from PyPI for '{}'",
                package_name
            )
        })?
        .to_string();

    // Get the releases for this version
    if let Some(releases) = json_data["releases"][&version].as_array() {
        // Find the source distribution (.tar.gz)
        for release in releases {
            if let Some(filename) = release["filename"].as_str() {
                if filename.ends_with(".tar.gz") {
                    if let Some(download_url) = release["url"].as_str() {
                        return Ok((version, download_url.to_string()));
                    }
                }
            }
        }
    }

    Err(format!(
        "Could not find .tar.gz distribution for '{}' on PyPI",
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
