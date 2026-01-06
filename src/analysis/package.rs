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
    // Build PyPI package URL
    let url = if let Some(version) = package_version {
        format!(
            "https://files.pythonhosted.org/packages/source/{}/{}-{}.tar.gz",
            &package_name.chars().next().unwrap().to_lowercase(),
            package_name,
            version
        )
    } else {
        // Fetch latest version from PyPI
        let latest_version = fetch_latest_version(package_name).await?;
        format!(
            "https://files.pythonhosted.org/packages/source/{}/{}-{}.tar.gz",
            &package_name.chars().next().unwrap().to_lowercase(),
            package_name,
            latest_version
        )
    };

    // Download package
    let package_data = reqwest::Client::new()
        .get(&url)
        .send()
        .await?
        .bytes()
        .await?;

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

/// Fetch latest version from PyPI JSON API
async fn fetch_latest_version(package_name: &str) -> Result<String, Box<dyn Error>> {
    let url = format!("https://pypi.org/pypi/{}/json", package_name);

    let response = reqwest::Client::new()
        .get(&url)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    let version = response["info"]["version"]
        .as_str()
        .ok_or("Could not extract version from PyPI")?;

    Ok(version.to_string())
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
