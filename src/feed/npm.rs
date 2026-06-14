use crate::feed::ecosystem::Ecosystem;
use crate::feed::ecosystem::PackageRef;
use serde::Deserialize;
use std::error::Error;

#[derive(Debug, Deserialize)]
struct ChangesResponse {
    results: Vec<ChangeEntry>,
    last_seq: String,
}

#[derive(Debug, Deserialize)]
struct ChangeEntry {
    id: String,
    changes: Vec<ChangeRev>,
}

#[derive(Debug, Deserialize)]
struct ChangeRev {
    rev: String,
}

#[derive(Debug, Deserialize)]
struct NpmPackageMetadata {
    name: Option<String>,
    description: Option<String>,
    #[serde(default)]
    versions: std::collections::HashMap<String, NpmVersionInfo>,
}

#[derive(Debug, Deserialize)]
struct NpmVersionInfo {
    #[serde(default)]
    dist: Option<NpmDist>,
}

#[derive(Debug, Deserialize)]
struct NpmDist {
    tarball: Option<String>,
}

pub async fn fetch_npm_changes(
    since: Option<&str>,
) -> Result<(Vec<PackageRef>, String), Box<dyn Error>> {
    let url = match since {
        Some(seq) => format!(
            "https://replicate.npmjs.com/_changes?since={}&limit=50",
            seq
        ),
        None => "https://replicate.npmjs.com/_changes?limit=50".to_string(),
    };

    let response = reqwest::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!("npm _changes request failed: HTTP {}", response.status()).into());
    }

    let changes: ChangesResponse = response.json().await?;
    let last_seq = changes.last_seq;

    let mut packages = Vec::new();
    for entry in &changes.results {
        let pkg_id = &entry.id;
        if pkg_id.starts_with('_') {
            continue;
        }

        match resolve_npm_metadata(pkg_id).await {
            Ok(meta) => {
                let latest_version = meta
                    .versions
                    .keys()
                    .max_by(|a, b| semver_cmp(a, b))
                    .cloned();

                packages.push(PackageRef {
                    ecosystem: Ecosystem::Npm,
                    name: meta.name.clone().unwrap_or_else(|| pkg_id.clone()),
                    version: latest_version,
                    title: meta.name.clone(),
                    description: meta.description.clone(),
                    link: Some(format!("https://www.npmjs.com/package/{}", pkg_id)),
                    author: None,
                    published_date: None,
                });
            }
            Err(e) => {
                log::warn!("npm: failed to resolve metadata for {}: {}", pkg_id, e);
                packages.push(PackageRef {
                    ecosystem: Ecosystem::Npm,
                    name: pkg_id.clone(),
                    version: None,
                    title: Some(pkg_id.clone()),
                    description: None,
                    link: Some(format!("https://www.npmjs.com/package/{}", pkg_id)),
                    author: None,
                    published_date: None,
                });
            }
        }
    }

    Ok((packages, last_seq))
}

async fn resolve_npm_metadata(package_name: &str) -> Result<NpmPackageMetadata, Box<dyn Error>> {
    let url = format!("https://registry.npmjs.org/{}", package_name);
    let response = reqwest::Client::new()
        .get(&url)
        .header("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!(
            "npm registry returned HTTP {} for {}",
            response.status(),
            package_name
        )
        .into());
    }

    let meta: NpmPackageMetadata = response.json().await?;
    Ok(meta)
}

fn semver_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let parse_parts = |v: &str| -> Vec<u32> {
        v.trim_start_matches('v')
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect()
    };
    let a_parts = parse_parts(a);
    let b_parts = parse_parts(b);
    a_parts.cmp(&b_parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semver_cmp() {
        assert_eq!(semver_cmp("1.0.0", "2.0.0"), std::cmp::Ordering::Less);
        assert_eq!(semver_cmp("2.0.0", "1.0.0"), std::cmp::Ordering::Greater);
        assert_eq!(semver_cmp("1.0.0", "1.0.0"), std::cmp::Ordering::Equal);
        assert_eq!(semver_cmp("1.2.3", "1.2.4"), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_changes_response_deserialize() {
        let json =
            r#"{"results":[{"id":"express","changes":[{"rev":"1-abc"}]}],"last_seq":"42-g1AAAAF"}"#;
        let resp: ChangesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.results.len(), 1);
        assert_eq!(resp.results[0].id, "express");
        assert_eq!(resp.last_seq, "42-g1AAAAF");
    }

    #[test]
    fn test_npm_metadata_deserialize() {
        let json = r#"{"name":"lodash","description":"Lodash modular utilities","versions":{"4.17.21":{}}}"#;
        let meta: NpmPackageMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.name, Some("lodash".to_string()));
        assert!(meta.versions.contains_key("4.17.21"));
    }
}
