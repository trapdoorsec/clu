#![allow(dead_code)]

use crate::config::{Config, FeedConfig};
use crate::feed::pypi::PythonPackage;
use levenshtein::levenshtein;
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Debug, Deserialize)]
struct PopularPackagesResponse {
    #[allow(dead_code)]
    last_update: String,
    #[allow(dead_code)]
    source: String,
    #[allow(dead_code)]
    meta: Vec<String>,
    rows: Vec<PackageRow>,
}

#[derive(Debug, Deserialize, Clone)]
struct PackageRow {
    #[allow(dead_code)]
    download_count: String,
    project: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct TypoSquatterMatch {
    pub rule_name: String,
    pub risk_score: u8,
    pub confidence: f32,
    pub evidence: String,
    pub legit_package_name: String,
}

async fn get_popular_packages(conf: &FeedConfig) -> Result<Vec<PackageRow>, Box<dyn Error>> {
    let url = &conf.popular_packages_endpoint;

    let response = reqwest::get(url)
        .await
        .map_err(|e| format!("Failed to fetch popular packages list: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Failed to fetch popular packages - HTTP {}: {}",
            response.status(),
            url
        ).into());
    }

    let json: PopularPackagesResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse popular packages JSON: {}", e))?;

    let top_1000: Vec<PackageRow> = json.rows.into_iter().take(1000).collect();
    Ok(top_1000)
}

/// Calculate Levenshtein distance between two strings (uses references - no cloning)
#[inline]
fn get_levenshtein_distance(str1: &str, str2: &str) -> usize {
    levenshtein(str1, str2)
}

/// Calculate risk score based on distance
fn calculate_risk_score(distance: usize) -> u8 {
    match distance {
        1 => 90, // Very suspicious - 1 char off
        2 => 75, // Suspicious - 2 chars off
        3 => 60, // Moderately suspicious
        _ => 40, // Less suspicious but still flagged
    }
}

/// Calculate confidence based on distance and package name length
fn calculate_confidence(distance: usize, pkg_len: usize) -> f32 {
    // Higher confidence for longer package names with small distance
    let base_confidence = 1.0 - (distance as f32 / pkg_len as f32);
    (base_confidence * 100.0).min(95.0) // Cap at 95%
}

pub async fn find_typosquatters(
    new_packages: Vec<PythonPackage>,
    config: &Config,
) -> Result<Vec<TypoSquatterMatch>, Box<dyn Error>> {
    let threshold = config.analysis.typosquat_distance_threshold;
    let min_len = config.analysis.min_package_length;

    // Fetch popular packages once
    let popular_packages = get_popular_packages(&config.feed).await?;
    let mut typosquats: Vec<TypoSquatterMatch> = Vec::new();

    // Iterate over new packages
    for new_pkg in &new_packages {
        // Extract package name, skip if missing
        let new_pkg_name = match &new_pkg.title {
            Some(name) => name.as_str(),
            None => continue,
        };

        // Skip short package names (too many false positives)
        if new_pkg_name.len() < min_len {
            continue;
        }

        // Check against all popular packages (use reference to avoid cloning!)
        for pop_pkg in &popular_packages {
            let distance = get_levenshtein_distance(new_pkg_name, &pop_pkg.project);

            // Found a potential typosquat
            if distance > 0 && distance <= threshold {
                let pkg_len = new_pkg_name.len();
                let risk_score = calculate_risk_score(distance);
                let confidence = calculate_confidence(distance, pkg_len);

                let squat = TypoSquatterMatch {
                    rule_name: "typosquat_detection".to_string(),
                    risk_score,
                    confidence,
                    evidence: format!(
                        "'{}' differs by {} character(s) from '{}'",
                        new_pkg_name, distance, pop_pkg.project
                    ),
                    legit_package_name: pop_pkg.project.clone(),
                };

                typosquats.push(squat);

                // Only report the closest match per new package
                break;
            }
        }
    }

    Ok(typosquats)
}
