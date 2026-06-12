#![allow(dead_code)]

use crate::config::{Config, FeedConfig};
use crate::feed::ecosystem::PackageRef;
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
    #[serde(default)]
    meta: serde_json::Value, // Changed from Vec<String> to accept any format
    rows: Vec<PackageRow>,
}

#[derive(Debug, Deserialize, Clone)]
struct PackageRow {
    #[allow(dead_code)]
    download_count: u64, // Changed from String to u64 (actual API returns integer)
    project: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TypoSquatterMatch {
    pub rule_name: String,
    pub risk_score: u8,
    pub confidence: f32,
    pub evidence: String,
    pub legit_package_name: String,
}

async fn get_popular_packages(conf: &FeedConfig) -> Vec<PackageRow> {
    let url = &conf.popular_packages_endpoint;

    log::debug!("Fetching popular packages from: {}", url);

    // Attempt to fetch popular packages, but gracefully degrade if endpoint is unavailable
    match reqwest::get(url).await {
        Ok(response) => {
            let status = response.status();
            if !status.is_success() {
                match response.text().await {
                    Ok(body) => {
                        log::warn!("HTTP {} from popular packages endpoint", status);
                        log::warn!(
                            "Response (first 200 chars): {}",
                            if body.len() > 200 {
                                &body[..200]
                            } else {
                                &body
                            }
                        );
                    }
                    Err(e) => {
                        log::warn!("HTTP {} - could not read response body: {}", status, e);
                    }
                }
                log::info!("Typosquat detection disabled - endpoint unavailable");
                return Vec::new();
            }

            match response.json::<PopularPackagesResponse>().await {
                Ok(json) => {
                    log::debug!("Successfully fetched {} popular packages", json.rows.len());
                    json.rows.into_iter().take(1000).collect()
                }
                Err(e) => {
                    log::warn!("Failed to parse popular packages JSON: {}", e);
                    log::debug!("JSON parse error details: {:?}", e);
                    log::info!("Typosquat detection disabled - invalid response format");
                    Vec::new()
                }
            }
        }
        Err(e) => {
            log::warn!("Failed to fetch popular packages list: {}", e);
            log::info!("Typosquat detection disabled - network error");
            Vec::new()
        }
    }
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
    new_packages: &[PackageRef],
    config: &Config,
) -> Result<Vec<TypoSquatterMatch>, Box<dyn Error>> {
    let threshold = config.analysis.typosquat_distance_threshold;
    let min_len = config.analysis.min_package_length;

    // Fetch popular packages - gracefully degrades to empty list if endpoint unavailable
    let popular_packages = get_popular_packages(&config.feed).await;

    if popular_packages.is_empty() {
        log::warn!("Typosquat stage skipped - no popular packages available for comparison");
        return Ok(Vec::new());
    }

    let mut typosquats: Vec<TypoSquatterMatch> = Vec::new();

    // Iterate over new packages
    for new_pkg in new_packages {
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
