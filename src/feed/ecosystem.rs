//! Ecosystem abstraction: unified package reference and registry types.
//!
//! `Ecosystem` discriminates between package registries (PyPI, npm).
//! `PackageRef` is the cross-ecosystem package descriptor used throughout
//! the analysis pipeline. `PyPIRegistry` and `NpmRegistry` are the
//! concrete per-ecosystem implementations.

use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;

type FeedResult<'a> = Pin<Box<dyn Future<Output = Result<Vec<PackageRef>, Box<dyn std::error::Error>>> + Send + 'a>>;

// ── Ecosystem ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ecosystem {
    #[serde(rename = "pypi")]
    PyPI,
    #[serde(rename = "npm")]
    Npm,
}

// ── PackageRef ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PackageRef {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub link: Option<String>,
    pub author: Option<String>,
    pub published_date: Option<String>,
}

impl PackageRef {
    pub fn pypi_name(&self) -> &str {
        self.name.as_str()
    }
}

// ── Conversion from PythonPackage ───────────────────────────────────────

impl From<crate::feed::pypi::PythonPackage> for PackageRef {
    fn from(pkg: crate::feed::pypi::PythonPackage) -> Self {
        let name = pkg.title.clone().unwrap_or_default();
        PackageRef {
            ecosystem: Ecosystem::PyPI,
            name,
            version: None,
            title: pkg.title,
            description: pkg.description,
            link: pkg.link,
            author: pkg.author,
            published_date: pkg.published_date,
        }
    }
}

// ── PyPI Registry ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PyPIRegistry {
    pub feed_endpoint: String,
    pub popular_packages_endpoint: String,
}

impl PyPIRegistry {
    pub fn new(feed_endpoint: &str, popular_packages_endpoint: &str) -> Self {
        PyPIRegistry {
            feed_endpoint: feed_endpoint.to_string(),
            popular_packages_endpoint: popular_packages_endpoint.to_string(),
        }
    }

    pub fn ecosystem(&self) -> Ecosystem {
        Ecosystem::PyPI
    }

    pub fn fetch_feed(&self) -> FeedResult<'_> {
        let feed_url = self.feed_endpoint.clone();
        Box::pin(async move {
            let url = url::Url::parse(&feed_url)?;
            let channel = crate::feed::fetch_rss_raw(&url).await?;
            let packages = crate::feed::serialize_packages(channel);
            Ok(packages.into_iter().map(PackageRef::from).collect())
        })
    }
}

// ── Npm Registry (stub for Phase 3) ────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct NpmRegistry {
    pub since_cursor: Option<String>,
}

impl NpmRegistry {
    pub fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    pub fn fetch_feed(&self) -> FeedResult<'_> {
        let since = self.since_cursor.clone();
        Box::pin(async move {
            match crate::feed::npm::fetch_npm_changes(since.as_deref()).await {
                Ok((packages, _last_seq)) => Ok(packages),
                Err(e) => {
                    log::warn!("npm feed fetch failed: {}", e);
                    Ok(Vec::new())
                }
            }
        })
    }
}

// ── EcosystemsConfig ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcosystemsConfig {
    #[serde(default = "default_pypi_enabled")]
    pub pypi_enabled: bool,
    #[serde(default = "default_npm_enabled")]
    pub npm_enabled: bool,
    #[serde(default)]
    pub npm_since_cursor: Option<String>,
}

fn default_pypi_enabled() -> bool {
    true
}

fn default_npm_enabled() -> bool {
    false
}

impl Default for EcosystemsConfig {
    fn default() -> Self {
        EcosystemsConfig {
            pypi_enabled: true,
            npm_enabled: false,
            npm_since_cursor: None,
        }
    }
}
