//! OpenSourceMalware (OSM) report export.
//!
//! This module owns the `OpenSourceMalwareReport` struct and the
//! `Finding (+ joined AnalysisReport) → OpenSourceMalwareReport` mapping.
//! The schema lives entirely here so it can evolve independently.

use serde::{Deserialize, Serialize};

use crate::db::findings::Finding;
use crate::output::AnalysisReport;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenSourceMalwareReport {
    pub id: i64,
    pub ecosystem: String,
    pub name: String,
    pub version: Option<String>,
    pub sha256: Option<String>,
    pub status: String,
    pub severity: i64,
    pub classification: Option<String>,
    pub score: i64,
    pub first_seen: String,
    pub last_updated: String,
    pub ioc: Option<IocData>,
    pub payload_excerpt: Option<String>,
    pub analyst_notes: Option<String>,
    pub reported_to: Option<ReportedTo>,
    pub scan_evidence: Option<ScanEvidence>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IocData {
    pub domains: Vec<String>,
    pub ips: Vec<String>,
    pub urls: Vec<String>,
    pub wallets: Vec<String>,
    pub webhooks: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportedTo {
    pub osm: bool,
    pub ossf: bool,
    pub registry: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanEvidence {
    pub heuristic_matches: Vec<String>,
    pub typosquat_matches: Vec<String>,
    pub yara_findings: Option<Vec<String>>,
    pub llm_assessment: Option<String>,
    pub recommendation: Option<String>,
}

/// Convert a `Finding` (and optionally its linked `AnalysisReport`) into an
/// OSM-shaped export struct.
pub fn to_osm_report(
    finding: &Finding,
    report: Option<&AnalysisReport>,
) -> OpenSourceMalwareReport {
    let ioc = finding
        .ioc
        .as_ref()
        .and_then(|s| serde_json::from_str::<IocData>(s).ok());

    let reported_to = finding
        .reported_to
        .as_ref()
        .and_then(|s| serde_json::from_str::<ReportedTo>(s).ok());

    let scan_evidence = report.map(|r| ScanEvidence {
        heuristic_matches: r
            .heuristic_matches
            .iter()
            .map(|h| h.rule_name.clone())
            .collect(),
        typosquat_matches: r
            .typosquat_matches
            .iter()
            .map(|t| t.evidence.clone())
            .collect(),
        yara_findings: r.yara_result.as_ref().map(|y| {
            y.findings
                .iter()
                .map(|f| format!("{}: {}", f.rule_name, f.description))
                .collect()
        }),
        llm_assessment: r.llm_analysis.as_ref().map(|a| a.reasoning.clone()),
        recommendation: Some(r.recommendation.clone()),
    });

    OpenSourceMalwareReport {
        id: finding.id,
        ecosystem: finding.ecosystem.clone(),
        name: finding.name.clone(),
        version: finding.version.clone(),
        sha256: finding.sha256.clone(),
        status: finding.status.as_str().to_string(),
        severity: finding.severity,
        classification: finding.classification.clone(),
        score: finding.score,
        first_seen: finding.first_seen.clone(),
        last_updated: finding.last_updated.clone(),
        ioc,
        payload_excerpt: finding.payload_excerpt.clone(),
        analyst_notes: finding.analyst_notes.clone(),
        reported_to,
        scan_evidence,
    }
}
