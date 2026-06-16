pub mod heuristics;
pub mod llm;
pub mod ollama_utils;
pub mod package;
pub mod typosquat;
pub mod yara;

/// Compute a risk-score-weighted severity from static analysis findings.
///
/// Each heuristic match, typosquat match, and YARA finding carries its own
/// `risk_score` (0-100). The combined risk sum is divided by 10 and clamped
/// to the 1-25 scale used throughout CLU.
///
/// Returns `(severity: u8, is_malicious: bool, static_risk: u32)`.
pub fn compute_static_severity(
    heuristic_risk: u32,
    typosquat_risk: u32,
    yara_risk: u32,
) -> (u8, bool, u32) {
    let static_risk = heuristic_risk
        .saturating_add(typosquat_risk)
        .saturating_add(yara_risk);

    let severity = if static_risk == 0 {
        1u8
    } else {
        ((static_risk / 10).clamp(1, 25)) as u8
    };
    let is_malicious = static_risk >= 70;

    (severity, is_malicious, static_risk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_no_findings() {
        let (severity, is_malicious, risk) = compute_static_severity(0, 0, 0);
        assert_eq!(severity, 1);
        assert!(!is_malicious);
        assert_eq!(risk, 0);
    }

    #[test]
    fn test_severity_missing_author_only() {
        let (severity, is_malicious, _) = compute_static_severity(5, 0, 0);
        assert_eq!(severity, 1);
        assert!(!is_malicious);
    }

    #[test]
    fn test_severity_missing_description_only() {
        let (severity, is_malicious, _) = compute_static_severity(35, 0, 0);
        assert_eq!(severity, 3);
        assert!(!is_malicious);
    }

    #[test]
    fn test_severity_eval_base64_only() {
        let (severity, is_malicious, _) = compute_static_severity(90, 0, 0);
        assert_eq!(severity, 9);
        assert!(is_malicious);
    }

    #[test]
    fn test_severity_dangerous_operations_only() {
        let (severity, is_malicious, _) = compute_static_severity(95, 0, 0);
        assert_eq!(severity, 9);
        assert!(is_malicious);
    }

    #[test]
    fn test_severity_missing_author_plus_description() {
        let (severity, is_malicious, _) = compute_static_severity(40, 0, 0);
        assert_eq!(severity, 4);
        assert!(!is_malicious);
    }

    #[test]
    fn test_severity_missing_author_plus_dangerous() {
        let (severity, is_malicious, _) = compute_static_severity(100, 0, 0);
        assert_eq!(severity, 10);
        assert!(is_malicious);
    }

    #[test]
    fn test_severity_typosquat_dist1() {
        let (severity, is_malicious, _) = compute_static_severity(0, 90, 0);
        assert_eq!(severity, 9);
        assert!(is_malicious);
    }

    #[test]
    fn test_severity_typosquat_dist2() {
        let (severity, is_malicious, _) = compute_static_severity(0, 75, 0);
        assert_eq!(severity, 7);
        assert!(is_malicious);
    }

    #[test]
    fn test_severity_combined_all_tiers() {
        let (severity, is_malicious, _) = compute_static_severity(5, 90, 70);
        assert_eq!(severity, 16);
        assert!(is_malicious);
    }

    #[test]
    fn test_severity_capped_at_25() {
        let (severity, is_malicious, _) = compute_static_severity(300, 0, 0);
        assert_eq!(severity, 25);
        assert!(is_malicious);
    }

    #[test]
    fn test_severity_minimum_1() {
        let (severity, is_malicious, _) = compute_static_severity(5, 0, 0);
        assert_eq!(severity, 1);
        assert!(!is_malicious);
    }

    #[test]
    fn test_severity_malicious_threshold_exactly_70() {
        let (severity, is_malicious, _) = compute_static_severity(70, 0, 0);
        assert_eq!(severity, 7);
        assert!(is_malicious);
    }

    #[test]
    fn test_severity_malicious_threshold_just_below() {
        let (severity, is_malicious, _) = compute_static_severity(69, 0, 0);
        assert_eq!(severity, 6);
        assert!(!is_malicious);
    }

    #[test]
    fn test_recommendation_thresholds() {
        let (sev_1, _, _) = compute_static_severity(5, 0, 0);
        assert!(sev_1 <= 4, "missing_author (risk=5) should be IGNORE");

        let (sev_4, _, _) = compute_static_severity(40, 0, 0);
        assert!(sev_4 <= 4, "missing_author+description (risk=40) should be IGNORE");

        let (sev_9, _, _) = compute_static_severity(90, 0, 0);
        assert!(sev_9 > 4, "eval_base64 alone should be INSPECT");
    }
}