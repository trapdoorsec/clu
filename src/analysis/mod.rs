pub mod guarddog;
pub mod heuristics;
pub mod llm;
pub mod ollama_utils;
pub mod package;
pub mod typosquat;

/// Compute a risk-score-weighted severity from static analysis findings.
///
/// Each heuristic match, typosquat match, and GuardDog finding carries its own
/// `risk_score` (0-100). The combined risk sum is divided by 10 and clamped
/// to the 1-25 scale used throughout CLU. This prevents low-signal findings
/// (e.g. missing_author at 30) from inflating severity as much as high-signal
/// ones (e.g. eval_base64 at 90).
///
/// Returns `(severity: u8, is_malicious: bool, static_risk: u32)`.
pub fn compute_static_severity(
    heuristic_risk: u32,
    typosquat_risk: u32,
    guarddog_risk: u32,
) -> (u8, bool, u32) {
    let static_risk = heuristic_risk
        .saturating_add(typosquat_risk)
        .saturating_add(guarddog_risk);

    let severity = if static_risk == 0 {
        1u8
    } else {
        ((static_risk / 10).max(1).min(25)) as u8
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
        // missing_author has risk_score=30 → severity 3 → IGNORE (≤4)
        let (severity, is_malicious, _) = compute_static_severity(30, 0, 0);
        assert_eq!(severity, 3);
        assert!(!is_malicious);
    }

    #[test]
    fn test_severity_missing_description_only() {
        // missing_description has risk_score=35 → severity 3 → IGNORE
        let (severity, is_malicious, _) = compute_static_severity(35, 0, 0);
        assert_eq!(severity, 3);
        assert!(!is_malicious);
    }

    #[test]
    fn test_severity_eval_base64_only() {
        // eval_base64 has risk_score=90 → severity 9 → INSPECT
        let (severity, is_malicious, _) = compute_static_severity(90, 0, 0);
        assert_eq!(severity, 9);
        assert!(is_malicious); // 90 >= 70
    }

    #[test]
    fn test_severity_dangerous_operations_only() {
        // dangerous_operations has risk_score=95 → severity 9 → INSPECT
        let (severity, is_malicious, _) = compute_static_severity(95, 0, 0);
        assert_eq!(severity, 9);
        assert!(is_malicious);
    }

    #[test]
    fn test_severity_missing_author_plus_description() {
        // 30 + 35 = 65 → severity 6 → INSPECT but not malicious
        let (severity, is_malicious, _) = compute_static_severity(65, 0, 0);
        assert_eq!(severity, 6);
        assert!(!is_malicious); // 65 < 70
    }

    #[test]
    fn test_severity_missing_author_plus_dangerous() {
        // 30 + 95 = 125 → severity 12 → INSPECT, malicious
        let (severity, is_malicious, _) = compute_static_severity(125, 0, 0);
        assert_eq!(severity, 12);
        assert!(is_malicious);
    }

    #[test]
    fn test_severity_typosquat_dist1() {
        // typosquat distance=1 → risk_score=90 → severity 9
        let (severity, is_malicious, _) = compute_static_severity(0, 90, 0);
        assert_eq!(severity, 9);
        assert!(is_malicious);
    }

    #[test]
    fn test_severity_typosquat_dist2() {
        // typosquat distance=2 → risk_score=75 → severity 7
        let (severity, is_malicious, _) = compute_static_severity(0, 75, 0);
        assert_eq!(severity, 7);
        assert!(is_malicious);
    }

    #[test]
    fn test_severity_combined_all_tiers() {
        // heuristic 30 + typosquat 90 + guarddog 70 = 190 → severity 19
        let (severity, is_malicious, _) = compute_static_severity(30, 90, 70);
        assert_eq!(severity, 19);
        assert!(is_malicious);
    }

    #[test]
    fn test_severity_capped_at_25() {
        // 300 / 10 = 30, but capped at 25
        let (severity, is_malicious, _) = compute_static_severity(300, 0, 0);
        assert_eq!(severity, 25);
        assert!(is_malicious);
    }

    #[test]
    fn test_severity_minimum_1() {
        // Even tiny risk should give severity ≥ 1
        let (severity, is_malicious, _) = compute_static_severity(5, 0, 0);
        assert_eq!(severity, 1); // 5/10 = 0 → max(1,...) = 1
        assert!(!is_malicious);
    }

    #[test]
    fn test_severity_malicious_threshold_exactly_70() {
        let (severity, is_malicious, _) = compute_static_severity(70, 0, 0);
        assert_eq!(severity, 7);
        assert!(is_malicious); // 70 >= 70
    }

    #[test]
    fn test_severity_malicious_threshold_just_below() {
        let (severity, is_malicious, _) = compute_static_severity(69, 0, 0);
        assert_eq!(severity, 6);
        assert!(!is_malicious); // 69 < 70
    }

    #[test]
    fn test_recommendation_thresholds() {
        // severity ≤ 4 → "IGNORE", severity ≥ 5 → "INSPECT"
        let (sev_3, _, _) = compute_static_severity(30, 0, 0);
        assert!(sev_3 <= 4, "missing_author should be IGNORE");

        let (sev_6, _, _) = compute_static_severity(65, 0, 0);
        assert!(sev_6 > 4, "missing_author+description should be INSPECT");

        let (sev_9, _, _) = compute_static_severity(90, 0, 0);
        assert!(sev_9 > 4, "eval_base64 alone should be INSPECT");
    }
}
