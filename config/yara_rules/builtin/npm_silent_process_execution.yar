rule npm_silent_process_execution
{
    meta:
        severity = "high"
        description = "Detects hidden or silent process execution in Node.js using child_process with stdio ignore or detached"
        ecosystem = "npm"
        risk_score = 80
    strings:
        $child_ignore = /child_process\s*\.\s*(spawn|exec|execFile|fork)\s*\([^)]*stdio\s*:\s*['"]ignore['"]/ nocase
        $child_detached = /child_process\s*\.\s*(spawn|exec|execFile)\s*\([^)]*detached\s*:\s*true/nocase
        $spawn_ignore = /spawn\s*\([^)]*stdio\s*:\s*['"]ignore['"]/ nocase
        $exec_devnull = /exec\s*\([^)]*\/dev\/null/nocase
        $exec_redirect = /exec\s*\([^)]*\d>\s*\/dev\/null/nocase
    condition:
        any of them
}