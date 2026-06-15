rule npm_exec_base64
{
    meta:
        severity = "critical"
        description = "Detects dynamic execution of base64-encoded code via eval or new Function in JavaScript"
        ecosystem = "npm"
        risk_score = 95
    strings:
        $eval_atob = /eval\s*\(\s*atob\s*\(/ nocase
        $eval_buffer = /eval\s*\(\s*Buffer\s*\.\s*from\s*\([^)]*\)\s*\.\s*toString\s*\(/ nocase
        $new_function_atob = /new\s+Function\s*\(\s*atob\s*\(/ nocase
        $new_function_buffer = /new\s+Function\s*\(\s*Buffer\s*\.\s*from\s*\(/ nocase
        $setTimeout_b64 = /setTimeout\s*\(\s*atob\s*\(/ nocase
        $setInterval_b64 = /setInterval\s*\(\s*atob\s*\(/ nocase
        $require_vm = /require\s*\(\s*['"]vm['"]\s*\)/ nocase
        $vm_run = /vm\s*\.\s*(runInThisContext|runInNewContext|compileFunction)\s*\(/ nocase
    condition:
        any of them
}