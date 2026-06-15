rule obfuscation_python
{
    meta:
        severity = "high"
        description = "Detects common obfuscation methods such as hex-encoded eval, BlankOBF patterns, chr joining, and large whitespace"
        ecosystem = "pypi"
        risk_score = 80
    strings:
        $hex_eval = /\\x[0-9a-f]{2}.*\beval\s*\(/ nocase
        $hex_exec = /\\x[0-9a-f]{2}.*\bexec\s*\(/ nocase
        $chr_join = /chr\s*\(\s*\d+\s*\).*\.join\s*\(/
        $blankobf = /[A-Za-z]{50,}/
        $large_ws = /\s{100,}/
        $decode_eval = /decode\s*\(\s*['"]utf-?8['"]\s*\).*\beval\s*\(/ nocase
        $decode_exec = /decode\s*\(\s*['"]utf-?8['"]\s*\).*\bexec\s*\(/ nocase
        $ord_join = /\(\s*ord\s*\(.+\)\s*[+\-]\s*ord\s*\(/ nocase
    condition:
        any of them
}