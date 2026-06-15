rule npm_obfuscation
{
    meta:
        severity = "high"
        description = "Detects obfuscation patterns in JavaScript/Node.js code such as hex-encoded eval, string splitting, and BlankOBF-like patterns"
        ecosystem = "npm"
        risk_score = 80
    strings:
        $hex_string = /\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){5,}/ nocase
        $unicode_escape = /\\u[0-9a-f]{4}(\\u[0-9a-f]{4}){3,}/ nocase
        $string_fromCharCode = /String\s*\.\s*fromCharCode\s*\(/ nocase
        $array_map_join = /\[\s*['"][^'"]+['"]\s*,\s*['"][^'"]+['"]\s*\]\s*\.\s*map\s*\(.+join\s*\(/ nocase
        $atob_eval = /atob\s*\(\s*['"][A-Za-z0-9+\/=]{20,}['"]\s*\)\s*\)/ nocase
        $reverse_join = /\.reverse\s*\(\s*\)\s*\.\s*join\s*\(\s*['"]/ nocase
    condition:
        any of them
}