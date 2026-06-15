rule api_obfuscation
{
    meta:
        severity = "medium"
        description = "Detects API obfuscation patterns such as dynamic URL construction, encoded API keys, and obfuscated network calls"
        ecosystem = "all"
        risk_score = 55
    strings:
        $base64_url = /base64\s*\.\s*b64decode\s*\(\s*['"][A-Za-z0-9+\/=]{20,}['"]/ nocase
        $hex_url = /\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){5,}/ nocase
        $dynamic_url = /requests\s*\.\s*(get|post|put|delete|patch)\s*\([^)]*\+/ nocase
        $urllib_dynamic = /urllib\s*\.\s*request\s*\.\s*urlopen\s*\([^)]*\+/ nocase
        $encoded_scheme = /\(['"]https?:\/\/['"]\s*\+\s*['"]/ nocase
    condition:
        any of them
}