rule npm_exfiltrate_sensitive_data
{
    meta:
        severity = "high"
        description = "Detects patterns that may exfiltrate sensitive data such as environment variables, AWS credentials, or cookies to remote servers in Node.js"
        ecosystem = "npm"
        risk_score = 70
    strings:
        $env_fetch = /process\s*\.\s*env\s*\.\s*\w+.*fetch\s*\(/ nocase
        $env_http = /process\s*\.\s*env\s*\.\s*\w+.*http\s*\.\s*(get|post|request)\s*\(/ nocase
        $env_axios = /process\s*\.\s*env\s*\.\s*\w+.*axios\s*\.\s*(get|post|put)\s*\(/ nocase
        $aws_key_pattern = /AKIA[0-9A-Z]{16}/ nocase
        $cookie_post = /document\s*\.\s*cookie.*\.(post|send|fetch)\s*\(/ nocase
        $env_to_remote = /process\s*\.\s*env.*https?:\/\// nocase
    condition:
        any of them
}