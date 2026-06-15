rule npm_serialize_environment
{
    meta:
        severity = "high"
        description = "Detects serialization of environment variables which may be used for data exfiltration in Node.js"
        ecosystem = "npm"
        risk_score = 70
    strings:
        $json_stringify_env = /JSON\s*\.\s*stringify\s*\(\s*process\s*\.\s*env/nocase
        $object_entries_env = /Object\s*\.\s*entries\s*\(\s*process\s*\.\s*env/nocase
        $assign_env = /Object\s*\.\s*assign\s*\(\s*\{\s*\}\s*,\s*process\s*\.\s*env/nocase
        $env_to_string = /process\s*\.\s*env\s*\.\s*toString\s*\(/ nocase
    condition:
        any of them
}