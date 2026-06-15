rule npm_install_script
{
    meta:
        severity = "medium"
        description = "Detects preinstall, postinstall, or install lifecycle scripts in package.json that may execute arbitrary code"
        ecosystem = "npm"
        risk_score = 50
    strings:
        $preinstall = /"preinstall"\s*:\s*"/ nocase
        $postinstall = /"postinstall"\s*:\s*"/ nocase
        $install_script = /"install"\s*:\s*"/ nocase
        $preinstall_curl = /"preinstall"\s*:\s*"[^"]*curl/nocase
        $postinstall_curl = /"postinstall"\s*:\s*"[^"]*curl/nocase
        $preinstall_bash = /"preinstall"\s*:\s*"[^"]*bash/nocase
        $postinstall_bash = /"postinstall"\s*:\s*"[^"]*bash/nocase
    condition:
        any of them
}