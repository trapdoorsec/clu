rule suspicious_passwd_access_linux
{
    meta:
        severity = "medium"
        description = "Detects suspicious read access to /etc/passwd file, which is often targeted by malware for credential harvesting"
        ecosystem = "all"
        risk_score = 40
    strings:
        $cli = /(cat|less|more|head|tail)\s+.{0,100}\/etc\/passwd/ nocase
        $read = /(readFile|readFileSync)\(\s*['"]\/etc\/passwd/ nocase
    condition:
        $cli or $read
}