rule exec_base64
{
    meta:
        severity = "critical"
        description = "Detects dynamic execution of base64-encoded code, a common obfuscation technique in malware"
        ecosystem = "pypi"
        risk_score = 95
    strings:
        $b64_exec = /b64decode\s*\(.*\)\s*\).*\beval\s*\(/ nocase
        $b64_exec2 = /b64decode\s*\(.*\)\s*\).*\bexec\s*\(/ nocase
        $b64_compile = /b64decode\s*\(.*\).*compile\s*\(.*exec/nocase
        $binascii_exec = /binascii\s*\.\s*a2b_base64\s*\(.*\).*\beval\s*\(/ nocase
        $binascii_exec2 = /binascii\s*\.\s*a2b_base64\s*\(.*\).*\bexec\s*\(/ nocase
        $decodestring_exec = /decodestring\s*\(.*\).*\beval\s*\(/ nocase
        $decodestring_exec2 = /decodestring\s*\(.*\).*\bexec\s*\(/ nocase
        $urlsafe_exec = /urlsafe_b64decode\s*\(.*\).*\beval\s*\(/ nocase
        $urlsafe_exec2 = /urlsafe_b64decode\s*\(.*\).*\bexec\s*\(/ nocase
    condition:
        any of them
}