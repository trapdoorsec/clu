rule cmd_overwrite
{
    meta:
        severity = "medium"
        description = "Detects overwriting or shadowing of system commands in Python code"
        ecosystem = "pypi"
        risk_score = 50
    strings:
        $os_system_assign = /os\s*\.\s*system\s*=/ nocase
        $subprocess_assign = /subprocess\s*\.\s*(call|run|Popen)\s*=/ nocase
        $builtins_import = /__import__\s*\(\s*['"]os['"]\s*\)\s*\.\s*system\s*=/ nocase
        $cmd_alias = /\bsystem\b\s*=\s*(os\.)?system/ nocase
    condition:
        any of them
}