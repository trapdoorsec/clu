rule pyarmor_obfuscation
{
    meta:
        severity = "high"
        description = "Detects PyArmor obfuscation patterns including bootstrap code and pytransform imports"
        ecosystem = "pypi"
        risk_score = 75
    strings:
        $pytransform = /pytransform\s*\./ nocase
        $pyarmor_bootstrap = /pyarmor\s*\.\s*__init__/ nocase
        $pyarmor_runtime = /pyarmor_runtime\s*\./ nocase
        $pyarmor_header = /from pyarmor import/ nocase
        $armor_stub = /__pyarmor__/ nocase
    condition:
        any of them
}