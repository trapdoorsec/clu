rule unicode_obfuscation
{
    meta:
        severity = "high"
        description = "Detects Unicode-based obfuscation using confusable homoglyphs and bidirectional override characters"
        ecosystem = "pypi"
        risk_score = 75
    strings:
        $zwnj = /\xee\x80\x8d/ wide
        $zwj = /\xee\x80\x8c/ wide
        $rtlo = /\xe2\x80\xae/ wide
        $ltr_embed = /\xe2\x80\xaa/ wide
        $rtl_embed = /\xe2\x80\xab/ wide
        $ltr_override = /\xe2\x80\xad/ wide
        $pdi = /\xe2\x80\xac/ wide
        $variation_selector = /\xef\xb8\x8[fA-F0-9]/ wide
    condition:
        any of them
}