rule clipboard_access
{
    meta:
        severity = "medium"
        description = "Detects clipboard read/write access which may be used to steal or replace clipboard content"
        ecosystem = "pypi"
        risk_score = 40
    strings:
        $pyperclip = /pyperclip\s*\.\s*(paste|copy)\s*\(/ nocase
        $pandas_clipboard = /\.to_clipboard\s*\(/ nocase
        $pandas_read_clipboard = /read_clipboard\s*\(/ nocase
    condition:
        any of them
}