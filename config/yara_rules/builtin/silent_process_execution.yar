rule silent_process_execution
{
    meta:
        severity = "high"
        description = "Detects hidden or silent process execution patterns such as DEVNULL redirection, CREATE_NO_WINDOW, or detached processes"
        ecosystem = "pypi"
        risk_score = 80
    strings:
        $devnull_subprocess = /subprocess\s*\.\s*\w+\s*\([^)]*DEVNULL/nocase
        $devnull_open = /open\s*\(\s*['"]\/dev\/null['"]/ nocase
        $no_window = /CREATE_NO_WINDOW/nocase
        $detach = /DETACHED_PROCESS/nocase
        $startupinfo_hidden = /STARTUPINFO.*STARTF_USESHOWWINDOW.*SW_HIDE/nocase
        $shell_false = /shell\s*=\s*False/nocase
        $devnull_popen = /Popen\s*\([^)]*devnull/nocase
        $supress_output = /\bsuppress\b.*\boutput\b/nocase
    condition:
        any of them
}