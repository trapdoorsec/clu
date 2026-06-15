rule screenshot_capture
{
    meta:
        severity = "medium"
        description = "Detects screen capture via ImageGrab, pyscreenshot, pyautogui, mss, or d3dshot"
        ecosystem = "pypi"
        risk_score = 45
    strings:
        $imagegrab = /ImageGrab\s*\.\s*grab\s*\(/ nocase
        $pyscreenshot = /pyscreenshot\s*\.\s*grab\s*\(/ nocase
        $pyautogui_screenshot = /pyautogui\s*\.\s*screenshot\s*\(/ nocase
        $mss = /\bmss\s*\.\s*grab\s*\(/ nocase
        $d3dshot = /d3dshot\s*\.\s*grab\s*\(/ nocase
    condition:
        any of them
}