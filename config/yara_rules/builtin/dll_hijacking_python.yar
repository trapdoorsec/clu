rule dll_hijacking_python
{
    meta:
        severity = "high"
        description = "Detects DLL side-loading, injection, and phantom DLL attacks via ctypes or other DLL loading mechanisms"
        ecosystem = "pypi"
        risk_score = 75
    strings:
        $ctypes_cdll = /ctypes\s*\.\s*cdll\s*\.\s*LoadLibrary\s*\(/ nocase
        $ctypes_windll = /ctypes\s*\.\s*windll\s*\.\s*LoadLibrary\s*\(/ nocase
        $ctypes_winmode = /ctypes\s*\.\s*WinDLL\s*\(/ nocase
        $ctypes_cdll_direct = /cdll\s*\.\s*LoadLibrary\s*\(/ nocase
        $ctypes_win_direct = /windll\s*\.\s*LoadLibrary\s*\(/ nocase
        $ctypes_generic = /ctypes\s*\.\s*[Cc]dll\s*\(/ nocase
        $dll_path = /['"][A-Za-z]:\\.*\.dll['"]/ nocase wide
        $dll_load = /LoadLibraryEx?\s*\(/ nocase
    condition:
        any of them
}