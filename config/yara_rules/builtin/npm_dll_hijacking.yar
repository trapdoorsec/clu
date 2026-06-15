rule npm_dll_hijacking
{
    meta:
        severity = "high"
        description = "Detects DLL loading via ffi, koffi, or node-ffi-napi in Node.js which may be used for DLL hijacking"
        ecosystem = "npm"
        risk_score = 75
    strings:
        $ffi_foreign = /ffi\s*\.\s*ForeignFunction\s*\(/ nocase
        $ffi_library = /ffi\s*\.\s*Library\s*\(/ nocase
        $koffi_load = /koffi\s*\.\s*load\s*\(/ nocase
        $node_ffi = /ffi-napi\s*\.\s*Library\s*\(/ nocase
        $dlopen = /dlopen\s*\(\s*['"][^'"]+\.dll['"]/ nocase
        $ffi_func = /ForeignFunction\s*\(\s*['"][^'"]+['"]/ nocase
    condition:
        any of them
}