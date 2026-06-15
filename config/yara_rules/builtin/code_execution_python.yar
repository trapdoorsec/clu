rule code_execution_python
{
    meta:
        severity = "high"
        description = "Detects execution of OS commands via subprocess, os.system, eval, exec, or popen in Python code"
        ecosystem = "pypi"
        risk_score = 90
    strings:
        $subprocess_run = /subprocess\s*\.\s*run\s*\(/ nocase
        $subprocess_call = /subprocess\s*\.\s*call\s*\(/ nocase
        $subprocess_popen = /subprocess\s*\.\s*Popen\s*\(/ nocase
        $subprocess_check_output = /subprocess\s*\.\s*check_output\s*\(/ nocase
        $subprocess_check_call = /subprocess\s*\.\s*check_call\s*\(/ nocase
        $subprocess_getoutput = /subprocess\s*\.\s*getoutput\s*\(/ nocase
        $os_system = /os\s*\.\s*system\s*\(/ nocase
        $os_popen = /os\s*\.\s*popen\s*\(/ nocase
        $eval = /\beval\s*\(/ nocase
        $exec = /\bexec\s*\(/ nocase
        $execfile = /\bexecfile\s*\(/ nocase
        $os_spawn = /os\s*\.\s*spawn[a-z]*\s*\(/ nocase
        $os_exec = /os\s*\.\s*exec[a-z]*\s*\(/ nocase
        $compile_exec = /compile\s*\([^)]*['\"][^'\"]*['\"],[^,]*,['\"]exec['\"]\)/ nocase
        $globals_eval = /globals\s*\(\s*\)\s*\[\s*['"]eval['"]\s*\]\s*\(/ nocase
        $builtins_exec = /vars\s*\(\s*__builtins__\s*\)\s*\[\s*['"]exec['"]\s*\]/ nocase
        $builtins_eval = /vars\s*\(\s*__builtins__\s*\)\s*\[\s*['"]eval['"]\s*\]/ nocase
    condition:
        any of them
}