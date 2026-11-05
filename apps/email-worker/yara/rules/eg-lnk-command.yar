// Windows shortcut (MS-SHLLINK) whose target or arguments name a command interpreter or script
// host: shortcuts in mail are a common loader (they run the interpreter when opened).

rule EG_Heuristic_LNK_Command_Interpreter
{
    meta:
        id = "eg-lnk-command-interpreter"
        severity = "medium"
        description = "Shortcut file that launches a command interpreter or script host"
        reference = "https://attack.mitre.org/techniques/T1204/002/"
    strings:
        $cmd = "cmd.exe" ascii wide nocase
        $powershell = "powershell.exe" ascii wide nocase
        $pwsh = "pwsh.exe" ascii wide nocase
        $mshta = "mshta.exe" ascii wide nocase
        $wscript = "wscript.exe" ascii wide nocase
        $cscript = "cscript.exe" ascii wide nocase
    condition:
        // HeaderSize 0x4C and LinkCLSID 00021401-0000-0000-C000-000000000046.
        filesize < 4MB
        and uint32(0) == 0x0000004C
        and uint32(4) == 0x00021401 and uint32(8) == 0x00000000
        and uint32(12) == 0x000000C0 and uint32(16) == 0x46000000
        and any of ($cmd, $powershell, $pwsh, $mshta, $wscript, $cscript)
}
