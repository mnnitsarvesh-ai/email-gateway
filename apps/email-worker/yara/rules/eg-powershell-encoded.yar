// PowerShell started with an encoded command (-EncodedCommand or any prefix PowerShell accepts:
// -e, -en, -enc, …, and -ec; also with "/") followed by a long base64 argument: a common first
// stage in script, shortcut and document droppers. Requires the interpreter name as well.

rule EG_Heuristic_PowerShell_EncodedCommand
{
    meta:
        id = "eg-powershell-encoded-command"
        severity = "medium"
        description = "PowerShell invocation with an encoded command argument"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
    strings:
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "pwsh" ascii wide nocase
        $enc_ascii = /\s[\-\/]e[a-z]{0,13}\s+["']?[A-Za-z0-9+\/]{40}/ ascii nocase
        $enc_wide = /\s[\-\/]e[a-z]{0,13}\s+["']?[A-Za-z0-9+\/]{40}/ wide nocase
    condition:
        filesize < 30MB and ($ps1 or $ps2) and ($enc_ascii or $enc_wide)
}
