// OOXML external template injection (MITRE ATT&CK T1221): a relationships part that loads the
// document template from a remote http(s) URL. The inspector runs YARA on every inspected
// archive entry, so this matches the decompressed word/_rels/settings.xml.rels of a docx.

rule EG_Heuristic_OOXML_External_Template
{
    meta:
        id = "eg-ooxml-external-template"
        severity = "medium"
        description = "Office Open XML relationship that loads a remote attached template"
        reference = "https://attack.mitre.org/techniques/T1221/"
    strings:
        $relationships = "<Relationships" ascii
        $template = "relationships/attachedTemplate" ascii
        $external = "TargetMode=\"External\"" ascii
        $remote = /Target="https?:\/\// ascii nocase
    condition:
        filesize < 1MB and $relationships and $template and $external and $remote
}
