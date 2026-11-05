// HTML smuggling (MITRE ATT&CK T1027.006): an HTML attachment that decodes an embedded base64
// blob in the browser and saves it as a file (msSaveOrOpenBlob, or createObjectURL + a download
// link). Low false-positive design: all of script, blob construction, base64 decoding and a save
// primitive must be present, plus a long base64 run, in an HTML-sized file.

rule EG_Heuristic_HTML_Smuggling
{
    meta:
        id = "eg-html-smuggling"
        severity = "medium"
        description = "HTML that rebuilds a base64 blob and saves it as a download"
        reference = "https://attack.mitre.org/techniques/T1027/006/"
    strings:
        $script = "<script" ascii wide nocase
        $save_ms = "msSaveOrOpenBlob" ascii wide
        $save_url = "createObjectURL" ascii wide
        $download = ".download" ascii wide
        $blob = "new Blob(" ascii wide
        $decode_atob = "atob(" ascii wide
        $decode_data = ";base64," ascii wide nocase
        // A quoted run of at least 256 base64 characters (the smuggled payload).
        $b64 = /["'][A-Za-z0-9+\/]{256}/ ascii
    condition:
        filesize > 2KB and filesize < 30MB
        and $script and $blob and ($decode_atob or $decode_data) and $b64
        and ($save_ms or ($save_url and $download))
}
