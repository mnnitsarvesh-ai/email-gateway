import { type Analysis, latin1 } from './analysis';

/**
 * Script analyzer (step 4.6 X4 `script`: js, vbs, ps1, bat, sh, hta): pattern checks only — the
 * script is never evaluated. Each family records the tokens of its fixed dictionary that matched.
 */

interface Rule {
  token: string;
  re: RegExp;
}

const ENCODED_POWERSHELL: Rule[] = [
  {
    token: '-EncodedCommand',
    re: /(^|[\s"'])-(e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+["']?[A-Za-z0-9+/]{16,}={0,2}/im,
  },
  { token: 'FromBase64String', re: /FromBase64String\s*\(/i },
];
const DOWNLOAD_CRADLE: Rule[] = [
  { token: 'DownloadString', re: /\.Download(String|File|Data)\s*\(/i },
  {
    token: 'Invoke-WebRequest',
    re: /\b(Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Start-BitsTransfer)\b/i,
  },
  { token: 'Net.WebClient', re: /Net\.WebClient/i },
  { token: 'curl-pipe-sh', re: /\b(curl|wget)\b[^\n|;]{0,512}\|\s*(sudo\s+)?(ba|da|z|k)?sh\b/i },
  { token: 'XMLHTTP-ADODB.Stream', re: /^(?=[\s\S]*XMLHTTP)(?=[\s\S]*ADODB\.Stream)/i },
];
const LOLBIN: Rule[] = [
  { token: 'mshta', re: /\bmshta(\.exe)?\b/i },
  { token: 'regsvr32-scrobj', re: /\bregsvr32(\.exe)?\b[^\n]{0,512}\/i:\s*["']?https?:/i },
  { token: 'rundll32-javascript', re: /\brundll32(\.exe)?\b[^\n]{0,512}javascript:/i },
  { token: 'certutil', re: /\bcertutil(\.exe)?\b[^\n]{0,512}-(decode|urlcache)\b/i },
  { token: 'bitsadmin', re: /\bbitsadmin(\.exe)?\b/i },
];
const SHELL_EXEC: Rule[] = [
  { token: 'WScript.Shell', re: /WScript\.Shell/i },
  { token: 'ActiveXObject', re: /\bActiveXObject\s*\(/i },
  { token: 'Shell.Application', re: /Shell\.Application/i },
  { token: 'child_process', re: /\bchild_process\b/ },
  { token: 'eval-long-string', re: /\beval\s*\(\s*(["'`])[^"'`]{200,}\1/ },
];
const OBFUSCATION: Rule[] = [
  { token: 'base64-run', re: /[A-Za-z0-9+/]{200,}={0,2}/ },
  { token: 'char-codes', re: /(\b\d{2,3}\s*,\s*){30,}\d{2,3}\b/ },
  { token: 'fromCharCode', re: /String\.fromCharCode\s*\((\s*\d{2,3}\s*,){10,}/i },
  { token: 'chr-concat', re: /(\bchrw?\s*\(\s*\d{1,3}\s*\)\s*[&+]\s*){10,}/i },
  {
    token: 'reverse',
    re: /\bStrReverse\s*\(|\.split\(\s*(""|'')\s*\)\s*\.reverse\(\)\s*\.join\(/i,
  },
];

function apply(text: string, rules: Rule[], analysis: Analysis): number {
  let hits = 0;
  for (const rule of rules) {
    if (rule.re.test(text)) {
      hits += 1;
      analysis.token(rule.token);
    }
  }
  return hits;
}

/** The script families over `text` (also used for HTA and LNK arguments). */
export function scanScriptText(text: string, analysis: Analysis): void {
  const encoded = apply(text, ENCODED_POWERSHELL, analysis);
  if (encoded > 0) analysis.add('static.script_encoded_powershell', encoded);
  const cradle = apply(text, DOWNLOAD_CRADLE, analysis);
  if (cradle > 0) analysis.add('static.script_download_cradle', cradle);
  const lolbin = apply(text, LOLBIN, analysis);
  if (lolbin > 0) analysis.add('static.script_lolbin', lolbin);
  const shell = apply(text, SHELL_EXEC, analysis);
  if (shell > 0) analysis.add('static.script_shell_exec', shell);
  const obfuscation = apply(text, OBFUSCATION, analysis);
  if (obfuscation > 0) analysis.add('static.script_obfuscation', obfuscation);
}

export function analyzeScript(bytes: Buffer, analysis: Analysis): void {
  analysis.format = 'script';
  analysis.supported = true;
  // UTF-16LE scripts (PowerShell, VBS saved as Unicode): decode when the BOM says so.
  const text =
    bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe
      ? bytes.subarray(2, Math.min(bytes.length, 16 * 1024 * 1024)).toString('utf16le')
      : latin1(bytes);
  analysis.fact('script.lines', Math.min(1_000_000, text.split('\n').length));
  scanScriptText(text, analysis);
}
