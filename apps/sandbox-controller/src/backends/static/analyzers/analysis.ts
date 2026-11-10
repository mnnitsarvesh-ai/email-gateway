/**
 * The accumulator every static analyzer writes into (step 4.6 X4), and the bounded result the
 * analyzer child returns over IPC. Child-side module: imports nothing but node built-ins and
 * relative files (enforced by a unit test), so the analyzer child loads only code of this
 * directory under Node's permission model.
 *
 * Only codes, counts, short facts, host names / canonical IPs of indicators and tokens of the
 * analyzers' own fixed dictionaries (matched import names, keywords) leave the child — never
 * sample text, names, paths or macro source.
 */

export const ANALYZER_VERSION = 'sandbox-static/1';

/** Every finding code a static analyzer can emit (⊆ `SANDBOX_FINDING_CODES`, tested). */
export const STATIC_FINDING_CODES = [
  'static.pe_injection_imports',
  'static.pe_downloader_imports',
  'static.pe_packed',
  'static.pe_anti_debug',
  'static.pe_overlay',
  'static.elf_packed',
  'static.office_macro',
  'static.office_auto_exec',
  'static.office_macro_shell',
  'static.office_auto_exec_shell',
  'static.office_ole_object',
  'static.office_external_template',
  'static.office_dde',
  'static.pdf_javascript',
  'static.pdf_open_action_js',
  'static.pdf_launch',
  'static.pdf_embedded_file',
  'static.pdf_obfuscated_names',
  'static.html_smuggling',
  'static.html_password_form',
  'static.html_external_form',
  'static.html_meta_refresh_external',
  'static.html_obfuscated_script',
  'static.script_encoded_powershell',
  'static.script_download_cradle',
  'static.script_lolbin',
  'static.script_shell_exec',
  'static.script_obfuscation',
  'static.lnk_present',
  'static.lnk_command',
  'static.eicar_test',
  'static.embedded_urls',
  'static.embedded_ips',
  'static.high_entropy',
] as const;
export type StaticFindingCode = (typeof STATIC_FINDING_CODES)[number];

/** Bounds of what one analysis may produce or consume. */
export const ANALYSIS_BOUNDS = Object.freeze({
  hosts: 50,
  ips: 50,
  /** Distinct hosts/IPs counted beyond the listed ones. */
  indicatorTotal: 1_000_000,
  facts: 64,
  tokens: 64,
  findingCount: 1_000_000,
  /** Total inflate output of one analysis (zip entries, PDF object streams). */
  inflateTotalBytes: 64 * 1024 * 1024,
  /** One inflated entry / stream. */
  inflateEntryBytes: 16 * 1024 * 1024,
  /** Text decoded for the regex-based analyzers. */
  textBytes: 16 * 1024 * 1024,
});

export type FactValue = number | string | boolean;

export interface AnalysisResult {
  v: 1;
  analyzerVersion: typeof ANALYZER_VERSION;
  /** The analyzer that understood the bytes (`pe`, `ole`, `ooxml`, …, `generic`). */
  format: string;
  /** A format-specific analyzer parsed the sample (or the type is a generic text type). */
  supported: boolean;
  findings: { code: StaticFindingCode; count: number }[];
  facts: Record<string, FactValue>;
  hosts: string[];
  hostTotal: number;
  ips: string[];
  ipTotal: number;
  /** Matched tokens of the analyzers' fixed dictionaries (never sample text). */
  tokens: string[];
}

const FACT_KEY = /^[a-z][a-zA-Z0-9_.]{0,47}$/;
const FACT_STRING = /^[A-Za-z0-9._+-]{0,32}$/;

export class Analysis {
  readonly findings = new Map<StaticFindingCode, number>();
  readonly facts: Record<string, FactValue> = {};
  readonly hosts = new Set<string>();
  readonly ips = new Set<string>();
  readonly tokens = new Set<string>();
  hostTotal = 0;
  ipTotal = 0;
  format = 'generic';
  supported = false;
  /** Inflate output consumed so far (bounded by `ANALYSIS_BOUNDS.inflateTotalBytes`). */
  inflated = 0;

  add(code: StaticFindingCode, count = 1): void {
    if (count <= 0) return;
    const next = (this.findings.get(code) ?? 0) + Math.floor(count);
    this.findings.set(code, Math.min(next, ANALYSIS_BOUNDS.findingCount));
  }

  has(code: StaticFindingCode): boolean {
    return this.findings.has(code);
  }

  fact(key: string, value: FactValue): void {
    if (!FACT_KEY.test(key)) return;
    if (!(key in this.facts) && Object.keys(this.facts).length >= ANALYSIS_BOUNDS.facts) return;
    if (typeof value === 'string' && !FACT_STRING.test(value)) return;
    if (typeof value === 'number' && !Number.isFinite(value)) return;
    this.facts[key] = typeof value === 'number' ? Math.round(value * 1000) / 1000 : value;
  }

  token(value: string): void {
    if (this.tokens.size < ANALYSIS_BOUNDS.tokens && /^[A-Za-z0-9_.()-]{1,64}$/.test(value)) {
      this.tokens.add(value);
    }
  }

  host(host: string): void {
    if (this.hosts.has(host)) return;
    if (this.hosts.size < ANALYSIS_BOUNDS.hosts) this.hosts.add(host);
    this.hostTotal = Math.min(this.hostTotal + 1, ANALYSIS_BOUNDS.indicatorTotal);
  }

  ip(ip: string): void {
    if (this.ips.has(ip)) return;
    if (this.ips.size < ANALYSIS_BOUNDS.ips) this.ips.add(ip);
    this.ipTotal = Math.min(this.ipTotal + 1, ANALYSIS_BOUNDS.indicatorTotal);
  }

  /** Reserves `bytes` of the inflate budget; false when it would be exceeded. */
  reserveInflate(bytes: number): boolean {
    if (this.inflated + bytes > ANALYSIS_BOUNDS.inflateTotalBytes) return false;
    this.inflated += bytes;
    return true;
  }

  result(): AnalysisResult {
    return {
      v: 1,
      analyzerVersion: ANALYZER_VERSION,
      format: this.format,
      supported: this.supported,
      findings: [...this.findings].map(([code, count]) => ({ code, count })),
      facts: { ...this.facts },
      hosts: [...this.hosts],
      hostTotal: Math.max(this.hostTotal, this.hosts.size),
      ips: [...this.ips],
      ipTotal: Math.max(this.ipTotal, this.ips.size),
      tokens: [...this.tokens],
    };
  }
}

/** Shannon entropy (bits per byte) of `bytes`, sampled evenly above `maxBytes`. */
export function entropy(bytes: Uint8Array, maxBytes = 16 * 1024 * 1024): number {
  if (bytes.length === 0) return 0;
  const counts = new Uint32Array(256);
  const step = bytes.length > maxBytes ? bytes.length / maxBytes : 1;
  let n = 0;
  for (let i = 0; i < bytes.length; i += step) {
    counts[bytes[Math.floor(i)] as number] = (counts[bytes[Math.floor(i)] as number] as number) + 1;
    n += 1;
  }
  let h = 0;
  for (const c of counts) {
    if (c === 0) continue;
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Bounded latin1 view of the first `ANALYSIS_BOUNDS.textBytes` bytes. */
export function latin1(bytes: Buffer, max = ANALYSIS_BOUNDS.textBytes): string {
  return bytes.subarray(0, Math.min(bytes.length, max)).toString('latin1');
}

/** Number of matches of a global regex in `text`, capped. */
export function countMatches(text: string, pattern: RegExp, cap = 10_000): number {
  const re = new RegExp(
    pattern.source,
    pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`,
  );
  let count = 0;
  let match: RegExpExecArray | null;
  while (count < cap && (match = re.exec(text)) !== null) {
    count += 1;
    if (match[0] === '') re.lastIndex += 1;
  }
  return count;
}
