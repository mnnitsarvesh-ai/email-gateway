import { domainToASCII } from 'node:url';
import type { RspamdCheckReply } from './reply';

/** RFC 8601 result names (same literals as `@email-gateway/security-contracts` AUTH_OUTCOMES). */
export type AuthOutcome =
  'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror';
export type DmarcPolicy = 'none' | 'quarantine' | 'reject';

export interface DkimSignatureResult {
  domain: string;
  result: AuthOutcome;
  selector: string | null;
}

/** Structurally identical to `AuthResults` of `@email-gateway/security-contracts` (S9). */
export interface RspamdAuthResults {
  spf: { result: AuthOutcome | null; domain: string | null };
  dkim: { result: AuthOutcome | null; signatures: DkimSignatureResult[] };
  dmarc: { result: AuthOutcome | null; policy: DmarcPolicy | null; domain: string | null };
  arc: { result: AuthOutcome | null };
}

export interface NormalizedSymbol {
  name: string;
  score: number;
  /** At most MAX_SYMBOL_OPTIONS, each at most MAX_OPTION_LENGTH characters, no control chars. */
  options: string[];
}

export interface NormalizedRspamdResult {
  score: number;
  requiredScore: number;
  action: string;
  /**
   * Rspamd did not scan the message (`is_skipped` without a deciding pre-filter). A
   * pre-filter result such as GTUBE (`is_skipped: true` with `passthrough_module: "GTUBE"`) is
   * a definite result, not a skip (verified against 3.12, see docs/deployment/rspamd.md).
   */
  skipped: boolean;
  /** Pre-filter that decided the result (`GTUBE`, …), null when the full scan ran. */
  passthroughModule: string | null;
  /** Sorted by |score| descending, then name; at most MAX_SYMBOLS. */
  symbols: NormalizedSymbol[];
  /** The reply had more than MAX_SYMBOLS usable symbols. */
  symbolsTruncated: boolean;
  auth: RspamdAuthResults;
}

export interface NormalizeContext {
  /** Envelope sender: the SPF domain when Rspamd's SPF symbol options carry none. */
  envelopeFrom?: string | null;
  /** HELO name: the SPF domain of the null sender. */
  helo?: string | null;
}

export const MAX_SYMBOLS = 200;
export const MAX_SYMBOL_OPTIONS = 5;
export const MAX_OPTION_LENGTH = 200;
export const MAX_DKIM_SIGNATURES = 10;
const MAX_SYMBOL_NAME_LENGTH = 128;

/** Symbol → SPF outcome (Rspamd 3.12 spf module; lua_auth_results uses the same names). */
export const SPF_SYMBOLS: Readonly<Record<string, AuthOutcome>> = {
  R_SPF_ALLOW: 'pass',
  R_SPF_FAIL: 'fail',
  R_SPF_SOFTFAIL: 'softfail',
  R_SPF_NEUTRAL: 'neutral',
  R_SPF_NA: 'none',
  R_SPF_DNSFAIL: 'temperror',
  R_SPF_PERMFAIL: 'permerror',
};

/** Symbol → DKIM outcome, in precedence order (any valid signature makes the message pass). */
export const DKIM_SYMBOLS: Readonly<Record<string, AuthOutcome>> = {
  R_DKIM_ALLOW: 'pass',
  R_DKIM_REJECT: 'fail',
  R_DKIM_TEMPFAIL: 'temperror',
  R_DKIM_PERMFAIL: 'permerror',
  R_DKIM_NA: 'none',
};

/** DKIM_TRACE option suffix → per-signature outcome (`domain:+`, `domain:-`, …). */
export const DKIM_TRACE_RESULTS: Readonly<Record<string, AuthOutcome>> = {
  '+': 'pass',
  '-': 'fail',
  '?': 'temperror',
  '~': 'permerror',
};

/** Symbol → DMARC outcome and the policy it implies, in precedence order. */
export const DMARC_SYMBOLS: Readonly<
  Record<string, { result: AuthOutcome; policy: DmarcPolicy | null }>
> = {
  DMARC_POLICY_REJECT: { result: 'fail', policy: 'reject' },
  DMARC_POLICY_QUARANTINE: { result: 'fail', policy: 'quarantine' },
  DMARC_POLICY_SOFTFAIL: { result: 'fail', policy: 'none' },
  DMARC_POLICY_ALLOW: { result: 'pass', policy: null },
  DMARC_POLICY_ALLOW_WITH_FAILURES: { result: 'pass', policy: null },
  DMARC_DNSFAIL: { result: 'temperror', policy: null },
  DMARC_BAD_POLICY: { result: 'permerror', policy: null },
  DMARC_NA: { result: 'none', policy: null },
};

/** Symbol → ARC outcome, in precedence order. */
export const ARC_SYMBOLS: Readonly<Record<string, AuthOutcome>> = {
  ARC_REJECT: 'fail',
  ARC_ALLOW: 'pass',
  ARC_DNSFAIL: 'temperror',
  ARC_INVALID: 'permerror',
  ARC_NA: 'none',
};

const DOMAIN_PATTERN = /^[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?$/;
const DMARC_POLICY_VALUES = new Set<string>(['none', 'quarantine', 'reject']);

/** Removes C0 controls and DEL, then bounds the length. */
export function sanitizeOption(value: string): string {
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\x00-\x1f\x7f]/g, '').slice(0, MAX_OPTION_LENGTH);
}

/** Lower-case ASCII (A-label) domain of at most 253 characters, or null. */
export function normalizeDomain(value: string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  let candidate = value.trim().replace(/\.$/, '').toLowerCase();
  if (candidate.length === 0) return null;
  // eslint-disable-next-line no-control-regex
  if (!/^[\x00-\x7f]*$/.test(candidate)) candidate = domainToASCII(candidate);
  if (candidate.length === 0 || candidate.length > 253 || !DOMAIN_PATTERN.test(candidate)) {
    return null;
  }
  return candidate.includes('.') ? candidate : null;
}

/** The leading domain token of an option such as `spoof.scan.test : No valid SPF` or `d.test,reject`. */
function leadingDomain(option: string | undefined): string | null {
  if (option === undefined) return null;
  const token = /^\s*([^\s,:;]+)/.exec(option)?.[1];
  return normalizeDomain(token);
}

function domainOfAddress(address: string | null | undefined): string | null {
  if (!address) return null;
  const at = address.lastIndexOf('@');
  return at < 0 ? null : normalizeDomain(address.slice(at + 1).replace(/>$/, ''));
}

function firstPresent<T>(
  table: Readonly<Record<string, T>>,
  symbols: ReadonlyMap<string, NormalizedSymbol>,
): [string, T] | null {
  for (const [name, value] of Object.entries(table)) {
    if (symbols.has(name)) return [name, value];
  }
  return null;
}

function extractDkim(symbols: ReadonlyMap<string, NormalizedSymbol>): RspamdAuthResults['dkim'] {
  const result = firstPresent(DKIM_SYMBOLS, symbols)?.[1] ?? null;
  // Selectors come from the R_DKIM_* options (`domain:s=selector`), in signature order.
  const selectors = new Map<string, string[]>();
  for (const name of Object.keys(DKIM_SYMBOLS)) {
    for (const option of symbols.get(name)?.options ?? []) {
      const match = /^([^:\s]+):s=([^\s]+)$/.exec(option);
      const domain = normalizeDomain(match?.[1]);
      if (match && domain) {
        const list = selectors.get(domain) ?? [];
        list.push(match[2]!);
        selectors.set(domain, list);
      }
    }
  }
  const signatures: DkimSignatureResult[] = [];
  for (const option of symbols.get('DKIM_TRACE')?.options ?? []) {
    if (signatures.length >= MAX_DKIM_SIGNATURES) break;
    const match = /^(.+):([+\-?~])$/.exec(option);
    if (!match) continue;
    const domain = normalizeDomain(match[1]);
    const outcome = DKIM_TRACE_RESULTS[match[2]!];
    if (!domain || !outcome) continue;
    const selector = selectors.get(domain)?.shift() ?? null;
    signatures.push({ domain, result: outcome, selector });
  }
  return { result, signatures };
}

function extractDmarc(symbols: ReadonlyMap<string, NormalizedSymbol>): RspamdAuthResults['dmarc'] {
  const found = firstPresent(DMARC_SYMBOLS, symbols);
  if (!found) return { result: null, policy: null, domain: null };
  const [name, outcome] = found;
  // Rspamd 3.12 options: [`<domain>` or `<domain> : <reason>`, `<published policy>`]. The
  // ALLOW_WITH_FAILURES composite has no options of its own: DMARC_POLICY_ALLOW carries them.
  let options = symbols.get(name)?.options ?? [];
  if (options.length === 0 && name === 'DMARC_POLICY_ALLOW_WITH_FAILURES') {
    options = symbols.get('DMARC_POLICY_ALLOW')?.options ?? [];
  }
  const published = options.map((option) => option.trim()).find((o) => DMARC_POLICY_VALUES.has(o));
  const policy =
    outcome.policy ?? (outcome.result === 'pass' && published ? (published as DmarcPolicy) : null);
  return { result: outcome.result, policy, domain: leadingDomain(options[0]) };
}

function extractSpf(
  symbols: ReadonlyMap<string, NormalizedSymbol>,
  context: NormalizeContext,
): RspamdAuthResults['spf'] {
  const found = firstPresent(SPF_SYMBOLS, symbols);
  if (!found) return { result: null, domain: null };
  // Rspamd's SPF options are the matched mechanism (`-all`, `+ip4:…`), not the domain: the
  // checked domain is the envelope sender's (the HELO name for the null sender, RFC 7208 §2.3).
  const from = context.envelopeFrom?.trim() ?? '';
  const domain =
    from !== '' && from !== '<>' ? domainOfAddress(from) : normalizeDomain(context.helo ?? null);
  return { result: found[1], domain };
}

function normalizeSymbols(reply: RspamdCheckReply): {
  symbols: NormalizedSymbol[];
  truncated: boolean;
} {
  const all: NormalizedSymbol[] = [];
  for (const [key, symbol] of Object.entries(reply.symbols ?? {})) {
    const name = symbol.name || key;
    if (name.length > MAX_SYMBOL_NAME_LENGTH || !/^[\x21-\x7e]+$/.test(name)) continue;
    const options = (symbol.options ?? []).slice(0, MAX_SYMBOL_OPTIONS).map(sanitizeOption);
    all.push({ name, score: symbol.score, options });
  }
  all.sort(
    (a, b) =>
      Math.abs(b.score) - Math.abs(a.score) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0),
  );
  return { symbols: all.slice(0, MAX_SYMBOLS), truncated: all.length > MAX_SYMBOLS };
}

/**
 * Normalizes a schema-valid `/checkv2` reply (S9): bounded, sorted symbols and the
 * SPF/DKIM/DMARC/ARC outcomes from the symbol tables above. Unknown symbols stay symbols and
 * are ignored by the authentication extraction. Platform verdicts are not decided here.
 */
export function normalizeReply(
  reply: RspamdCheckReply,
  context: NormalizeContext = {},
): NormalizedRspamdResult {
  const { symbols, truncated } = normalizeSymbols(reply);
  // Authentication reads every symbol of the reply, also those beyond the MAX_SYMBOLS cut.
  const byName = new Map<string, NormalizedSymbol>();
  for (const [key, symbol] of Object.entries(reply.symbols ?? {})) {
    byName.set(symbol.name || key, {
      name: symbol.name || key,
      score: symbol.score,
      options: (symbol.options ?? []).slice(0, MAX_SYMBOL_OPTIONS).map(sanitizeOption),
    });
  }
  const passthroughModule =
    typeof reply.passthrough_module === 'string' && reply.passthrough_module.length > 0
      ? sanitizeOption(reply.passthrough_module).slice(0, 64)
      : null;
  return {
    score: reply.score,
    requiredScore: reply.required_score,
    action: reply.action,
    skipped: reply.is_skipped === true && passthroughModule === null,
    passthroughModule,
    symbols,
    symbolsTruncated: truncated,
    auth: {
      spf: extractSpf(byName, context),
      dkim: extractDkim(byName),
      dmarc: extractDmarc(byName),
      arc: { result: firstPresent(ARC_SYMBOLS, byName)?.[1] ?? null },
    },
  };
}
