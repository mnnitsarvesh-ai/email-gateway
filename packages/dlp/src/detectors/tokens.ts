import { registrableDomainOf } from '@email-gateway/url-security';
import {
  ALNUM,
  BASE64_CHARS,
  JWT_CHARS,
  TOKEN_CHARS,
  forEachToken,
  isAlnumCode,
  isLowerCode,
  isUpperCode,
  isDigitCode,
} from '../scan/chars';
import { PAN_PATTERN, gstinValid, ifscValid, isIso3166Alpha2, mod97Valid } from '../validators';
import { enabled, type DetectorContext } from './context';
import type { Candidate } from './types';

/**
 * Token detectors (step 4.5 D5): anchored checks on single tokens of at most 128 code units —
 * BA1 IBAN (compact and print form), BA3 SWIFT/BIC, NI1 PAN, PP1 Indian passport, PI4 GSTIN,
 * CR2 AWS access key id, CR3 AWS secret access key, CR4 JWT, CR5 API tokens, PI1 e-mail
 * addresses. Every scan is linear in the chunk.
 */

/** The documented AWS example access key id (never a finding). */
export const AWS_EXAMPLE_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
/** The documented AWS example secret access key (never a finding). */
export const AWS_EXAMPLE_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

const PASSPORT_PATTERN = /^[A-PR-WY][1-9][0-9]{6}$/;
const SWIFT_PATTERN = /^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?$/;
const AWS_KEY_PATTERN = /^(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}$/;

const base = (
  ctx: DetectorContext,
  detector: Candidate['detector'],
  start: number,
  end: number,
  fields: Partial<Candidate> & Pick<Candidate, 'base'>,
): Candidate => {
  const value = ctx.text.slice(start, end);
  return {
    detector,
    segment: ctx.segment,
    start,
    end,
    value,
    compact: value.toUpperCase(),
    context: [],
    contextBonus: 0,
    requiresContext: false,
    negative: null,
    codePenalty: false,
    extra: {},
    ...fields,
  };
};

/** IFSC tokens of a whole segment (BA2 pairs them with account numbers). */
export function ifscTokens(text: string): { start: number; end: number; value: string }[] {
  const out: { start: number; end: number; value: string }[] = [];
  forEachToken(text, 0, text.length, ALNUM, (start, end) => {
    if (end - start !== 11) return;
    const value = text.slice(start, end);
    if (ifscValid(value)) out.push({ start, end, value });
  });
  return out;
}

const IBAN_MAX = 34;

/** BA1: compact `GB82WEST12345698765432` or print form `GB82 WEST 1234 5698 7654 32`. */
function ibanAt(ctx: DetectorContext, start: number, end: number): void {
  const { text } = ctx;
  const token = text.slice(start, end);
  if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]*$/.test(token)) return;
  let compact = token;
  let stop = end;
  if (token.length === 4) {
    // Print form: groups of four separated by single spaces, the last of 1–4.
    let i = end;
    while (compact.length < IBAN_MAX && text.charCodeAt(i) === 32) {
      let j = i + 1;
      while (
        j < text.length &&
        j - i - 1 < 5 &&
        (isUpperCode(text.charCodeAt(j)) || isDigitCode(text.charCodeAt(j)))
      )
        j += 1;
      const group = j - i - 1;
      if (group < 1 || group > 4 || isAlnumCode(text.charCodeAt(j))) break;
      compact += text.slice(i + 1, j);
      stop = j;
      i = j;
      if (group < 4) break;
    }
  } else if (token.length < 15) {
    return;
  }
  if (compact.length < 15 || compact.length > IBAN_MAX || !mod97Valid(compact)) return;
  ctx.emit(
    base(ctx, 'BA1', start, stop, {
      compact,
      base: 0.7,
      context: ['iban'],
      contextBonus: 0.2,
    }),
  );
}

function alnumToken(ctx: DetectorContext, start: number, end: number): void {
  const { text } = ctx;
  const length = end - start;
  const token = text.slice(start, end);
  if (length >= 4 && enabled(ctx, 'BA1')) ibanAt(ctx, start, end);
  if (length === 10 && enabled(ctx, 'NI1') && PAN_PATTERN.test(token)) {
    ctx.emit(
      base(ctx, 'NI1', start, end, {
        base: 0.5,
        context: ['pan'],
        contextBonus: 0.35,
        negative: 'standard',
        codePenalty: true,
      }),
    );
  }
  if (length === 8 && enabled(ctx, 'PP1') && PASSPORT_PATTERN.test(token)) {
    ctx.emit(
      base(ctx, 'PP1', start, end, {
        base: 0.3,
        context: ['passport'],
        contextBonus: 0.5,
        requiresContext: true,
        negative: 'standard',
        codePenalty: true,
      }),
    );
  }
  if (length === 15 && enabled(ctx, 'PI4') && gstinValid(token)) {
    ctx.emit(base(ctx, 'PI4', start, end, { base: 0.8 }));
  }
  if (
    (length === 8 || length === 11) &&
    enabled(ctx, 'BA3') &&
    SWIFT_PATTERN.test(token) &&
    isIso3166Alpha2(token.slice(4, 6))
  ) {
    ctx.emit(
      base(ctx, 'BA3', start, end, {
        base: 0.4,
        context: ['swift'],
        contextBonus: 0.3,
        requiresContext: true,
      }),
    );
  }
  if (
    length === 20 &&
    enabled(ctx, 'CR2') &&
    AWS_KEY_PATTERN.test(token) &&
    token !== AWS_EXAMPLE_ACCESS_KEY_ID
  ) {
    ctx.emit(base(ctx, 'CR2', start, end, { base: 0.85, extra: { tokenKind: 'aws' } }));
  }
}

/** Mixed upper/lower case and a digit or `/`/`+` (random base64; excludes hex SHAs and words). */
const looksRandomBase64 = (token: string): boolean => {
  let upper = false;
  let lower = false;
  let other = false;
  for (let i = 0; i < token.length; i += 1) {
    const c = token.charCodeAt(i);
    if (isUpperCode(c)) upper = true;
    else if (isLowerCode(c)) lower = true;
    else other = true;
  }
  return upper && lower && other;
};

/** CR3 tokens; the CR2 neighbour context is resolved by `detect()` (`awsKeyNear`). */
function secretToken(ctx: DetectorContext, start: number, end: number): void {
  if (end - start !== 40 || !enabled(ctx, 'CR3')) return;
  const token = ctx.text.slice(start, end);
  // Not glued to `=` padding or a longer base64 value.
  if (ctx.text[end] === '=') return;
  if (!looksRandomBase64(token) || token === AWS_EXAMPLE_SECRET_ACCESS_KEY) return;
  ctx.emit(
    base(ctx, 'CR3', start, end, {
      compact: token,
      base: 0.9,
      context: ['aws_secret'],
      contextBonus: 0,
      requiresContext: true,
      extra: { tokenKind: 'aws_secret' },
    }),
  );
}

const B64URL = /^[A-Za-z0-9_-]+$/;

/** The `alg` of a JWT header (base64url JSON object with a string `alg`), or null. */
export function jwtAlg(token: string): string | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [header, payload, signature] = parts as [string, string, string];
  if (!header.startsWith('eyJ') || !payload.startsWith('eyJ')) return null;
  if (![header, payload, signature].every((p) => p.length > 0 && B64URL.test(p))) return null;
  try {
    const parsed: unknown = JSON.parse(Buffer.from(header, 'base64url').toString('utf8'));
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    const alg = (parsed as Record<string, unknown>).alg;
    if (typeof alg !== 'string' || !/^[A-Za-z0-9]{1,16}$/.test(alg)) return null;
    return alg;
  } catch {
    return null;
  }
}

const JWT_MAX = 8192;

function jwtToken(ctx: DetectorContext, start: number, end: number): void {
  if (!enabled(ctx, 'CR4') || end - start < 20) return;
  const token = ctx.text.slice(start, end);
  if (!token.startsWith('eyJ')) return;
  const alg = jwtAlg(token);
  if (!alg) return;
  ctx.emit(
    base(ctx, 'CR4', start, end, {
      compact: token,
      base: 0.8,
      extra: { alg, tokenKind: 'jwt' },
    }),
  );
}

/** CR5: the provider of a prefixed API token with its exact length, or null. */
export function apiTokenKind(token: string): string | null {
  const rest = (prefix: string) => token.slice(prefix.length);
  const alnum = (s: string) => /^[A-Za-z0-9]+$/.test(s);
  if (/^gh[pousr]_/.test(token))
    return token.length === 40 && alnum(rest('ghp_')) ? 'github' : null;
  if (token.startsWith('github_pat_')) {
    return token.length === 93 && /^[A-Za-z0-9_]+$/.test(rest('github_pat_')) ? 'github' : null;
  }
  if (/^xox[abprs]-/.test(token)) {
    const body = rest('xoxb-');
    return body.length >= 24 && /^[A-Za-z0-9-]+$/.test(body) && /[0-9]/.test(body) ? 'slack' : null;
  }
  if (token.startsWith('AIza')) {
    return token.length === 39 && /^[A-Za-z0-9_-]+$/.test(rest('AIza')) ? 'google' : null;
  }
  if (token.startsWith('sk_live_') || token.startsWith('rk_live_')) {
    return token.length >= 32 && alnum(rest('sk_live_')) ? 'stripe' : null;
  }
  return null;
}

function apiToken(ctx: DetectorContext, start: number, end: number): void {
  if (!enabled(ctx, 'CR5')) return;
  const token = ctx.text.slice(start, end);
  const kind = apiTokenKind(token);
  if (!kind) return;
  ctx.emit(base(ctx, 'CR5', start, end, { compact: token, base: 0.9, extra: { tokenKind: kind } }));
}

const AZURE_PREFIX = 'AccountKey=';

/** CR5 Azure storage: `AccountKey=` + 88 base64 characters. */
function azureKeys(ctx: DetectorContext, from: number, to: number): void {
  if (!enabled(ctx, 'CR5')) return;
  const { text } = ctx;
  let i = text.indexOf(AZURE_PREFIX, Math.max(0, from));
  while (i >= 0 && i < to) {
    const start = i + AZURE_PREFIX.length;
    let j = start;
    while (
      j < text.length &&
      j - start <= 88 &&
      (BASE64_CHARS(text.charCodeAt(j)) || text[j] === '=')
    )
      j += 1;
    const value = text.slice(start, j);
    if (value.length === 88 && /^[A-Za-z0-9/+]{86}==$/.test(value)) {
      ctx.emit(
        base(ctx, 'CR5', i, j, {
          compact: value,
          base: 0.9,
          extra: { tokenKind: 'azure_storage' },
        }),
      );
    }
    i = text.indexOf(AZURE_PREFIX, i + 1);
  }
}

const LOCAL_CHARS = (c: number): boolean =>
  isAlnumCode(c) ||
  c === 46 || // .
  c === 95 || // _
  c === 45 || // -
  c === 43 || // +
  c === 37; // %
const DOMAIN_CHARS = (c: number): boolean => isAlnumCode(c) || c === 46 || c === 45;

/** PI1: `local@domain` with a registrable domain; the envelope addresses are not counted. */
function emails(ctx: DetectorContext, from: number, to: number): void {
  if (!enabled(ctx, 'PI1')) return;
  const { text } = ctx;
  let at = text.indexOf('@', Math.max(0, from));
  while (at >= 0 && at < to) {
    let s = at;
    while (s > 0 && at - s < 64 && LOCAL_CHARS(text.charCodeAt(s - 1))) s -= 1;
    let e = at + 1;
    while (e < text.length && e - at <= 253 && DOMAIN_CHARS(text.charCodeAt(e))) e += 1;
    while (e > at + 1 && (text[e - 1] === '.' || text[e - 1] === '-')) e -= 1;
    while (s < at && text[s] === '.') s += 1;
    const local = text.slice(s, at);
    const domain = text.slice(at + 1, e).toLowerCase();
    const next = text.indexOf('@', at + 1);
    if (
      local.length >= 1 &&
      !local.endsWith('.') &&
      !local.includes('..') &&
      domain.includes('.') &&
      !(s > 0 && LOCAL_CHARS(text.charCodeAt(s - 1))) &&
      text[e] !== '@'
    ) {
      const registrable = safeRegistrable(domain);
      const address = `${local.toLowerCase()}@${domain}`;
      if (registrable && !ctx.excludedAddresses.has(address)) {
        ctx.emit({
          ...base(ctx, 'PI1', s, e, { base: 0.9 }),
          compact: address,
        });
      }
    }
    at = next;
  }
}

/** Hand-written host check: labels of 1..63 `[a-z0-9-]`, no leading/trailing `-`, not numeric. */
const hostShape = (domain: string): boolean => {
  const labels = domain.split('.');
  if (labels.length < 2 || domain.length > 253) return false;
  for (const label of labels) {
    if (label.length < 1 || label.length > 63) return false;
    if (label.startsWith('-') || label.endsWith('-')) return false;
  }
  return !labels.every((label) => /^[0-9]+$/.test(label));
};

const safeRegistrable = (domain: string): string | null => {
  if (!hostShape(domain)) return null;
  try {
    return registrableDomainOf(domain);
  } catch {
    return null;
  }
};

/** Every token detector over tokens starting in [from, to). */
export function scanTokens(ctx: DetectorContext, from: number, to: number): void {
  forEachToken(ctx.text, from, to, ALNUM, (s, e) => alnumToken(ctx, s, e));
  forEachToken(ctx.text, from, to, BASE64_CHARS, (s, e) => secretToken(ctx, s, e));
  forEachToken(ctx.text, from, to, JWT_CHARS, (s, e) => jwtToken(ctx, s, e), JWT_MAX);
  forEachToken(ctx.text, from, to, TOKEN_CHARS, (s, e) => apiToken(ctx, s, e));
  azureKeys(ctx, from, to);
  emails(ctx, from, to);
}
