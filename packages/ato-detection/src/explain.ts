/**
 * Explanations (step 8.4 D10, D11): every rule code has an English template rendered from its
 * evidence (no message content), the score has a one-line summary, and evidence is guarded by an
 * allow-list (keys, sizes, no address, URL or token-shaped value) before it is stored.
 */
import { ATO_RULES, ruleByCode } from './rules/catalogue';
import type { ScoreResult } from './scoring';

/** Evidence keys allowed in `ato_risk_signals.evidence` (D10). */
export const EVIDENCE_KEYS = [
  'ip',
  'ipPrefix',
  'country',
  'fromCountry',
  'toCountry',
  'asn',
  'asnOrg',
  'deviceLabel',
  'distanceKm',
  'speedKmh',
  'elapsedMinutes',
  'count',
  'threshold',
  'baseline',
  'windowMinutes',
  'messageId',
  'connectorId',
  'failures',
  'distinctIps',
  'distinctAccounts',
  'categories',
  'codes',
  'permille',
  'action',
  'provider',
  'ruleHash',
  'domain',
  'attachmentType',
  'domainCount',
] as const;
export type EvidenceKey = (typeof EVIDENCE_KEYS)[number];

export const EVIDENCE_MAX_BYTES = 4096;
export const EVIDENCE_STRING_MAX = 128;
export const EVIDENCE_ARRAY_MAX = 32;

export class UnsafeEvidenceError extends Error {
  constructor(readonly reason: string) {
    super(`Unsafe evidence: ${reason}`);
    this.name = 'UnsafeEvidenceError';
  }
}

const ALLOWED = new Set<string>(EVIDENCE_KEYS);
// A long run of base64/hex/token alphabet is never a legitimate evidence value.
const TOKEN_SHAPED = /[A-Za-z0-9+/_=-]{40,}/;
const URL_SHAPED = /[a-z][a-z0-9+.-]*:\/\//i;

function checkString(key: string, value: string): void {
  if (value.length > EVIDENCE_STRING_MAX) throw new UnsafeEvidenceError(`${key} too long`);
  if (value.includes('@')) throw new UnsafeEvidenceError(`${key} looks like an address`);
  if (URL_SHAPED.test(value)) throw new UnsafeEvidenceError(`${key} looks like a URL`);
  if (TOKEN_SHAPED.test(value)) throw new UnsafeEvidenceError(`${key} looks like a token`);
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(value)) throw new UnsafeEvidenceError(`${key} has controls`);
}

/**
 * Throws `UnsafeEvidenceError` unless the evidence is a flat object of allow-listed keys whose
 * values are finite numbers, booleans, null, bounded strings or bounded arrays of those strings,
 * serialized in at most 4 KiB.
 */
export function assertEvidenceSafe(evidence: unknown): asserts evidence is Record<string, unknown> {
  if (evidence === null || typeof evidence !== 'object' || Array.isArray(evidence)) {
    throw new UnsafeEvidenceError('not an object');
  }
  for (const [key, value] of Object.entries(evidence)) {
    if (!ALLOWED.has(key)) throw new UnsafeEvidenceError(`key ${key} not allowed`);
    if (value === null || typeof value === 'boolean') continue;
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) throw new UnsafeEvidenceError(`${key} not finite`);
      continue;
    }
    if (typeof value === 'string') {
      checkString(key, value);
      continue;
    }
    if (Array.isArray(value)) {
      if (value.length > EVIDENCE_ARRAY_MAX) throw new UnsafeEvidenceError(`${key} too many items`);
      for (const item of value) {
        if (typeof item === 'number' && Number.isFinite(item)) continue;
        if (typeof item !== 'string') throw new UnsafeEvidenceError(`${key} item type`);
        checkString(key, item);
      }
      continue;
    }
    throw new UnsafeEvidenceError(`${key} has a nested value`);
  }
  if (Buffer.byteLength(JSON.stringify(evidence), 'utf8') > EVIDENCE_MAX_BYTES) {
    throw new UnsafeEvidenceError('larger than 4 KiB');
  }
}

/** Whether evidence passes `assertEvidenceSafe`. */
export function isEvidenceSafe(evidence: unknown): boolean {
  try {
    assertEvidenceSafe(evidence);
    return true;
  } catch {
    return false;
  }
}

const format = (value: unknown): string => {
  if (value === undefined || value === null) return '–';
  if (Array.isArray(value)) return value.map((v) => format(v)).join(', ') || '–';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value);
};

/** Explanation templates of every rule code (from the catalogue). */
export const EXPLANATION_TEMPLATES: Readonly<Record<string, string>> = Object.freeze(
  Object.fromEntries(ATO_RULES.map((r) => [r.code, r.explanation])),
);

/**
 * `renderExplanation(code, evidence)`: the rule's template with `{key}` placeholders replaced by
 * evidence values (missing values render as `–`). An unknown code renders as the code itself.
 */
export function renderExplanation(code: string, evidence: Record<string, unknown>): string {
  const rule = ruleByCode(code);
  if (!rule) return code;
  return rule.explanation.replace(/\{([a-zA-Z]+)\}/g, (_m, key: string) => format(evidence[key]));
}

/** Rule title of a code (the code itself when unknown). */
export function ruleTitle(code: string): string {
  return ruleByCode(code)?.title ?? code;
}

/** One-line summary of a score result. */
export function renderScoreExplanation(result: ScoreResult): string {
  const parts = result.contributions
    .filter((c) => c.counted)
    .slice(0, 10)
    .map((c) => `${ruleTitle(c.code)} +${c.contribution}`);
  const gates: string[] = [];
  if (result.gates.weakOnlyCapApplied) gates.push('weak signals only: capped');
  if (result.gates.strongFloorApplied) gates.push('strong evidence: floor applied');
  if (result.override.outcome === 'applied')
    gates.push(`analyst override ${result.override.verdict}`);
  if (result.override.outcome === 'contradicted') gates.push('benign override contradicted');
  const head = `Risk ${result.score} (${result.level})`;
  const body = parts.length > 0 ? parts.join('; ') : 'no active signals';
  return gates.length > 0 ? `${head}: ${body}; ${gates.join('; ')}` : `${head}: ${body}`;
}
