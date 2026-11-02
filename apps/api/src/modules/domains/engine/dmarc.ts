import { isNameAtOrUnder } from '../../../dns/dns-names';
import type { DnsResult } from '../../../dns/dns-resolver';
import type { GatewayDnsConfig } from './gateway-dns-config';
import type { DmarcStage, DnsCheckOutcome } from './types';

export type DmarcPolicy = 'none' | 'quarantine' | 'reject';

export interface ParsedDmarc {
  /** Tags in record order (`v` first when valid); names lower-case, values trimmed. */
  tags: Array<[string, string]>;
  /** Problems that make the record invalid for receivers (RFC 7489 §6.3). */
  errors: string[];
}

const POLICIES = new Set(['none', 'quarantine', 'reject']);
/** Tag order used when a recommendation adds tags. */
const TAG_ORDER = ['v', 'p', 'sp', 'pct', 'rua', 'ruf', 'adkim', 'aspf', 'fo', 'ri', 'rf'];

/** True when a TXT string looks like a DMARC record (`v=DMARC1` anywhere in its tags). */
export function isDmarcCandidate(txt: string): boolean {
  return /(?:^|;)\s*v\s*=\s*DMARC1\s*(?:;|$)/i.test(txt);
}

/** Parses `v=DMARC1; p=…` tags (p, sp, pct, rua, ruf, adkim, aspf, fo, ri; others kept). */
export function parseDmarc(record: string): ParsedDmarc {
  const tags: Array<[string, string]> = [];
  const errors: string[] = [];
  const seen = new Set<string>();
  for (const part of record.split(';')) {
    const trimmed = part.trim();
    if (trimmed === '') continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) {
      errors.push('syntax');
      continue;
    }
    const name = trimmed.slice(0, eq).trim().toLowerCase();
    const value = trimmed.slice(eq + 1).trim();
    if (!/^[a-z][a-z0-9_]*$/.test(name)) {
      errors.push('syntax');
      continue;
    }
    if (seen.has(name)) {
      errors.push(`duplicate:${name}`);
      continue;
    }
    seen.add(name);
    tags.push([name, value]);
  }
  const get = (name: string) => tags.find(([n]) => n === name)?.[1];
  if (tags[0]?.[0] !== 'v' || tags[0][1].toUpperCase() !== 'DMARC1') errors.push('v');
  const p = get('p')?.toLowerCase();
  if (p === undefined || !POLICIES.has(p)) errors.push('p');
  const sp = get('sp');
  if (sp !== undefined && !POLICIES.has(sp.toLowerCase())) errors.push('sp');
  const pct = get('pct');
  if (pct !== undefined && (!/^\d{1,3}$/.test(pct) || Number(pct) > 100)) errors.push('pct');
  for (const name of ['adkim', 'aspf']) {
    const v = get(name);
    if (v !== undefined && !/^[rs]$/i.test(v)) errors.push(name);
  }
  for (const name of ['rua', 'ruf']) {
    const v = get(name);
    if (v !== undefined && splitUris(v).some((uri) => !/^[a-z][a-z0-9+.-]*:\S+$/i.test(uri))) {
      errors.push(name);
    }
  }
  return { tags, errors };
}

function splitUris(value: string): string[] {
  return value
    .split(',')
    .map((uri) => uri.trim())
    .filter(Boolean);
}

/** Domain of a `mailto:` URI (size suffix removed), lower-case; null for other schemes. */
function mailtoDomain(uri: string): string | null {
  const match = /^mailto:[^@]+@([^!?]+)/i.exec(uri);
  return match ? match[1]!.toLowerCase().replace(/\.$/, '') : null;
}

function serialize(tags: Array<[string, string]>): string {
  return tags.map(([n, v]) => `${n}=${v}`).join('; ');
}

function upsert(tags: Array<[string, string]>, name: string, value: string): void {
  const existing = tags.find(([n]) => n === name);
  if (existing) {
    existing[1] = value;
    return;
  }
  const order = TAG_ORDER.indexOf(name);
  const insertAt = tags.findIndex(([n]) => {
    const other = TAG_ORDER.indexOf(n);
    return other === -1 || other > order;
  });
  if (insertAt === -1) tags.push([name, value]);
  else tags.splice(insertAt, 0, [name, value]);
}

/** Keeps existing URIs and appends the configured ones that are absent (case-insensitive). */
function mergeUris(existing: string | undefined, add: readonly string[]): string | undefined {
  const uris = existing ? splitUris(existing) : [];
  for (const uri of add) {
    if (!uris.some((u) => u.toLowerCase() === uri.toLowerCase())) uris.push(uri);
  }
  return uris.length > 0 ? uris.join(',') : undefined;
}

export interface DmarcRecommendation {
  stage: DmarcStage;
  partial: boolean;
  recommendedValue: string;
  nextStep: string;
}

const NEXT_STEPS = {
  missing: 'Publish a monitoring policy (p=none) and review the aggregate reports.',
  none: 'When reports show your legitimate mail passes, move to p=quarantine.',
  partial: 'Apply the policy to all mail (pct=100).',
  quarantine: 'When reports show no legitimate mail is quarantined, move to p=reject.',
  final: 'No change needed: the domain enforces p=reject.',
} as const;

/**
 * Recommendation and stage for the current DMARC record (D8). `current` = parsed tags of the
 * (first) record, or null when there is none. Invalid records are recommended as for
 * `missing`, merged with their parsable tags. Existing rua/ruf URIs are kept; the gateway's are
 * added when configured, else `mailto:dmarc-reports@<domain>` is suggested when no rua exists.
 */
export function recommendDmarc(
  current: ParsedDmarc | null,
  domain: string,
  gateway: Pick<GatewayDnsConfig, 'dmarcRua' | 'dmarcRuf'>,
): DmarcRecommendation {
  return buildRecommendation(
    current,
    current !== null && current.errors.length === 0,
    domain,
    gateway,
  );
}

function buildRecommendation(
  current: ParsedDmarc | null,
  valid: boolean,
  domain: string,
  gateway: Pick<GatewayDnsConfig, 'dmarcRua' | 'dmarcRuf'>,
): DmarcRecommendation {
  const tags: Array<[string, string]> = [['v', 'DMARC1']];
  if (current) {
    for (const [name, value] of current.tags) {
      if (name === 'v') continue;
      if (!valid && current.errors.includes(name)) continue; // drop unparsable tags
      tags.push([name, value]);
    }
  }
  const get = (name: string) => tags.find(([n]) => n === name)?.[1];

  let stage: DmarcStage = 'missing';
  let partial = false;
  let nextStep: string = NEXT_STEPS.missing;
  if (!valid) {
    if (get('p') === undefined) upsert(tags, 'p', 'none');
    if (get('fo') === undefined) upsert(tags, 'fo', '1');
  } else {
    stage = get('p')!.toLowerCase() as DmarcPolicy;
    partial = get('pct') !== undefined && Number(get('pct')) < 100;
    if (partial) {
      upsert(tags, 'pct', '100');
      nextStep = NEXT_STEPS.partial;
    } else if (stage === 'none') {
      upsert(tags, 'p', 'quarantine');
      nextStep = NEXT_STEPS.none;
    } else if (stage === 'quarantine') {
      upsert(tags, 'p', 'reject');
      nextStep = NEXT_STEPS.quarantine;
    } else {
      nextStep = NEXT_STEPS.final;
    }
  }

  upsert(tags, 'rua', mergeUris(get('rua'), gateway.dmarcRua) ?? `mailto:dmarc-reports@${domain}`);
  const ruf = mergeUris(get('ruf'), gateway.dmarcRuf);
  if (ruf !== undefined) upsert(tags, 'ruf', ruf);

  return { stage, partial, recommendedValue: serialize(tags), nextStep };
}

export interface DmarcEvaluation extends DmarcRecommendation {
  outcome: DnsCheckOutcome;
  observedValue: string | null;
  warnings: string[];
}

/** Evaluates the TXT answer at `_dmarc.<domain>` (D8). Never gates activation. */
export function evaluateDmarc(
  result: DnsResult<string>,
  domain: string,
  gateway: Pick<GatewayDnsConfig, 'dmarcRua' | 'dmarcRuf'>,
): DmarcEvaluation {
  if (result.outcome === 'indeterminate') {
    return {
      ...recommendDmarc(null, domain, gateway),
      outcome: 'indeterminate',
      observedValue: null,
      warnings: [],
    };
  }
  const records = result.outcome === 'answer' ? result.records.filter(isDmarcCandidate) : [];
  const warnings: string[] = [];
  if (records.length === 0) {
    const recommendation = recommendDmarc(null, domain, gateway);
    return {
      ...recommendation,
      outcome: 'missing',
      observedValue: null,
      warnings: externalRuaWarning(recommendation.recommendedValue, domain),
    };
  }
  const parsed = parseDmarc(records[0]!);
  let outcome: DnsCheckOutcome = 'valid';
  if (records.length > 1) {
    outcome = 'invalid';
    warnings.push('dmarc_multiple_records');
  }
  if (parsed.errors.length > 0) {
    outcome = 'invalid';
    warnings.push('dmarc_syntax_error');
  }
  const recommendation = buildRecommendation(parsed, outcome === 'valid', domain, gateway);
  if (outcome === 'valid') {
    const get = (name: string) => parsed.tags.find(([n]) => n === name)?.[1];
    if (get('rua') === undefined) warnings.push('dmarc_no_rua');
    if (get('p')!.toLowerCase() === 'none') warnings.push('dmarc_policy_none');
    if (recommendation.partial) warnings.push('dmarc_pct_partial');
  }
  warnings.push(...externalRuaWarning(recommendation.recommendedValue, domain));
  return {
    ...recommendation,
    outcome,
    observedValue: records.join('\n'),
    warnings,
  };
}

/**
 * RFC 7489 §7.1: report destinations outside the domain must publish an authorization record
 * (`<domain>._report._dmarc.<destination domain>`).
 */
function externalRuaWarning(recommendedValue: string, domain: string): string[] {
  const { tags } = parseDmarc(recommendedValue);
  const uris = tags.filter(([n]) => n === 'rua' || n === 'ruf').flatMap(([, v]) => splitUris(v));
  const external = uris.some((uri) => {
    const target = mailtoDomain(uri);
    return target !== null && !isNameAtOrUnder(target, domain);
  });
  return external ? ['dmarc_external_rua_needs_authorization'] : [];
}
