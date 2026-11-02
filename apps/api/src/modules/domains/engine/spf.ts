import type { DnsQueryOptions, DnsResolver, DnsResult } from '../../../dns/dns-resolver';
import type { DnsCheckOutcome } from './types';

/** RFC 7208 §4.6.4: at most 10 DNS-querying terms per evaluation. */
export const SPF_LOOKUP_LIMIT = 10;
/** Recursion depth for include/redirect targets. */
export const SPF_MAX_DEPTH = 10;
/** DNS resolutions one lookup count may perform. */
export const SPF_MAX_RESOLUTIONS = 20;
/** Longer records risk exceeding 512-byte UDP answers together with other apex TXT records. */
export const SPF_MAX_RECORD_LENGTH = 450;

export type SpfQualifier = '+' | '-' | '~' | '?';
export type SpfMechanismName = 'all' | 'include' | 'a' | 'mx' | 'ptr' | 'ip4' | 'ip6' | 'exists';

export type SpfTerm =
  | {
      kind: 'mechanism';
      raw: string;
      qualifier: SpfQualifier;
      /** True when the qualifier was written explicitly. */
      explicitQualifier: boolean;
      name: SpfMechanismName;
      /** Domain spec / address after `:`, if any. */
      value: string | null;
    }
  | { kind: 'modifier'; raw: string; name: string; value: string };

export interface ParsedSpf {
  terms: SpfTerm[];
  /** Raw terms that are not valid RFC 7208 syntax. */
  syntaxErrors: string[];
}

const MECHANISM =
  /^([+\-~?]?)(all|include|a|mx|ptr|ip4|ip6|exists)(?::([^/\s]+))?(\/\d{1,3}(?:\/\/\d{1,3})?|\/\/\d{1,3})?$/i;
const MODIFIER = /^([a-z][a-z0-9_.-]*)=(\S*)$/i;
const DNS_LOOKUP_MECHANISMS = new Set<SpfMechanismName>(['include', 'a', 'mx', 'ptr', 'exists']);

/** True when a TXT string is an SPF record (`v=spf1` followed by a space or the end). */
export function isSpfRecord(txt: string): boolean {
  return /^v=spf1(?:\s|$)/i.test(txt.trim());
}

function validMechanism(
  name: SpfMechanismName,
  value: string | null,
  cidr: string | null,
): boolean {
  switch (name) {
    case 'all':
      return value === null && cidr === null;
    case 'include':
    case 'exists':
      return value !== null && cidr === null;
    case 'ptr':
      return cidr === null;
    case 'ip4':
      return (
        value !== null &&
        /^\d{1,3}(\.\d{1,3}){3}$/.test(value) &&
        (cidr === null || /^\/\d{1,2}$/.test(cidr))
      );
    case 'ip6':
      return value !== null && value.includes(':') && (cidr === null || /^\/\d{1,3}$/.test(cidr));
    default:
      return true; // a, mx: optional domain spec and dual CIDR
  }
}

/** Parses the terms of an SPF record (RFC 7208 §4.6.1). The `v=spf1` prefix must be present. */
export function parseSpf(record: string): ParsedSpf {
  const tokens = record.trim().split(/\s+/);
  const terms: SpfTerm[] = [];
  const syntaxErrors: string[] = [];
  if (!isSpfRecord(record)) return { terms, syntaxErrors: [tokens[0] ?? ''] };
  for (const raw of tokens.slice(1)) {
    const mechanism = MECHANISM.exec(raw);
    if (mechanism) {
      const name = mechanism[2]!.toLowerCase() as SpfMechanismName;
      const value = mechanism[3] ?? null;
      const cidr = mechanism[4] ?? null;
      if (validMechanism(name, value, cidr)) {
        terms.push({
          kind: 'mechanism',
          raw,
          qualifier: (mechanism[1] || '+') as SpfQualifier,
          explicitQualifier: mechanism[1] !== '',
          name,
          value,
        });
        continue;
      }
    } else {
      const modifier = MODIFIER.exec(raw);
      const name = modifier?.[1]?.toLowerCase();
      if (modifier && name && !((name === 'redirect' || name === 'exp') && modifier[2] === '')) {
        terms.push({ kind: 'modifier', raw, name, value: modifier[2]! });
        continue;
      }
    }
    syntaxErrors.push(raw);
  }
  return { terms, syntaxErrors };
}

function includeTargets(record: string): string[] {
  return parseSpf(record)
    .terms.filter((t) => t.kind === 'mechanism' && t.name === 'include')
    .map((t) => (t.value ?? '').toLowerCase());
}

/**
 * Inserts `include:<gatewayInclude>` directly after `v=spf1` unless already present
 * (case-insensitive), keeping every other term, including `all`/`redirect`, unchanged.
 * Without a current record, recommends `v=spf1 include:<gatewayInclude> ~all`.
 */
export function recommendSpf(current: string | null, gatewayInclude: string): string {
  if (current === null || !isSpfRecord(current)) return `v=spf1 include:${gatewayInclude} ~all`;
  const tokens = current.trim().split(/\s+/);
  if (includeTargets(current).includes(gatewayInclude.toLowerCase())) return tokens.join(' ');
  return [tokens[0]!, `include:${gatewayInclude}`, ...tokens.slice(1)].join(' ');
}

export interface SpfLookupCount {
  /** DNS-querying terms counted recursively (a lower bound when `exact` is false). */
  lookupCount: number;
  /** False when an include/redirect target could not be resolved or followed. */
  exact: boolean;
  /** DNS resolutions performed for the count. */
  resolutions: number;
  /** Names that include themselves through a chain (receivers then exceed the limit). */
  loops: string[];
}

/**
 * Counts the DNS-querying terms (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`) of an SPF
 * record recursively through `include:` and `redirect=` targets resolved with `resolver`
 * (depth ≤ 10, ≤ 20 resolutions, loop detection). `redirect` is ignored when the record has an
 * `all` mechanism (RFC 7208 §6.1). A loop makes the count exceed the limit, as it would for a
 * receiver.
 */
export async function countSpfLookups(
  record: string,
  resolver: DnsResolver,
  options: DnsQueryOptions = {},
): Promise<SpfLookupCount> {
  const state = { resolutions: 0, exact: true, loops: new Set<string>() };
  const lookups = new Map<string, Promise<DnsResult<string>>>();

  const resolve = (name: string): Promise<DnsResult<string>> | null => {
    const known = lookups.get(name);
    if (known) return known;
    if (state.resolutions >= SPF_MAX_RESOLUTIONS) return null;
    state.resolutions++;
    const pending = resolver.resolveTxt(name, options);
    lookups.set(name, pending);
    return pending;
  };

  const count = async (spf: string, depth: number, chain: ReadonlySet<string>): Promise<number> => {
    const { terms } = parseSpf(spf);
    const hasAll = terms.some((t) => t.kind === 'mechanism' && t.name === 'all');
    let total = 0;
    const targets: string[] = [];
    for (const term of terms) {
      if (term.kind === 'mechanism' && DNS_LOOKUP_MECHANISMS.has(term.name)) {
        total++;
        if (term.name === 'include') targets.push(term.value ?? '');
      } else if (term.kind === 'modifier' && term.name === 'redirect' && !hasAll) {
        total++;
        targets.push(term.value);
      }
    }
    for (const rawTarget of targets) {
      const target = rawTarget.toLowerCase().replace(/\.$/, '');
      if (target.includes('%') || !/^[a-z0-9_.-]+$/.test(target) || target.length > 253) {
        state.exact = false; // macros and odd names cannot be followed
        continue;
      }
      if (chain.has(target)) {
        state.loops.add(target);
        continue;
      }
      if (depth >= SPF_MAX_DEPTH) {
        state.exact = false;
        continue;
      }
      const pending = resolve(target);
      if (!pending) {
        state.exact = false;
        continue;
      }
      let result: DnsResult<string>;
      try {
        result = await pending;
      } catch {
        state.exact = false; // invalid name: cannot be followed
        continue;
      }
      if (result.outcome === 'indeterminate') {
        state.exact = false;
        continue;
      }
      if (result.outcome !== 'answer') continue; // void lookup: permerror for receivers
      const records = result.records.filter(isSpfRecord);
      if (records.length !== 1) continue; // none or several: permerror, nothing more to count
      total += await count(records[0]!, depth + 1, new Set([...chain, target]));
    }
    return total;
  };

  let lookupCount = await count(record, 0, new Set());
  if (state.loops.size > 0) lookupCount = Math.max(lookupCount, SPF_LOOKUP_LIMIT + 1);
  return {
    lookupCount,
    exact: state.exact,
    resolutions: state.resolutions,
    loops: [...state.loops],
  };
}

export interface SpfEvaluation {
  outcome: DnsCheckOutcome;
  observedValue: string | null;
  recommendedValue: string;
  warnings: string[];
  /** Lookup count of the recommended record (includes the gateway include's own lookups). */
  lookupCount: number;
  lookupCountExact: boolean;
  /** The SPF records found at the apex. */
  records: string[];
}

/**
 * Evaluates the apex TXT answer (D7). Indeterminate apex → indeterminate; indeterminate
 * includes only make the lookup count inexact (`spf_lookup_count_unknown`).
 */
export async function evaluateSpf(
  apex: DnsResult<string>,
  gatewayInclude: string,
  resolver: DnsResolver,
  options: DnsQueryOptions = {},
): Promise<SpfEvaluation> {
  if (apex.outcome === 'indeterminate') {
    return {
      outcome: 'indeterminate',
      observedValue: null,
      recommendedValue: recommendSpf(null, gatewayInclude),
      warnings: [],
      lookupCount: 0,
      lookupCountExact: false,
      records: [],
    };
  }
  const records = apex.outcome === 'answer' ? apex.records.filter(isSpfRecord) : [];
  const current = records[0] ?? null;
  const recommendedValue = recommendSpf(current, gatewayInclude);
  const counted = await countSpfLookups(recommendedValue, resolver, options);
  const warnings: string[] = [];

  let outcome: DnsCheckOutcome;
  if (records.length === 0) {
    outcome = 'missing';
  } else if (records.length > 1) {
    outcome = 'invalid';
    warnings.push('spf_multiple_records');
  } else {
    const hasInclude = includeTargets(current!).includes(gatewayInclude.toLowerCase());
    outcome = hasInclude && counted.lookupCount <= SPF_LOOKUP_LIMIT ? 'valid' : 'invalid';
  }

  if (counted.lookupCount > SPF_LOOKUP_LIMIT) warnings.push('spf_lookup_limit_exceeded');
  if (!counted.exact) warnings.push('spf_lookup_count_unknown');
  if (current !== null) {
    const parsed = parseSpf(current);
    if (parsed.terms.some((t) => t.kind === 'mechanism' && t.name === 'ptr')) {
      warnings.push('spf_ptr_mechanism');
    }
    if (
      parsed.terms.some((t) => t.kind === 'mechanism' && t.name === 'all' && t.qualifier === '+')
    ) {
      warnings.push('spf_plus_all');
    }
    for (const term of parsed.syntaxErrors) warnings.push(`spf_syntax_error:${term}`);
  }
  if (recommendedValue.length > SPF_MAX_RECORD_LENGTH) warnings.push('spf_record_too_long');

  return {
    outcome,
    observedValue: records.length > 0 ? records.join('\n') : null,
    recommendedValue,
    warnings,
    lookupCount: counted.lookupCount,
    lookupCountExact: counted.exact,
    records,
  };
}
