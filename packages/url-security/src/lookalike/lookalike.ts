import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { domainToUnicode } from 'node:url';
import { z } from 'zod';
import { readDataFile } from '../data';
import { hostMatchesAny, normalizeDomainInput, registrableDomainOf } from '../normalize/url';
import { damerauLevenshtein } from './distance';
import { isHighlyRestrictive } from './script';
import { confusablesVersion, skeleton } from './skeleton';

/**
 * Lookalike detection (docs/plan/steps/11-url-protection.md U7), rules L1–L6 with the explicit
 * thresholds of the design (configurable through `LookalikeParams`).
 */

export const LOOKALIKE_RULES = ['L1', 'L2', 'L3', 'L5'] as const;
export type LookalikeRule = (typeof LOOKALIKE_RULES)[number];
export type LookalikeTargetKind = 'brand' | 'tenant' | 'extra';

export interface Brand {
  id: string;
  label: string;
  officialDomains: string[];
}

export interface LookalikeParams {
  /** URL_LOOKALIKE_MIN_LABEL: shortest protected label for L2. */
  minLabel: number;
  /** URL_LOOKALIKE_LONG_LABEL: labels this long use the long distance. */
  longLabel: number;
  maxDistanceShort: number;
  maxDistanceLong: number;
  /** URL_LOOKALIKE_HIGH_SCORE: L2 at or above is high confidence. */
  highScore: number;
}

export const DEFAULT_LOOKALIKE_PARAMS: LookalikeParams = {
  minLabel: 5,
  longLabel: 9,
  maxDistanceShort: 1,
  maxDistanceLong: 2,
  highScore: 0.85,
};

/** L3 needs a protected label of at least this length. */
export const COMBOSQUAT_MIN_LABEL = 4;
export const MAX_LOOKALIKE_FINDINGS = 5;
const SCORE = { L1: 1, L3: 0.8, L5: 0.6 } as const;

export interface LookalikeFinding {
  rule: LookalikeRule;
  targetKind: LookalikeTargetKind;
  /** Registrable domain of the protected entry the candidate imitates. */
  targetDomain: string;
  /** 0..1, rounded to 3 decimals. */
  score: number;
  /** Damerau–Levenshtein distance between the skeletons (L2), else null. */
  distance: number | null;
}

export interface LookalikeResult {
  findings: LookalikeFinding[];
  /** L4: a host label fails UTS #39 Highly Restrictive. */
  mixedScript: boolean;
  /** L6: the host has an `xn--` label. */
  idn: boolean;
  /** L1, L3, or L2 with score ≥ highScore. */
  highConfidence: boolean;
  /** U10 codes of the findings (S1 and the informational L5/L6 codes), sorted. */
  codes: string[];
}

const brandSchema = z.strictObject({
  id: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,62}$/),
  label: z.string().min(1).max(63),
  officialDomains: z.array(z.string().min(3).max(253)).min(1).max(100),
});
const brandsFileSchema = z.object({ brands: z.array(brandSchema).min(1).max(2000) }).loose();

/** Loads and validates a brands file (default: the packaged data/brands.json). */
export function loadBrands(file?: string | null): Brand[] {
  const text = file ? readFileSync(file, 'utf8') : readDataFile('brands.json');
  const parsed = brandsFileSchema.parse(JSON.parse(text));
  const ids = new Set<string>();
  for (const brand of parsed.brands) {
    if (ids.has(brand.id)) throw new Error(`duplicate brand id ${brand.id}`);
    ids.add(brand.id);
    for (const domain of brand.officialDomains) {
      if (registrableDomainOf(domain) !== domain) {
        throw new Error(`brand ${brand.id}: ${domain} is not a registrable domain`);
      }
    }
  }
  return parsed.brands;
}

/** `lookalike/1;cf=<unicode version>;brands=<8 hex>` (part of the engine version). */
export function lookalikeVersion(brands: readonly Brand[]): string {
  const canonical = JSON.stringify(
    [...brands]
      .map((b) => ({ id: b.id, label: b.label, officialDomains: [...b.officialDomains].sort() }))
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
  );
  const hash = createHash('sha256').update(canonical).digest('hex').slice(0, 8);
  return `lookalike/1;cf=${confusablesVersion()};brands=${hash}`;
}

interface ProtectedEntry {
  kind: LookalikeTargetKind;
  /** Brand id, or the protected registrable domain (tenant/extra). */
  id: string;
  targetDomain: string;
  /** Unicode label (registrable domain minus public suffix). */
  label: string;
  skeleton: string;
  official: ReadonlySet<string>;
}

/** Label (registrable domain minus public suffix) of an ASCII registrable domain, in Unicode. */
function labelOf(registrable: string): { label: string; suffix: string } | null {
  const dot = registrable.indexOf('.');
  if (dot <= 0) return null;
  return {
    label: domainToUnicode(registrable.slice(0, dot)) || registrable.slice(0, dot),
    suffix: registrable.slice(dot + 1),
  };
}

export interface ProtectedSetInput {
  brands: readonly Brand[];
  /** The tenant's active domains. */
  tenantDomains?: readonly string[];
  /** URL_PROTECTED_EXTRA_DOMAINS and the tenant's lookalike.extraProtectedDomains. */
  extraDomains?: readonly string[];
}

/** The protected set of one evaluation (brands + tenant domains + extra domains). */
export class ProtectedSet {
  readonly entries: readonly ProtectedEntry[];
  /** Registrable domains of the tenant: never lookalikes of anything. */
  readonly tenantRegistrables: ReadonlySet<string>;

  constructor(input: ProtectedSetInput) {
    const entries: ProtectedEntry[] = [];
    for (const brand of input.brands) {
      const target =
        brand.officialDomains.find((d) => labelOf(d)?.label === brand.label) ??
        brand.officialDomains[0] ??
        brand.id;
      entries.push({
        kind: 'brand',
        id: brand.id,
        targetDomain: target,
        label: brand.label,
        skeleton: skeleton(brand.label),
        official: new Set(brand.officialDomains),
      });
    }
    const tenant = new Set<string>();
    const addDomains = (domains: readonly string[] | undefined, kind: 'tenant' | 'extra'): void => {
      for (const raw of domains ?? []) {
        const normalized = normalizeDomainInput(raw);
        if (!normalized.ok) continue;
        const registrable = normalized.registrableDomain;
        if (kind === 'tenant') tenant.add(registrable);
        const parts = labelOf(registrable);
        if (!parts) continue;
        if (entries.some((e) => e.kind === kind && e.targetDomain === registrable)) continue;
        entries.push({
          kind,
          id: registrable,
          targetDomain: registrable,
          label: parts.label,
          skeleton: skeleton(parts.label),
          official: new Set([registrable]),
        });
      }
    };
    addDomains(input.tenantDomains, 'tenant');
    addDomains(input.extraDomains, 'extra');
    this.entries = entries;
    this.tenantRegistrables = tenant;
  }

  /** Entries usable as title brand matches (landing features): brands and extra domains. */
  titleEntries(): ReadonlyArray<{ id: string; label: string; official: ReadonlySet<string> }> {
    return this.entries.filter((e) => e.kind !== 'tenant');
  }
}

export interface LookalikeCandidate {
  host: string;
  hostKind: 'domain' | 'ipv4' | 'ipv6';
  registrableDomain: string | null;
}

const round3 = (value: number): number => Math.round(value * 1000) / 1000;

export function detectLookalikes(
  candidate: LookalikeCandidate,
  set: ProtectedSet,
  params: LookalikeParams = DEFAULT_LOOKALIKE_PARAMS,
  allowedDomains: readonly string[] = [],
): LookalikeResult {
  const empty: LookalikeResult = {
    findings: [],
    mixedScript: false,
    idn: false,
    highConfidence: false,
    codes: [],
  };
  if (candidate.hostKind !== 'domain') return empty;
  const hostLabels = candidate.host.split('.');
  const idn = hostLabels.some((label) => label.startsWith('xn--'));
  const mixedScript = hostLabels.some((label) => {
    const unicode = label.startsWith('xn--') ? domainToUnicode(label) : label;
    return !isHighlyRestrictive(unicode);
  });
  const codes = new Set<string>();
  if (idn) codes.add('url.idn');
  if (mixedScript) codes.add('url.mixed_script');

  const registrable = candidate.registrableDomain;
  const excluded =
    registrable === null ||
    set.tenantRegistrables.has(registrable) ||
    hostMatchesAny(candidate.host, allowedDomains);
  const parts = registrable === null ? null : labelOf(registrable);
  const findings: LookalikeFinding[] = [];

  if (!excluded && parts && registrable !== null) {
    const label = parts.label;
    const labelSkeleton = skeleton(label);
    const tokens = label.split(/[-.]/).filter(Boolean);
    const tokenSkeletons = tokens.map((token) => skeleton(token));
    const subdomainLabels = hostLabels
      .slice(0, hostLabels.length - registrable.split('.').length)
      .map((l) => (l.startsWith('xn--') ? domainToUnicode(l) : l));
    const subdomainSkeletons = subdomainLabels.map((l) => skeleton(l));

    for (const entry of set.entries) {
      if (entry.official.has(registrable)) continue;
      const push = (rule: LookalikeRule, score: number, distance: number | null): void => {
        findings.push({
          rule,
          targetKind: entry.kind,
          targetDomain: entry.targetDomain,
          score: round3(score),
          distance,
        });
      };
      const protectedLength = [...entry.label].length;
      if (label === entry.label) {
        push('L5', SCORE.L5, null); // same label, other suffix, not official
      } else if (labelSkeleton === entry.skeleton) {
        push('L1', SCORE.L1, null);
      } else if (protectedLength >= params.minLabel) {
        const d = damerauLevenshtein(labelSkeleton, entry.skeleton);
        const max =
          protectedLength < params.longLabel ? params.maxDistanceShort : params.maxDistanceLong;
        if (d >= 1 && d <= max) {
          const longest = Math.max([...labelSkeleton].length, [...entry.skeleton].length);
          push('L2', 1 - d / longest, d);
        }
      }
      if (protectedLength >= COMBOSQUAT_MIN_LABEL && label !== entry.label) {
        const inLabel =
          tokens.length > 1 &&
          (tokens.includes(entry.label) || tokenSkeletons.includes(entry.skeleton));
        const inSubdomain =
          subdomainLabels.includes(entry.label) || subdomainSkeletons.includes(entry.skeleton);
        if (inLabel || inSubdomain) push('L3', SCORE.L3, null);
      }
    }
  }

  findings.sort(
    (a, b) =>
      b.score - a.score ||
      (a.rule < b.rule ? -1 : a.rule > b.rule ? 1 : 0) ||
      (a.targetDomain < b.targetDomain ? -1 : a.targetDomain > b.targetDomain ? 1 : 0),
  );
  const kept = findings.slice(0, MAX_LOOKALIKE_FINDINGS);
  for (const finding of kept) {
    if (finding.rule === 'L1') codes.add('url.lookalike_homoglyph');
    else if (finding.rule === 'L2') codes.add('url.lookalike_edit_distance');
    else if (finding.rule === 'L3') codes.add('url.lookalike_combosquat');
    else
      codes.add(
        finding.targetKind === 'brand' ? 'url.brand_tld_variant' : 'url.lookalike_tld_swap',
      );
  }
  const highConfidence = kept.some(
    (f) => f.rule === 'L1' || f.rule === 'L3' || (f.rule === 'L2' && f.score >= params.highScore),
  );
  return { findings: kept, mixedScript, idn, highConfidence, codes: [...codes].sort() };
}

/** Merges the lookalike results of a URL and its final URL (U10 "merged by the caller"). */
export function mergeLookalike(a: LookalikeResult, b: LookalikeResult | null): LookalikeResult {
  if (!b) return a;
  const findings = [...a.findings, ...b.findings]
    .sort((x, y) => y.score - x.score)
    .filter(
      (f, i, all) =>
        all.findIndex((g) => g.rule === f.rule && g.targetDomain === f.targetDomain) === i,
    )
    .slice(0, 5);
  return {
    findings,
    mixedScript: a.mixedScript || b.mixedScript,
    idn: a.idn || b.idn,
    highConfidence: a.highConfidence || b.highConfidence,
    codes: [...new Set([...a.codes, ...b.codes])].sort(),
  };
}
