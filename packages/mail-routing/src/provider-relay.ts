import { createHash, randomBytes } from 'node:crypto';
import { parseEgressCidr } from '@email-gateway/database';
import { z } from 'zod';
import { base32Lower } from './route-token';

/**
 * Pure rules of the provider relay (step 8.2 D7, D8, D10; ADR-0078, ADR-0079; contracts §33):
 * provider egress range matching, the `provider-relay-proof/1` policy and its evaluation, and
 * the probe addresses of connector validation. No I/O: the smtp-adapter loads the ranges,
 * verifies DKIM, counts replays and feeds the evidence in.
 */

/** Providers whose shared outbound infrastructure the relay accepts (IntegrationProvider). */
export const RELAY_PROVIDERS = ['microsoft_365', 'google_workspace'] as const;
export type RelayProvider = (typeof RELAY_PROVIDERS)[number];

export const isRelayProvider = (value: unknown): value is RelayProvider =>
  typeof value === 'string' && (RELAY_PROVIDERS as readonly string[]).includes(value);

// --- Egress ranges (D7.2) --------------------------------------------------------------------

/** One range in the `provider_egress_ranges` encoding (4 or 16 bytes big-endian). */
export interface EgressRangeInput {
  provider: RelayProvider;
  ipVersion: 4 | 6;
  rangeStart: Uint8Array;
  rangeEnd: Uint8Array;
}

/** A client address as raw bytes (4 or 16, big-endian). */
export interface IpBytes {
  version: 4 | 6;
  bytes: Uint8Array;
}

interface Interval {
  start: Buffer;
  end: Buffer;
}

const byteLength = (version: 4 | 6): number => (version === 4 ? 4 : 16);

/**
 * In-memory index of the active egress ranges of every provider: per provider and IP version,
 * the ranges sorted and merged (overlapping or adjacent ranges become one interval), looked up
 * by binary search. Immutable; the smtp-adapter swaps in a new index on every refresh.
 */
export class ProviderEgressIndex {
  private constructor(
    private readonly intervals: ReadonlyMap<string, readonly Interval[]>,
    private readonly counts: ReadonlyMap<RelayProvider, number>,
  ) {}

  static empty(): ProviderEgressIndex {
    return new ProviderEgressIndex(new Map(), new Map());
  }

  /** Throws on a malformed range (wrong byte length, start after end, unknown provider). */
  static build(ranges: Iterable<EgressRangeInput>): ProviderEgressIndex {
    const lists = new Map<string, Interval[]>();
    const counts = new Map<RelayProvider, number>();
    for (const range of ranges) {
      if (!isRelayProvider(range.provider)) throw new Error('unknown egress range provider');
      if (range.ipVersion !== 4 && range.ipVersion !== 6) {
        throw new Error('egress range IP version must be 4 or 6');
      }
      const length = byteLength(range.ipVersion);
      const start = Buffer.from(range.rangeStart);
      const end = Buffer.from(range.rangeEnd);
      if (start.length !== length || end.length !== length) {
        throw new Error('egress range bytes do not match the IP version');
      }
      if (Buffer.compare(start, end) > 0) throw new Error('egress range start is after its end');
      const key = `${range.provider}:${range.ipVersion}`;
      const list = lists.get(key) ?? [];
      list.push({ start, end });
      lists.set(key, list);
      counts.set(range.provider, (counts.get(range.provider) ?? 0) + 1);
    }
    const merged = new Map<string, Interval[]>();
    for (const [key, list] of lists) {
      list.sort((a, b) => Buffer.compare(a.start, b.start));
      const out: Interval[] = [];
      for (const interval of list) {
        const last = out[out.length - 1];
        if (last && Buffer.compare(interval.start, last.end) <= 0) {
          if (Buffer.compare(interval.end, last.end) > 0) last.end = interval.end;
        } else {
          out.push({ start: interval.start, end: interval.end });
        }
      }
      merged.set(key, out);
    }
    return new ProviderEgressIndex(merged, counts);
  }

  /** True when the address lies in one of the provider's ranges. */
  contains(provider: RelayProvider, ip: IpBytes): boolean {
    const list = this.intervals.get(`${provider}:${ip.version}`);
    const bytes = Buffer.from(ip.bytes);
    if (!list || list.length === 0 || bytes.length !== byteLength(ip.version)) return false;
    // Last interval whose start is ≤ ip.
    let low = 0;
    let high = list.length - 1;
    let found = -1;
    while (low <= high) {
      const mid = (low + high) >> 1;
      if (Buffer.compare(list[mid]!.start, bytes) <= 0) {
        found = mid;
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    return found !== -1 && Buffer.compare(bytes, list[found]!.end) <= 0;
  }

  /** Every provider whose ranges contain the address (in RELAY_PROVIDERS order). */
  providersFor(ip: IpBytes): RelayProvider[] {
    return RELAY_PROVIDERS.filter((provider) => this.contains(provider, ip));
  }

  /** Number of ranges loaded for the provider (before merging). */
  count(provider: RelayProvider): number {
    return this.counts.get(provider) ?? 0;
  }
}

/**
 * Canonical CIDRs → ranges (strict `parseEgressCidr`: canonical text, host bits clear, prefix
 * at least /8). Throws on the first invalid entry.
 */
export function egressRangesFromCidrs(
  provider: RelayProvider,
  cidrs: readonly string[],
): EgressRangeInput[] {
  return cidrs.map((cidr) => {
    const parsed = parseEgressCidr(cidr);
    return {
      provider,
      ipVersion: parsed.ipVersion,
      rangeStart: parsed.rangeStart,
      rangeEnd: parsed.rangeEnd,
    };
  });
}

// --- Proof policy `provider-relay-proof/1` (D8) ----------------------------------------------

export const PROVIDER_RELAY_PROOF_SCHEMA = 'provider-relay-proof/1';

/** Bounds of the Google freshness window and replay counter. */
export const DKIM_MAX_AGE_BOUNDS = { min: 300, max: 86_400 } as const;
export const DKIM_REPLAY_MAX_BOUNDS = { min: 1, max: 100 } as const;
/** Clock skew tolerated for a DKIM `t=` in the future. */
export const DKIM_FUTURE_SKEW_SECONDS = 300;

const ruleMode = z.enum(['required', 'off']);

/**
 * Shape of `provider_connections.relay_proof` (NULL = the provider default). The provider-
 * dependent bounds are checked by `providerRelayProofIssues`.
 */
export const providerRelayProofPolicySchema = z
  .object({
    tenantHeader: ruleMode.optional(),
    dkimAligned: ruleMode,
    dkimMaxAgeSeconds: z
      .number()
      .int()
      .min(DKIM_MAX_AGE_BOUNDS.min)
      .max(DKIM_MAX_AGE_BOUNDS.max)
      .optional(),
    dkimReplayMax: z
      .number()
      .int()
      .min(DKIM_REPLAY_MAX_BOUNDS.min)
      .max(DKIM_REPLAY_MAX_BOUNDS.max)
      .optional(),
  })
  .strict();

export type ProviderRelayProofPolicy = z.infer<typeof providerRelayProofPolicySchema>;

/** Provider defaults (D8): the policy of a connection whose `relay_proof` is NULL. */
export const DEFAULT_PROVIDER_RELAY_PROOF: Readonly<
  Record<RelayProvider, Readonly<ProviderRelayProofPolicy>>
> = Object.freeze({
  microsoft_365: Object.freeze({ tenantHeader: 'required', dkimAligned: 'required' }),
  google_workspace: Object.freeze({
    dkimAligned: 'required',
    dkimMaxAgeSeconds: 3600,
    dkimReplayMax: 5,
  }),
} as const);

/**
 * The provider-dependent bounds of a policy (empty = valid):
 * - `tenantHeader` exists only for Microsoft 365, and may be `off` only with `dkimAligned:
 *   required` (at least one rule is always required) AND with the freshness window and the
 *   replay counter: DKIM is then the only proof, with the same replay residual risk as Google
 *   (§11, ADR-0078);
 * - `dkimAligned` is never `off` for Google Workspace, whose policy also always keeps the
 *   freshness window and the replay counter (the residual-risk bounds of §11);
 * - the freshness and replay options need `dkimAligned: required`.
 */
export function providerRelayProofIssues(
  provider: RelayProvider,
  policy: ProviderRelayProofPolicy,
): string[] {
  const issues: string[] = [];
  const dkim = policy.dkimAligned === 'required';
  if (provider === 'microsoft_365') {
    if (policy.tenantHeader === undefined)
      issues.push('tenantHeader is required for Microsoft 365');
    if (policy.tenantHeader === 'off' && !dkim) {
      issues.push('tenantHeader may be off only with dkimAligned required');
    }
    if (policy.tenantHeader === 'off' && dkim) {
      if (policy.dkimMaxAgeSeconds === undefined) {
        issues.push('dkimMaxAgeSeconds is required when tenantHeader is off');
      }
      if (policy.dkimReplayMax === undefined) {
        issues.push('dkimReplayMax is required when tenantHeader is off');
      }
    }
  } else {
    if (policy.tenantHeader !== undefined) {
      issues.push('tenantHeader applies only to Microsoft 365');
    }
    if (!dkim) issues.push('dkimAligned may never be off for Google Workspace');
    if (policy.dkimMaxAgeSeconds === undefined) {
      issues.push('dkimMaxAgeSeconds is required for Google Workspace');
    }
    if (policy.dkimReplayMax === undefined) {
      issues.push('dkimReplayMax is required for Google Workspace');
    }
  }
  if (!dkim && (policy.dkimMaxAgeSeconds !== undefined || policy.dkimReplayMax !== undefined)) {
    issues.push('dkimMaxAgeSeconds and dkimReplayMax need dkimAligned required');
  }
  return issues;
}

export class ProviderRelayProofPolicyError extends Error {}

/**
 * The effective policy of a connection: the provider default for NULL, else the stored value,
 * validated. Throws `ProviderRelayProofPolicyError` for an invalid stored value (the relay then
 * fails closed with a temporary error; the api never stores one).
 */
export function parseProviderRelayProofPolicy(
  provider: RelayProvider,
  stored: unknown,
): ProviderRelayProofPolicy {
  if (stored === null || stored === undefined) return { ...DEFAULT_PROVIDER_RELAY_PROOF[provider] };
  const parsed = providerRelayProofPolicySchema.safeParse(stored);
  if (!parsed.success) throw new ProviderRelayProofPolicyError('relay_proof does not parse');
  const issues = providerRelayProofIssues(provider, parsed.data);
  if (issues.length > 0) throw new ProviderRelayProofPolicyError(issues.join('; '));
  return parsed.data;
}

// --- Proof evaluation (D8) -------------------------------------------------------------------

/** One DKIM-Signature as the verifier reports it. */
export interface DkimSignatureEvidence {
  /** Verifier result: `pass`, `fail`, `neutral`, `policy`, `temperror`, `permerror`, … */
  status: string;
  /** `d=`, lower-case ASCII. */
  domain: string;
  /** `a=`, lower-case. */
  algorithm: string;
  /** The signature has an `l=` tag. */
  bodyLengthLimited: boolean;
  /** `h=` header names, lower-case. */
  signedHeaders: readonly string[];
  /** RSA modulus length; null for ed25519 or unknown. */
  keyBits: number | null;
  /** `t=`; null when absent. */
  signedAt: Date | null;
  /** Lower-case hex SHA-256 of the `b=` value (whitespace removed): the replay counter key. */
  signatureId: string;
}

export interface ProviderProofEvidence {
  provider: RelayProvider;
  /** `provider_connections.external_tenant_id` (verified); null when unknown. */
  expectedTenantId: string | null;
  /** Every `X-MS-Exchange-CrossTenant-Id` value, trimmed and lower-cased. */
  tenantHeaderValues: readonly string[];
  /** Domain of the single header-From address (ASCII, lower-case); null when not exactly one. */
  headerFromDomain: string | null;
  /** Active gateway domains of the organization linked to the connection (ASCII, lower-case). */
  linkedDomains: readonly string[];
  signatures: readonly DkimSignatureEvidence[];
  /** The header block ended within INGEST_HEADER_MAX_BYTES (else evidence may be hidden). */
  headerBlockComplete: boolean;
  /** The DKIM verifier itself failed (stream or library error). */
  verifierError: boolean;
  /** Replay counts after the increment, per `signatureId` (Google); absent = not counted. */
  replayCounts?: ReadonlyMap<string, number>;
  /** The replay counter could not be read or incremented (Redis). */
  replayError?: boolean;
  now: Date;
}

export type TenantHeaderResult = 'match' | 'mismatch' | 'absent' | 'not_applicable';
export type DkimProofResult =
  'aligned_pass' | 'unaligned_pass' | 'fail' | 'none' | 'temperror' | 'replayed' | 'stale';
export type ProofResult = 'pass' | 'fail' | 'temperror';
export type ProofRule = 'tenant_header' | 'dkim_aligned' | 'dkim_fresh' | 'dkim_replay';

export interface ProviderProofOutcome {
  result: ProofResult;
  tenantHeader: TenantHeaderResult;
  dkim: DkimProofResult;
  /** First failing reason (bounded vocabulary); null on pass. */
  failureCode: string | null;
  /** Per evaluated rule (metrics `smtp_provider_proof_total{rule,result}`). */
  rules: { rule: ProofRule; result: ProofResult }[];
  /** Distinct `d=` values of the message, at most 5. */
  dkimDomains: string[];
  /** Age of the accepted (or best aligned) signature in seconds; null without `t=`. */
  dkimAgeSeconds: number | null;
}

const ALLOWED_ALGORITHMS = new Set(['rsa-sha256', 'ed25519-sha256']);
const MIN_RSA_BITS = 1024;
export const MAX_EVIDENCE_DKIM_DOMAINS = 5;

export type DkimSignatureClass = 'aligned_pass' | 'unaligned_pass' | 'weak' | 'fail' | 'temperror';

const normalize = (domain: string): string => domain.trim().toLowerCase().replace(/\.$/, '');

/** `d` equals the From domain or is a parent of it (relaxed alignment by label suffix). */
export function dkimDomainAligned(signingDomain: string, fromDomain: string): boolean {
  const d = normalize(signingDomain);
  const from = normalize(fromDomain);
  return d.length > 0 && (from === d || from.endsWith(`.${d}`));
}

/**
 * One signature against the D8 "aligned pass" definition: result `pass`; `d=` the From domain
 * or a parent of it; `d` linked to the connection; no `l=`; `h=` covers `from`; `rsa-sha256` or
 * `ed25519-sha256`; RSA key ≥ 1024 bits. A verified signature that breaks one of the last four
 * conditions is `weak`; one that is not aligned or not linked is `unaligned_pass`.
 */
export function classifyDkimSignature(
  signature: DkimSignatureEvidence,
  context: { headerFromDomain: string | null; linkedDomains: ReadonlySet<string> },
): DkimSignatureClass {
  if (signature.status === 'temperror') return 'temperror';
  if (signature.status !== 'pass') return 'fail';
  const algorithm = signature.algorithm.toLowerCase();
  if (
    signature.bodyLengthLimited ||
    !signature.signedHeaders.some((name) => name.toLowerCase() === 'from') ||
    !ALLOWED_ALGORITHMS.has(algorithm) ||
    (algorithm.startsWith('rsa-') &&
      (signature.keyBits === null || signature.keyBits < MIN_RSA_BITS))
  ) {
    return 'weak';
  }
  const domain = normalize(signature.domain);
  if (
    context.headerFromDomain === null ||
    !dkimDomainAligned(domain, context.headerFromDomain) ||
    !context.linkedDomains.has(domain)
  ) {
    return 'unaligned_pass';
  }
  return 'aligned_pass';
}

const fresh = (signature: DkimSignatureEvidence, maxAge: number, now: Date): boolean => {
  if (signature.signedAt === null) return false;
  const age = (now.getTime() - signature.signedAt.getTime()) / 1000;
  return age <= maxAge && age >= -DKIM_FUTURE_SKEW_SECONDS;
};

const ageSeconds = (signature: DkimSignatureEvidence | undefined, now: Date): number | null =>
  signature?.signedAt
    ? Math.max(0, Math.round((now.getTime() - signature.signedAt.getTime()) / 1000))
    : null;

/**
 * The aligned, fresh signatures whose replay counter must be incremented before
 * `evaluateProviderProof` (only when the policy has `dkimReplayMax`). Distinct by signature id.
 */
export function dkimReplayCandidates(
  evidence: ProviderProofEvidence,
  policy: ProviderRelayProofPolicy,
): DkimSignatureEvidence[] {
  if (policy.dkimAligned !== 'required' || policy.dkimReplayMax === undefined) return [];
  const linked = new Set(evidence.linkedDomains.map(normalize));
  const seen = new Set<string>();
  return evidence.signatures.filter((signature) => {
    if (seen.has(signature.signatureId)) return false;
    const aligned =
      classifyDkimSignature(signature, {
        headerFromDomain: evidence.headerFromDomain,
        linkedDomains: linked,
      }) === 'aligned_pass';
    const ok =
      aligned &&
      (policy.dkimMaxAgeSeconds === undefined ||
        fresh(signature, policy.dkimMaxAgeSeconds, evidence.now));
    if (ok) seen.add(signature.signatureId);
    return ok;
  });
}

interface DkimEvaluation {
  dkim: DkimProofResult;
  result: ProofResult;
  failureCode: string | null;
  rules: { rule: ProofRule; result: ProofResult }[];
  accepted: DkimSignatureEvidence | undefined;
}

function evaluateDkim(
  evidence: ProviderProofEvidence,
  policy: ProviderRelayProofPolicy,
): DkimEvaluation {
  const linked = new Set(evidence.linkedDomains.map(normalize));
  const classes = evidence.signatures.map((signature) => ({
    signature,
    cls: classifyDkimSignature(signature, {
      headerFromDomain: evidence.headerFromDomain,
      linkedDomains: linked,
    }),
  }));
  const aligned = classes.filter((c) => c.cls === 'aligned_pass').map((c) => c.signature);
  const required = policy.dkimAligned === 'required';
  const rules: DkimEvaluation['rules'] = [];
  const done = (
    dkim: DkimProofResult,
    result: ProofResult,
    failureCode: string | null,
    accepted?: DkimSignatureEvidence,
  ): DkimEvaluation => ({ dkim, result, failureCode, rules, accepted });

  if (evidence.verifierError) {
    if (required) rules.push({ rule: 'dkim_aligned', result: 'temperror' });
    return done('temperror', required ? 'temperror' : 'pass', required ? 'verifier_error' : null);
  }
  if (aligned.length === 0) {
    let dkim: DkimProofResult;
    let code: string;
    let result: ProofResult = 'fail';
    if (classes.some((c) => c.cls === 'temperror')) {
      // A signature that could not be checked might have been the aligned one (I7).
      dkim = 'temperror';
      code = 'dkim_temperror';
      result = 'temperror';
    } else if (classes.length === 0) {
      dkim = 'none';
      code = 'dkim_none';
    } else if (classes.some((c) => c.cls === 'unaligned_pass')) {
      dkim = 'unaligned_pass';
      code = 'dkim_unaligned';
    } else if (classes.some((c) => c.cls === 'weak')) {
      dkim = 'fail';
      code = 'dkim_weak';
    } else {
      dkim = 'fail';
      code = 'dkim_failed';
    }
    if (!required) return done(dkim, 'pass', null);
    rules.push({ rule: 'dkim_aligned', result });
    return done(dkim, result, code);
  }
  if (!required) return done('aligned_pass', 'pass', null, aligned[0]);
  rules.push({ rule: 'dkim_aligned', result: 'pass' });

  let candidates = aligned;
  if (policy.dkimMaxAgeSeconds !== undefined) {
    const maxAge = policy.dkimMaxAgeSeconds;
    candidates = aligned.filter((signature) => fresh(signature, maxAge, evidence.now));
    if (candidates.length === 0) {
      rules.push({ rule: 'dkim_fresh', result: 'fail' });
      return done('stale', 'fail', 'dkim_stale', aligned[0]);
    }
    rules.push({ rule: 'dkim_fresh', result: 'pass' });
  }
  if (policy.dkimReplayMax !== undefined) {
    const max = policy.dkimReplayMax;
    if (evidence.replayError === true || evidence.replayCounts === undefined) {
      rules.push({ rule: 'dkim_replay', result: 'temperror' });
      return done('temperror', 'temperror', 'replay_counter_error', candidates[0]);
    }
    const counts = evidence.replayCounts;
    if (candidates.some((signature) => !counts.has(signature.signatureId))) {
      rules.push({ rule: 'dkim_replay', result: 'temperror' });
      return done('temperror', 'temperror', 'replay_counter_error', candidates[0]);
    }
    const unreplayed = candidates.filter(
      (signature) => (counts.get(signature.signatureId) ?? Number.POSITIVE_INFINITY) <= max,
    );
    if (unreplayed.length === 0) {
      rules.push({ rule: 'dkim_replay', result: 'fail' });
      return done('replayed', 'fail', 'dkim_replayed', candidates[0]);
    }
    rules.push({ rule: 'dkim_replay', result: 'pass' });
    candidates = unreplayed;
  }
  return done('aligned_pass', 'pass', null, candidates[0]);
}

/**
 * `evaluateProviderProof(evidence, policy)` (D8): the tenant header rule (Microsoft 365: at least
 * one `X-MS-Exchange-CrossTenant-Id` and every value equal to the connection's tenant id, so a
 * forged second value fails) and the aligned-DKIM rule with the optional freshness window and
 * replay counter. A failing rule is `fail` (permanent) even when another rule could not be
 * checked; otherwise any rule that could not be checked is `temperror` (fail closed, I7). A
 * header block cut by INGEST_HEADER_MAX_BYTES fails: evidence beyond the limit is unseen.
 */
export function evaluateProviderProof(
  evidence: ProviderProofEvidence,
  policy: ProviderRelayProofPolicy,
): ProviderProofOutcome {
  const rules: ProviderProofOutcome['rules'] = [];
  let tenantHeader: TenantHeaderResult = 'not_applicable';
  let tenantFailure: string | null = null;
  if (evidence.provider === 'microsoft_365' && policy.tenantHeader === 'required') {
    const expected = evidence.expectedTenantId?.trim().toLowerCase() ?? null;
    const values = evidence.tenantHeaderValues.map((value) => value.trim().toLowerCase());
    if (values.length === 0) {
      tenantHeader = 'absent';
      tenantFailure = 'tenant_header_absent';
    } else if (expected === null || expected === '' || values.some((value) => value !== expected)) {
      tenantHeader = 'mismatch';
      tenantFailure = 'tenant_header_mismatch';
    } else {
      tenantHeader = 'match';
    }
    rules.push({ rule: 'tenant_header', result: tenantFailure === null ? 'pass' : 'fail' });
  }

  const dkim = evaluateDkim(evidence, policy);
  rules.push(...dkim.rules);

  const dkimDomains = [
    ...new Set(evidence.signatures.map((signature) => normalize(signature.domain)).filter(Boolean)),
  ].slice(0, MAX_EVIDENCE_DKIM_DOMAINS);
  const base = {
    tenantHeader,
    dkim: dkim.dkim,
    rules,
    dkimDomains,
    dkimAgeSeconds: ageSeconds(dkim.accepted, evidence.now),
  };

  if (!evidence.headerBlockComplete) {
    return { ...base, result: 'fail', failureCode: 'header_block_truncated' };
  }
  if (tenantFailure !== null) return { ...base, result: 'fail', failureCode: tenantFailure };
  if (dkim.result === 'fail') return { ...base, result: 'fail', failureCode: dkim.failureCode };
  if (dkim.result === 'temperror') {
    return { ...base, result: 'temperror', failureCode: dkim.failureCode };
  }
  return { ...base, result: 'pass', failureCode: null };
}

// --- Probe addresses (D10) -------------------------------------------------------------------

/** Local-part prefix of a validation probe address. */
export const PROBE_LOCAL_PREFIX = 'eg-probe-';
/** A probe token: 16 random bytes as 26 lower-case base32 characters. */
export const PROBE_TOKEN_PATTERN = /^[a-z2-7]{26}$/;

const splitAt = (address: string): { local: string; domain: string } | null => {
  const at = address.lastIndexOf('@');
  if (at <= 0 || at === address.length - 1) return null;
  return { local: address.slice(0, at), domain: normalize(address.slice(at + 1)) };
};

/** The domain equals PROVIDER_PROBE_DOMAIN or is under it (case-insensitive). */
export function isProbeDomain(domain: string, probeDomain: string): boolean {
  const d = normalize(domain);
  const probe = normalize(probeDomain);
  return probe.length > 0 && (d === probe || d.endsWith(`.${probe}`));
}

/**
 * The token of a probe address `eg-probe-<26 lower-case base32>@<PROVIDER_PROBE_DOMAIN>` (the
 * local part is matched case-insensitively and returned lower-case); null for anything else,
 * including addresses under a subdomain of the probe domain.
 */
export function probeTokenOf(address: string, probeDomain: string): string | null {
  const parts = splitAt(address.trim());
  if (!parts || parts.domain !== normalize(probeDomain) || parts.domain.length === 0) return null;
  const local = parts.local.toLowerCase();
  if (!local.startsWith(PROBE_LOCAL_PREFIX)) return null;
  const token = local.slice(PROBE_LOCAL_PREFIX.length);
  return PROBE_TOKEN_PATTERN.test(token) ? token : null;
}

export const isProbeAddress = (address: string, probeDomain: string): boolean =>
  probeTokenOf(address, probeDomain) !== null;

/** `provider_validation_runs.probe_token_sha256`: lower-case hex SHA-256 of the token text. */
export function probeTokenSha256(token: string): string {
  if (!PROBE_TOKEN_PATTERN.test(token)) throw new Error('not a probe token');
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

/** A new probe token (16 random bytes, 26 lower-case base32 characters). */
export function generateProbeToken(random: (size: number) => Uint8Array = randomBytes): string {
  const token = base32Lower(random(16));
  if (!PROBE_TOKEN_PATTERN.test(token)) throw new Error('random source returned the wrong size');
  return token;
}

/** The probe address of a token. */
export function probeAddress(token: string, probeDomain: string): string {
  if (!PROBE_TOKEN_PATTERN.test(token)) throw new Error('not a probe token');
  return `${PROBE_LOCAL_PREFIX}${token}@${normalize(probeDomain)}`;
}
