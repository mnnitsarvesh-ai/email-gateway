import { z } from 'zod';
import type {
  CheckSeverity,
  CheckStatus,
  ProviderOutboundMode,
  ProviderValidationKind,
} from '../types';

/** `provider-validation/1` result codes (D10; stable). */
export const VALIDATION_CHECK_CODES = [
  'credentials.token',
  'permissions.granted',
  'tenant.identity',
  'domains.gateway_verified',
  'domains.provider_verified',
  'dns.mx_gateway',
  'inbound.destination',
  'inbound.destination_matches_provider',
  'inbound.smtp',
  'inbound.recent_deliveries',
  'dns.spf_gateway',
  'dns.dkim_provider',
  'outbound.probe',
  'routing.no_loops',
  'lockdown.attested',
] as const;
export type ValidationCheckCode = (typeof VALIDATION_CHECK_CODES)[number];

export interface ValidationCheckSpec {
  code: ValidationCheckCode;
  kinds: readonly ProviderValidationKind[];
  /**
   * Whether a `fail` blocks the wizard's `validate` step: `always`, `outbound` (only when the
   * outbound mode is not `off`), `never` (warning only).
   */
  required: 'always' | 'outbound' | 'never';
  /** Microsoft 365 only. */
  microsoftOnly?: boolean;
}

/** The D10 table. */
export const VALIDATION_CHECKS: readonly ValidationCheckSpec[] = Object.freeze([
  {
    code: 'credentials.token',
    kinds: ['full', 'credentials', 'inbound', 'outbound'],
    required: 'always',
  },
  { code: 'permissions.granted', kinds: ['full', 'credentials'], required: 'always' },
  { code: 'tenant.identity', kinds: ['full', 'credentials'], required: 'always' },
  { code: 'domains.gateway_verified', kinds: ['full', 'inbound'], required: 'always' },
  { code: 'domains.provider_verified', kinds: ['full', 'inbound'], required: 'always' },
  { code: 'dns.mx_gateway', kinds: ['full', 'inbound'], required: 'always' },
  { code: 'inbound.destination', kinds: ['full', 'inbound'], required: 'always' },
  {
    code: 'inbound.destination_matches_provider',
    kinds: ['full', 'inbound'],
    required: 'never',
    microsoftOnly: true,
  },
  { code: 'inbound.smtp', kinds: ['full', 'inbound'], required: 'always' },
  { code: 'inbound.recent_deliveries', kinds: ['full', 'inbound'], required: 'never' },
  { code: 'dns.spf_gateway', kinds: ['full', 'outbound'], required: 'outbound' },
  { code: 'dns.dkim_provider', kinds: ['full', 'outbound'], required: 'never' },
  { code: 'outbound.probe', kinds: ['full', 'outbound'], required: 'outbound' },
  { code: 'routing.no_loops', kinds: ['full'], required: 'always' },
  { code: 'lockdown.attested', kinds: ['full'], required: 'never' },
] satisfies ValidationCheckSpec[]);

/** The checks a run of `kind` executes for a provider and outbound mode. */
export function checksForRun(
  kind: ProviderValidationKind,
  provider: 'microsoft_365' | 'google_workspace',
): ValidationCheckSpec[] {
  return VALIDATION_CHECKS.filter(
    (c) => c.kinds.includes(kind) && (!c.microsoftOnly || provider === 'microsoft_365'),
  );
}

export const isRequiredCheck = (
  spec: ValidationCheckSpec,
  outboundMode: ProviderOutboundMode,
): boolean =>
  spec.required === 'always' || (spec.required === 'outbound' && outboundMode !== 'off');

export const CHECK_STATUSES = [
  'pass',
  'warn',
  'fail',
  'skipped',
  'error',
] as const satisfies readonly CheckStatus[];
export const CHECK_SEVERITIES = [
  'info',
  'warning',
  'critical',
] as const satisfies readonly CheckSeverity[];

export const VALIDATION_SCHEMA = 'provider-validation/1';
export const MAX_EVIDENCE_BYTES = 2_048;
export const MAX_RESULTS = 64;
export const MAX_RESULTS_BYTES = 65_536;

const evidenceValue: z.ZodType<unknown> = z.lazy(() =>
  z.union([
    z.string().max(512),
    z.number(),
    z.boolean(),
    z.null(),
    z.array(evidenceValue).max(32),
    z.record(z.string().max(64), evidenceValue),
  ]),
);

/** One result entry of `provider-validation/1`. */
export const validationResultSchema = z
  .object({
    code: z.string().regex(/^[a-z0-9_.]{1,64}$/),
    /** Domain name, profile key, destination host or `''`. */
    subject: z.string().max(253),
    status: z.enum(CHECK_STATUSES),
    severity: z.enum(CHECK_SEVERITIES),
    evidence: z
      .record(z.string().max(64), evidenceValue)
      .refine(
        (e) => Buffer.byteLength(JSON.stringify(e)) <= MAX_EVIDENCE_BYTES,
        'evidence is at most 2 KiB',
      ),
    remediation: z.string().max(256),
  })
  .strict();
export type ValidationResult = z.infer<typeof validationResultSchema>;

/** The `results` column: ≤ 64 entries, ≤ 64 KiB. */
export const validationResultsSchema = z
  .array(validationResultSchema)
  .max(MAX_RESULTS)
  .refine(
    (r) => Buffer.byteLength(JSON.stringify(r)) <= MAX_RESULTS_BYTES,
    'results are at most 64 KiB',
  );

/**
 * Bounds evidence to 2 KiB: strings truncated to 256 characters, arrays to 10 items, then
 * keys dropped from the end until it fits (marked `truncated: true`). Never call it with
 * secrets: evidence is non-secret by construction.
 */
export function boundEvidence(evidence: Record<string, unknown>): Record<string, unknown> {
  const clip = (value: unknown, depth: number): unknown => {
    if (typeof value === 'string') return value.length > 256 ? `${value.slice(0, 255)}…` : value;
    if (typeof value === 'number') return Number.isFinite(value) ? value : null;
    if (typeof value === 'boolean' || value === null) return value;
    if (value instanceof Date) return value.toISOString();
    if (typeof value === 'bigint') return value.toString();
    if (depth >= 3) return null;
    if (Array.isArray(value)) return value.slice(0, 10).map((v) => clip(v, depth + 1));
    if (typeof value === 'object') {
      return Object.fromEntries(
        Object.entries(value as Record<string, unknown>)
          .filter(([, v]) => v !== undefined)
          .slice(0, 16)
          .map(([k, v]) => [k.slice(0, 64), clip(v, depth + 1)]),
      );
    }
    return null;
  };
  const out = clip(evidence, 0) as Record<string, unknown>;
  const keys = Object.keys(out);
  while (Buffer.byteLength(JSON.stringify(out)) > MAX_EVIDENCE_BYTES && keys.length > 0) {
    delete out[keys.pop()!];
    out.truncated = true;
  }
  return out;
}

export interface ValidationSummary {
  pass: number;
  warn: number;
  fail: number;
  skipped: number;
  error: number;
}

export function summarizeResults(
  results: readonly Pick<ValidationResult, 'status'>[],
): ValidationSummary {
  const summary: ValidationSummary = { pass: 0, warn: 0, fail: 0, skipped: 0, error: 0 };
  for (const r of results) summary[r.status] += 1;
  return summary;
}

/**
 * The run's final status (D10, D13): `failed` when a required check failed or errored,
 * `warning` when anything else is not a pass (non-required failures, warnings), else `passed`.
 * A required check with no result at all counts as failed.
 */
export function validationOutcome(input: {
  kind: ProviderValidationKind;
  provider: 'microsoft_365' | 'google_workspace';
  outboundMode: ProviderOutboundMode;
  results: readonly Pick<ValidationResult, 'code' | 'status'>[];
}): 'passed' | 'warning' | 'failed' {
  let warning = false;
  for (const spec of checksForRun(input.kind, input.provider)) {
    const own = input.results.filter((r) => r.code === spec.code);
    const required = isRequiredCheck(spec, input.outboundMode);
    if (own.length === 0) {
      if (required) return 'failed';
      continue;
    }
    for (const r of own) {
      if (r.status === 'fail' || r.status === 'error') {
        if (required) return 'failed';
        warning = true;
      } else if (r.status === 'warn') warning = true;
    }
  }
  return warning ? 'warning' : 'passed';
}
