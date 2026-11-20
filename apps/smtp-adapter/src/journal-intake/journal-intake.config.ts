import { ConfigValidationError } from '@email-gateway/config';
import { z } from 'zod';

const flag = z.enum(['true', 'false', '1', '0']).transform((v) => v === 'true' || v === '1');
const port = z.coerce.number().int().min(1).max(65535);

const DOMAIN_LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
/** At least two labels: a platform-owned domain such as `journal.<platform domain>`. */
const MULTI_LABEL_DOMAIN = new RegExp(`^${DOMAIN_LABEL}(?:\\.${DOMAIN_LABEL})+$`);

/** Lower-case, trimmed, without the root dot. */
export const normalizeIntakeDomain = (value: string): string =>
  value.trim().toLowerCase().replace(/\.$/, '');

/**
 * Journal intake keys of the smtp-adapter (step 8.6 §4.4, D2; `.env.example` section "Journal
 * intake and archive dedupe (step 8.6)"). Intake is on only when JOURNAL_INTAKE_ENABLED is true
 * AND JOURNAL_INTAKE_DOMAIN is set (empty = off: Postfix renders nothing for it, the policy
 * branch is inert, no journal LMTP listener).
 */
export const journalIntakeConfigShape = {
  JOURNAL_INTAKE_ENABLED: flag.default(true),
  /** Platform-owned intake domain (`journal-<token>@<domain>`); never a tenant domain. */
  JOURNAL_INTAKE_DOMAIN: z
    .string()
    .transform(normalizeIntakeDomain)
    .refine((v) => MULTI_LABEL_DOMAIN.test(v) && v.length <= 253, 'must be a multi-label domain')
    .optional(),
  /** The journal LMTP listener (Postfix `transport_maps` → `lmtp:…:10053`). */
  LMTP_JOURNAL_PORT: port.default(10053),
  /** Platform ceiling of one intake message (also min'ed with the source and the plan). */
  JOURNAL_INTAKE_MAX_MESSAGE_BYTES: z.coerce.number().int().min(1024).default(52_428_800),
  /** Envelope part of a journal report (encoded bytes); a larger one is stored unparsed. */
  JOURNAL_INTAKE_ENVELOPE_MAX_BYTES: z.coerce
    .number()
    .int()
    .min(1024)
    .max(16 * 1_048_576)
    .default(1_048_576),
  /** Recipients kept from one journal envelope (`truncated: true` beyond). */
  JOURNAL_INTAKE_MAX_RECIPIENTS: z.coerce.number().int().min(1).max(10_000).default(10_000),
  /** RCPT-time source cache `sa:jintake:src:<addressHash>` (positive and negative entries). */
  JOURNAL_INTAKE_SOURCE_CACHE_SECONDS: z.coerce.number().int().min(1).max(3600).default(30),
  /** Messages per source and minute (`jintake_src`); 0 refuses every message. */
  JOURNAL_INTAKE_RATE_PER_SOURCE_PER_MINUTE: z.coerce.number().int().min(0).default(6000),
  /** Flush interval of the per-source daily counters into `journal_intake_counters`. */
  JOURNAL_INTAKE_COUNTER_FLUSH_SECONDS: z.coerce.number().int().min(1).max(3600).default(30),
};

export type JournalIntakeConfig = z.infer<z.ZodObject<typeof journalIntakeConfigShape>>;

/** The intake domain when intake is on, else null. */
export function journalIntakeDomain(
  config: Pick<JournalIntakeConfig, 'JOURNAL_INTAKE_ENABLED' | 'JOURNAL_INTAKE_DOMAIN'>,
): string | null {
  return config.JOURNAL_INTAKE_ENABLED && config.JOURNAL_INTAKE_DOMAIN
    ? config.JOURNAL_INTAKE_DOMAIN
    : null;
}

/** One domain equals the other or is under it (either way round; both normalized). */
export const domainsOverlap = (a: string, b: string): boolean =>
  a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`);

/** The domain equals the intake domain or is a subdomain of it (case-insensitive). */
export function isUnderIntakeDomain(domain: string, intakeDomain: string | null): boolean {
  if (intakeDomain === null) return false;
  const d = normalizeIntakeDomain(domain);
  return d === intakeDomain || d.endsWith(`.${intakeDomain}`);
}

/**
 * Cross-field rules: the intake domain must not overlap the reserved bounce or probe domains
 * (either way round), or one listener could accept mail meant for another.
 */
export function assertJournalIntakeConfig(
  config: Pick<JournalIntakeConfig, 'JOURNAL_INTAKE_ENABLED' | 'JOURNAL_INTAKE_DOMAIN'> & {
    POSTFIX_BOUNCE_DOMAIN: string;
    PROVIDER_PROBE_DOMAIN: string;
  },
): void {
  const domain = journalIntakeDomain(config);
  if (domain === null) return;
  const issues: string[] = [];
  if (domainsOverlap(domain, normalizeIntakeDomain(config.POSTFIX_BOUNCE_DOMAIN))) {
    issues.push('JOURNAL_INTAKE_DOMAIN: must not overlap POSTFIX_BOUNCE_DOMAIN');
  }
  if (domainsOverlap(domain, normalizeIntakeDomain(config.PROVIDER_PROBE_DOMAIN))) {
    issues.push('JOURNAL_INTAKE_DOMAIN: must not overlap PROVIDER_PROBE_DOMAIN');
  }
  if (issues.length > 0) throw new ConfigValidationError(issues);
}
