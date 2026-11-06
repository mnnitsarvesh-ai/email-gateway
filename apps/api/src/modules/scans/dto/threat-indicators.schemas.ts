import {
  THREAT_CATEGORIES,
  KNOWN_HASH_SEVERITIES,
  URL_MAX_LENGTH,
} from '@email-gateway/security-contracts';
import { z } from 'zod';
import { PageQuerySchema } from '../../../http/pagination';

/**
 * Shapes of the platform threat-indicator routes (step 4.3 U16):
 * `GET|POST /platform/threat-indicators`, `DELETE /platform/threat-indicators/{id}?reason=`. The
 * catalog is the platform rows of `threat_indicators` (`organization_id` NULL): URLs, domains and
 * IP addresses the URL engine (`local_feed` provider) and the click-service consult on every scan
 * and click (never cached). Values are normalized by `@email-gateway/url-security`: a URL in its
 * identity form (no userinfo, no fragment), a domain as lower-case ASCII (A-labels; never a
 * public suffix), an IP address canonical. Never message content.
 */

const noControl = (value: string): boolean => {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
};

/** The indicator types this API manages (the `email` and `file_sha256` types are not URL data). */
export const THREAT_INDICATOR_TYPES = ['url', 'domain', 'ip'] as const;
export type ThreatIndicatorType = (typeof THREAT_INDICATOR_TYPES)[number];
export const ThreatIndicatorTypeSchema = z.enum(THREAT_INDICATOR_TYPES);

/** `analyst` (this API) or `feed:<name>` (future feed imports, §10). */
export const ThreatIndicatorSourceSchema = z
  .string()
  .regex(/^(analyst|feed:[a-z0-9][a-z0-9_.-]{0,58})$/, 'Unknown source');

const Reason = z
  .string()
  .trim()
  .min(1)
  .max(512)
  .refine(noControl, 'Must not contain control characters');

/** Raw input value (normalized by the service); bounded before normalization. */
const RawValue = z
  .string()
  .trim()
  .min(1)
  .max(URL_MAX_LENGTH * 2)
  .refine(noControl, 'Must not contain control characters');

export const ThreatIndicatorSeveritySchema = z.enum(KNOWN_HASH_SEVERITIES);
export const ThreatIndicatorCategorySchema = z.enum(THREAT_CATEGORIES);

export const ThreatIndicatorCreateSchema = z.strictObject({
  type: ThreatIndicatorTypeSchema.describe(
    '`url` (matched by its identity form), `domain` (matches the host and every subdomain), ' +
      '`ip` (a literal IP host)',
  ),
  value: RawValue.describe(
    'The URL, domain or IP address; normalized before storage (the response shows the stored ' +
      'value). A public suffix (`co.uk`, `github.io`) is refused',
  ),
  severity: ThreatIndicatorSeveritySchema.describe(
    '`high`/`critical` → the URL is `malicious` (rule M1); `low`/`medium` → `suspicious` (S6)',
  ),
  category: ThreatIndicatorCategorySchema.describe('Threat category'),
  reason: Reason.describe('Why the indicator is added (audited)'),
  expiresAt: z.iso
    .datetime()
    .optional()
    .describe('The lookup ignores the indicator after this instant (must be in the future)'),
});
export type ThreatIndicatorCreate = z.output<typeof ThreatIndicatorCreateSchema>;

export const ThreatIndicatorListQuerySchema = PageQuerySchema.extend({
  type: ThreatIndicatorTypeSchema.optional().describe('Only indicators of this type'),
  source: ThreatIndicatorSourceSchema.optional().describe('Only indicators of this source'),
  value: RawValue.optional().describe(
    'Only this value (normalized like a new indicator; requires `type`)',
  ),
}).strict();
export type ThreatIndicatorListQuery = z.output<typeof ThreatIndicatorListQuerySchema>;

export const ThreatIndicatorDeleteQuerySchema = z.strictObject({
  reason: Reason.describe('Why the indicator is removed (audited)'),
});
export type ThreatIndicatorDeleteQuery = z.output<typeof ThreatIndicatorDeleteQuerySchema>;

/** `{id}`: the decimal id of the indicator (from the list or the create response). */
export const ThreatIndicatorIdSchema = z
  .string()
  .refine(
    (value) => /^[1-9][0-9]{0,19}$/.test(value) && BigInt(value) <= 18_446_744_073_709_551_615n,
    'Expected a decimal indicator id',
  );

const IsoDate = z.iso.datetime();

export const ThreatIndicatorViewSchema = z.object({
  id: z.string().describe('Indicator id (decimal)'),
  type: ThreatIndicatorTypeSchema,
  value: z.string().describe('Normalized value'),
  valueSha256: z.string().describe('SHA-256 (hex) of the normalized value'),
  severity: ThreatIndicatorSeveritySchema,
  category: ThreatIndicatorCategorySchema.nullable(),
  source: z.string().describe('`analyst` or `feed:<name>`'),
  reason: z.string().nullable(),
  expiresAt: IsoDate.nullable(),
  addedByUserId: z.uuid().nullable().describe('Public id of the analyst; null for feeds'),
  firstSeenAt: IsoDate,
  lastSeenAt: IsoDate,
  createdAt: IsoDate,
  updatedAt: IsoDate,
});
export type ThreatIndicatorView = z.output<typeof ThreatIndicatorViewSchema>;

export const ThreatIndicatorPageSchema = z.object({
  data: z.array(ThreatIndicatorViewSchema).describe('Newest first'),
  nextCursor: z.string().nullable(),
});
export type ThreatIndicatorPage = z.output<typeof ThreatIndicatorPageSchema>;
