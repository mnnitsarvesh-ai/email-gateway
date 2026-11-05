import { KNOWN_HASH_SEVERITIES } from '@email-gateway/security-contracts';
import { z } from 'zod';
import { PageQuerySchema } from '../../../http/pagination';

/**
 * Shapes of the platform known-threat hash routes (step 4.2 A16, A17):
 * `GET|POST /platform/threat-hashes`, `DELETE /platform/threat-hashes/{sha256}?reason=`. The
 * catalog is `malware_signatures` (platform-wide): hashes, severities, family names and the
 * analyst's reason only, never file content.
 */

const noControl = (value: string): boolean => {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
};

export const Sha256Schema = z
  .string()
  .regex(/^[0-9a-f]{64}$/, 'Expected a lower-case hex SHA-256 (64 characters)');
const Md5Schema = z
  .string()
  .regex(/^[0-9a-f]{32}$/, 'Expected a lower-case hex MD5 (32 characters)');

/** `analyst` (this API), `sandbox` (step 4.6) or `feed:<name>` (future feeds). */
export const ThreatHashSourceSchema = z
  .string()
  .regex(/^(analyst|sandbox|feed:[a-z0-9][a-z0-9_.-]{0,58})$/, 'Unknown source');

const Reason = z
  .string()
  .trim()
  .min(1)
  .max(512)
  .refine(noControl, 'Must not contain control characters');

export const ThreatHashSeveritySchema = z.enum(KNOWN_HASH_SEVERITIES);

export const ThreatHashCreateSchema = z.strictObject({
  sha256: Sha256Schema.describe('SHA-256 of the file (lower-case hex)'),
  md5: Md5Schema.optional().describe('MD5 of the same file (lower-case hex), informational'),
  severity: ThreatHashSeveritySchema.describe(
    '`high`/`critical` → the attachment is `malicious` (rule M1); `low`/`medium` → `suspicious` (S2)',
  ),
  family: z
    .string()
    .trim()
    .min(1)
    .max(128)
    .refine(noControl, 'Must not contain control characters')
    .optional()
    .describe('Malware family name'),
  reason: Reason.describe('Why the hash is added (audited)'),
  expiresAt: z.iso
    .datetime()
    .optional()
    .describe('The lookup ignores the hash after this instant (must be in the future)'),
});
export type ThreatHashCreate = z.output<typeof ThreatHashCreateSchema>;

export const ThreatHashListQuerySchema = PageQuerySchema.extend({
  source: ThreatHashSourceSchema.optional().describe('Only hashes of this source'),
  sha256: Sha256Schema.optional().describe('Only this hash'),
}).strict();
export type ThreatHashListQuery = z.output<typeof ThreatHashListQuerySchema>;

export const ThreatHashDeleteQuerySchema = z.strictObject({
  reason: Reason.describe('Why the hash is removed (audited)'),
});
export type ThreatHashDeleteQuery = z.output<typeof ThreatHashDeleteQuerySchema>;

export const ThreatHashParamSchema = Sha256Schema;

const IsoDate = z.iso.datetime();

export const ThreatHashViewSchema = z.object({
  sha256: z.string(),
  md5: z.string().nullable(),
  severity: ThreatHashSeveritySchema,
  family: z.string().nullable(),
  source: z.string().describe('`analyst`, `sandbox` or `feed:<name>`'),
  reason: z.string().nullable(),
  expiresAt: IsoDate.nullable(),
  addedByUserId: z.uuid().nullable().describe('Public id of the analyst; null for feeds'),
  firstSeenAt: IsoDate,
  lastSeenAt: IsoDate,
  createdAt: IsoDate,
  updatedAt: IsoDate,
});
export type ThreatHashView = z.output<typeof ThreatHashViewSchema>;

export const ThreatHashPageSchema = z.object({
  data: z.array(ThreatHashViewSchema).describe('Newest first'),
  nextCursor: z.string().nullable(),
});
export type ThreatHashPage = z.output<typeof ThreatHashPageSchema>;
