import { z } from 'zod';
import {
  addressSchema,
  categorySchema,
  dateOrDateTimeSchema,
  directionSchema,
  setOf,
  sourceSchema,
  uuidSchema,
} from './common';

/**
 * `archive-retention/1` (§4.2, A11): criteria of `archive_retention_policies.criteria`. A record
 * matches when every present criterion matches; an empty document matches every record.
 */
export const archiveRetentionCriteriaSchema = z.strictObject({
  directions: setOf(directionSchema, 3).optional(),
  categories: setOf(categorySchema, 4).optional(),
  sources: setOf(sourceSchema, 2).optional(),
  policyRuleRefs: setOf(z.string().min(1).max(128), 50).optional(),
  /** Verified domains (public ids) of an org-side party. */
  domainIds: setOf(uuidSchema, 100).optional(),
  /** Departments (public ids) with an org-side party as member. */
  departmentIds: setOf(uuidSchema, 50).optional(),
});
export type ArchiveRetentionCriteria = z.infer<typeof archiveRetentionCriteriaSchema>;

export const ARCHIVE_RETENTION_CRITERIA_EXAMPLE: ArchiveRetentionCriteria = {
  directions: ['outbound'],
  categories: ['delivered'],
  sources: ['journal'],
};

/**
 * The legacy criteria subset step 5.3 understood (`criteria_version` NULL): `{ custodians, from,
 * to }`. Anything else in a legacy row makes it unparsable (= matches everything).
 */
export const legacyLegalHoldCriteriaSchema = z.strictObject({
  custodians: z.array(z.string().min(1).max(320)).max(10_000).optional(),
  from: dateOrDateTimeSchema.optional(),
  to: dateOrDateTimeSchema.optional(),
});
export type LegacyLegalHoldCriteria = z.infer<typeof legacyLegalHoldCriteriaSchema>;

/**
 * `archive-hold/1` (§4.2, A12): `{ custodians?, from?, to?, directions? }` — the legacy subset
 * plus `directions`. Custodians are addresses (matched case-insensitively); an empty custodian
 * list, like an absent one, places no constraint (5.3 semantics).
 */
export const archiveHoldCriteriaSchema = z.strictObject({
  custodians: z.array(z.string().min(1).max(320)).max(10_000).optional(),
  from: dateOrDateTimeSchema.optional(),
  to: dateOrDateTimeSchema.optional(),
  directions: setOf(directionSchema, 3).optional(),
});
export type ArchiveHoldCriteria = z.infer<typeof archiveHoldCriteriaSchema>;

/**
 * The stricter shape the api accepts when a hold is **created** (A12): custodian addresses,
 * `from ≤ to`. Stored rows are matched with `archiveHoldCriteriaSchema` (fail-safe).
 */
export const archiveHoldCreateCriteriaSchema = z
  .strictObject({
    custodians: z.array(addressSchema).max(10_000).optional(),
    from: dateOrDateTimeSchema.optional(),
    to: dateOrDateTimeSchema.optional(),
    directions: setOf(directionSchema, 3).optional(),
  })
  .refine(
    (c) =>
      c.from === undefined ||
      c.to === undefined ||
      Date.parse(c.from.length === 10 ? `${c.from}T00:00:00Z` : c.from) <=
        Date.parse(c.to.length === 10 ? `${c.to}T23:59:59.999Z` : c.to),
    { message: 'from must not be after to', path: ['to'] },
  );

export const ARCHIVE_HOLD_CRITERIA_EXAMPLE: ArchiveHoldCriteria = {
  custodians: ['custodian@example.com'],
  from: '2026-01-01',
  to: '2026-06-30',
  directions: ['inbound', 'outbound'],
};
