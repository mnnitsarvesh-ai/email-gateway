import { explanationLineSchema } from '@email-gateway/policy-dsl';
import { z } from 'zod';
import { ENTRY_ACTIONS } from './access';
import { APPROVAL_REASONS } from './release';
import {
  QUARANTINE_ACTOR_TYPES,
  QUARANTINE_APPROVAL_KINDS,
  QUARANTINE_APPROVAL_STATUSES,
  QUARANTINE_DIRECTIONS,
  QUARANTINE_ENTRY_KINDS,
  QUARANTINE_ORIGINS,
  QUARANTINE_PRIMARY_ENGINES,
  QUARANTINE_REASONS,
  QUARANTINE_RELEASE_MODES,
  QUARANTINE_RELEASE_STATUSES,
  QUARANTINE_RISK_LEVELS,
  QUARANTINE_STATES,
} from './vocabulary';

/**
 * The API DTOs of the quarantine (step 5.3 Q26), shared by the api (OpenAPI, response
 * validation) and the portal (7.x). Stable field names; ids are public UUIDs; times ISO 8601; enums as in §3. Ids,
 * enums, counts, addresses already stored by earlier steps and the sanitized subject only: never
 * message bodies, attachments or URLs. `messageId` is the message's registry public id
 * (`message_identities.public_id`), the id every `/messages/{messageId}` route takes (WP4 fix:
 * the decimal internal id is never exposed by the api).
 */

const uuid = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
const decimal = z.string().regex(/^[0-9]{1,20}$/);
const iso = z.iso.datetime({ offset: false });
const address = z.string().min(1).max(320);
const code = z.string().max(64);

export const quarantineEntrySummarySchema = z.strictObject({
  id: uuid,
  messageId: uuid,
  lifecycleRound: z.number().int().min(0).max(65_535),
  state: z.enum(QUARANTINE_STATES),
  kind: z.enum(QUARANTINE_ENTRY_KINDS),
  origin: z.enum(QUARANTINE_ORIGINS),
  reason: z.enum(QUARANTINE_REASONS),
  direction: z.enum(QUARANTINE_DIRECTIONS),
  recipient: address,
  sender: z.strictObject({ envelope: address.nullable(), headerFrom: address.nullable() }),
  /** Sanitized (control/bidi removed, ≤ 256); only with `quarantine:preview` or on self routes. */
  subject: z.string().max(256).nullable(),
  receivedAt: iso,
  quarantinedAt: iso,
  expiresAt: iso,
  riskLevel: z.enum(QUARANTINE_RISK_LEVELS).nullable(),
  riskScore: z.number().int().min(0).max(1000).nullable(),
  hardBlocks: z.array(code).max(9),
  primaryEngine: z.enum(QUARANTINE_PRIMARY_ENGINES),
  decisive: z.strictObject({
    source: z.enum(['tenant_rule', 'platform_default', 'floor']).nullable(),
    policyId: uuid.nullable(),
    versionNo: z.number().int().min(1).nullable(),
    ruleId: z.string().max(48).nullable(),
  }),
  hasAttachments: z.boolean(),
  attachmentCount: z.number().int().min(0),
  sizeBytes: z.number().int().min(0),
  approvalRequestId: uuid.nullable(),
  rowVersion: z.number().int().min(1),
});
export type QuarantineEntrySummary = z.infer<typeof quarantineEntrySummarySchema>;

const actorRefSchema = z.strictObject({
  type: z.enum(QUARANTINE_ACTOR_TYPES),
  id: uuid.nullable(),
});

/** The 13.3 re-validation summary as stored in the release log (content-free). */
export const releaseRevalidationSummarySchema = z.strictObject({
  disposition: z.enum(['allow', 'require_approval', 'quarantine', 'reject']),
  source: z.enum(['tenant_rule', 'platform_default', 'floor']),
  decisiveRuleRef: z.string().max(96).nullable(),
  floorReasons: z.array(code).max(16),
  hardBlocks: z.array(code).max(9),
  level: z.enum(QUARANTINE_RISK_LEVELS).nullable(),
  score: z.number().int().min(0).max(1000).nullable(),
  recommendedAction: z.string().max(32).nullable(),
  generation: decimal,
  snapshotSha256: z.string().regex(/^[0-9a-f]{64}$/),
  inputSha256: z.string().regex(/^[0-9a-f]{64}$/),
  evaluatorVersion: z.string().max(32),
  scanId: decimal.nullable(),
  scanCompletedAt: z.iso.datetime({ offset: false }).nullable(),
});

export const quarantineReleaseViewSchema = z.strictObject({
  id: uuid,
  status: z.enum(QUARANTINE_RELEASE_STATUSES),
  mode: z.enum(QUARANTINE_RELEASE_MODES),
  requestedBy: actorRefSchema,
  requestedAt: iso,
  completedAt: iso.nullable(),
  revalidation: releaseRevalidationSummarySchema.nullable(),
  deliveredObject: z.enum(['original', 'rewritten', 'policy_copy', 'none']).nullable(),
  approvalRequestId: uuid.nullable(),
});
export type QuarantineReleaseView = z.infer<typeof quarantineReleaseViewSchema>;

export const quarantineEntryDetailSchema = quarantineEntrySummarySchema.extend({
  explanation: z.strictObject({
    lines: z.array(explanationLineSchema).max(24),
    text: z.string().max(2048),
  }),
  floorReasons: z.array(code).max(16),
  reasonCodes: z.array(code).max(32),
  releases: z.array(quarantineReleaseViewSchema).max(100),
  allowedActions: z.array(z.enum(ENTRY_ACTIONS)).max(ENTRY_ACTIONS.length),
  contentAvailable: z.boolean(),
});
export type QuarantineEntryDetail = z.infer<typeof quarantineEntryDetailSchema>;

export const quarantineApprovalViewSchema = z.strictObject({
  id: uuid,
  kind: z.enum(QUARANTINE_APPROVAL_KINDS),
  status: z.enum(QUARANTINE_APPROVAL_STATUSES),
  entryId: uuid,
  approvalReasons: z.array(z.enum(APPROVAL_REASONS)).max(APPROVAL_REASONS.length),
  requestedBy: actorRefSchema,
  requestedAt: iso,
  expiresAt: iso,
  decidedBy: uuid.nullable(),
  decidedAt: iso.nullable(),
  decisionReason: z.string().max(512).nullable(),
});
export type QuarantineApprovalView = z.infer<typeof quarantineApprovalViewSchema>;

/** `Page<T> { items, nextCursor }` (keyset pagination; no total count). */
export const pageSchema = <T extends z.ZodType>(item: T, maxItems = 500) =>
  z.strictObject({
    items: z.array(item).max(maxItems),
    nextCursor: z.string().max(512).nullable(),
  });
export type Page<T> = { items: T[]; nextCursor: string | null };

export { bulkResultSchema, type BulkResult } from './bulk';
