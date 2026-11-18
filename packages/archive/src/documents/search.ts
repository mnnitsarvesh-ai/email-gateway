import { z } from 'zod';
import { ARCHIVE_RECORD_STATUSES, EDISCOVERY_REVIEW_TAGS } from '../vocabulary';
import {
  actionSchema,
  categorySchema,
  dateOrDateTimeSchema,
  decimalIdSchema,
  directionSchema,
  isoDateTimeSchema,
  setOf,
  sha256HexSchema,
  sourceSchema,
  uuidSchema,
  verdictSchema,
} from './common';

/**
 * `archive-search/1` (§4.2, A17, A18): the archive search vocabulary of eDiscovery searches
 * (`ediscovery_searches.criteria`); `GET /archive/messages` maps its query filters onto the same
 * shape. Reveal-gated criteria (`recipients`, `subject`, `custodians`) and `holdId` are enforced
 * by `buildArchiveSearchQuery`, not by the schema.
 */
const addressText = z.string().min(1).max(320);
const domainText = z.string().min(1).max(253);

export const archiveSearchCriteriaSchema = z.strictObject({
  from: dateOrDateTimeSchema,
  to: dateOrDateTimeSchema,
  directions: setOf(directionSchema, 3).optional(),
  categories: setOf(categorySchema, 4).optional(),
  sources: setOf(sourceSchema, 2).optional(),
  statuses: setOf(z.enum(ARCHIVE_RECORD_STATUSES), 3).optional(),
  senders: setOf(addressText, 100).optional(),
  senderDomains: setOf(domainText, 100).optional(),
  recipients: setOf(addressText, 1_000).optional(),
  recipientDomains: setOf(domainText, 100).optional(),
  custodians: z.union([z.literal('case'), setOf(addressText, 10_000)]).optional(),
  subject: z.string().min(1).max(256).optional(),
  internetMessageId: z.string().min(1).max(998).optional(),
  hasAttachments: z.boolean().optional(),
  attachmentName: z.string().min(1).max(256).optional(),
  attachmentSha256: setOf(sha256HexSchema, 100).optional(),
  verdicts: setOf(verdictSchema, 9).optional(),
  finalActions: setOf(actionSchema, 7).optional(),
  riskScoreGte: z.number().int().min(0).max(1000).optional(),
  riskScoreLte: z.number().int().min(0).max(1000).optional(),
  malicious: z.boolean().optional(),
  holdId: uuidSchema.optional(),
});
export type ArchiveSearchCriteria = z.infer<typeof archiveSearchCriteriaSchema>;

export const ARCHIVE_SEARCH_CRITERIA_EXAMPLE: ArchiveSearchCriteria = {
  from: '2026-01-01',
  to: '2026-06-30',
  directions: ['inbound', 'outbound'],
  custodians: 'case',
  hasAttachments: true,
};

/**
 * `archive-export-manifest/1` (§4.2, A18): `manifest.json` of an export package, signed with
 * Ed25519 over its exact bytes (`manifest.sig`).
 */
export const archiveExportManifestSchema = z.strictObject({
  version: z.literal('archive-export-manifest/1'),
  exportId: uuidSchema,
  caseId: uuidSchema,
  searchId: uuidSchema,
  /** Organization public id. */
  organizationId: z.union([uuidSchema, decimalIdSchema]),
  generatedAt: isoDateTimeSchema,
  generator: z.literal('archive-worker'),
  signingKeyId: z.string().regex(/^[a-z][a-z0-9]{0,15}$/),
  reviewTags: setOf(z.enum(EDISCOVERY_REVIEW_TAGS), 4),
  counts: z.strictObject({
    items: z.number().int().min(0),
    malicious: z.number().int().min(0),
    bytes: z.number().int().min(0),
  }),
  items: z.array(
    z.strictObject({
      messageId: uuidSchema,
      receivedAt: isoDateTimeSchema,
      internetMessageId: z.string().max(998).nullable(),
      path: z.string().min(1).max(512),
      sha256: sha256HexSchema,
      sizeBytes: z.number().int().min(0),
      verdict: verdictSchema.nullable(),
      malicious: z.boolean(),
    }),
  ),
});
export type ArchiveExportManifest = z.infer<typeof archiveExportManifestSchema>;
