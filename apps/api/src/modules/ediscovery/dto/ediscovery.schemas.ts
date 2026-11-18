import {
  addressSchema,
  archiveHoldCreateCriteriaSchema,
  archiveSearchCriteriaSchema,
  EDISCOVERY_REVIEW_TAGS,
  EXPORT_DEFAULT_REVIEW_TAGS,
} from '@email-gateway/archive';
import { z } from 'zod';
import { stripControlCharacters } from '../../webhooks/domain/control-chars';
import { defineListQuery } from '../../../http/listing/list-query';
import {
  ARCHIVE_EXAMPLE_IDS as ID,
  ARCHIVE_EXAMPLES,
  ArchiveMessageSchema,
  PublicIdSchema,
} from '../../archive/dto/archive.schemas';

/**
 * Request and response shapes of the legal hold and eDiscovery routes (step 8.1 §4.4 #24–#41;
 * A12, A18, ADR-0069). Request schemas are strict at every node. Custodian addresses and hold
 * criteria are shown to the holders of the hold/case permissions; search criteria that would
 * confirm a masked value (recipients, subject, custodian addresses) are masked unless the caller
 * holds `message:reveal`; hits are masked like archive search results.
 */

const isoInstant = z.iso.datetime({ offset: true });
const nullableInstant = isoInstant.nullable();
const sha256 = z.string().regex(/^[0-9a-f]{64}$/);

const text = (min: number, max: number) =>
  z
    .string()
    .max(max * 4)
    .transform((v) => stripControlCharacters(v).trim())
    .pipe(z.string().min(min).max(max));

const uniqueAddresses = (max: number) =>
  z
    .array(addressSchema)
    .max(max)
    .transform((list) => [...new Set(list.map((a) => a.trim().toLowerCase()))]);

// ---- legal holds (#24–#27) ----------------------------------------------------------------------

export const HOLD_STATUSES = ['active', 'released'] as const;

export const LegalHoldSchema = z.object({
  id: PublicIdSchema,
  caseId: PublicIdSchema.nullable().describe('Null for holds created before step 8.1'),
  name: z.string(),
  reason: z.string(),
  status: z.enum(HOLD_STATUSES),
  criteria: z
    .record(z.string(), z.unknown())
    .nullable()
    .describe(
      '`archive-hold/1` (legacy rows: the 5.3 subset; unparsable criteria hold everything)',
    ),
  criteriaVersion: z.string().nullable(),
  createdBy: PublicIdSchema.nullable(),
  createdAt: isoInstant,
  releasedAt: nullableInstant,
  releasedBy: PublicIdSchema.nullable(),
  releaseReason: z.string().nullable(),
  rowVersion: z.number().int(),
});
export type LegalHoldView = z.infer<typeof LegalHoldSchema>;

export const LegalHoldPageSchema = z.object({
  data: z.array(LegalHoldSchema),
  nextCursor: z.string().nullable(),
});
export type LegalHoldPage = z.infer<typeof LegalHoldPageSchema>;

export const LegalHoldListQuerySchema = defineListQuery({
  filters: {
    status: { type: 'enum', values: HOLD_STATUSES, maxValues: 2 },
    caseId: { type: 'publicId' },
  },
  sorts: ['-id'],
  defaultSort: '-id',
});
export type LegalHoldListQuery = z.output<typeof LegalHoldListQuerySchema>;

export const ReleaseHoldBodySchema = z.strictObject({
  reason: text(1, 1024).describe('Why the hold is released (audited)'),
});
export type ReleaseHoldBody = z.output<typeof ReleaseHoldBodySchema>;

export const CreateHoldBodySchema = z.strictObject({
  name: text(1, 128),
  reason: text(1, 1024).describe('Why the hold is placed (audited)'),
  criteria: archiveHoldCreateCriteriaSchema
    .optional()
    .describe(
      '`archive-hold/1`: `custodians` (addresses), `from`/`to` (date or date-time), ' +
        '`directions`. Empty criteria hold every record of the organization',
    ),
  useCaseCustodians: z
    .boolean()
    .optional()
    .describe('Snapshot the case’s custodians into the hold (instead of `criteria.custodians`)'),
});
export type CreateHoldBody = z.output<typeof CreateHoldBodySchema>;

// ---- cases (#28–#32) ----------------------------------------------------------------------------

export const CASE_STATUSES = ['open', 'closed'] as const;

export const CaseSummarySchema = z.object({
  id: PublicIdSchema,
  name: z.string(),
  description: z.string().nullable(),
  matterReference: z.string().nullable(),
  status: z.enum(CASE_STATUSES),
  rowVersion: z.number().int(),
  createdBy: PublicIdSchema.nullable(),
  createdAt: isoInstant,
  updatedAt: isoInstant,
  closedAt: nullableInstant,
});
export type CaseSummaryView = z.infer<typeof CaseSummarySchema>;

export const CaseDetailSchema = CaseSummarySchema.extend({
  custodians: z.array(
    z.object({
      id: PublicIdSchema,
      address: z.string(),
      userId: PublicIdSchema.nullable().describe('The organization user with this address, if any'),
    }),
  ),
  counts: z.object({
    custodians: z.number().int(),
    activeHolds: z.number().int(),
    searches: z.number().int(),
    exports: z.number().int(),
  }),
});
export type CaseDetailView = z.infer<typeof CaseDetailSchema>;

export const CasePageSchema = z.object({
  data: z.array(CaseSummarySchema),
  nextCursor: z.string().nullable(),
});
export type CasePage = z.infer<typeof CasePageSchema>;

export const CaseListQuerySchema = defineListQuery({
  filters: { status: { type: 'enum', values: CASE_STATUSES, maxValues: 2 } },
  sorts: ['-id'],
  defaultSort: '-id',
});
export type CaseListQuery = z.output<typeof CaseListQuerySchema>;

export const CreateCaseBodySchema = z.strictObject({
  name: text(1, 128).describe('Unique per organization'),
  description: text(0, 1024).optional(),
  matterReference: text(0, 128).optional(),
  custodians: uniqueAddresses(10_000)
    .optional()
    .describe('Custodian addresses (≤ ARCHIVE_CASE_MAX_CUSTODIANS, lower-cased)'),
});
export type CreateCaseBody = z.output<typeof CreateCaseBodySchema>;

export const UpdateCaseBodySchema = z
  .strictObject({
    expectedRowVersion: z.number().int().min(1).max(4_294_967_295),
    name: text(1, 128).optional(),
    description: text(0, 1024).nullable().optional(),
    matterReference: text(0, 128).nullable().optional(),
    custodians: uniqueAddresses(10_000)
      .optional()
      .describe('The complete custodian list (replaces the current one)'),
  })
  .refine((b) => Object.keys(b).some((k) => k !== 'expectedRowVersion'), {
    message: 'must change at least one field',
  });
export type UpdateCaseBody = z.output<typeof UpdateCaseBodySchema>;

// ---- searches, hits, review (#33–#37) -----------------------------------------------------------

export const SEARCH_STATUSES = ['queued', 'running', 'completed', 'failed'] as const;

export const SearchSchema = z.object({
  id: PublicIdSchema,
  caseId: PublicIdSchema,
  status: z.enum(SEARCH_STATUSES),
  criteria: z
    .record(z.string(), z.unknown())
    .describe(
      '`archive-search/1`; recipients, subject and custodian addresses masked without `message:reveal`',
    ),
  criteriaSha256: sha256,
  hitCount: z.number().int(),
  truncated: z.boolean().describe('ARCHIVE_CASE_SEARCH_MAX_HITS reached'),
  indexComplete: z
    .boolean()
    .nullable()
    .describe('true only when the index had no lag and every day of the range was verified'),
  incompleteReason: z
    .string()
    .nullable()
    .describe('`index_lag`, `unverified_days`, `mismatched_days`'),
  errorCode: z.string().nullable(),
  requestedBy: PublicIdSchema.nullable(),
  createdAt: isoInstant,
  startedAt: nullableInstant,
  completedAt: nullableInstant,
});
export type SearchView = z.infer<typeof SearchSchema>;

export const SearchPageSchema = z.object({
  data: z.array(SearchSchema),
  nextCursor: z.string().nullable(),
});
export type SearchPage = z.infer<typeof SearchPageSchema>;

export const SearchListQuerySchema = defineListQuery({
  filters: { status: { type: 'enum', values: SEARCH_STATUSES, maxValues: 4 } },
  sorts: ['-id'],
  defaultSort: '-id',
});
export type SearchListQuery = z.output<typeof SearchListQuerySchema>;

export const CreateSearchBodySchema = z.strictObject({
  criteria: archiveSearchCriteriaSchema.describe(
    '`archive-search/1`: `from`/`to` (≤ ARCHIVE_CASE_SEARCH_MAX_RANGE_DAYS), filters, ' +
      '`custodians: "case"` for the case’s custodians',
  ),
});
export type CreateSearchBody = z.output<typeof CreateSearchBodySchema>;

export const HitSchema = z.object({
  messageId: PublicIdSchema,
  receivedAt: isoInstant,
  reviewTag: z.enum(EDISCOVERY_REVIEW_TAGS),
  reviewedBy: PublicIdSchema.nullable(),
  reviewedAt: nullableInstant,
  message: ArchiveMessageSchema.nullable().describe(
    'The masked record (null when it was disposed since the search)',
  ),
});
export type HitView = z.infer<typeof HitSchema>;

export const HitPageSchema = z.object({
  data: z.array(HitSchema),
  nextCursor: z.string().nullable(),
});
export type HitPage = z.infer<typeof HitPageSchema>;

export const HitListQuerySchema = defineListQuery({
  filters: { reviewTag: { type: 'enum', values: EDISCOVERY_REVIEW_TAGS, maxValues: 4 } },
  sorts: ['-id'],
  defaultSort: '-id',
});
export type HitListQuery = z.output<typeof HitListQuerySchema>;

export const ReviewBodySchema = z.strictObject({
  tag: z.enum(EDISCOVERY_REVIEW_TAGS),
  messageIds: z
    .array(PublicIdSchema)
    .min(1)
    .max(5000)
    .refine((v) => new Set(v.map((x) => x.toLowerCase())).size === v.length, {
      message: 'must not repeat a value',
    })
    .describe('Hits to tag (≤ ARCHIVE_REVIEW_MAX_ITEMS: `400 ediscovery_review_limit`)'),
});
export type ReviewBody = z.output<typeof ReviewBodySchema>;

export const ReviewResultSchema = z.object({
  searchId: PublicIdSchema,
  tag: z.enum(EDISCOVERY_REVIEW_TAGS),
  updated: z.number().int(),
  notFound: z.number().int().describe('Ids that are not hits of this search'),
});
export type ReviewResultView = z.infer<typeof ReviewResultSchema>;

// ---- exports (#38–#41) --------------------------------------------------------------------------

export const EXPORT_STATUSES = ['queued', 'building', 'completed', 'failed', 'expired'] as const;

export const ExportSchema = z.object({
  id: PublicIdSchema,
  caseId: PublicIdSchema,
  searchId: PublicIdSchema,
  status: z.enum(EXPORT_STATUSES),
  reviewTags: z.array(z.enum(EDISCOVERY_REVIEW_TAGS)),
  acknowledgeMalicious: z.boolean(),
  itemCount: z.number().int(),
  maliciousCount: z.number().int(),
  packageBytes: z.number().int().nullable(),
  packageSha256: sha256.nullable().describe('SHA-256 of the ZIP as downloaded'),
  manifestSha256: sha256.nullable(),
  signingKeyId: z.string().nullable(),
  expiresAt: nullableInstant,
  errorCode: z.string().nullable(),
  requestedBy: PublicIdSchema.nullable(),
  createdAt: isoInstant,
  completedAt: nullableInstant,
});
export type ExportView = z.infer<typeof ExportSchema>;

export const ExportPageSchema = z.object({
  data: z.array(ExportSchema),
  nextCursor: z.string().nullable(),
});
export type ExportPage = z.infer<typeof ExportPageSchema>;

export const ExportListQuerySchema = defineListQuery({
  filters: { status: { type: 'enum', values: EXPORT_STATUSES, maxValues: 5 } },
  sorts: ['-id'],
  defaultSort: '-id',
});
export type ExportListQuery = z.output<typeof ExportListQuerySchema>;

export const CreateExportBodySchema = z.strictObject({
  searchId: PublicIdSchema.describe('A completed search of the case'),
  reviewTags: z
    .array(z.enum(EDISCOVERY_REVIEW_TAGS))
    .min(1)
    .max(4)
    .refine((v) => new Set(v).size === v.length, { message: 'must not repeat a value' })
    .default([...EXPORT_DEFAULT_REVIEW_TAGS])
    .describe('Hits with these tags (default: every tag except `not_relevant`)'),
  acknowledgeMalicious: z
    .boolean()
    .default(false)
    .describe('Required when the selection contains malicious records (put under `malicious/`)'),
});
export type CreateExportBody = z.output<typeof CreateExportBodySchema>;

// ---- examples -----------------------------------------------------------------------------------

const SEARCH_ID = '0193a1c2-9999-7a00-8000-000000000001';
const EXPORT_ID = '0193a1c2-aaaa-7a00-8000-000000000001';

const hold: LegalHoldView = {
  id: ID.hold,
  caseId: ID.case,
  name: 'Smith v. Example',
  reason: 'Litigation notice received',
  status: 'active',
  criteria: { custodians: ['custodian@example.com'], from: '2026-01-01', to: '2026-06-30' },
  criteriaVersion: 'archive-hold/1',
  createdBy: ID.user,
  createdAt: '2026-11-16T11:00:00.000Z',
  releasedAt: null,
  releasedBy: null,
  releaseReason: null,
  rowVersion: 1,
};

const caseSummary: CaseSummaryView = {
  id: ID.case,
  name: 'Smith v. Example',
  description: 'Contract dispute',
  matterReference: 'MATTER-EXAMPLE-1',
  status: 'open',
  rowVersion: 1,
  createdBy: ID.user,
  createdAt: '2026-11-16T10:55:00.000Z',
  updatedAt: '2026-11-16T10:55:00.000Z',
  closedAt: null,
};

const search: SearchView = {
  id: SEARCH_ID,
  caseId: ID.case,
  status: 'completed',
  criteria: { from: '2026-01-01', to: '2026-06-30', custodians: 'case', hasAttachments: true },
  criteriaSha256: 'c'.repeat(64),
  hitCount: 42,
  truncated: false,
  indexComplete: true,
  incompleteReason: null,
  errorCode: null,
  requestedBy: ID.user,
  createdAt: '2026-11-16T11:05:00.000Z',
  startedAt: '2026-11-16T11:05:01.000Z',
  completedAt: '2026-11-16T11:05:04.000Z',
};

const exportView: ExportView = {
  id: EXPORT_ID,
  caseId: ID.case,
  searchId: SEARCH_ID,
  status: 'completed',
  reviewTags: ['untagged', 'relevant', 'privileged'],
  acknowledgeMalicious: false,
  itemCount: 40,
  maliciousCount: 0,
  packageBytes: 1_048_576,
  packageSha256: 'd'.repeat(64),
  manifestSha256: 'e'.repeat(64),
  signingKeyId: 'es1',
  expiresAt: '2026-11-23T11:10:00.000Z',
  errorCode: null,
  requestedBy: ID.user,
  createdAt: '2026-11-16T11:08:00.000Z',
  completedAt: '2026-11-16T11:10:00.000Z',
};

export const EDISCOVERY_EXAMPLES = {
  hold,
  holdPage: { data: [hold], nextCursor: null } satisfies LegalHoldPage,
  holdCreate: {
    name: 'Smith v. Example',
    reason: 'Litigation notice received',
    criteria: { from: '2026-01-01', to: '2026-06-30' },
    useCaseCustodians: true,
  },
  release: { reason: 'Matter settled' },
  released: {
    ...hold,
    status: 'released',
    releasedAt: '2026-11-20T09:00:00.000Z',
    releasedBy: ID.user,
    releaseReason: 'Matter settled',
    rowVersion: 2,
  } satisfies LegalHoldView,
  caseSummary,
  casePage: { data: [caseSummary], nextCursor: null } satisfies CasePage,
  caseDetail: {
    ...caseSummary,
    custodians: [
      {
        id: '0193a1c2-bbbb-7a00-8000-000000000001',
        address: 'custodian@example.com',
        userId: ID.user,
      },
    ],
    counts: { custodians: 1, activeHolds: 1, searches: 1, exports: 1 },
  } satisfies CaseDetailView,
  caseCreate: {
    name: 'Smith v. Example',
    description: 'Contract dispute',
    matterReference: 'MATTER-EXAMPLE-1',
    custodians: ['custodian@example.com'],
  },
  caseUpdate: {
    expectedRowVersion: 1,
    custodians: ['custodian@example.com', 'second.custodian@example.com'],
  },
  search,
  searchQueued: {
    ...search,
    status: 'queued',
    hitCount: 0,
    indexComplete: null,
    startedAt: null,
    completedAt: null,
  } satisfies SearchView,
  searchPage: { data: [search], nextCursor: null } satisfies SearchPage,
  searchCreate: {
    criteria: { from: '2026-01-01', to: '2026-06-30', custodians: 'case', hasAttachments: true },
  },
  hits: {
    data: [
      {
        messageId: ID.message,
        receivedAt: '2026-11-16T10:15:00.000Z',
        reviewTag: 'relevant',
        reviewedBy: ID.user,
        reviewedAt: '2026-11-16T12:00:00.000Z',
        message: ARCHIVE_EXAMPLES.message,
      },
    ],
    nextCursor: null,
  } satisfies HitPage,
  review: { tag: 'relevant', messageIds: [ID.message] },
  reviewed: {
    searchId: SEARCH_ID,
    tag: 'relevant',
    updated: 1,
    notFound: 0,
  } satisfies ReviewResultView,
  export: exportView,
  exportQueued: {
    ...exportView,
    status: 'queued',
    packageBytes: null,
    packageSha256: null,
    manifestSha256: null,
    signingKeyId: null,
    expiresAt: null,
    completedAt: null,
  } satisfies ExportView,
  exportPage: { data: [exportView], nextCursor: null } satisfies ExportPage,
  exportCreate: {
    searchId: SEARCH_ID,
    reviewTags: ['relevant', 'privileged'],
    acknowledgeMalicious: false,
  },
  grant: {
    token: 'v1.EXAMPLE-PAYLOAD.EXAMPLE-MAC',
    expiresAt: '2026-11-17T08:02:00.000Z',
    filename: `ediscovery-export-${EXPORT_ID}.zip`,
    sizeBytes: 1_048_576,
    sha256: 'd'.repeat(64),
  },
} as const;

export const EDISCOVERY_EXAMPLE_IDS = { search: SEARCH_ID, export: EXPORT_ID } as const;
