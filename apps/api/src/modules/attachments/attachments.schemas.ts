import { z } from 'zod';
import { defineListQuery } from '../../http/listing/list-query';
import {
  AttachmentScanViewSchema,
  tenantAttachmentShape,
} from '../messages/dto/message-scans.schemas';

/**
 * Request and response shapes of the step 6.1 attachment routes (WP2, §3.3):
 * `GET /messages/{messageId}/attachments` and `GET /attachments?sha256=`. Metadata and verdicts
 * only: never content, object keys, original (unsanitized) filenames or archive entry names, and
 * no download route (downloads only through the step 5.3 quarantine grants).
 */

export const MESSAGE_ATTACHMENTS_RESOURCE = 'message_attachments';
export const ATTACHMENT_SEARCH_RESOURCE = 'attachments';

export const SHA256_HEX = /^[0-9a-fA-F]{64}$/;

export const MessageAttachmentsQuerySchema = defineListQuery({
  filters: {},
  sorts: ['partIndex'],
  defaultSort: 'partIndex',
});
export type MessageAttachmentsQuery = z.output<typeof MessageAttachmentsQuerySchema>;

export const AttachmentSearchQuerySchema = defineListQuery({
  filters: { sha256: { type: 'string', maxLength: 64 } },
  sorts: ['-receivedAt'],
  defaultSort: '-receivedAt',
  range: true,
});
export type AttachmentSearchQuery = z.output<typeof AttachmentSearchQuerySchema>;

export const ATTACHMENT_SEARCH_PARAMETERS: Record<string, string> = {
  sha256: 'Required. Hex SHA-256 of the decoded attachment (64 characters, case-insensitive)',
  from: 'Start of the range (ISO 8601 with offset, inclusive); default `to` − 24 h',
  to: 'End of the range (exclusive); default now. At most API_MESSAGES_MAX_RANGE_DAYS days',
  limit: 'Page size, 1-100 (default 25)',
  cursor: '`nextCursor` of the previous page (signed, bound to the hash and the caller)',
  sort: '`-receivedAt` (the only order: newest first)',
};

const IsoDate = z.iso.datetime();

/** The latest round's result of one attachment, through the scans view mapper (A16). */
export const AttachmentLatestScanSchema = AttachmentScanViewSchema.pick({
  verdict: true,
  reasonCodes: true,
  detectedType: true,
  typeFamily: true,
  typeMismatch: true,
  clamav: true,
  yara: true,
  archive: true,
  knownHash: true,
}).extend({
  round: z.number().int().min(0).describe('Lifecycle round of the scan (0 = initial scan)'),
});
export type AttachmentLatestScan = z.output<typeof AttachmentLatestScanSchema>;

export const MessageAttachmentItemSchema = z.object({
  partIndex: tenantAttachmentShape.partIndex,
  filename: z
    .string()
    .nullable()
    .describe('Sanitized display filename (attacker-controlled text, escaped; step 3.1 M9)'),
  declaredContentType: z.string().nullable(),
  detectedContentType: z.string().nullable(),
  sizeBytes: z.number().int().min(0).describe('Decoded size'),
  sha256: tenantAttachmentShape.sha256,
  disposition: z.enum(['attachment', 'inline']).nullable(),
  depth: z.number().int().min(0).nullable().describe('MIME nesting depth (0 = root)'),
  verdict: AttachmentScanViewSchema.shape.verdict
    .nullable()
    .describe('Verdict of the latest scan round, null before the attachment engine ran'),
  latestScan: AttachmentLatestScanSchema.nullable(),
});
export type MessageAttachmentItem = z.output<typeof MessageAttachmentItemSchema>;

export const MessageAttachmentsPageSchema = z.object({
  data: z.array(MessageAttachmentItemSchema),
  nextCursor: z.string().nullable(),
});
export type MessageAttachmentsPage = z.output<typeof MessageAttachmentsPageSchema>;

export const AttachmentSearchItemSchema = z.object({
  messageId: z.uuid().describe('Public id of the message'),
  receivedAt: IsoDate,
  partIndex: tenantAttachmentShape.partIndex,
  filename: z.string().nullable().describe('Sanitized display filename'),
  sizeBytes: z.number().int().min(0),
  detectedContentType: z.string().nullable(),
  verdict: AttachmentScanViewSchema.shape.verdict.nullable(),
});
export type AttachmentSearchItem = z.output<typeof AttachmentSearchItemSchema>;

export const AttachmentSearchPageSchema = z.object({
  data: z.array(AttachmentSearchItemSchema),
  nextCursor: z.string().nullable(),
});
export type AttachmentSearchPage = z.output<typeof AttachmentSearchPageSchema>;

export const ATTACHMENT_EXAMPLES = {
  messagePage: {
    data: [
      {
        partIndex: 2,
        filename: 'invoice-2026-11.pdf',
        declaredContentType: 'application/pdf',
        detectedContentType: 'application/pdf',
        sizeBytes: 48213,
        sha256: '9f2c4b8e1d7a6f3c5b0e2d4a8c6f1e3b7d9a0c2e4f6b8d1a3c5e7f9b0d2a4c6e',
        disposition: 'attachment',
        depth: 1,
        verdict: 'clean',
        latestScan: {
          round: 0,
          verdict: 'clean',
          reasonCodes: ['clean.no_findings'],
          detectedType: 'pdf',
          typeFamily: 'document',
          typeMismatch: false,
          clamav: { signature: null, engineVersion: '1.4.1', dbVersion: 27450 },
          yara: null,
          archive: null,
          knownHash: null,
        },
      },
    ],
    nextCursor: null,
  },
  searchPage: {
    data: [
      {
        messageId: '0193a1b2-7c3d-7e4f-8a5b-6c7d8e9f0a1b',
        receivedAt: '2026-11-12T08:15:30.125Z',
        partIndex: 2,
        filename: 'invoice-2026-11.pdf',
        sizeBytes: 48213,
        detectedContentType: 'application/pdf',
        verdict: 'clean',
      },
    ],
    nextCursor: null,
  },
} as const;
