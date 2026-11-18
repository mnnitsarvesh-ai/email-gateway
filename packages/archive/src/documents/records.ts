import { z } from 'zod';
import {
  categorySchema,
  decimalIdSchema,
  directionSchema,
  isoDateTimeSchema,
  recipientStatusSchema,
  sha256HexSchema,
  storedAddressSchema,
  uuidSchema,
} from './common';

/**
 * Documents stored with or inside an archive record (§4.2): `archive-parties/1`
 * (`email_archives.parties`), `archive-journal/1` (the encrypted journal object) and the
 * `objects` / `scan_rounds` columns.
 */

export const archivePartiesSchema = z.strictObject({
  v: z.literal(1),
  /** Envelope sender (MAIL FROM; empty for the null sender). */
  from: storedAddressSchema,
  headerFrom: storedAddressSchema.nullable(),
  recipients: z
    .array(
      z.strictObject({
        seq: z.number().int().min(0).max(65_535),
        address: storedAddressSchema,
        direction: directionSchema,
        status: recipientStatusSchema,
        finalAction: z.string().min(1).max(32).nullable(),
      }),
    )
    .max(65_535),
});
export type ArchiveParties = z.infer<typeof archivePartiesSchema>;

export const ARCHIVE_PARTIES_EXAMPLE: ArchiveParties = {
  v: 1,
  from: 'sender@example.org',
  headerFrom: 'Sender <sender@example.org>',
  recipients: [
    {
      seq: 0,
      address: 'user@example.com',
      direction: 'inbound',
      status: 'delivered',
      finalAction: 'deliver',
    },
  ],
};

const nullableText = (max: number) => z.string().max(max).nullable();

export const archiveJournalSchema = z.strictObject({
  version: z.literal('archive-journal/1'),
  /** Internal organization id (decimal), the id of the S3 prefix. */
  organizationId: decimalIdSchema,
  /** Message public id. */
  messageId: uuidSchema,
  receivedAt: isoDateTimeSchema,
  capturedAt: isoDateTimeSchema,
  captureId: uuidSchema,
  direction: directionSchema,
  category: categorySchema,
  sources: z.strictObject({
    journal: z.boolean(),
    policy: z.boolean(),
    policyRuleRef: z.string().min(1).max(128).nullable(),
  }),
  settingsGeneration: z.number().int().min(0),
  message: z.strictObject({
    internetMessageId: nullableText(998),
    envelopeFrom: storedAddressSchema,
    headerFrom: storedAddressSchema.nullable(),
    subject: nullableText(998),
    sizeBytes: z.number().int().min(0),
    emlSha256: sha256HexSchema,
    clientIp: nullableText(45),
    clientHelo: nullableText(255),
    clientName: nullableText(255),
  }),
  envelope: z.strictObject({
    recipients: z
      .array(
        z.strictObject({
          seq: z.number().int().min(0).max(65_535),
          address: storedAddressSchema,
          direction: directionSchema,
          status: recipientStatusSchema,
        }),
      )
      .max(65_535),
  }),
  /** The stored header allow-list (`email_headers`), in order. */
  headers: z
    .array(z.strictObject({ name: z.string().min(1).max(128), value: z.string().max(65_536) }))
    .max(10_000),
  parse: z.strictObject({
    status: z.string().min(1).max(32).nullable(),
    codes: z.array(z.string().min(1).max(64)).max(256),
  }),
  body: z.strictObject({
    text: z.string().nullable(),
    html: z.string().nullable(),
    truncated: z.boolean(),
    unavailableReason: z.string().min(1).max(64).nullable(),
  }),
  attachments: z
    .array(
      z.strictObject({
        partIndex: z.number().int().min(0).max(65_535),
        fileName: nullableText(1024),
        contentType: nullableText(255),
        detectedType: nullableText(255),
        sizeBytes: z.number().int().min(0),
        sha256: sha256HexSchema.nullable(),
      }),
    )
    .max(10_000),
  deliveries: z
    .array(
      z.strictObject({
        seq: z.number().int().min(0).max(65_535),
        status: z.string().min(1).max(32),
        finalAt: isoDateTimeSchema.nullable(),
      }),
    )
    .max(65_535),
});
export type ArchiveJournal = z.infer<typeof archiveJournalSchema>;

export const ARCHIVE_JOURNAL_EXAMPLE: ArchiveJournal = {
  version: 'archive-journal/1',
  organizationId: '42',
  messageId: '0190a5d0-0000-7000-8000-0000000000aa',
  receivedAt: '2026-11-16T10:15:00.000Z',
  capturedAt: '2026-11-16T10:17:03.120Z',
  captureId: '0190a5d0-0000-7000-8000-0000000000bb',
  direction: 'inbound',
  category: 'delivered',
  sources: { journal: true, policy: false, policyRuleRef: null },
  settingsGeneration: 3,
  message: {
    internetMessageId: '<example-1@example.org>',
    envelopeFrom: 'sender@example.org',
    headerFrom: 'Sender <sender@example.org>',
    subject: 'Quarterly report',
    sizeBytes: 2048,
    emlSha256: 'a'.repeat(64),
    clientIp: '192.0.2.10',
    clientHelo: 'mail.example.org',
    clientName: null,
  },
  envelope: {
    recipients: [
      { seq: 0, address: 'user@example.com', direction: 'inbound', status: 'delivered' },
    ],
  },
  headers: [{ name: 'Subject', value: 'Quarterly report' }],
  parse: { status: 'parsed', codes: [] },
  body: { text: 'Hello', html: null, truncated: false, unavailableReason: null },
  attachments: [
    {
      partIndex: 2,
      fileName: 'report.pdf',
      contentType: 'application/pdf',
      detectedType: 'application/pdf',
      sizeBytes: 1024,
      sha256: 'b'.repeat(64),
    },
  ],
  deliveries: [{ seq: 0, status: 'delivered', finalAt: '2026-11-16T10:15:04.000Z' }],
};

const objectRef = z.strictObject({
  key: z.string().min(1).max(1024),
  versionId: z.string().min(1).max(1024).nullable(),
  /** SHA-256 of the stored ciphertext. */
  sha256: sha256HexSchema,
  bytes: z.number().int().min(0),
});
export type ArchiveObjectRef = z.infer<typeof objectRef>;

/** `email_archives.objects`: the capture id and exact versions written by the capture (A6). */
export const archiveRecordObjectsSchema = z.strictObject({
  captureId: uuidSchema,
  eml: objectRef,
  journal: objectRef,
  scans: z
    .array(
      objectRef.extend({
        round: z.number().int().min(0).max(65_535),
        revision: z.number().int().min(0).max(65_535),
      }),
    )
    .max(16),
});
export type ArchiveRecordObjects = z.infer<typeof archiveRecordObjectsSchema>;

/** `email_archives.scan_rounds`: ≤ 16 linked rounds and revisions (A5, A7). */
export const archiveScanRoundsSchema = z
  .array(
    z.strictObject({
      round: z.number().int().min(0).max(65_535),
      revision: z.number().int().min(0).max(65_535),
      frozenAt: isoDateTimeSchema,
    }),
  )
  .max(16);
export type ArchiveScanRounds = z.infer<typeof archiveScanRoundsSchema>;
