import * as contracts from '@email-gateway/event-contracts';
import * as parser from '@email-gateway/mime-parser';
import { describe, expect, it } from 'vitest';
import { emlMessage } from './fakes.test-support';
import type { FinalOutcome } from './mime-store';
import { buildParsedPayload, buildParseFailedPayload } from './payloads';

const message = emlMessage('From: a@example.org\r\n\r\nhi\r\n', { id: 123n });
const stats = {
  bytesRead: message.sizeBytes,
  sha256: message.emlSha256,
  inputComplete: true,
  partCount: 3,
  maxDepth: 1,
  headerCount: 7,
  attachmentCount: 2,
  decodedBytes: 99,
  durationMs: 4,
};
const attachment = (flags: parser.AttachmentFlag[]): parser.AttachmentResult => ({
  partIndex: 2,
  partPath: '0.2',
  depth: 1,
  disposition: 'attachment',
  declaredContentType: 'application/zip',
  detectedContentType: 'application/zip',
  sizeBytes: 10,
  encodedSizeBytes: 16,
  sha256: 'c'.repeat(64),
  key: 'org/42/part/2026/11/03/123/2.att',
  filename: 'a.zip',
  originalFilename: 'a.zip',
  flags,
  archiveInfo: null,
});
const result = (overrides: Partial<parser.MimeParseResult>): parser.MimeParseResult => ({
  status: 'parsed',
  limitsExceeded: [],
  defects: [],
  stats,
  subject: 'x',
  headers: [],
  textBody: {
    key: 'org/42/part/2026/11/03/123/1.text',
    sha256: 'd'.repeat(64),
    sizeBytes: 2,
    charset: 'utf-8',
    partIndex: 1,
    flags: [],
  },
  htmlBody: null,
  attachments: [],
  structure: [],
  ...overrides,
});
const outcome = (r: parser.MimeParseResult): FinalOutcome => ({
  status: r.status,
  failureReason: r.status === 'parse_failed' ? 'parser_error' : null,
  limitsExceeded: r.limitsExceeded,
  defects: r.defects,
  result: r,
  stats: r.stats,
});

describe('parse event payloads (design M14)', () => {
  it('keeps mime-parser and event-contracts limit names equal (M14)', () => {
    expect([...parser.MIME_LIMIT_NAMES]).toEqual([...contracts.MIME_LIMIT_NAMES]);
    // The final statuses of mail.message.parsed.v1 are the parser's minus parse_failed.
    expect([...contracts.MESSAGE_PARSE_STATUSES]).toEqual(
      parser.MESSAGE_PARSE_STATUSES.filter((s) => s !== 'parse_failed'),
    );
    // Every code the parser can emit is a valid snake_case code of the contract.
    for (const code of [...parser.MIME_DEFECT_CODES, ...parser.ATTACHMENT_FLAGS]) {
      expect(code).toMatch(/^[a-z0-9_]{1,48}$/);
    }
  });

  it('builds a schema-valid parsed payload with flag union and counts', () => {
    const r = result({
      status: 'parsed_with_defects',
      defects: ['invalid_base64'],
      attachments: [
        attachment(['archive', 'archive_nested']),
        attachment([]),
        attachment(['archive']),
      ],
    });
    const payload = buildParsedPayload({
      message,
      attempts: 1,
      parserVersion: 'mime-1',
      outcome: outcome(r),
    });
    expect(contracts.messageParsedV1.parse(payload)).toEqual(payload);
    expect(payload).toMatchObject({
      messageId: '123',
      parseStatus: 'parsed_with_defects',
      attachmentCount: 3,
      flaggedAttachmentCount: 2,
      attachmentFlags: ['archive', 'archive_nested'],
      partCount: 3,
      maxDepth: 1,
      headerCount: 7,
      textBody: { s3Key: 'org/42/part/2026/11/03/123/1.text', sizeBytes: 2 },
      htmlBody: null,
    });
  });

  it('carries limits only with parse_limit_exceeded and a null key for an unstored body', () => {
    const r = result({
      status: 'parse_limit_exceeded',
      limitsExceeded: ['body_size'],
      textBody: {
        key: null,
        sha256: 'e'.repeat(64),
        sizeBytes: 10,
        charset: null,
        partIndex: 1,
        flags: ['not_stored_size_limit'],
      },
    });
    const payload = buildParsedPayload({
      message,
      attempts: 1,
      parserVersion: 'mime-1',
      outcome: outcome(r),
    });
    expect(payload.textBody).toEqual({ s3Key: null, sha256: 'e'.repeat(64), sizeBytes: 10 });
    // A contract violation (limits without the status) is refused before any write.
    expect(() =>
      buildParsedPayload({
        message,
        attempts: 1,
        parserVersion: 'mime-1',
        outcome: { ...outcome(r), status: 'parsed' },
      }),
    ).toThrow();
  });

  it('builds a schema-valid parse_failed payload', () => {
    const payload = buildParseFailedPayload({
      message,
      attempts: 6,
      parserVersion: 'mime-1',
      outcome: {
        status: 'parse_failed',
        failureReason: 'max_attempts_exceeded',
        limitsExceeded: [],
        defects: [],
        result: null,
        stats: null,
      },
    });
    expect(contracts.messageParseFailedV1.parse(payload)).toEqual(payload);
    expect(payload).toMatchObject({
      reason: 'max_attempts_exceeded',
      attempts: 6,
      emlS3Key: message.emlObjectKey,
    });
    // No address, subject, filename or header value in either payload.
    expect(Object.keys(payload).sort()).toEqual(
      [
        'attempts',
        'direction',
        'emlS3Key',
        'messageId',
        'parserVersion',
        'reason',
        'receivedAt',
      ].sort(),
    );
  });

  it('publishes eml_key_mismatch with a null key when the key is not organization-prefixed', () => {
    for (const emlObjectKey of ['eml/x.eml', 'org/0/eml/x.eml', '/org/7/eml/x.eml', '']) {
      const payload = buildParseFailedPayload({
        message: { ...message, emlObjectKey },
        attempts: 1,
        parserVersion: 'mime-1',
        outcome: {
          status: 'parse_failed',
          failureReason: 'eml_key_mismatch',
          limitsExceeded: [],
          defects: [],
          result: null,
          stats: null,
        },
      });
      expect(payload.emlS3Key, emlObjectKey).toBeNull();
      expect(payload.reason).toBe('eml_key_mismatch');
    }
    // A key of another organization is carried as it is (the consumer sees the mismatch).
    const foreign = buildParseFailedPayload({
      message: { ...message, emlObjectKey: 'org/7/eml/x.eml' },
      attempts: 1,
      parserVersion: 'mime-1',
      outcome: {
        status: 'parse_failed',
        failureReason: 'eml_key_mismatch',
        limitsExceeded: [],
        defects: [],
        result: null,
        stats: null,
      },
    });
    expect(foreign.emlS3Key).toBe('org/7/eml/x.eml');
  });
});
