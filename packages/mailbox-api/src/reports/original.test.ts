import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { copyMessageIdHash } from '../identifiers';
import { canonicalJson } from '../remediation/policy';
import type { ReportExtraction } from './extract';
import {
  assessReport,
  buildReportOriginal,
  reporterCheck,
  reportGroupKey,
  reportIdentificationOf,
  reportOriginalSchema,
  type ReportOriginal,
  type ReporterCheckInput,
} from './original';
import {
  REPORT_ANALYST_VERDICTS,
  REPORT_ASSESSMENTS,
  REPORT_FEEDBACK_KINDS,
  REPORT_FEEDBACK_STATES,
  REPORT_IDENTIFICATIONS,
  REPORT_REJECT_REASONS,
  REPORT_STATUSES,
} from './vocabulary';

const H = (seed: string) => createHash('sha256').update(seed).digest('hex');

describe('report vocabularies (mirror the Prisma enums of §3.1)', () => {
  it('pins every list', () => {
    expect(REPORT_STATUSES).toEqual([
      'received',
      'parsing',
      'scanning',
      'pending_triage',
      'in_review',
      'resolved',
      'rejected',
    ]);
    expect(REPORT_IDENTIFICATIONS).toEqual(['attachment', 'inline', 'none', 'unsupported']);
    expect(REPORT_REJECT_REASONS).toEqual([
      'external_reporter',
      'loop',
      'auto_submitted',
      'rate_limited',
      'analyst_rejected',
      'too_large',
      'parse_failed',
    ]);
    expect(REPORT_ASSESSMENTS).toEqual(['malicious', 'suspicious', 'clean', 'unknown']);
    expect(REPORT_ANALYST_VERDICTS).toEqual([
      'malicious',
      'phishing_simulation',
      'spam',
      'clean',
      'inconclusive',
    ]);
    expect(REPORT_FEEDBACK_STATES).toEqual(['none', 'queued', 'skipped']);
    expect(REPORT_FEEDBACK_KINDS).toEqual(['received', 'resolved']);
  });
});

const attachment: ReportExtraction = {
  ok: true,
  identification: 'attachment',
  original: new Uint8Array([1]),
  headers: {
    messageId: '<orig-123@mx.example.net>',
    from: 'Billing@example.net',
    date: new Date('2026-11-24T09:41:12.000Z'),
    subject: 'Re: Fwd:  Rechnung   für Müller ',
  },
  extraOriginals: 2,
  attachmentSha256: [H('pdf'), H('pdf'), H('png')],
  attachmentsComplete: true,
};

const inline: ReportExtraction = {
  ok: true,
  identification: 'inline',
  headers: {
    messageId: null,
    from: 'billing@example.net',
    date: new Date('2026-11-23T10:15:00.000Z'),
    subject: 'Invoice 4711',
  },
  extraOriginals: 0,
  separator: 'forwarded_message',
};

describe('buildReportOriginal (api-report-original/1, C10.2)', () => {
  it('builds the attachment document (hashes de-duplicated, keys normalized)', () => {
    const original = buildReportOriginal({
      organizationId: 42n,
      extraction: attachment,
      fallbackAttachmentSha256: [H('ignored')],
      urlSha256: [H('u1'), H('u1').toUpperCase(), 'not-a-hash'],
    });
    expect(original).toEqual({
      v: 1,
      messageIdHash: copyMessageIdHash(42n, '<orig-123@mx.example.net>'),
      sender: 'billing@example.net',
      subjectKey: 'Rechnung für Müller',
      date: '2026-11-24T09:41:12.000Z',
      attachmentSha256: [H('pdf'), H('png')],
      urlSha256: [H('u1')],
      extraOriginals: 2,
    });
    expect(reportOriginalSchema.parse(original)).toEqual(original);
  });

  it('builds the inline document with the report message attachments', () => {
    const original = buildReportOriginal({
      organizationId: 42,
      extraction: inline,
      fallbackAttachmentSha256: Array.from({ length: 25 }, (_, i) => H(`a${i}`)),
      urlSha256: Array.from({ length: 60 }, (_, i) => H(`u${i}`)),
    });
    expect(original).toMatchObject({
      messageIdHash: null,
      sender: 'billing@example.net',
      subjectKey: 'Invoice 4711',
      extraOriginals: 0,
    });
    expect(original?.attachmentSha256).toHaveLength(20);
    expect(original?.urlSha256).toHaveLength(50);
    expect(reportOriginalSchema.safeParse(original).success).toBe(true);
  });

  it('has no original for none, unsupported and failures; marker-only subjects give null keys', () => {
    for (const extraction of [
      { ok: true, identification: 'none', extraOriginals: 0 },
      { ok: true, identification: 'unsupported', extraOriginals: 0 },
      { ok: false, code: 'parse_failed' },
    ] as ReportExtraction[]) {
      expect(buildReportOriginal({ organizationId: 1, extraction })).toBeNull();
    }
    const blank = buildReportOriginal({
      organizationId: 1,
      extraction: {
        ...inline,
        headers: { messageId: '  ', from: 'nobody', date: null, subject: 'Re:' },
      },
    });
    expect(blank).toMatchObject({
      messageIdHash: null,
      sender: null,
      subjectKey: null,
      date: null,
    });
    expect(reportIdentificationOf(attachment)).toBe('attachment');
    expect(reportIdentificationOf({ ok: false, code: 'too_large', limit: 'bytes' })).toBeNull();
  });

  it('refuses bodies or unknown fields in the stored document', () => {
    const doc = buildReportOriginal({ organizationId: 1, extraction: inline }) as ReportOriginal;
    expect(reportOriginalSchema.safeParse({ ...doc, body: 'x' }).success).toBe(false);
    expect(reportOriginalSchema.safeParse({ ...doc, subjectKey: '' }).success).toBe(false);
    expect(
      reportOriginalSchema.safeParse({ ...doc, attachmentSha256: Array(21).fill(H('x')) }).success,
    ).toBe(false);
  });
});

describe('reportGroupKey (C11.3)', () => {
  const base: ReportOriginal = {
    v: 1,
    messageIdHash: null,
    sender: 'billing@example.net',
    subjectKey: 'Invoice 4711',
    date: '2026-11-23T10:15:00.000Z',
    attachmentSha256: [],
    urlSha256: [],
    extraOriginals: 0,
  };

  it('is the Message-ID hash when known', () => {
    expect(reportGroupKey({ ...base, messageIdHash: H('m') })).toBe(H('m'));
  });

  it('else hashes sender, subject key and the date hour', () => {
    const expected = createHash('sha256')
      .update(
        canonicalJson({
          v: 'api-report-group/1',
          sender: 'billing@example.net',
          subjectKey: 'Invoice 4711',
          dateHour: '2026-11-23T10:00:00.000Z',
        }),
      )
      .digest('hex');
    expect(reportGroupKey(base)).toBe(expected);
    expect(reportGroupKey({ ...base, date: '2026-11-23T10:59:59.999Z' })).toBe(expected);
    expect(reportGroupKey({ ...base, date: '2026-11-23T11:00:00.000Z' })).not.toBe(expected);
  });

  it('is null without enough keys', () => {
    expect(reportGroupKey(null)).toBeNull();
    expect(reportGroupKey({ ...base, sender: null })).toBeNull();
    expect(reportGroupKey({ ...base, subjectKey: null })).toBeNull();
    expect(reportGroupKey({ ...base, date: null })).toBeNull();
  });
});

describe('assessReport (C11.2)', () => {
  it.each([
    [null, 'unknown'],
    [{ verdict: null, level: null, hardBlocks: [] }, 'unknown'],
    [{ verdict: 'unknown', level: 'low', hardBlocks: [] }, 'unknown'],
    [{ verdict: 'clean', level: 'none', hardBlocks: [] }, 'clean'],
    [{ verdict: 'phishing', level: 'critical', hardBlocks: [] }, 'malicious'],
    [{ verdict: 'malware', level: 'medium', hardBlocks: ['hb.malware_attachment'] }, 'malicious'],
    [{ verdict: 'phishing', level: 'high', hardBlocks: [] }, 'suspicious'],
    [{ verdict: 'bec', level: 'critical', hardBlocks: ['hb.bec_malicious'] }, 'suspicious'],
    [{ verdict: 'suspicious', level: 'medium', hardBlocks: [] }, 'suspicious'],
    [{ verdict: 'spam', level: 'low', hardBlocks: [] }, 'suspicious'],
    [{ verdict: 'bulk', level: null, hardBlocks: [] }, 'suspicious'],
  ] as const)('%j → %s', (scan, expected) => {
    expect(assessReport(scan)).toBe(expected);
  });
});

describe('reporterCheck (C10.1)', () => {
  const input = (overrides: Partial<ReporterCheckInput> = {}): ReporterCheckInput => ({
    reporterAddress: 'alice@example.com',
    orgDomains: ['Example.com', 'example.org.'],
    reportMailboxAddresses: ['phish-report@example.com', 'abuse@example.org'],
    headers: { autoSubmitted: null, precedence: null },
    ...overrides,
  });

  it.each<[string, Partial<ReporterCheckInput>, object]>([
    ['organization reporter', {}, { ok: true }],
    ['second domain, upper case', { reporterAddress: 'Bob@EXAMPLE.ORG' }, { ok: true }],
    ['Auto-Submitted: no', { headers: { autoSubmitted: 'no', precedence: null } }, { ok: true }],
    ['Precedence: list', { headers: { autoSubmitted: null, precedence: 'list' } }, { ok: true }],
    [
      'external',
      { reporterAddress: 'mallory@example.net' },
      { ok: false, reason: 'external_reporter' },
    ],
    [
      'subdomain is not the domain',
      { reporterAddress: 'a@sub.example.com' },
      { ok: false, reason: 'external_reporter' },
    ],
    ['no reporter', { reporterAddress: null }, { ok: false, reason: 'external_reporter' }],
    [
      'not an address',
      { reporterAddress: 'example.com' },
      { ok: false, reason: 'external_reporter' },
    ],
    [
      'report mailbox itself',
      { reporterAddress: 'Phish-Report@example.com' },
      { ok: false, reason: 'loop' },
    ],
    [
      'report mailbox alias',
      { reporterAddress: 'abuse@example.org' },
      { ok: false, reason: 'loop' },
    ],
    [
      'auto-replied',
      { headers: { autoSubmitted: 'auto-replied; owner="x"', precedence: null } },
      { ok: false, reason: 'auto_submitted' },
    ],
    [
      'auto-generated',
      { headers: { autoSubmitted: 'auto-generated', precedence: null } },
      { ok: false, reason: 'auto_submitted' },
    ],
    [
      'Precedence: bulk',
      { headers: { autoSubmitted: null, precedence: 'Bulk' } },
      { ok: false, reason: 'auto_submitted' },
    ],
    [
      'Precedence: auto_reply',
      { headers: { autoSubmitted: null, precedence: 'auto_reply' } },
      { ok: false, reason: 'auto_submitted' },
    ],
    [
      'order: external before auto',
      {
        reporterAddress: 'x@example.net',
        headers: { autoSubmitted: 'auto-replied', precedence: null },
      },
      { ok: false, reason: 'external_reporter' },
    ],
  ])('%s', (_name, overrides, expected) => {
    expect(reporterCheck(input(overrides))).toEqual(expected);
  });
});
