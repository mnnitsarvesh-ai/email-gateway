import { describe, expect, it } from 'vitest';
import {
  pageSchema,
  quarantineApprovalViewSchema,
  quarantineEntryDetailSchema,
  quarantineEntrySummarySchema,
  quarantineReleaseViewSchema,
  type QuarantineEntrySummary,
} from './dto';
import {
  checkSearchRange,
  decodeSearchCursor,
  encodeSearchCursor,
  searchFilterHash,
} from './search';
import { sanitizeDisplayText, sanitizeSubject } from './text';

const U = (n: number) => `01930000-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;
const T = '2026-11-12T10:00:00.000Z';

const summary: QuarantineEntrySummary = {
  id: U(1),
  messageId: '0190a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a7b',
  lifecycleRound: 0,
  state: 'held',
  kind: 'quarantine',
  origin: 'policy',
  reason: 'phishing',
  direction: 'inbound',
  recipient: 'a@corp.example',
  sender: { envelope: 'x@ext.example', headerFrom: null },
  subject: null,
  receivedAt: T,
  quarantinedAt: T,
  expiresAt: T,
  riskLevel: 'high',
  riskScore: 650,
  hardBlocks: ['hb.known_phishing'],
  primaryEngine: 'url',
  decisive: { source: 'floor', policyId: null, versionNo: null, ruleId: null },
  hasAttachments: false,
  attachmentCount: 0,
  sizeBytes: 2048,
  approvalRequestId: null,
  rowVersion: 1,
};

describe('DTO schemas (Q26)', () => {
  it('summary, detail, release, approval and page', () => {
    expect(quarantineEntrySummarySchema.parse(summary)).toEqual(summary);
    expect(() => quarantineEntrySummarySchema.parse({ ...summary, body: 'x' })).toThrow();
    expect(() =>
      quarantineEntrySummarySchema.parse({ ...summary, state: 'quarantined' }),
    ).toThrow();
    const release = {
      id: U(2),
      status: 'dispatched' as const,
      mode: 'approved' as const,
      requestedBy: { type: 'user' as const, id: U(3) },
      requestedAt: T,
      completedAt: T,
      revalidation: {
        disposition: 'quarantine' as const,
        source: 'floor' as const,
        decisiveRuleRef: null,
        floorReasons: ['policy.floor.hard_block'],
        hardBlocks: ['hb.known_phishing'],
        level: 'high' as const,
        score: 650,
        recommendedAction: 'quarantine',
        generation: '3',
        snapshotSha256: 'a'.repeat(64),
        inputSha256: 'b'.repeat(64),
        evaluatorVersion: 'policy-eval/2',
        scanId: '11',
        scanCompletedAt: T,
      },
      deliveredObject: 'policy_copy' as const,
      approvalRequestId: U(4),
    };
    expect(quarantineReleaseViewSchema.parse(release)).toEqual(release);
    const detail = {
      ...summary,
      explanation: {
        lines: [
          { code: 'summary' as const, params: { disposition: 'quarantine', source: 'floor' } },
        ],
        text: 'Policy decision: quarantine (decided by floor).',
      },
      floorReasons: ['policy.floor.hard_block'],
      reasonCodes: ['policy.floor.hard_block'],
      releases: [release],
      allowedActions: ['preview' as const, 'release' as const],
      contentAvailable: true,
    };
    expect(quarantineEntryDetailSchema.parse(detail)).toEqual(detail);
    const approval = {
      id: U(4),
      kind: 'release_approval' as const,
      status: 'pending' as const,
      entryId: U(1),
      approvalReasons: ['hard_block' as const],
      requestedBy: { type: 'user' as const, id: U(3) },
      requestedAt: T,
      expiresAt: T,
      decidedBy: null,
      decidedAt: null,
      decisionReason: null,
    };
    expect(quarantineApprovalViewSchema.parse(approval)).toEqual(approval);
    expect(() =>
      quarantineApprovalViewSchema.parse({ ...approval, approvalReasons: ['because'] }),
    ).toThrow();
    const page = pageSchema(quarantineEntrySummarySchema, 100);
    expect(page.parse({ items: [summary], nextCursor: null })).toEqual({
      items: [summary],
      nextCursor: null,
    });
  });
});

describe('search cursors (Q9)', () => {
  const filter = {
    from: '2026-11-01T00:00:00.000Z',
    to: '2026-11-12T00:00:00.000Z',
    state: ['held'],
    limit: 50,
  };
  it('round trip, bound to the canonical filter (pagination fields excluded)', () => {
    const f = searchFilterHash(filter);
    expect(f).toMatch(/^[0-9a-f]{16}$/);
    expect(
      searchFilterHash({
        state: ['held'],
        to: filter.to,
        from: filter.from,
        cursor: 'x',
        recipient: undefined,
      }),
    ).toBe(f);
    const c = encodeSearchCursor({ t: T, id: '42', f });
    expect(c).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(decodeSearchCursor(c, f)).toEqual({ t: T, id: '42', f });
    expect(decodeSearchCursor(c, searchFilterHash({ ...filter, state: ['expired'] }))).toBeNull();
  });
  it.each([
    '',
    'not base64!',
    Buffer.from('{}').toString('base64url'),
    Buffer.from('[1]').toString('base64url'),
    Buffer.from(JSON.stringify({ t: 'yesterday', id: '1', f: 'x' })).toString('base64url'),
    Buffer.from(JSON.stringify({ t: T, id: '-1', f: 'x' })).toString('base64url'),
    Buffer.from(JSON.stringify({ t: T, id: '1', f: 'x', extra: 1 })).toString('base64url'),
    'a'.repeat(600),
  ])('refuses malformed cursors (%#)', (c) => {
    expect(decodeSearchCursor(c, 'x')).toBeNull();
  });
  it('range bound', () => {
    const from = new Date('2026-09-01T00:00:00Z');
    expect(checkSearchRange(from, new Date(from.getTime() + 62 * 86_400_000))).toBe(true);
    expect(checkSearchRange(from, new Date(from.getTime() + 62 * 86_400_000 + 1))).toBe(false);
    expect(checkSearchRange(from, from)).toBe(false);
    expect(checkSearchRange(from, new Date(Number.NaN))).toBe(false);
  });
});

describe('display text sanitization', () => {
  it('removes controls, bidi overrides and zero-width characters; NFC; single line', () => {
    expect(sanitizeSubject('Invoice\u202e fdp.exe\u200b\r\n paid\u0007')).toBe(
      'Invoice fdp.exe paid',
    );
    expect(sanitizeSubject('Cafe\u0301')).toBe('Caf\u00e9');
    expect(sanitizeSubject(null)).toBeNull();
    expect(sanitizeSubject('x'.repeat(300))!.length).toBe(256);
    expect(sanitizeSubject('x'.repeat(300), 78)!.length).toBe(78);
  });
  it('multiline keeps newlines and tabs, counts code points', () => {
    expect(
      sanitizeDisplayText('a\tb\r\nc\u0000\u2066d', { maxChars: 100, multiline: true }),
    ).toEqual({
      text: 'a\tb\nc' + 'd',
      truncated: false,
    });
    expect(sanitizeDisplayText('😀😀😀', { maxChars: 2 })).toEqual({
      text: '😀😀',
      truncated: true,
    });
  });
});
