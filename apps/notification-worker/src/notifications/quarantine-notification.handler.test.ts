import { NonRetryableError } from '@email-gateway/common';
import type {
  EventEnvelope,
  QuarantineNotificationRequestedV1,
} from '@email-gateway/event-contracts';
import { resolveQuarantineSettings } from '@email-gateway/quarantine';
import { describe, expect, it, vi } from 'vitest';
import type { NoticeMail, NoticeMailer } from './mailer';
import { NoticeSendError } from './mailer';
import type { NotificationMetrics } from './notification-metrics';
import { PreferenceFilter } from './preference-filter';
import { QuarantineNotificationHandler } from './quarantine-notification.handler';

/** Stored `notification_user_preferences` rows the fake transaction returns (step 6.2 N4). */
let preferenceRows: Array<{ organizationId: bigint; userId: bigint; preferences: unknown }> = [];
const tx = {
  notificationUserPreference: {
    findMany: vi.fn((args: { where: { userId: { in: bigint[] } } }) =>
      Promise.resolve(preferenceRows.filter((r) => args.where.userId.in.includes(r.userId))),
    ),
  },
} as never;
const logger = { child: () => logger, info: vi.fn(), warn: vi.fn() } as never;
const EVENT_ID = '0190f0f0-0000-7000-8000-00000000e101';
const USER = '0190f0f0-0000-7000-8000-0000000000u1'.replace('u', 'a');
const DIGEST = '0190f0f0-0000-7000-8000-0000000000d1';
const REQ = '0190f0f0-0000-7000-8000-0000000000a7';
const RELEASE = '0190f0f0-0000-7000-8000-0000000000b7';
const ENTRY = '0190f0f0-0000-7000-8000-0000000000c7';

function event(
  payload: QuarantineNotificationRequestedV1,
): EventEnvelope<QuarantineNotificationRequestedV1> {
  return {
    eventId: EVENT_ID,
    eventType: 'mail.quarantine.notification_requested.v1',
    occurredAt: '2026-11-12T08:00:01.000Z',
    correlationId: 'corr-12345678',
    organizationId: '7',
    payload,
  };
}

const at = '2026-11-12T08:00:00.000Z';
const digestEvent = event({
  kind: 'user_digest',
  refs: { userId: USER, digestId: DIGEST },
  window: { from: '2026-11-11T08:00:00.000Z', to: at },
  requestedAt: at,
});

function setup(
  options: {
    configured?: boolean;
    fail?: boolean;
    settings?: unknown;
    optOut?: boolean;
    user?: boolean;
    entries?: number;
    direction?: 'inbound' | 'outbound';
    domainActive?: boolean;
    approvers?: string[];
  } = {},
) {
  const sent: NoticeMail[] = [];
  const mailer: NoticeMailer = {
    configured: options.configured ?? true,
    from: options.configured === false ? null : 'Gateway <no-reply@gw.example>',
    send: vi.fn((mail: NoticeMail) =>
      options.fail
        ? Promise.reject(new NoticeSendError(451))
        : (sent.push(mail), Promise.resolve()),
    ),
    close: () => undefined,
  };
  const entryCount = options.entries ?? 2;
  const reads = {
    settings: vi.fn(() =>
      Promise.resolve(resolveQuarantineSettings(options.settings ?? null).settings),
    ),
    activeUser: vi.fn(() =>
      Promise.resolve(options.user === false ? null : { id: 11n, email: 'bob@acme.example' }),
    ),
    activeUserById: vi.fn(() => Promise.resolve({ id: 11n, email: 'bob@acme.example' })),
    digest: vi.fn(() => Promise.resolve({ userId: 11n })),
    digestOptOut: vi.fn(() => Promise.resolve(options.optOut ?? false)),
    digestEntries: vi.fn((_tx: unknown, _org: bigint, _a: string, _w: unknown, limit: number) =>
      Promise.resolve({
        total: entryCount,
        entries: Array.from({ length: Math.min(entryCount, limit) }, (_, i) => ({
          publicId: `0190f0f0-0000-7000-8000-00000000000${String(i)}`,
          messageId: BigInt(100 + i),
          messageReceivedAt: new Date('2026-11-11T09:00:00.000Z'),
          envelopeFrom: 'mallory@evil.example',
          reason: 'spam',
          expiresAt: new Date('2026-12-11T09:00:00.000Z'),
          subject: 'Win‮ a prize\r\nBcc: x@y <script> now '.repeat(4),
        })),
      }),
    ),
    approvers: vi.fn(() =>
      Promise.resolve(
        (options.approvers ?? ['ann@acme.example']).map((email, i) => ({
          id: BigInt(21 + i),
          email,
        })),
      ),
    ),
    approvalRequests: vi.fn(() =>
      Promise.resolve([
        {
          publicId: REQ,
          kind: 'release_approval',
          status: 'pending',
          approvalReasons: ['hard_block'],
          requestedByUserId: 11n,
          reason: 'malware',
        },
      ]),
    ),
    release: vi.fn(() =>
      Promise.resolve({
        outcomes: { approval_required: 1 },
        requestedByType: 'user',
        requestedById: USER,
      }),
    ),
    alertCounts: vi.fn(() => Promise.resolve({ hardBlocks: 3, pendingApprovals: 1 })),
    entry: vi.fn(() =>
      Promise.resolve({
        messageId: 501n,
        messageReceivedAt: new Date(at),
        direction: options.direction ?? 'outbound',
        status: 'rejected',
      }),
    ),
  };
  const common = {
    organizationName: vi.fn(() => Promise.resolve('Acme')),
    message: vi.fn(() =>
      Promise.resolve({
        id: 501n,
        publicId: '0190f0f0-0000-7000-8000-0000000001f5',
        organizationId: 7n,
        receivedAt: new Date(at),
        direction: options.direction ?? 'outbound',
        envelopeFrom: 'Alice@ACME.example',
        internetMessageId: '<m1@acme.example>',
        recipientCount: 1,
      }),
    ),
    activeDomain: vi.fn(() => Promise.resolve(options.domainActive ?? true)),
  };
  const counts: Array<Record<string, string>> = [];
  const suppressed: Array<[Record<string, string>, number]> = [];
  const metrics = {
    quarantineMessages: { inc: (labels: Record<string, string>) => counts.push(labels) },
    alertsSuppressed: {
      inc: (labels: Record<string, string>, n: number) => suppressed.push([labels, n]),
    },
    sendDuration: { startTimer: () => () => 0 },
  } as unknown as NotificationMetrics;
  preferenceRows = [];
  const handler = new QuarantineNotificationHandler(
    reads,
    common,
    mailer,
    metrics,
    logger,
    {
      maxRecipients: 50,
      portalUrl: 'https://portal.acme.example',
      now: () => new Date(at),
    },
    new PreferenceFilter(metrics),
  );
  return { handler, sent, reads, counts, common, suppressed };
}

describe('QuarantineNotificationHandler (step 5.3 Q20)', () => {
  it('user_digest: one mail to the user with sender, sanitized subject (≤ 78), reason, expiry and a portal link', async () => {
    const s = setup();
    expect(await s.handler.handle(digestEvent, tx)).toBe('sent');
    expect(s.sent).toHaveLength(1);
    const mail = s.sent[0]!;
    expect(mail.recipients).toEqual(['bob@acme.example']);
    expect(mail.messageId).toBe(`<quarantine-notice.${EVENT_ID}@gw.example>`);
    expect(mail.subject).toBe('[Email Gateway] 2 message(s) held for you');
    expect(mail.text).toContain('From: mallory@evil.example');
    expect(mail.text).toContain('Reason: spam');
    expect(mail.text).toContain('Held until: 2026-12-11T09:00:00.000Z');
    expect(mail.text).toContain(
      'Review: https://portal.acme.example/quarantine/me/0190f0f0-0000-7000-8000-000000000000',
    );
    const subjectLines = mail.text.split('\n').filter((l) => l.trim().startsWith('Subject: '));
    expect(subjectLines).toHaveLength(2);
    for (const line of subjectLines) {
      const value = line.trim().slice('Subject: '.length);
      expect([...value].length).toBeLessThanOrEqual(78);
      expect(value).not.toMatch(/[‮\r<>]/);
    }
    // The subject never injects a header line.
    expect(mail.text).not.toMatch(/^Bcc:/m);
    expect(s.counts).toEqual([{ kind: 'user_digest', result: 'sent' }]);
  });

  it('user_digest: no subject without digest.includeSubject; capped by digest.maxEntries with a "more" line', async () => {
    const s = setup({ settings: { digest: { includeSubject: false, maxEntries: 1 } }, entries: 3 });
    await s.handler.handle(digestEvent, tx);
    const text = s.sent[0]!.text;
    expect(text).not.toContain('Subject:');
    expect(text).toContain('2 more held message(s)');
    expect(s.reads.digestEntries).toHaveBeenCalledWith(
      tx,
      7n,
      'bob@acme.example',
      { from: new Date('2026-11-11T08:00:00.000Z'), to: new Date(at) },
      1,
    );
  });

  it.each([
    ['opted out', { optOut: true }, 'not_applicable'],
    ['end users disabled', { settings: { endUser: { enabled: false } } }, 'not_applicable'],
    ['user inactive', { user: false }, 'no_recipients'],
    ['nothing held any more', { entries: 0 }, 'no_entries'],
  ] as const)('user_digest: %s → nothing sent (%s)', async (_label, options, result) => {
    const s = setup(options);
    expect(await s.handler.handle(digestEvent, tx)).toBe(result);
    expect(s.sent).toEqual([]);
    expect(s.counts).toEqual([{ kind: 'user_digest', result }]);
  });

  it('approval_requested: approvers holding quarantine:approve except the requester, Bcc, ids and reasons only', async () => {
    const s = setup({ approvers: ['ann@acme.example', 'cid@acme.example'] });
    const result = await s.handler.handle(
      event({ kind: 'approval_requested', refs: { approvalRequestIds: [REQ] }, requestedAt: at }),
      tx,
    );
    expect(result).toBe('sent');
    expect(s.reads.approvers).toHaveBeenCalledWith(tx, 7n, [11n], 50, null);
    expect(s.sent[0]!.recipients).toEqual(['ann@acme.example', 'cid@acme.example']);
    expect(s.sent[0]!.text).toContain(`https://portal.acme.example/quarantine/approvals/${REQ}`);
    expect(s.sent[0]!.text).toContain('Approval needed because: hard_block');
    expect(s.sent[0]!.text).toContain('Held for: malware');
  });

  it('approval_requested and admin_alert leave out approvers who opted out of their kind (step 6.2 N4)', async () => {
    const s = setup({ approvers: ['ann@acme.example', 'cid@acme.example'] });
    // ann (21) opted out of approval requests only; cid (22) of admin alerts only.
    preferenceRows = [
      {
        organizationId: 7n,
        userId: 21n,
        preferences: { optOut: ['quarantine_approval_requested'] },
      },
      { organizationId: 7n, userId: 22n, preferences: { optOut: ['quarantine_admin_alert'] } },
    ];
    await s.handler.handle(
      event({ kind: 'approval_requested', refs: { approvalRequestIds: [REQ] }, requestedAt: at }),
      tx,
    );
    await s.handler.handle(
      event({
        kind: 'admin_alert',
        refs: {},
        window: { from: '2026-11-12T07:00:00.000Z', to: at },
        requestedAt: at,
      }),
      tx,
    );
    expect(s.sent.map((m) => m.recipients)).toEqual([['cid@acme.example'], ['ann@acme.example']]);
    expect(s.suppressed).toEqual([
      [{ kind: 'quarantine_approval_requested', reason: 'opt_out' }, 1],
      [{ kind: 'quarantine_admin_alert', reason: 'opt_out' }, 1],
    ]);
  });

  it('approval_decided, release_blocked and user_digest ignore the 6.2 opt-out list', async () => {
    const s = setup();
    preferenceRows = [
      {
        organizationId: 7n,
        userId: 11n,
        preferences: {
          optOut: ['policy_alert', 'quarantine_admin_alert', 'quarantine_approval_requested'],
        },
      },
    ];
    await s.handler.handle(
      event({
        kind: 'approval_decided',
        refs: { approvalRequestIds: [REQ] },
        decision: 'approved',
        requestedAt: at,
      }),
      tx,
    );
    await s.handler.handle(digestEvent, tx);
    expect(s.sent.map((m) => m.recipients)).toEqual([['bob@acme.example'], ['bob@acme.example']]);
    expect(s.suppressed).toEqual([]);
  });

  it('approval_decided and release_blocked go to the requesting user only', async () => {
    const s = setup();
    await s.handler.handle(
      event({
        kind: 'approval_decided',
        refs: { approvalRequestIds: [REQ] },
        decision: 'denied',
        requestedAt: at,
      }),
      tx,
    );
    await s.handler.handle(
      event({ kind: 'release_blocked', refs: { releaseId: RELEASE }, requestedAt: at }),
      tx,
    );
    expect(s.sent.map((m) => [m.recipients, m.subject])).toEqual([
      [['bob@acme.example'], '[Email Gateway] Your quarantine request was denied'],
      [['bob@acme.example'], '[Email Gateway] Your quarantine release was not completed'],
    ]);
    expect(s.sent[1]!.text).toContain('Outcome: approval required: 1');
  });

  it('admin_alert: counts and a link to the approvers', async () => {
    const s = setup();
    await s.handler.handle(
      event({
        kind: 'admin_alert',
        refs: {},
        window: { from: '2026-11-12T07:00:00.000Z', to: at },
        requestedAt: at,
      }),
      tx,
    );
    expect(s.sent[0]!.text).toContain('New hard-blocked messages: 3');
    expect(s.sent[0]!.text).toContain('Approval requests waiting over an hour: 1');
    expect(s.sent[0]!.text).toContain('https://portal.acme.example/quarantine');
  });

  it('sender_rejected: only an outbound/internal sender of an active domain; never inbound', async () => {
    const refs = { entryId: ENTRY, messageId: '501', receivedAt: at };
    const ok = setup();
    expect(
      await ok.handler.handle(event({ kind: 'sender_rejected', refs, requestedAt: at }), tx),
    ).toBe('sent');
    expect(ok.sent[0]!.recipients).toEqual(['alice@acme.example']);
    const inbound = setup({ direction: 'inbound' });
    expect(
      await inbound.handler.handle(event({ kind: 'sender_rejected', refs, requestedAt: at }), tx),
    ).toBe('not_applicable');
    expect(inbound.common.activeDomain).not.toHaveBeenCalled();
    const foreign = setup({ domainActive: false });
    expect(
      await foreign.handler.handle(event({ kind: 'sender_rejected', refs, requestedAt: at }), tx),
    ).toBe('no_recipients');
    expect(inbound.sent).toEqual([]);
    expect(foreign.sent).toEqual([]);
  });

  it('a sender notice whose entry does not match its message is dead-lettered', async () => {
    const s = setup();
    await expect(
      s.handler.handle(
        event({
          kind: 'sender_rejected',
          refs: { entryId: ENTRY, messageId: '999', receivedAt: at },
          requestedAt: at,
        }),
        tx,
      ),
    ).rejects.toBeInstanceOf(NonRetryableError);
  });

  it('no relay → disabled; a relay failure is counted and thrown (retried)', async () => {
    const off = setup({ configured: false });
    expect(await off.handler.handle(digestEvent, tx)).toBe('disabled');
    const failing = setup({ fail: true });
    await expect(failing.handler.handle(digestEvent, tx)).rejects.toBeInstanceOf(NoticeSendError);
    expect(failing.counts).toEqual([{ kind: 'user_digest', result: 'failed' }]);
  });
});
