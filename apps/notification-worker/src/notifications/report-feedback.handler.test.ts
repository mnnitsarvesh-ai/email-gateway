import type { EventEnvelope, ReportFeedbackRequestedV1 } from '@email-gateway/event-contracts';
import { describe, expect, it, vi } from 'vitest';
import type { NoticeMail, NoticeMailer } from './mailer';
import { NoticeSendError } from './mailer';
import type { NotificationMetrics } from './notification-metrics';
import type { FeedbackReport } from './report-feedback-reads';
import { REPORT_FEEDBACK_CONSUMER, ReportFeedbackHandler } from './report-feedback.handler';

/**
 * Reporter feedback (step API-3 C12, docs/plan/steps/37-api-mode-clawback-reporting.md):
 * send-time decisions, the fixed templates per kind and verdict, the handler ledger, and no
 * leakage of the reported message. Synthetic organizations, addresses and ids only.
 */
const logger = { child: () => logger, info: vi.fn(), warn: vi.fn() } as never;
const REPORT = '0192f0c4-eeee-7fff-8aaa-0000000000d1';
const EVENT_ID = '0190f0f0-0000-7000-8000-00000000e501';
const REPORTED_AT = new Date('2026-11-26T08:15:00.000Z');

function event(
  kind: ReportFeedbackRequestedV1['kind'],
  organizationId = '7',
): EventEnvelope<ReportFeedbackRequestedV1> {
  return {
    eventId: EVENT_ID,
    eventType: 'mail.report.feedback_requested.v1',
    occurredAt: '2026-11-27T08:00:00.000Z',
    correlationId: 'corr-12345678',
    organizationId,
    payload: { reportId: REPORT, kind, requestedAt: '2026-11-27T08:00:00.000Z' },
  };
}

const report = (over: Partial<FeedbackReport> = {}): FeedbackReport => ({
  publicId: REPORT,
  organizationId: 7n,
  status: 'pending_triage',
  reporterAddress: 'pat@acme.example',
  analystVerdict: null,
  reportedAt: REPORTED_AT,
  ...over,
});

interface SetupOptions {
  report?: FeedbackReport | null;
  ownDomains?: string[];
  resolves?: boolean;
  configured?: boolean;
  fail?: boolean;
  duplicate?: boolean;
}

function setup(options: SetupOptions = {}) {
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
  const stored = options.report === undefined ? report() : options.report;
  const reads = {
    report: vi.fn((_tx: unknown, organizationId: bigint, publicId: string) =>
      Promise.resolve(
        stored !== null && stored.organizationId === organizationId && stored.publicId === publicId
          ? stored
          : null,
      ),
    ),
    organizationName: vi.fn(() => Promise.resolve('Acme')),
    ownDomain: vi.fn((_tx: unknown, _org: bigint, domain: string) =>
      Promise.resolve((options.ownDomains ?? ['acme.example']).includes(domain)),
    ),
    reporterResolves: vi.fn(() => Promise.resolve(options.resolves ?? true)),
  };
  const ledger: Array<{ consumer: string; eventId: string }> = [];
  const tx = {
    messageIdempotency: {
      createMany: vi.fn((args: { data: Array<{ consumer: string; eventId: string }> }) => {
        ledger.push(...args.data);
        return Promise.resolve({ count: options.duplicate ? 0 : args.data.length });
      }),
    },
  } as never;
  const counts: Array<Record<string, string>> = [];
  const metrics = {
    reportFeedback: { inc: (labels: Record<string, string>) => counts.push(labels) },
    sendDuration: { startTimer: () => () => 0 },
  } as unknown as NotificationMetrics;
  const handler = new ReportFeedbackHandler(reads, mailer, metrics, logger);
  return { handler, reads, sent, counts, tx, ledger };
}

/** The reported message's content never appears (the fixtures put none in; the copy is fixed). */
function assertNoLeak(mail: NoticeMail): void {
  for (const part of [mail.subject, mail.text, mail.html ?? '']) {
    expect(part).not.toMatch(/subject:|from:|sender/i);
    expect(part).not.toContain('pat@acme.example');
    expect(part).not.toContain('://');
  }
}

describe('ReportFeedbackHandler received (step API-3 C12)', () => {
  it('sends the acknowledgement To the reporter with the date and public id, text + HTML', async () => {
    const s = setup();
    expect(await s.handler.handle(event('received'), s.tx)).toBe('sent');
    expect(s.ledger).toEqual([{ consumer: REPORT_FEEDBACK_CONSUMER, eventId: EVENT_ID }]);
    expect(s.reads.report).toHaveBeenCalledWith(s.tx, 7n, REPORT);
    expect(s.reads.ownDomain).toHaveBeenCalledWith(s.tx, 7n, 'acme.example');
    expect(s.reads.reporterResolves).toHaveBeenCalledWith(s.tx, 7n, 'pat@acme.example');
    const mail = s.sent[0]!;
    expect(mail.to).toBe('pat@acme.example');
    expect(mail.recipients).toEqual([]);
    expect(mail.subject).toBe('[Email Gateway] We received your report');
    expect(mail.text).toContain('Thank you — we received the message you reported.');
    expect(mail.text).toContain(`Report reference: ${REPORT}`);
    expect(mail.text).toContain('Reported: 2026-11-26 08:15 UTC');
    expect(mail.text).toContain('security team of Acme.');
    expect(mail.html).toContain(`Report reference: ${REPORT}`);
    expect(mail.messageId).toBe(`<report-feedback.${EVENT_ID}@gw.example>`);
    assertNoLeak(mail);
    expect(s.counts).toEqual([{ kind: 'report_feedback_received', result: 'sent' }]);
  });

  it('a received acknowledgement needs no verdict', async () => {
    const s = setup({ report: report({ status: 'received' }) });
    expect(await s.handler.handle(event('received'), s.tx)).toBe('sent');
  });
});

describe('ReportFeedbackHandler resolved (step API-3 C12)', () => {
  it.each([
    ['malicious', 'Thank you — this message was dangerous and has been removed.'],
    ['phishing_simulation', 'This was a phishing simulation — well spotted.'],
    ['spam', 'This message was unwanted mail (spam), not a targeted attack.'],
    ['clean', 'This message is safe.'],
    ['inconclusive', 'could not reach a clear conclusion'],
  ] as const)('%s: the fixed result copy', async (verdict, headline) => {
    const s = setup({ report: report({ status: 'resolved', analystVerdict: verdict }) });
    expect(await s.handler.handle(event('resolved'), s.tx)).toBe('sent');
    const mail = s.sent[0]!;
    expect(mail.text.split('\n')[0]).toContain(headline);
    expect(mail.html).toContain(headline);
    expect(mail.text).toContain(`Report reference: ${REPORT}`);
    assertNoLeak(mail);
    expect(s.counts).toEqual([{ kind: 'report_feedback_resolved', result: 'sent' }]);
  });

  it('no analyst verdict (or an unknown one) → no mail', async () => {
    for (const analystVerdict of [null, 'bogus']) {
      const s = setup({ report: report({ status: 'in_review', analystVerdict }) });
      expect(await s.handler.handle(event('resolved'), s.tx)).toBe('no_verdict');
      expect(s.sent).toEqual([]);
      expect(s.counts).toEqual([{ kind: 'report_feedback_resolved', result: 'no_verdict' }]);
    }
  });
});

describe('ReportFeedbackHandler send-time refusals (step API-3 C12)', () => {
  it('a rejected report sends nothing (either kind)', async () => {
    for (const kind of ['received', 'resolved'] as const) {
      const s = setup({ report: report({ status: 'rejected', analystVerdict: 'clean' }) });
      expect(await s.handler.handle(event(kind), s.tx)).toBe('rejected');
      expect(s.sent).toEqual([]);
    }
  });

  it('an external reporter address sends nothing', async () => {
    const s = setup({ report: report({ reporterAddress: 'someone@outside.example' }) });
    expect(await s.handler.handle(event('received'), s.tx)).toBe('external_reporter');
    expect(s.reads.reporterResolves).not.toHaveBeenCalled();
    expect(s.sent).toEqual([]);
    const malformed = setup({ report: report({ reporterAddress: 'not-an-address' }) });
    expect(await malformed.handler.handle(event('received'), malformed.tx)).toBe(
      'external_reporter',
    );
    expect(malformed.reads.ownDomain).not.toHaveBeenCalled();
  });

  it('a reporter that no longer resolves to an organization mailbox or user sends nothing', async () => {
    const s = setup({ resolves: false });
    expect(await s.handler.handle(event('received'), s.tx)).toBe('reporter_unresolved');
    expect(s.sent).toEqual([]);
  });

  it('a missing report is acked with a metric (no throw, no mail)', async () => {
    const s = setup({ report: null });
    expect(await s.handler.handle(event('received'), s.tx)).toBe('report_missing');
    expect(s.counts).toEqual([{ kind: 'report_feedback_received', result: 'report_missing' }]);
    expect(s.sent).toEqual([]);
  });

  it('an envelope of another organization finds nothing and sends nothing', async () => {
    const s = setup();
    expect(await s.handler.handle(event('received', '8'), s.tx)).toBe('report_missing');
    expect(s.reads.report).toHaveBeenCalledWith(s.tx, 8n, REPORT);
    expect(s.reads.ownDomain).not.toHaveBeenCalled();
    expect(s.sent).toEqual([]);
  });

  it('a handler ledger duplicate sends nothing', async () => {
    const s = setup({ duplicate: true });
    expect(await s.handler.handle(event('received'), s.tx)).toBe('duplicate');
    expect(s.reads.report).not.toHaveBeenCalled();
    expect(s.sent).toEqual([]);
  });

  it('no relay → disabled; a relay failure is counted and thrown (retried)', async () => {
    const off = setup({ configured: false });
    expect(await off.handler.handle(event('received'), off.tx)).toBe('disabled');
    const failing = setup({ fail: true });
    await expect(failing.handler.handle(event('received'), failing.tx)).rejects.toBeInstanceOf(
      NoticeSendError,
    );
    expect(failing.counts).toEqual([{ kind: 'report_feedback_received', result: 'failed' }]);
  });
});
