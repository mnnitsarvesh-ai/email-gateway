import { createHash } from 'node:crypto';
import { NonRetryableError } from '@email-gateway/common';
import type {
  AssistantReportEmailRequestedV1,
  EventEnvelope,
} from '@email-gateway/event-contracts';
import { describe, expect, it, vi } from 'vitest';
import type { ReportDeliveryRow, ReportObjectRead } from './assistant-report-reads';
import { AssistantReportEmailHandler } from './assistant-report.handler';
import { REPORT_PORTAL_NOTE } from './assistant-report-templates';
import { type NoticeMail, type NoticeMailer, NoticeSendError } from './mailer';
import type { NotificationMetrics } from './notification-metrics';

const DELIVERY = '0193a1b2-5a61-7b72-9c83-0d9e8f7a6b52';
const REPORT = '0193a1b2-4f50-7a61-8b72-9c8d7e6f5a41';
const HTML = Buffer.from('<!doctype html><html><body><h1>Café report</h1></body></html>');
const KEY = `org/7/assistant/report/2026/11/23/${REPORT}.html`;
const tx = {} as never;

const logs: unknown[] = [];
const logger = {
  child: () => logger,
  info: (o: unknown) => void logs.push(o),
  warn: (o: unknown) => void logs.push(o),
} as never;

function event(
  over: Partial<EventEnvelope<AssistantReportEmailRequestedV1>> = {},
): EventEnvelope<AssistantReportEmailRequestedV1> {
  return {
    eventId: DELIVERY,
    eventType: 'assistant.report.email_requested.v1',
    occurredAt: '2026-11-23T10:00:00.000Z',
    correlationId: 'corr-report-0001',
    organizationId: '7',
    payload: { deliveryId: DELIVERY, reportId: REPORT, requestedAt: '2026-11-23T10:00:00.000Z' },
    ...over,
  };
}

function row(
  over: Partial<ReportDeliveryRow> = {},
  report: Partial<ReportDeliveryRow['report']> = {},
) {
  return {
    id: 11n,
    publicId: DELIVERY,
    organizationId: 7n,
    status: 'queued',
    recipientAddress: 'owner@acme.example',
    organizationName: 'Acme Corp',
    ...over,
    report: {
      id: 5n,
      publicId: REPORT,
      status: 'available',
      title: 'Security report: Acme Corp (Last 7 days)',
      periodFrom: new Date('2026-11-16T10:00:00.000Z'),
      periodTo: new Date('2026-11-23T10:00:00.000Z'),
      figures: [{ label: 'Messages processed', value: '1,248' }],
      objectKey: KEY,
      sizeBytes: HTML.length,
      sha256: createHash('sha256').update(HTML).digest('hex'),
      createdAt: new Date('2026-11-23T09:59:00.000Z'),
      ...report,
    },
  } satisfies ReportDeliveryRow;
}

function setup(
  options: {
    delivery?: ReportDeliveryRow | null;
    object?: ReportObjectRead;
    configured?: boolean;
    sendError?: Error;
    updated?: boolean;
    maxHtmlBytes?: number;
  } = {},
) {
  const delivery = options.delivery === undefined ? row() : options.delivery;
  const reads = {
    delivery: vi.fn((_tx: unknown, _org: bigint, _id: string) => Promise.resolve(delivery)),
    markFailed: vi.fn((_tx: unknown, _org: bigint, _id: bigint, _code: string) =>
      Promise.resolve(options.updated ?? true),
    ),
    markSent: vi.fn((_tx: unknown, _org: bigint, _id: bigint, _m: string, _at: Date) =>
      Promise.resolve(options.updated ?? true),
    ),
  };
  const objects = {
    read: vi.fn((_org: bigint, _key: string, _e: unknown, _max: number) =>
      Promise.resolve<ReportObjectRead>(options.object ?? { kind: 'ok', bytes: HTML }),
    ),
  };
  const sent: NoticeMail[] = [];
  const mailer: NoticeMailer = {
    configured: options.configured ?? true,
    from: options.configured === false ? null : 'Email Gateway <no-reply@gateway.test>',
    send: (mail) => {
      if (options.sendError) return Promise.reject(options.sendError);
      sent.push(mail);
      return Promise.resolve();
    },
    close: () => undefined,
  };
  const counts: Array<Record<string, string>> = [];
  const metrics = {
    assistantReportEmails: { inc: (labels: Record<string, string>) => void counts.push(labels) },
    sendDuration: { startTimer: () => () => 0 },
  } as unknown as NotificationMetrics;
  const handler = new AssistantReportEmailHandler(reads, objects, mailer, metrics, logger, {
    portalUrl: 'https://portal.test',
    maxHtmlBytes: options.maxHtmlBytes ?? 2_097_152,
  });
  return { handler, reads, objects, sent, counts };
}

describe('AssistantReportEmailHandler (step AI-R D8)', () => {
  it('sends one mail To the recipient with the stored HTML, the attachment and the link', async () => {
    const { handler, reads, objects, sent, counts } = setup();
    expect(await handler.handle(event(), tx)).toBe('sent');
    expect(reads.delivery).toHaveBeenCalledWith(tx, 7n, DELIVERY);
    expect(objects.read).toHaveBeenCalledWith(
      7n,
      KEY,
      { sizeBytes: HTML.length, sha256: row().report.sha256 },
      2_097_152,
    );
    expect(sent).toHaveLength(1);
    const mail = sent[0]!;
    expect(mail.to).toBe('owner@acme.example');
    expect(mail.recipients).toEqual(['owner@acme.example']);
    expect(mail.subject).toBe(
      'Security report: Acme Corp (2026-11-16 10:00 to 2026-11-23 10:00 UTC)',
    );
    expect(Buffer.from(mail.html!, 'utf8').equals(HTML)).toBe(true);
    expect(mail.attachments).toEqual([
      {
        filename: 'security-report-2026-11-23.html',
        content: HTML,
        contentType: 'text/html; charset=utf-8',
      },
    ]);
    expect(mail.text).toContain(
      `https://portal.test/assistant/reports/${REPORT} ${REPORT_PORTAL_NOTE}`,
    );
    expect(mail.text).toContain('- Messages processed: 1,248');
    expect(mail.messageId).toBe(`<assistant-report.${DELIVERY}@gateway.test>`);
    expect(reads.markSent).toHaveBeenCalledWith(
      tx,
      7n,
      11n,
      `<assistant-report.${DELIVERY}@gateway.test>`,
      expect.any(Date),
    );
    expect(reads.markFailed).not.toHaveBeenCalled();
    expect(counts).toEqual([{ result: 'sent' }]);
  });

  it('logs ids and codes only (never the address, subject, title or HTML)', async () => {
    logs.length = 0;
    const { handler } = setup();
    await handler.handle(event(), tx);
    await setup({ object: { kind: 'sha_mismatch' } }).handler.handle(event(), tx);
    const text = JSON.stringify(logs);
    expect(text).not.toContain('owner@acme.example');
    expect(text).not.toContain('Acme');
    expect(text).not.toContain('<h1>');
    expect(text).toContain('assistant_report_integrity');
  });

  it('missing delivery (purged, or another organization) → not_applicable, nothing sent', async () => {
    const { handler, reads, objects, sent, counts } = setup({ delivery: null });
    expect(await handler.handle(event({ organizationId: '8' }), tx)).toBe('not_applicable');
    expect(reads.delivery).toHaveBeenCalledWith(tx, 8n, DELIVERY);
    expect(objects.read).not.toHaveBeenCalled();
    expect(reads.markFailed).not.toHaveBeenCalled();
    expect(sent).toHaveLength(0);
    expect(counts).toEqual([{ result: 'not_applicable' }]);
  });

  it.each(['sent', 'failed'] as const)(
    'a %s delivery (redelivery) → skipped, no write',
    async (status) => {
      const { handler, reads, objects, sent, counts } = setup({ delivery: row({ status }) });
      expect(await handler.handle(event(), tx)).toBe('skipped');
      expect(objects.read).not.toHaveBeenCalled();
      expect(reads.markFailed).not.toHaveBeenCalled();
      expect(reads.markSent).not.toHaveBeenCalled();
      expect(sent).toHaveLength(0);
      expect(counts).toEqual([{ result: 'skipped' }]);
    },
  );

  it('dead-letters an envelope whose report id is not the delivery report', async () => {
    const { handler, sent } = setup({ delivery: row({}, { publicId: 'another' }) });
    await expect(handler.handle(event(), tx)).rejects.toBeInstanceOf(NonRetryableError);
    expect(sent).toHaveLength(0);
  });

  it.each([
    ['report purged', { delivery: row({}, { status: 'purged' }) }, 'assistant_report_purged'],
    ['report failed', { delivery: row({}, { status: 'failed' }) }, 'assistant_report_purged'],
    ['recipient purged', { delivery: row({ recipientAddress: null }) }, 'assistant_report_purged'],
    [
      'recipient malformed',
      { delivery: row({ recipientAddress: 'a@b.example\r\nBcc: x@y.example' }) },
      'assistant_report_recipient_invalid',
    ],
    ['no relay', { configured: false }, 'relay_not_configured'],
    ['object missing', { object: { kind: 'missing' } }, 'assistant_report_missing'],
    ['object key missing', { delivery: row({}, { objectKey: null }) }, 'assistant_report_missing'],
    ['SHA-256 mismatch', { object: { kind: 'sha_mismatch' } }, 'assistant_report_integrity'],
    ['object too large', { object: { kind: 'too_large' } }, 'assistant_report_integrity'],
    ['foreign key', { object: { kind: 'foreign_key' } }, 'assistant_report_integrity'],
    ['row without hash', { delivery: row({}, { sha256: null }) }, 'assistant_report_integrity'],
    [
      'row larger than the bound',
      { delivery: row({}, { sizeBytes: 70_000 }), maxHtmlBytes: 65_536 },
      'assistant_report_integrity',
    ],
    [
      'bytes not UTF-8',
      { object: { kind: 'ok', bytes: Buffer.from([0x3c, 0xff, 0xfe, 0x3e]) } },
      'assistant_report_integrity',
    ],
  ] as const)('%s → delivery failed %s, nothing sent', async (_name, options, code) => {
    const { handler, reads, sent, counts } = setup(options);
    expect(await handler.handle(event(), tx)).toBe('failed');
    expect(reads.markFailed).toHaveBeenCalledWith(tx, 7n, 11n, code);
    expect(reads.markSent).not.toHaveBeenCalled();
    expect(sent).toHaveLength(0);
    expect(counts).toEqual([{ result: 'failed' }]);
  });

  it('a delivery settled concurrently before the failure write → skipped', async () => {
    const { handler, counts } = setup({ object: { kind: 'missing' }, updated: false });
    expect(await handler.handle(event(), tx)).toBe('skipped');
    expect(counts).toEqual([{ result: 'skipped' }]);
  });

  it('a relay failure is rethrown (retried) and the delivery stays queued', async () => {
    const { handler, reads, counts } = setup({ sendError: new NoticeSendError(451) });
    await expect(handler.handle(event(), tx)).rejects.toBeInstanceOf(NoticeSendError);
    expect(reads.markSent).not.toHaveBeenCalled();
    expect(reads.markFailed).not.toHaveBeenCalled();
    expect(counts).toEqual([{ result: 'failed' }]);
  });
});
