import { randomBytes } from 'node:crypto';
import { eicar } from '@email-gateway/attachment-corpus';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, idempotencyKey, type ApiSession } from './support/api-client';
import { attachmentMessage } from './support/attachment-stack';
import { purgeDormantQueues } from './support/broker';
import { compose, composeExec, runningServices, waitFor } from './support/compose';
import { waitForMessage } from './support/deliveries';
import { waitForLifecycle } from './support/lifecycle';
import { clearSinkDomain, sinkFiles, sinkMessage } from './support/mail-sink';
import { record, sleep } from './support/messaging-stack';
import { restoreNotificationWorker } from './support/policy';
import { noticeText } from './support/quarantine';
import { deleteQueued, involving, listQueue } from './support/postfix';
import { MAIL_SINK_HOST, organizationRef } from './support/routing';
import { messagePublicId, sendToMx } from './support/scan-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply } from './support/smtp-tools';
import {
  createWebhook,
  deliveryDetail,
  NOTIFY_RELAY_SINK_ADDRESS,
  pointPostfixNotifyAtRelaySink,
  postfixNotifyRelayhost,
  programReceiver,
  putAlertSettings,
  receivedRequests,
  recreateWebhookWorker,
  restorePostfixNotify,
  verifyReceived,
  webhooksStackGate,
  webhookWorkerEnv,
  type CreatedWebhook,
} from './support/webhooks';

/**
 * Step 6.2 security alert e-mails end to end (docs/plan/steps/19-webhooks-notifications.md N1–N4,
 * W11, §10.4; ADR-0056): the webhook-worker requests the alert (`notification.alert_requested.v1`,
 * throttle window), the notification-worker renders it and sends it through its DEFAULT relay
 * `postfix-notify`, which this suite recreates with `NOTIFY_RELAY_HOST=172.31.250.31` (the
 * TEST-ONLY `notify-relay-sink`: submission 587, mandatory STARTTLS with the pinned test-pki
 * certificate, SASL with NOTIFY_RELAY_SINK_USER/_PASSWORD). The relay settings travel by Compose
 * interpolation of the child environment only: `.env` is never written. Restored in afterAll.
 *
 * 1. A malicious (EICAR) message produces exactly ONE threat alert e-mail (a second one in the
 *    same window is counted, not mailed), without subject, addresses, file name or URLs from
 *    the message.
 * 2. A subscription whose endpoint always answers 500 is disabled by the worker
 *    (`sustained_failure`) under minimal thresholds (the webhook-worker is recreated with
 *    WEBHOOK_DISABLE_AFTER_FAILURES=5, WEBHOOK_DISABLE_AFTER_HOURS=1 and a 1 s retry base) and
 *    the `webhook_disabled` alert e-mail arrives. FIXTURE WRITE: the subscription's
 *    `failing_since` is set two hours back before the first attempt, because the smallest
 *    allowed duration (1 h, §4.4) cannot elapse in a test; the failure count is real.
 */
const gate = await webhooksStackGate();
const fx = new SmtpFixtures();
const run = randomBytes(3).toString('hex');

let orgN = 0n;
let orgNPublicId = '';
let inN: FixtureDomain;
let opsDomain = '';
let adminN: ApiSession | undefined;
let adminEmail = '';
let postfixNotifyRedirected = false;
let workerRecreated = false;
let failing: CreatedWebhook | undefined;

const SUBJECT_TOKEN = `WH6N${run}`;
const EICAR_FILE = `wh6n-${run}-report.txt`;
const SENDER = 'alice@clean.scan.test';
const LP = 'wh6nx';
/** Minimal auto-disable thresholds of case 2 (bounds of §4.4) and a fast retry base. */
const WORKER_OVERRIDES = {
  WEBHOOK_DISABLE_AFTER_FAILURES: '5',
  WEBHOOK_DISABLE_AFTER_HOURS: '1',
  WEBHOOK_RETRY_BASE_SECONDS: '1',
  WEBHOOK_RETRY_MAX_DELAY_SECONDS: '60',
};

interface Mail {
  path: string;
  headers: string;
  subject: string;
  messageId: string;
  body: string;
}

async function relayMails(): Promise<Mail[]> {
  const files = await sinkFiles(adminEmail, 'notify-relay-sink');
  const mails: Mail[] = [];
  for (const path of files) {
    const raw = noticeText(await sinkMessage(path, 'notify-relay-sink'));
    const split = raw.indexOf('\n\n');
    const headers = raw.slice(0, split);
    const unfolded = headers.replace(/\n[ \t]+/g, ' ');
    mails.push({
      path,
      headers,
      subject: /^Subject: (.*)$/im.exec(unfolded)?.[1]?.trim() ?? '',
      messageId: /^Message-ID: (.*)$/im.exec(unfolded)?.[1]?.trim() ?? '',
      body: raw.slice(split + 2),
    });
  }
  return mails;
}

const ofKind = (mails: readonly Mail[], kind: string) =>
  mails.filter((m) => m.subject.endsWith(`: ${kind}`));

/** No content of the message or the endpoint in an alert body (N4). */
function alertBodyProblems(body: string, extra: readonly string[] = []): string[] {
  const portal = process.env.PORTAL_PUBLIC_URL || 'http://localhost:3001';
  const withoutPortal = body.split(portal).join('');
  const problems: string[] = [];
  if (withoutPortal.includes('@')) problems.push(`'@'`);
  if (withoutPortal.includes('://')) problems.push(`'://' outside the portal link`);
  for (const value of [
    SUBJECT_TOKEN,
    EICAR_FILE,
    'alice',
    'clean.scan.test',
    LP,
    'whsec_',
    ...extra,
  ]) {
    if (body.toLowerCase().includes(value.toLowerCase())) problems.push(`'${value}'`);
  }
  return problems;
}

async function eicarMessage(): Promise<{ id: bigint; receivedAt: Date; publicId: string }> {
  const rcpt = `${LP}@${inN.name}`;
  const built = attachmentMessage({
    from: `Alice <${SENDER}>`,
    to: [rcpt],
    subject: `${SUBJECT_TOKEN} quarterly report`,
    attachments: [{ filename: EICAR_FILE, contentType: 'text/plain', bytes: eicar() }],
  });
  const sent = await sendToMx({
    from: SENDER,
    to: [rcpt],
    helo: 'mx.clean.scan.test',
    data: built.text,
  });
  expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
  const row = await waitForMessage(fx.prisma, orgN, { mtaQueueId: sent.queueId! });
  const message = {
    id: row.id,
    receivedAt: row.receivedAt,
    publicId: await messagePublicId(fx.prisma, row),
  };
  await waitForLifecycle(fx.prisma, message, 'rejected', undefined, 240_000);
  return message;
}

beforeAll(async () => {
  assertStackReady(gate);
  const services = await runningServices();
  for (const s of ['notify-relay-sink', 'postfix-notify', 'notification-worker']) {
    if (!services.has(s)) throw new Error(`${s} is not running (profiles apps + smtp-test)`);
  }
  orgN = await fx.organization('wh6n');
  inN = await fx.domain(orgN, 'wh6n-in');
  await fx.destinations(inN, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  await fx.feature(orgN, 'webhooks', true);
  opsDomain = fx.name('wh6n-ops');
  adminEmail = `wh6adm${run}@${opsDomain}`;
  const ref = await organizationRef(fx, orgN);
  orgNPublicId = ref.publicId;
  adminN = await apiSession(fx.prisma, ref, 'organization_admin', { email: adminEmail });
  // The fixture default switches every alert off; this organization opts in through the api.
  await putAlertSettings(adminN, {
    threatDetected: { enabled: true, minSeverity: 'high', throttleMinutes: 60 },
    webhookDisabled: { enabled: true, throttleMinutes: 60 },
    domainDnsFailed: { enabled: false },
    includeOrganizationContact: false,
  });

  // The notification-worker must use its default relay (an earlier suite may have left it on
  // mail-sink): postfix-notify.
  const relay = await compose(
    ['exec', '-T', 'notification-worker', 'printenv', 'NOTIFY_SMTP_HOST'],
    {
      timeoutMs: 20_000,
    },
  );
  if (relay.stdout.trim() !== 'postfix-notify') await restoreNotificationWorker();
  await pointPostfixNotifyAtRelaySink();
  postfixNotifyRedirected = true;
  expect(await postfixNotifyRelayhost()).toBe(`[${NOTIFY_RELAY_SINK_ADDRESS}]:587`);
  // Fanout caches settings and subscriptions for WEBHOOK_SUBSCRIPTION_CACHE_SECONDS (5 s).
  await sleep(6_000);
}, 600_000);

afterAll(async () => {
  if (gate.skip) return;
  if (workerRecreated) {
    await recreateWebhookWorker();
    expect(await webhookWorkerEnv('WEBHOOK_DISABLE_AFTER_FAILURES')).toBe(
      process.env.WEBHOOK_DISABLE_AFTER_FAILURES ?? '50',
    );
  }
  if (postfixNotifyRedirected) {
    // Nothing of this suite may stay queued for the developer's own relay after the restore.
    const queued = await composeExec('postfix-notify', ['postqueue', '-j'], { timeoutMs: 20_000 });
    const ids = queued.stdout
      .split('\n')
      .filter((l) => l.trim().startsWith('{'))
      .map((l) => JSON.parse(l) as { queue_id: string; recipients: { address: string }[] })
      .filter((m) => m.recipients.every((r) => r.address.toLowerCase().endsWith('.test')))
      .map((m) => m.queue_id);
    for (const id of ids) {
      await composeExec('postfix-notify', ['postsuper', '-d', id], { timeoutMs: 20_000 });
    }
    await restorePostfixNotify();
  }
  if (failing && adminN) await adminN.delete(`/webhooks/${failing.id}`, idempotencyKey());
  await adminN?.remove();
  for (const service of ['postfix-outbound', 'postfix'] as const) {
    const names = [inN?.name].filter((n): n is string => Boolean(n));
    const queued = involving(await listQueue(service), names);
    await deleteQueued(
      service,
      queued.map((m) => m.queue_id),
    );
  }
  if (opsDomain) await clearSinkDomain(opsDomain, 'notify-relay-sink').catch(() => undefined);
  if (inN) await clearSinkDomain(inN.name, 'all').catch(() => undefined);
  await fx.cleanup();
  await purgeDormantQueues();
}, 600_000);

describe.skipIf(gate.skip)(
  'security alert e-mails through postfix-notify',
  { timeout: 900_000 },
  () => {
    it('(1) a malicious message: exactly one threat alert e-mail, relayed by postfix-notify to the authenticated relay, no message content', async () => {
      const first = await eicarMessage();
      const mail = await waitFor(
        'the threat alert in notify-relay-sink',
        async () => ofKind(await relayMails(), 'threat detected')[0],
        { timeoutMs: 240_000, intervalMs: 2_000 },
      );
      expect(mail.subject).toBe('[Email Gateway] Security alert (high): threat detected');
      expect(mail.messageId).toMatch(/^<security-alert\.[0-9a-f-]{36}@[a-z0-9.-]+>$/);
      // The path: notification-worker → postfix-notify (hostname `notify`) → notify-relay-sink.
      expect(mail.headers).toMatch(/^Received: from notify\b/m);
      expect(mail.headers).toMatch(/by notify-relay\.sink\.test/);
      expect(mail.headers).toMatch(/with ESMTPS?A/);
      expect(mail.body).toContain(first.publicId);
      expect(mail.body).toContain(`/messages/${first.publicId}`);
      expect(alertBodyProblems(mail.body)).toEqual([]);

      // A second malicious message in the same window is counted, not mailed (N2).
      const second = await eicarMessage();
      await waitFor(
        'the window counting the second threat',
        async () => {
          const w = await fx.prisma.notificationAlertWindow.findFirst({
            where: { organizationId: orgN, kind: 'threat_detected' },
          });
          return w && w.eventCount >= 2 ? w : undefined;
        },
        { timeoutMs: 180_000, intervalMs: 1_000 },
      );
      await sleep(15_000);
      const threats = ofKind(await relayMails(), 'threat detected');
      expect(threats).toHaveLength(1);
      expect(threats[0]!.body).not.toContain(second.publicId);
      record('webhooks-notifications', { threat_alerts: threats.length });
    });

    it('(2) sustained failure disables the subscription (audited) and mails the webhook_disabled alert', async () => {
      await recreateWebhookWorker(WORKER_OVERRIDES);
      workerRecreated = true;
      expect(await webhookWorkerEnv('WEBHOOK_DISABLE_AFTER_FAILURES')).toBe('5');
      failing = await createWebhook(adminN!, {
        name: 'WH6N failing endpoint',
        path: `it-wh6n-${run}/n/failing`,
        eventTypes: ['email.received'],
      });
      await programReceiver(failing.path, [], 500);
      // FIXTURE WRITE (see the suite comment): the failure streak started two hours ago.
      const sub = await fx.prisma.webhookSubscription.findUniqueOrThrow({
        where: { publicId: failing.id },
        select: { id: true, organizationId: true },
      });
      expect(sub.organizationId).toBe(orgN);
      await fx.prisma.webhookSubscription.update({
        where: { id: sub.id },
        data: { failingSince: new Date(Date.now() - 2 * 3_600_000) },
      });
      const test = await adminN!.post(`/webhooks/${failing.id}/test`, {});
      expect(test.status, JSON.stringify(test.body)).toBe(202);
      const { deliveryId } = test.body as { deliveryId: string };

      const disabled = await waitFor(
        'the subscription disabled by the worker',
        async () => {
          const res = await adminN!.get(`/webhooks/${failing!.id}`);
          const body = res.body as { status: string };
          return body.status === 'disabled' ? (res.body as Record<string, unknown>) : undefined;
        },
        { timeoutMs: 180_000, intervalMs: 1_000 },
      );
      expect(disabled).toMatchObject({ status: 'disabled', disabledReason: 'sustained_failure' });
      expect(disabled.consecutiveFailures as number).toBeGreaterThanOrEqual(5);

      const requests = await receivedRequests(failing.path);
      expect(requests.length).toBeGreaterThanOrEqual(5);
      for (const r of requests) {
        expect(r.signatureValid).toBe(true);
        expect(verifyReceived(r, [failing.secret])).toEqual({ ok: true });
        expect(r.eventType).toBe('webhook.ping');
        expect(r.envelope.organizationId).toBe(orgNPublicId);
      }
      const detail = await deliveryDetail(adminN!, failing.id, deliveryId);
      expect(detail.trigger).toBe('test');
      expect(detail.attempts.length).toBeGreaterThanOrEqual(5);
      for (const a of detail.attempts)
        expect([a.outcome, a.httpStatus]).toEqual(['http_error', 500]);

      const audit = await fx.prisma.auditLog.findFirst({
        where: { organizationId: orgN, action: 'webhook.auto_disabled', resourceId: failing.id },
      });
      expect(audit).toMatchObject({ actorType: 'system', resourceType: 'webhook' });
      expect(JSON.stringify(audit!.metadata)).not.toMatch(/receiver\.test|whsec_|:\/\//);

      const mail = await waitFor(
        'the webhook_disabled alert in notify-relay-sink',
        async () => ofKind(await relayMails(), 'webhook endpoint disabled')[0],
        { timeoutMs: 240_000, intervalMs: 2_000 },
      );
      expect(mail.subject).toBe('[Email Gateway] Security alert (high): webhook endpoint disabled');
      expect(mail.body).toContain(failing.id);
      expect(mail.body).toContain('sustained_failure');
      expect(alertBodyProblems(mail.body, ['receiver.test', failing.secret])).toEqual([]);
      await sleep(5_000);
      expect(ofKind(await relayMails(), 'webhook endpoint disabled')).toHaveLength(1);
      record('webhooks-notifications', {
        auto_disable: `${String(disabled.consecutiveFailures)} failures, ${requests.length} requests`,
      });
    });
  },
);
