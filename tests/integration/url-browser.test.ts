import { urlInspectionRequestedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ManagementApi, purgeDormantQueues } from './support/broker';
import { compose, waitFor } from './support/compose';
import { waitForMessage } from './support/deliveries';
import { stack } from './support/env';
import { clearSinkDomain } from './support/mail-sink';
import { record } from './support/messaging-stack';
import { MAIL_SINK_HOST } from './support/routing';
import { scanStackGate, sendToMx, waitForRoundComplete } from './support/scan-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply } from './support/smtp-tools';
import {
  click,
  clickServiceReady,
  clickTokensIn,
  forgetChains,
  linkMessage,
  messageUrlsOf,
  urlResultsOf,
  urlTestReady,
} from './support/url-stack';
import { waitForSinkMessage } from './support/mail-sink';
import { waitForLifecycle } from './support/lifecycle';

/**
 * Focused suite of the step 4.3 dynamic inspection THROUGH THE PIPELINE (docs/plan/steps/
 * 11-url-protection.md §9, U15; profile `url-browser`, never with analytics/observability): a
 * message whose link is `suspicious` at scan time makes the URL engine write a `pending`
 * `url_dynamic_inspections` row and its `mail.url.inspection_requested.v1` (outbox → relay →
 * `scan.url.inspect`); the isolated `url-browser-worker` (real Chromium through `url-egress-proxy`)
 * publishes `mail.url.inspection_completed.v1` (confirms) to `scan.url.results`, where the
 * email-worker's results consumer completes the row with the signals and the dynamic verdict; a
 * click then uses it (warn page).
 *
 * The link `http://probe@phish-login.test/` is a scan-time fetch candidate (userinfo, S7); its
 * landing page has a password form posting to `collector-site.test` (S8). The browser receives
 * the URL without userinfo (U5 identity form).
 *
 * Skipped (with the reason) unless the `url-browser` profile runs (`docker compose --profile
 * smtp-test --profile url-browser up -d --no-deps url-egress-proxy url-browser-worker`); not part
 * of the default chain. The worker's own container suite is
 * `pnpm --filter @email-gateway/url-browser-worker test:integration` (docs/runbooks/
 * url-browser-worker.md).
 */
async function browserRunning(): Promise<boolean> {
  const ps = await compose(['ps', '--status', 'running', '--quiet', 'url-browser-worker'], {
    timeoutMs: 20_000,
  });
  if (!ps.stdout.trim()) return false;
  try {
    const queue = await new ManagementApi().queue(stack.rabbitmqVhost(), 'scan.url.inspect');
    return queue.consumers >= 1;
  } catch {
    return false;
  }
}

const base = await scanStackGate();
const profileUp = !base.skip && (await browserRunning());
const gate = { ...base };
if (!base.skip) {
  const problems: string[] = [];
  if (!(await clickServiceReady())) problems.push('the click-service is not ready');
  if (!(await urlTestReady())) problems.push('url-test (smtp-test profile) is not running');
  if (problems.length > 0) gate.problem = [gate.problem, ...problems].filter(Boolean).join('\n');
}
const fx = new SmtpFixtures();
let org = 0n;
let domain: FixtureDomain;
const LINK = 'http://probe@phish-login.test/';
const INSPECTED = 'http://phish-login.test/';

beforeAll(async () => {
  if (!profileUp) return;
  assertStackReady(gate);
  org = await fx.organization('url-browser');
  domain = await fx.domain(org, 'url-browser');
  await fx.destinations(domain, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
}, 120_000);

afterAll(async () => {
  if (!profileUp) return;
  if (domain) await clearSinkDomain(domain.name, 'all').catch(() => undefined);
  await fx.cleanup();
  await purgeDormantQueues();
}, 120_000);

describe.skipIf(base.skip || !profileUp)(
  'url stack: dynamic inspection through the pipeline (profile url-browser)',
  { timeout: 300_000 },
  () => {
    it('a suspicious link is inspected by the isolated browser and the result is used at click time', async () => {
      await forgetChains([LINK]);
      const rcpt = `phish@${domain.name}`;
      const built = linkMessage({
        from: 'alice@clean.scan.test',
        to: [rcpt],
        subject: 'URL browser stack: credential form',
        textLinks: [],
        htmlLinks: [LINK],
      });
      const sent = await sendToMx({
        from: 'alice@clean.scan.test',
        to: [rcpt],
        helo: 'mx.clean.scan.test',
        data: built.text,
      });
      expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
      const message = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });
      const round = await waitForRoundComplete(fx.prisma, message, 0, 180_000);
      expect(round.status).toBe('completed');
      const [url] = await messageUrlsOf(fx.prisma, message);
      expect(url).toMatchObject({ url: INSPECTED, host: 'phish-login.test' });
      expect(url!.flags).toEqual(expect.arrayContaining(['url.userinfo']));
      const [result] = await urlResultsOf(fx.prisma, message);
      expect(['suspicious', 'unknown']).toContain(result!.verdict);
      expect(result).toMatchObject({ dynamicRequested: true });

      // The request: a pending row and its outbox event (the only event that carries a URL).
      const inspection = await fx.prisma.urlDynamicInspection.findFirstOrThrow({
        where: { messageId: message.id, receivedAt: message.receivedAt },
      });
      const outbox = await fx.prisma.messageOutbox.findFirstOrThrow({
        where: { organizationId: org, eventId: inspection.requestedEventId },
      });
      expect(urlInspectionRequestedV1.parse(outbox.payload)).toMatchObject({
        inspectionId: inspection.id.toString(),
        url: INSPECTED,
        urlSeq: url!.urlSeq,
      });

      // The browser worker inspects it; the results consumer completes the row.
      const completed = await waitFor(
        'the dynamic inspection to complete',
        async () => {
          const row = await fx.prisma.urlDynamicInspection.findUniqueOrThrow({
            where: { id_receivedAt: { id: inspection.id, receivedAt: inspection.receivedAt } },
          });
          return row.status === 'pending' ? undefined : row;
        },
        { timeoutMs: 120_000, intervalMs: 1_000 },
      );
      expect(completed.status).toBe('completed');
      expect(completed.workerVersion).toMatch(/\S/);
      const signals = completed.signals as {
        passwordFields: number;
        crossOriginFormAction: boolean;
        formActionHosts: string[];
      };
      expect(signals.passwordFields).toBeGreaterThanOrEqual(1);
      expect(signals.crossOriginFormAction).toBe(true);
      expect(signals.formActionHosts).toContain('collector-site.test');
      expect(['suspicious', 'malicious']).toContain(completed.verdict);
      expect(completed.finalHost).toBe('phish-login.test');
      // No page content stored: signals are counts, booleans, hosts and brand ids only.
      expect(JSON.stringify(completed.signals)).not.toMatch(/Sign in|<form|password"/);

      // Delivered with the protected link; the click uses the dynamic result (never allowed).
      await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete', 180_000);
      const [token] = clickTokensIn((await waitForSinkMessage(rcpt)).toString('utf8'));
      const res = await click(`/c/${token}`);
      expect([200, 403]).toContain(res.status);
      expect(res.location).toBeNull();
      const event = await waitFor(
        'the click event',
        async () =>
          (
            await fx.prisma.urlClickEvent.findMany({
              where: { messageId: message.id, messageReceivedAt: message.receivedAt },
            })
          ).at(0),
        { timeoutMs: 15_000, intervalMs: 250 },
      );
      expect(['warned', 'blocked']).toContain(event.decision);
      expect((event.recheck as { dynamic?: string } | null)?.dynamic).toBe('used');
      record('url-browser', {
        scan_verdict: result!.verdict,
        dynamic_status: completed.status,
        dynamic_verdict: completed.verdict,
        dynamic_codes: JSON.stringify(completed.reasonCodes),
        click_decision: event.decision,
      });
    });
  },
);
