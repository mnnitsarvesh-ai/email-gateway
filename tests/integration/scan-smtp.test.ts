import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { purgeDormantQueues } from './support/broker';
import { waitForMessage } from './support/deliveries';
import { record } from './support/messaging-stack';
import { MAIL_SINK_HOST, sleep } from './support/routing';
import { composeExec } from './support/compose';
import {
  corpusEml,
  ensureRspamdRunning,
  gatewayAuthservId,
  headerFieldsOf,
  scanStackGate,
  sendToMx,
  stopRspamd,
  waitForRoundComplete,
  withLeadingHeaders,
} from './support/scan-stack';
import { sha256, SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply } from './support/smtp-tools';
import { clearSinkDomain } from './support/mail-sink';

/**
 * Rspamd at SMTP time through the inbound Postfix (docs/plan/steps/09-rspamd.md S11, ADR-0027,
 * §9 "Stack"): smtp-tools → postfix:25 → milter inet:rspamd:11332 (proxy worker, self_scan).
 *
 * - The GTUBE pattern is rejected in-session with `554 5.7.1` and nothing is stored (no
 *   `email_messages` row, no S3 object): the milter's reject happens at end of DATA, before
 *   Postfix queues the message or hands it to the smtp-adapter over LMTP.
 * - Headers that could forge our results are removed and ours is added: a sender's
 *   `Authentication-Results` carrying OUR authserv-id (Postfix `myhostname`) and every
 *   `X-Spam*` / `X-Spamd-*` / `X-Rspamd-*` header are gone from the stored EML in MinIO, a
 *   foreign `Authentication-Results` is kept unchanged, and exactly one `Authentication-Results`
 *   with our authserv-id (SPF/DKIM/DMARC of the real check) is present. No score header is added.
 * - The same forged headers are removed when Rspamd is DOWN (the milter fails open,
 *   `milter_default_action = accept`): Postfix cleanup's `header_checks` strip them before the
 *   message is queued, independently of the milter (ADR-0027 decision 3). No
 *   `Authentication-Results` with our authserv-id is stored at all then; the post-queue scan
 *   produces the authentication results of record once Rspamd is back.
 * - The trusted envelope of the post-queue scan: `client_ip`, `client_helo` and `client_name`
 *   come from Postfix XFORWARD (WP1 S3: XFORWARD sends `[UNAVAILABLE]` or a name, never
 *   `[TEMPUNAVAIL]`).
 */
const gate = await scanStackGate();
const fx = new SmtpFixtures();
let org = 0n;
let domain: FixtureDomain;
let authservId = '';

beforeAll(async () => {
  assertStackReady(gate);
  org = await fx.organization('scan-smtp');
  domain = await fx.domain(org, 'scan-smtp');
  await fx.destinations(domain, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  authservId = await gatewayAuthservId();
}, 60_000);

afterAll(async () => {
  if (gate.skip) return;
  await ensureRspamdRunning().catch(() => undefined);
  if (domain) await clearSinkDomain(domain.name).catch(() => undefined);
  await fx.cleanup();
  await purgeDormantQueues();
}, 120_000);

describe.skipIf(gate.skip)('scan stack: Rspamd milter at SMTP time', { timeout: 180_000 }, () => {
  it('rejects the GTUBE pattern in-session with 554 5.7.1 and stores nothing', async () => {
    const rcpt = `gtube@${domain.name}`;
    const sent = await sendToMx({
      from: 'tester@spam-sender.scan.test',
      to: [rcpt],
      helo: 'mail.spam-sender.scan.test',
      data: corpusEml('spam/gtube.eml'),
    });
    expect(reply(sent, 'RCPT#0').code, sent.transcript).toBe(250);
    const end = reply(sent, 'DATA-END');
    expect(end.code, sent.transcript).toBe(554);
    expect(end.text).toMatch(/^554 5\.7\.1 /);
    expect(sent.queueId).toBeUndefined();
    // Nothing reached the smtp-adapter: no message row, no EML object, no outbox row.
    await sleep(5_000);
    expect(await fx.messageCount(org)).toBe(0);
    expect(await fx.emlObjectKeys(org)).toEqual([]);
    expect(await fx.prisma.messageOutbox.count({ where: { organizationId: org } })).toBe(0);
    record('scan-smtp', { gtube_reply: JSON.stringify(end.text) });
  });

  const forgedHeaders = () => [
    // Our authserv-id: a forgery of our own result (must be removed).
    `Authentication-Results: ${authservId}; spf=pass smtp.mailfrom=clean.scan.test; dkim=pass header.d=clean.scan.test; dmarc=pass (forged-by-sender)`,
    // The same with an RFC 8601 comment before the authserv-id and different case.
    `Authentication-Results: (forged) ${authservId.toUpperCase()};\r\n\tdmarc=pass (forged-by-sender)`,
    // A foreign authserv-id: an earlier hop's result (kept unchanged, never trusted).
    'Authentication-Results: relay.origin.example; spf=pass smtp.mailfrom=origin.example',
    'X-Spam-Flag: NO',
    'X-Spam-Status: No, score=-100.0',
    'X-Spamd-Result: default: False [-50.00 / 15.00]',
    'X-Rspamd-Score: -50.00',
    'X-Rspamd-Action: no action',
  ];
  const foreignResult = {
    name: 'Authentication-Results',
    value: 'relay.origin.example; spf=pass smtp.mailfrom=origin.example',
  };

  it('renders the cleanup header_checks with our authserv-id (independent of the milter)', async () => {
    const probe = async (header: string) => {
      const r = await composeExec('postfix', [
        'postmap',
        '-q',
        header,
        'regexp:/etc/postfix/header_checks',
      ]);
      return r.exitCode === 0 ? r.stdout.trim() : null;
    };
    expect(await probe(`Authentication-Results: ${authservId}; dmarc=pass`)).toBe('IGNORE');
    expect(await probe(`Authentication-Results: (c) ${authservId.toUpperCase()};x`)).toBe('IGNORE');
    expect(await probe(`Authentication-Results: ${authservId}.evil.test; dmarc=pass`)).toBeNull();
    expect(await probe('Authentication-Results: relay.origin.example; spf=pass')).toBeNull();
    expect(await probe('X-Spam-Flag: NO')).toBe('IGNORE');
    expect(await probe('X-Spamd-Result: default')).toBe('IGNORE');
    expect(await probe('X-Rspamd-Score: -50')).toBe('IGNORE');
    expect(await probe('X-Mailer: test')).toBeNull();
  });

  it('removes forged Authentication-Results and X-Spam*/X-Rspamd* headers and adds ours', async () => {
    const rcpt = `headers@${domain.name}`;
    const forged = forgedHeaders();
    // The DKIM signature of the clean fixture does not cover these fields, so it stays valid.
    const sent = await sendToMx({
      from: 'alice@clean.scan.test',
      to: [rcpt],
      helo: 'mx.clean.scan.test',
      data: withLeadingHeaders(corpusEml('clean/clean-dkim-aligned.eml'), forged),
    });
    expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
    const message = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });

    const eml = (await fx.object(message.emlObjectKey)).toString('utf8');
    expect(sha256(Buffer.from(eml, 'utf8'))).toBe(message.emlSha256);
    const fields = headerFieldsOf(eml);
    const ar = fields.filter((f) => f.name.toLowerCase() === 'authentication-results');
    const ours = ar.filter((f) => f.value.toLowerCase().startsWith(`${authservId.toLowerCase()};`));
    expect(ours, JSON.stringify(ar)).toHaveLength(1);
    expect(ours[0]!.value).not.toContain('forged-by-sender');
    // The real result of the milter's check (smtp-tools is in clean.scan.test's SPF).
    expect(ours[0]!.value).toMatch(/spf=pass/);
    expect(ours[0]!.value).toMatch(/dkim=pass/);
    expect(ours[0]!.value).toMatch(/dmarc=pass/);
    expect(ar.filter((f) => f.value.startsWith('relay.origin.example;'))).toEqual([foreignResult]);
    expect(ar.some((f) => f.value.includes('forged-by-sender'))).toBe(false);
    const spamHeaders = fields.filter((f) => /^x-(spam|spamd-|rspamd-)/i.test(f.name));
    expect(spamHeaders).toEqual([]);

    // The trusted envelope recorded by smtp-adapter from Postfix XFORWARD (WP1 S3).
    expect(message.clientHelo).toBe('mx.clean.scan.test');
    expect(message.clientIp).toMatch(/^172\.31\.250\.\d{1,3}$/);
    expect(message.clientName).not.toBe('[TEMPUNAVAIL]');
    expect(message.clientName).not.toBe('[UNAVAILABLE]');
    if (message.clientName !== null) {
      expect(message.clientName).toMatch(/^[a-z0-9._-]+$/);
    }

    // The post-queue scan of the same message: our own SPF/DKIM/DMARC, not the sender's header.
    const round = await waitForRoundComplete(fx.prisma, message, 0);
    expect(round.status).toBe('completed');
    const auth = await fx.prisma.emailAuthResult.findFirstOrThrow({
      where: { scanId: round.id, receivedAt: round.receivedAt },
    });
    expect(auth).toMatchObject({ spf: 'pass', dkim: 'pass', dmarc: 'pass' });
    record('scan-smtp', {
      authserv_id: authservId,
      authentication_results_stored: ar.length,
      client_name: message.clientName ?? 'NULL',
    });
  });

  it('removes the forged headers when Rspamd is down and the milter fails open', async () => {
    const rcpt = `headers-down@${domain.name}`;
    await stopRspamd();
    let message;
    try {
      const sent = await sendToMx({
        from: 'alice@clean.scan.test',
        to: [rcpt],
        helo: 'mx.clean.scan.test',
        data: withLeadingHeaders(corpusEml('clean/clean-dkim-aligned.eml'), forgedHeaders()),
      });
      // milter_default_action = accept: no tempfail while the milter is unreachable.
      expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
      message = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });
    } finally {
      await ensureRspamdRunning();
    }

    const eml = (await fx.object(message.emlObjectKey)).toString('utf8');
    const fields = headerFieldsOf(eml);
    const ar = fields.filter((f) => f.name.toLowerCase() === 'authentication-results');
    // Nothing with our authserv-id (forged ones stripped by cleanup; the milter added none).
    expect(ar, JSON.stringify(ar)).toEqual([foreignResult]);
    expect(eml).not.toContain('forged-by-sender');
    expect(fields.filter((f) => /^x-(spam|spamd-|rspamd-)/i.test(f.name))).toEqual([]);

    // Once Rspamd is back the post-queue scan records the authentication results of record.
    const round = await waitForRoundComplete(fx.prisma, message, 0, 240_000);
    expect(round.status).toBe('completed');
    const auth = await fx.prisma.emailAuthResult.findFirstOrThrow({
      where: { scanId: round.id, receivedAt: round.receivedAt },
    });
    expect(auth).toMatchObject({ spf: 'pass', dkim: 'pass', dmarc: 'pass' });
    record('scan-smtp', { rspamd_down_authentication_results_stored: ar.length });
  }, 420_000);
});
