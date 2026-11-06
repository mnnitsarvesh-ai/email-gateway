import { randomBytes } from 'node:crypto';
import { GetObjectTaggingCommand, HeadObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { urlClickedV1 } from '@email-gateway/event-contracts';
import { signToken, verifyToken } from '@email-gateway/url-security';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, type ApiSession } from './support/api-client';
import { waitFor } from './support/compose';
import { waitForMessage } from './support/deliveries';
import { stack } from './support/env';
import { waitForLifecycle } from './support/lifecycle';
import { clearSinkDomain, sinkFiles, waitForSinkMessage } from './support/mail-sink';
import { purgeDormantQueues } from './support/broker';
import { record } from './support/messaging-stack';
import { platformAdminSession, type PlatformAdminSession } from './support/platform-admin';
import { MAIL_SINK_HOST, organizationRef } from './support/routing';
import {
  engineResultsOf,
  messagePublicId,
  REQUIRED_ENGINES,
  scanStackGate,
  sendToMx,
  waitForRoundComplete,
} from './support/scan-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply } from './support/smtp-tools';
import {
  bodyOf,
  click,
  forgetChains,
  clickBaseUrl,
  clickEventsOf,
  clickServiceReady,
  clickTokensIn,
  currentTokenKey,
  linkMessage,
  messageUrlsOf,
  partContentTypes,
  plainMessage,
  purgeInspectionQueue,
  smimeSignedMessage,
  urlResultsOf,
  urlRewritesOf,
  urlTestReady,
} from './support/url-stack';

/**
 * The step 4.3 URL engine, rewriting and time-of-click end to end through the inbound Postfix
 * (docs/plan/steps/11-url-protection.md §9 "Stack", U1, U3, U11, U12, U14, U16, U20):
 * smtp-tools → postfix:25 → smtp-adapter (EML in MinIO) → email-worker MIME role (body objects)
 * → `parsed.v1` → `scan.spam`, `scan.attachment` and `scan.url` (the URL engine: extraction,
 * reputation through dns-sink, the guarded fetcher against url-test, the rewritten copy in
 * MinIO and the `url_rewrites` row) → round completion → dev pass-through (the rewritten copy of
 * the round, U20) → postfix-outbound → mail-sink; then the click-service on its published port.
 *
 * - A message with a clean link (a per-run host under `clean-site.test`), a shortener link, a
 *   link to an excluded domain (`www.clean-site.test`, tenant `rewrite.excludedDomains`) and a
 *   `mailto:`: `scanned` with a url final, rewritten (tagged S3 object whose SHA-256/size match
 *   the row), delivered to the sink with protected links (`URL_CLICK_BASE_URL/c/<token>` in the
 *   text and HTML parts), the excluded link and the mailto untouched, the MIME structure kept.
 * - Clicking the clean link → 302 to the original URL (stored server side) and an `allowed`
 *   event; adding the link's domain to the platform feed through the api, then clicking →
 *   403 block page with the reference id, a `blocked` click event row with
 *   `url.feed_malicious` and its `mail.url.clicked.v1` outbox row published by the relay; the
 *   indicator is removed again through the api.
 * - A tampered token → 404 (no event); a token signed in the test with the `.env` key and an
 *   expiry in the past → 410 and an `expired` event.
 * - A message without URLs → url final `skipped` (`url.none`), rewrite `skipped`/`no_urls`,
 *   delivered unchanged.
 * - An S/MIME-signed message → delivered unchanged (no click URL, the signed body
 *   byte-identical) with `skip_reason = signed_smime`.
 */
const gate = { ...(await scanStackGate()) };
if (!gate.skip) {
  const problems: string[] = [];
  if (!(await clickServiceReady())) problems.push('the click-service (apps profile) is not ready');
  if (!(await urlTestReady())) problems.push('url-test (smtp-test profile) is not running');
  if (problems.length > 0) {
    gate.problem = [gate.problem, ...problems].filter(Boolean).join('\n');
  }
}
const fx = new SmtpFixtures();
const run = randomBytes(4).toString('hex');
const CLEAN_HOST = `r${run}.clean-site.test`;
const CLEAN_URL = `http://${CLEAN_HOST}/landing`;
const SHORT_URL = 'http://short-link.test/s/clean';
const EXCLUDED_URL = 'http://www.clean-site.test/docs';
const MAILTO = 'mailto:help@clean-site.test';
let org = 0n;
let domain: FixtureDomain;
let tenant: ApiSession | undefined;
let platform: PlatformAdminSession | undefined;
const indicatorIds = new Set<string>();
const s3 = new S3Client({
  endpoint: stack.s3().endpoint,
  region: stack.s3().region,
  forcePathStyle: true,
  credentials: {
    accessKeyId: stack.s3().accessKeyId,
    secretAccessKey: stack.s3().secretAccessKey,
  },
});

beforeAll(async () => {
  assertStackReady(gate);
  org = await fx.organization('url-smtp');
  domain = await fx.domain(org, 'url-smtp');
  await fx.destinations(domain, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  tenant = await apiSession(fx.prisma, await organizationRef(fx, org), 'organization_admin');
  platform = await platformAdminSession(fx.prisma);
  // The tenant's URL settings before its first message (the engine reads them on first use).
  const saved = await tenant.put('/scan-settings/url', {
    expectedVersion: 0,
    settings: { rewrite: { excludedDomains: ['WWW.Clean-Site.test'] } },
  });
  expect(saved.status, JSON.stringify(saved.body)).toBe(200);
  expect(saved.body).toMatchObject({
    engine: 'url',
    effective: { rewrite: { excludedDomains: ['www.clean-site.test'] } },
  });
}, 180_000);

afterAll(async () => {
  if (gate.skip) return;
  for (const id of indicatorIds) {
    await platform
      ?.call('DELETE', `/platform/threat-indicators/${id}?reason=stack%20test%20cleanup`)
      .catch(() => undefined);
  }
  await platform?.remove();
  await tenant?.remove();
  if (domain) await clearSinkDomain(domain.name, 'all').catch(() => undefined);
  await fx.cleanup();
  await purgeDormantQueues();
  await purgeInspectionQueue();
  s3.destroy();
}, 180_000);

async function send(local: string, data: (rcpt: string) => string) {
  const rcpt = `${local}@${domain.name}`;
  const sent = await sendToMx({
    from: 'alice@clean.scan.test',
    to: [rcpt],
    helo: 'mx.clean.scan.test',
    data: data(rcpt),
  });
  expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
  const message = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });
  const round = await waitForRoundComplete(fx.prisma, message, 0, 180_000);
  const finals = (await engineResultsOf(fx.prisma, message)).filter((r) => r.isFinal);
  return { rcpt, message, round, finals, urlFinal: finals.find((r) => r.engine === 'url') };
}

type UrlEngineView = {
  engine: string;
  outcome: string | null;
  durationMs: number | null;
  urls?: {
    urlSeq: number;
    url: string;
    verdict: string;
    rewritten: boolean;
    clicks: { total: number; lastDecision: string | null };
  }[];
  rewrite?: { status: string; skipReason: string | null; linksRewritten: number } | null;
};

async function urlEngineView(publicId: string, predicate: (e: UrlEngineView) => boolean) {
  return waitFor(
    `GET /messages/${publicId}/scans with the url engine`,
    async () => {
      const res = await tenant!.get(`/messages/${publicId}/scans`);
      if (res.status !== 200) return undefined;
      const body = res.body as { data: { engines: UrlEngineView[] }[] };
      const engine = body.data[0]?.engines.find((e) => e.engine === 'url');
      return engine && predicate(engine) ? engine : undefined;
    },
    { timeoutMs: 30_000, intervalMs: 500 },
  );
}

const codes = (value: unknown): string[] => (Array.isArray(value) ? (value as string[]) : []);

describe.skipIf(gate.skip)(
  'url stack: engine, rewriting and time-of-click',
  { timeout: 300_000 },
  () => {
    it('scans, rewrites and delivers protected links; time-of-click allows, then blocks after a feed add', async () => {
      const built = linkMessage({
        from: 'alice@clean.scan.test',
        to: [`links@${domain.name}`],
        subject: 'URL stack: links',
        textLinks: [CLEAN_URL, SHORT_URL, EXCLUDED_URL],
        htmlLinks: [CLEAN_URL, SHORT_URL, EXCLUDED_URL, MAILTO],
      });
      await forgetChains([SHORT_URL]);
      const started = Date.now();
      const { rcpt, message, round, finals, urlFinal } = await send('links', () => built.text);
      expect(round).toMatchObject({ status: 'completed', requiredEngines: [...REQUIRED_ENGINES] });
      expect(round.scanVerdict).not.toBe('malicious');
      expect(finals.map((f) => f.engine).sort()).toEqual(['attachment', 'rspamd', 'url']);
      expect(urlFinal).toMatchObject({ errorCode: null });
      expect(urlFinal!.engineVersion).toMatch(/^url\/2;url-fetch\/1;/);
      expect(urlFinal!.settingsVersion).toMatch(/^url-map\/1;/);

      // message_urls: the three http(s) URLs (mailto ignored), seqs in extraction order.
      const urls = await messageUrlsOf(fx.prisma, message);
      expect(urls.map((u) => u.url).sort()).toEqual([CLEAN_URL, EXCLUDED_URL, SHORT_URL].sort());
      expect(urls.every((u) => u.organizationId === org)).toBe(true);
      const seqOf = (url: string) => urls.find((u) => u.url === url)!.urlSeq;
      const results = await urlResultsOf(fx.prisma, message);
      expect(results).toHaveLength(3);
      const resultOf = (url: string) => results.find((r) => r.urlSeq === seqOf(url))!;
      expect(resultOf(CLEAN_URL)).toMatchObject({ verdict: 'clean', rewritten: true });
      expect(codes(resultOf(CLEAN_URL).reasonCodes)).toEqual(['clean.no_findings']);
      // The shortener is resolved through the guard at scan time (clean final).
      expect(resultOf(SHORT_URL)).toMatchObject({
        fetchStatus: 'completed',
        finalUrl: 'http://clean-site.test/landing',
        rewritten: true,
      });
      expect(codes(resultOf(SHORT_URL).reasonCodes)).toContain('url.shortened');
      expect(resultOf(EXCLUDED_URL)).toMatchObject({ rewritten: false });

      // The rewritten copy: url_rewrites row + tagged MinIO object; the original is untouched.
      const [rewrite, ...moreRewrites] = await urlRewritesOf(fx.prisma, message);
      expect(moreRewrites).toEqual([]);
      expect(rewrite).toMatchObject({
        organizationId: org,
        scanId: round.id,
        lifecycleRound: 0,
        status: 'rewritten',
        skipReason: null,
        dkimSigned: false,
        tokenKid: currentTokenKey().id,
      });
      expect(rewrite!.linksRewritten).toBeGreaterThanOrEqual(4); // 2 text + 2 html
      expect(rewrite!.partsRewritten).toBe(2);
      expect(rewrite!.objectKey).toMatch(
        new RegExp(
          `^org/${org.toString()}/rewrite/\\d{4}/\\d{2}/\\d{2}/${message.id.toString()}/r0-`,
        ),
      );
      const head = await s3.send(
        new HeadObjectCommand({ Bucket: stack.s3().mailBucket, Key: rewrite!.objectKey! }),
      );
      expect(head.ContentLength).toBe(rewrite!.objectSizeBytes);
      expect(head.ContentType).toBe('message/rfc822');
      const tags = await s3.send(
        new GetObjectTaggingCommand({ Bucket: stack.s3().mailBucket, Key: rewrite!.objectKey! }),
      );
      expect(tags.TagSet).toEqual(expect.arrayContaining([{ Key: 'eg-object', Value: 'rewrite' }]));

      // Delivered (dev pass-through approved the rewritten copy, U20) with protected links.
      await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete', 180_000);
      const [approval] = (
        await fx.prisma.messageOutbox.findMany({
          where: { organizationId: org, eventType: 'mail.delivery.approved.v1' },
          select: { payload: true },
        })
      ).filter((a) => (a.payload as { messageId?: string }).messageId === message.id.toString());
      expect((approval!.payload as { emlS3Key: string }).emlS3Key).toBe(rewrite!.objectKey);
      const delivered = (await waitForSinkMessage(rcpt)).toString('utf8');
      const body = bodyOf(delivered);
      const tokens = clickTokensIn(body);
      expect(tokens.length).toBe(rewrite!.linksRewritten);
      expect(body).not.toContain(CLEAN_URL);
      expect(body).not.toContain(SHORT_URL);
      expect(body).toContain(EXCLUDED_URL); // excluded domain, never rewritten
      expect(body).toContain(`href="${MAILTO}"`); // mailto untouched
      expect(body).toContain(`href="${clickBaseUrl()}/c/`);
      // The MIME structure is kept: same boundary, the two parts in order, 7bit kept.
      expect(delivered).toContain(`boundary="${built.boundary}"`);
      expect(partContentTypes(body, built.boundary)).toEqual(['text/plain', 'text/html']);
      expect(body.match(/Content-Transfer-Encoding: 7bit/g)).toHaveLength(2);
      expect(delivered).toContain(`Message-ID: ${built.messageId}`);

      // Every token verifies with the .env key and names this message and one of its seqs.
      const key = currentTokenKey();
      const claims = tokens.map((t) => verifyToken(t, { current: key }));
      for (const c of claims) {
        expect(c.outcome).toBe('ok');
        expect(c).toMatchObject({
          claims: {
            organizationId: org,
            messageId: message.id,
            receivedAtMs: message.receivedAt.getTime(),
          },
        });
      }
      const cleanToken = tokens.find(
        (_t, i) => (claims[i] as { claims: { urlSeq: number } }).claims.urlSeq === seqOf(CLEAN_URL),
      )!;
      expect(cleanToken).toBeDefined();

      // Time of click: the clean link redirects to the stored URL.
      const allowed = await click(`/c/${cleanToken}`);
      expect(allowed.status).toBe(302);
      expect(allowed.location).toBe(CLEAN_URL);
      expect(allowed.headers.get('cache-control')).toBe('no-store');
      expect(allowed.headers.get('referrer-policy')).toBe('no-referrer');
      await waitFor(
        'the allowed click event',
        async () => (await clickEventsOf(fx.prisma, message)).some((e) => e.decision === 'allowed'),
        { timeoutMs: 15_000, intervalMs: 250 },
      );

      // The analyst adds the link's domain to the platform feed through the api (effective at once).
      const added = await platform!.call('POST', '/platform/threat-indicators', {
        type: 'domain',
        value: CLEAN_HOST.toUpperCase(),
        severity: 'high',
        category: 'phishing',
        reason: 'stack test: time-of-click block',
      });
      expect(added.status, JSON.stringify(added.body)).toBe(201);
      indicatorIds.add(added.body.id as string);
      expect(added.body).toMatchObject({ value: CLEAN_HOST, source: 'analyst' });
      const blocked = await click(`/c/${cleanToken}`);
      expect(blocked.status).toBe(403);
      expect(blocked.location).toBeNull();
      const event = await waitFor(
        'the blocked click event',
        async () => (await clickEventsOf(fx.prisma, message)).find((e) => e.decision === 'blocked'),
        { timeoutMs: 15_000, intervalMs: 250 },
      );
      expect(event).toMatchObject({
        organizationId: org,
        urlSeq: seqOf(CLEAN_URL),
        verdict: 'malicious',
        tokenKid: key.id,
      });
      expect(codes(event.reasonCodes)).toContain('url.feed_malicious');
      expect(blocked.body).toContain(event.publicId); // the reference id on the block page
      expect(blocked.body).not.toContain(CLEAN_HOST);
      expect(blocked.body).not.toContain(domain.name);
      // The click event's outbox row, published by the relay (no URL, no IP in the payload).
      const outbox = await waitFor(
        'the mail.url.clicked.v1 outbox row to be published',
        async () => {
          // The outbox event id is its own UUIDv7; the payload's clickId is the public id.
          const rows = await fx.prisma.messageOutbox.findMany({
            where: { organizationId: org, eventType: 'mail.url.clicked.v1' },
          });
          const row = rows.find(
            (r) => (r.payload as { clickId?: string }).clickId === event.publicId,
          );
          return row?.publishedAt ? row : undefined;
        },
        { timeoutMs: 60_000, intervalMs: 500 },
      );
      expect(outbox).toMatchObject({
        aggregateType: 'message',
        aggregateId: message.id.toString(),
      });
      const clicked = urlClickedV1.parse(outbox.payload);
      expect(clicked).toMatchObject({
        clickId: event.publicId,
        messageId: message.id.toString(),
        urlSeq: seqOf(CLEAN_URL),
        decision: 'blocked',
        verdict: 'malicious',
      });
      expect(JSON.stringify(outbox.payload)).not.toContain(CLEAN_HOST);

      // The analyst removes the indicator (before-image audited); the click is allowed again.
      const removed = await platform!.call(
        'DELETE',
        `/platform/threat-indicators/${added.body.id as string}?reason=stack%20test`,
      );
      expect(removed.status).toBe(204);
      indicatorIds.delete(added.body.id as string);
      const audit = await fx.prisma.auditLog.findFirst({
        where: { action: 'threat_indicator.removed', resourceId: added.body.id as string },
      });
      expect(audit?.metadata).toMatchObject({ before: { value: CLEAN_HOST, severity: 'high' } });
      expect((await click(`/c/${cleanToken}`)).status).toBe(302);

      // The scans read API shows the URLs, the rewrite and the click summary (no durations).
      const view = await urlEngineView(await messagePublicId(fx.prisma, message), (e) =>
        (e.urls ?? []).some((u) => u.clicks.total >= 3),
      );
      expect(view.durationMs).toBeNull();
      expect(view.rewrite).toMatchObject({ status: 'rewritten', skipReason: null });
      expect(view.urls!.find((u) => u.url === CLEAN_URL)).toMatchObject({
        verdict: 'clean',
        rewritten: true,
        clicks: { total: 3, lastDecision: 'allowed' },
      });
      expect(JSON.stringify(view)).not.toMatch(/"cache"|fetchCache/);
      record('url-smtp', {
        links_round_verdict: round.scanVerdict,
        links_url_outcome: urlFinal!.outcome,
        links_rewritten: rewrite!.linksRewritten,
        links_unmapped: rewrite!.linksUnmapped,
        smtp_to_delivered_ms: Date.now() - started,
        click_allowed: allowed.status,
        click_blocked: blocked.status,
      });
    });

    it('a tampered token is 404 without an event; an expired token is 410 and logged', async () => {
      const message = await fx.prisma.emailMessage.findFirstOrThrow({
        where: { organizationId: org },
        orderBy: { receivedAt: 'asc' },
        select: { id: true, receivedAt: true },
      });
      const [url] = await messageUrlsOf(fx.prisma, message);
      const key = currentTokenKey();
      const valid = signToken(
        {
          organizationId: org,
          messageId: message.id,
          receivedAtMs: message.receivedAt.getTime(),
          urlSeq: url!.urlSeq,
          expiresAt: Math.floor(Date.now() / 1000) + 3_600,
        },
        key,
      );
      const before = (await clickEventsOf(fx.prisma, message)).length;
      const flip = (token: string, at: number) =>
        token.slice(0, at) + (token[at] === 'A' ? 'B' : 'A') + token.slice(at + 1);
      for (const tampered of [
        flip(valid, 20),
        flip(valid, 50),
        valid.slice(0, 61),
        'not-a-token',
      ]) {
        const res = await click(`/c/${tampered}`);
        expect(res.status, tampered.length.toString()).toBe(404);
        expect(res.location).toBeNull();
      }
      expect((await clickEventsOf(fx.prisma, message)).length).toBe(before);

      const expired = signToken(
        {
          organizationId: org,
          messageId: message.id,
          receivedAtMs: message.receivedAt.getTime(),
          urlSeq: url!.urlSeq,
          expiresAt: Math.floor(Date.now() / 1000) - 60,
        },
        key,
      );
      const gone = await click(`/c/${expired}`);
      expect(gone.status).toBe(410);
      expect(gone.location).toBeNull();
      const event = await waitFor(
        'the expired click event',
        async () => (await clickEventsOf(fx.prisma, message)).find((e) => e.decision === 'expired'),
        { timeoutMs: 15_000, intervalMs: 250 },
      );
      expect(event).toMatchObject({ organizationId: org, urlSeq: url!.urlSeq, verdict: null });
    });

    it('a message without URLs: url engine skipped (url.none), rewrite skipped (no_urls), delivered unchanged', async () => {
      const built = plainMessage({
        from: 'alice@clean.scan.test',
        to: [`nourls@${domain.name}`],
        subject: 'URL stack: no URLs',
        body: 'Plain words only, no links at all.',
      });
      const { rcpt, message, round, urlFinal } = await send('nourls', () => built.text);
      expect(round).toMatchObject({ status: 'completed', requiredEngines: [...REQUIRED_ENGINES] });
      expect(urlFinal).toMatchObject({ outcome: 'skipped', attempt: 1, reasonCodes: ['url.none'] });
      expect(await messageUrlsOf(fx.prisma, message)).toEqual([]);
      const [rewrite] = await urlRewritesOf(fx.prisma, message);
      expect(rewrite).toMatchObject({ status: 'skipped', skipReason: 'no_urls', objectKey: null });
      await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete', 180_000);
      const delivered = (await waitForSinkMessage(rcpt)).toString('utf8');
      // The sink's Maildir file ends with one more newline than the SMTP data (local delivery).
      expect(bodyOf(delivered).trimEnd()).toBe(bodyOf(built.text).trimEnd());
      expect(await sinkFiles(rcpt)).toHaveLength(1);
      const view = await urlEngineView(
        await messagePublicId(fx.prisma, message),
        (e) => e.rewrite !== null && e.rewrite !== undefined,
      );
      expect(view).toMatchObject({
        outcome: 'skipped',
        urls: [],
        rewrite: { status: 'skipped', skipReason: 'no_urls' },
      });
    });

    it('an S/MIME-signed message is delivered unchanged with skip_reason signed_smime', async () => {
      const built = smimeSignedMessage({
        from: 'alice@clean.scan.test',
        to: [`signed@${domain.name}`],
        subject: 'URL stack: S/MIME signed',
        link: CLEAN_URL,
      });
      const { rcpt, message, round, urlFinal } = await send('signed', () => built.text);
      expect(round.status).toBe('completed');
      expect(urlFinal).toMatchObject({ errorCode: null });
      expect((await messageUrlsOf(fx.prisma, message)).map((u) => u.url)).toEqual([CLEAN_URL]);
      const [rewrite] = await urlRewritesOf(fx.prisma, message);
      expect(rewrite).toMatchObject({
        status: 'skipped',
        skipReason: 'signed_smime',
        objectKey: null,
      });
      const [result] = await urlResultsOf(fx.prisma, message);
      expect(result).toMatchObject({ rewritten: false });
      await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete', 180_000);
      const delivered = (await waitForSinkMessage(rcpt)).toString('utf8');
      expect(clickTokensIn(delivered)).toEqual([]);
      // The signed structure is byte-identical (a changed byte would break the signature).
      expect(
        bodyOf(delivered).trimEnd().endsWith(built.signedBody.replace(/\r\n/g, '\n').trimEnd()),
      ).toBe(true);
      expect(delivered).toContain(`Link: ${CLEAN_URL}`);
    });
  },
);
