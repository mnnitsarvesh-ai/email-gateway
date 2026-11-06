import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { purgeDormantQueues } from './support/broker';
import { waitForMessage } from './support/deliveries';
import { clearSinkDomain } from './support/mail-sink';
import { record } from './support/messaging-stack';
import { metricValue } from './support/metrics';
import { MAIL_SINK_HOST } from './support/routing';
import {
  engineResultsOf,
  REQUIRED_ENGINES,
  scanStackGate,
  sendToMx,
  waitForRoundComplete,
} from './support/scan-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply } from './support/smtp-tools';
import {
  forgetChains,
  linkMessage,
  messageUrlsOf,
  purgeInspectionQueue,
  resetRebind,
  urlResultsOf,
  urlTestReady,
} from './support/url-stack';

/**
 * The step 4.3 SSRF guard at scan time through the inbound Postfix and the live email-worker
 * container (docs/plan/steps/11-url-protection.md §9 "Stack", U8, U10 S5, U19): links whose
 * redirects lead to internal addresses, and DNS-rebinding names, end with
 * `url.redirect_blocked_internal` and no connection to the internal target.
 *
 * The links are scan-time fetch candidates under the default `scanTimeFetch=suspicious`: the
 * fake shortener `short-link.test` (always fetched, U9) and links with a static risk signal
 * (userinfo, S7) to `redirect-chain.test/to/<case>`. The email-worker runs in direct egress mode
 * (in-process guard, restricted resolver on dns-sink).
 *
 * "No connection" is shown by the fetch result itself: every refused hop is recorded with its
 * guard reason (`blocked`, `fetch_status = blocked`), never as `connection_error`/`timeout`
 * (which a dial to 127.0.0.1:80 or 169.254.169.254 inside the container would produce), and the
 * email-worker's `url_fetch_blocked_total{component="engine"}` grows by the refused hops. url-test
 * keeps no access log; for DNS rebinding, `public first` proves the connection went to the
 * validated public address (the page was fetched) while `private first` is refused before any
 * connection.
 */
const gate = { ...(await scanStackGate()) };
if (!gate.skip && !(await urlTestReady())) {
  gate.problem = [gate.problem, 'url-test (smtp-test profile) is not running']
    .filter(Boolean)
    .join('\n');
}
const fx = new SmtpFixtures();
let org = 0n;
let domain: FixtureDomain;

beforeAll(async () => {
  assertStackReady(gate);
  org = await fx.organization('url-ssrf');
  domain = await fx.domain(org, 'url-ssrf');
  await fx.destinations(domain, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
}, 120_000);

afterAll(async () => {
  if (gate.skip) return;
  if (domain) await clearSinkDomain(domain.name, 'all').catch(() => undefined);
  await fx.cleanup();
  await purgeDormantQueues();
  await purgeInspectionQueue();
  await resetRebind('public').catch(() => undefined);
}, 120_000);

async function scan(local: string, links: readonly string[]) {
  // Fetch again (never a chain cached by an earlier run): the suite asserts the fetch itself.
  await forgetChains(links);
  const rcpt = `${local}@${domain.name}`;
  const built = linkMessage({
    from: 'alice@clean.scan.test',
    to: [rcpt],
    subject: `URL SSRF stack: ${local}`,
    textLinks: links,
    htmlLinks: [],
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
  expect(round).toMatchObject({ status: 'completed', requiredEngines: [...REQUIRED_ENGINES] });
  const urlFinal = (await engineResultsOf(fx.prisma, message)).find(
    (r) => r.engine === 'url' && r.isFinal,
  );
  expect(urlFinal).toMatchObject({ errorCode: null });
  expect(await messageUrlsOf(fx.prisma, message)).toHaveLength(links.length);
  const results = await urlResultsOf(fx.prisma, message);
  return { message, round, urlFinal: urlFinal!, results };
}

type Hop = { host: string; status: number | null; kind: string; blocked: string | null };
const chainOf = (value: unknown): Hop[] => (Array.isArray(value) ? (value as Hop[]) : []);
const codes = (value: unknown): string[] => (Array.isArray(value) ? (value as string[]) : []);
const blockedTotal = () =>
  metricValue('email-worker', 'url_fetch_blocked_total', { component: 'engine' });

describe.skipIf(gate.skip)('url stack: SSRF guard at scan time', { timeout: 300_000 }, () => {
  it('redirects to loopback, metadata and encoded internal forms are refused before connecting', async () => {
    const links = {
      internal: 'http://short-link.test/s/internal', // → http://127.0.0.1/
      metadata: 'http://short-link.test/s/metadata', // → http://169.254.169.254/latest/meta-data/
      decimal: 'http://probe@redirect-chain.test/to/decimal', // → http://2130706433/
      mapped: 'http://probe@redirect-chain.test/to/v6-mapped', // → http://[::ffff:127.0.0.1]/
      metadataName: 'http://probe@redirect-chain.test/to/metadata-name', // → metadata.google.internal
      private10: 'http://probe@redirect-chain.test/to/private-10', // → http://10.0.0.5/
    };
    const blockedBefore = await blockedTotal();
    const { round, urlFinal, results } = await scan('redirects', Object.values(links));
    expect(results).toHaveLength(Object.keys(links).length);
    expect(['suspicious', 'malicious', 'spam', 'unknown']).toContain(round.scanVerdict);
    expect(urlFinal.outcome).not.toBe('clean');
    expect(codes(urlFinal.reasonCodes)).toContain('url.redirect_blocked_internal');
    const expected: Record<string, string[]> = {
      internal: ['loopback'],
      metadata: ['metadata', 'link_local'],
      decimal: ['loopback'],
      mapped: ['loopback', 'mapped'],
      metadataName: ['name', 'metadata'],
      private10: ['private'],
    };
    const outcome: Record<string, string | null> = {};
    for (const result of results) {
      // Every one of them was fetched and stopped by the guard at the internal hop.
      expect(result.fetchStatus, `seq ${result.urlSeq}`).toBe('blocked');
      expect(['connection_error', 'timeout']).not.toContain(result.fetchError);
      expect(result.verdict).not.toBe('clean');
      expect(codes(result.reasonCodes)).toContain('url.redirect_blocked_internal');
      const chain = chainOf(result.redirectChain);
      const last = chain.at(-1)!;
      expect(last.blocked, JSON.stringify(chain)).not.toBeNull();
      expect(last.status).toBeNull(); // never answered: never connected
      // Hosts only in the chain JSON, never a path or a query string.
      for (const hop of chain) expect(hop.host).not.toMatch(/[/?#]/);
      outcome[String(result.urlSeq)] = last.blocked;
    }
    const reasons = Object.values(outcome);
    for (const [name, allowed] of Object.entries(expected)) {
      expect(
        reasons.some((r) => r !== null && allowed.includes(r)),
        `${name}: ${JSON.stringify(outcome)}`,
      ).toBe(true);
    }
    const blockedAfter = await blockedTotal();
    expect(blockedAfter - blockedBefore).toBeGreaterThanOrEqual(Object.keys(links).length);
    record('url-ssrf', {
      redirects_verdict: urlFinal.outcome,
      redirects_blocked_reasons: reasons.join(','),
      engine_blocked_delta: blockedAfter - blockedBefore,
    });
  });

  it('DNS rebinding: private first is refused; public first connects to the validated public address only', async () => {
    // rebind.test answers 127.0.0.1 and 203.0.113.10 alternately with TTL 0 (url-test dns).
    await resetRebind('private');
    const privateFirst = await scan('rebind-private', ['http://short-link.test/s/rebind']);
    const [refused] = privateFirst.results;
    expect(refused).toMatchObject({ fetchStatus: 'blocked' });
    expect(['connection_error', 'timeout']).not.toContain(refused!.fetchError);
    const chain = chainOf(refused!.redirectChain);
    expect(chain.at(-1)).toMatchObject({ host: 'rebind.test', blocked: 'loopback', status: null });
    expect(codes(refused!.reasonCodes)).toContain('url.redirect_blocked_internal');
    expect(refused!.verdict).not.toBe('clean');

    await resetRebind('public');
    const publicFirst = await scan('rebind-public', ['http://short-link.test/s/rebind']);
    const [fetched] = publicFirst.results;
    // The validated public answer was dialled (url-test answered 200); the private answer of the
    // next query was never used for this connection.
    expect(fetched).toMatchObject({ fetchStatus: 'completed', finalStatus: 200 });
    expect(fetched!.finalUrl).toBe('http://rebind.test/landing');
    expect(chainOf(fetched!.redirectChain).every((hop) => hop.blocked === null)).toBe(true);
    record('url-ssrf', {
      rebind_private_first: chain.at(-1)?.blocked ?? null,
      rebind_public_first: fetched!.fetchStatus,
    });
  });
});
