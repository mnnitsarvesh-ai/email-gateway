import { randomUUID } from 'node:crypto';
import type { PrismaClient } from '@email-gateway/database';
import {
  chainCacheKey,
  FETCHER_VERSION,
  normalizeUrl,
  parseTokenKey,
  type TokenKey,
} from '@email-gateway/url-security';
import Redis from 'ioredis';
import { ManagementApi } from './broker';
import { stack } from './env';
import type { MessageKey } from './lifecycle';

/**
 * Helpers of the step 4.3 URL protection stack suites (tests/integration/url-*.test.ts,
 * docs/plan/steps/11-url-protection.md §9 "Stack"). Every URL points at the TEST-ONLY corpus of
 * `url-test` / `dns-sink` (`.test` names, documentation addresses); nothing reaches the Internet.
 */
const CRLF = '\r\n';

/** The click host of the running stack (`URL_CLICK_BASE_URL`, e.g. `http://localhost:3080`). */
export const clickBaseUrl = (): string =>
  (process.env.URL_CLICK_BASE_URL || 'http://localhost:3080').replace(/\/+$/, '');

/** The click-service public port as reached from the host (CLICK_SERVICE_HOST_PORT). */
export const clickServiceUrl = (): string =>
  `http://${stack.host}:${Number(process.env.CLICK_SERVICE_HOST_PORT ?? 3080)}`;

/** The click-service admin port (health, metrics; CLICK_SERVICE_ADMIN_HOST_PORT). */
export const clickAdminUrl = (): string =>
  `http://${stack.host}:${Number(process.env.CLICK_SERVICE_ADMIN_HOST_PORT ?? 3081)}`;

/** url-test HTTP as published on the host (URL_TEST_HTTP_HOST_PORT). */
export const urlTestHttpUrl = (): string =>
  `http://${stack.host}:${Number(process.env.URL_TEST_HTTP_HOST_PORT ?? 18080)}`;

/** The current token signing key of `.env` (never printed). */
export function currentTokenKey(): TokenKey {
  const hex = process.env.URL_TOKEN_KEY_CURRENT;
  if (!hex) throw new Error('URL_TOKEN_KEY_CURRENT is not set (append the URL protection keys)');
  return parseTokenKey(hex, Number(process.env.URL_TOKEN_KEY_CURRENT_ID ?? 1));
}

const escapeRegExp = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Every click token of the click host found in `text` (in order of appearance). */
export function clickTokensIn(text: string): string[] {
  const re = new RegExp(`${escapeRegExp(clickBaseUrl())}/c/([A-Za-z0-9_-]{62})`, 'g');
  return [...text.matchAll(re)].map((m) => m[1]!);
}

export interface LinkMessage {
  text: string;
  messageId: string;
  boundary: string;
}

/**
 * multipart/alternative with a text/plain and a text/html part (7bit, CRLF, one link per line so
 * the rewritten lines stay below 998 octets and the parts keep their transfer encoding).
 */
export function linkMessage(options: {
  from: string;
  to: readonly string[];
  subject: string;
  textLinks: readonly string[];
  htmlLinks: readonly string[];
}): LinkMessage {
  const messageId = `<${randomUUID()}@url.integration.test>`;
  const boundary = `alt-${randomUUID()}`;
  const lines = [
    `From: ${options.from}`,
    `To: ${options.to.join(', ')}`,
    `Subject: ${options.subject}`,
    `Message-ID: ${messageId}`,
    `Date: ${new Date().toUTCString().replace('GMT', '+0000')}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    '',
    'This is a multi-part message in MIME format.',
    `--${boundary}`,
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    `Body of ${options.subject}.`,
    ...options.textLinks.map((link, i) => `Link ${i + 1}: ${link}`),
    `--${boundary}`,
    'Content-Type: text/html; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    '<!doctype html><html><body>',
    `<p>Body of ${options.subject}.</p>`,
    ...options.htmlLinks.map((href, i) => `<p><a href="${href}">Link ${i + 1}</a></p>`),
    '</body></html>',
    `--${boundary}--`,
    '',
  ];
  return { text: lines.join(CRLF), messageId, boundary };
}

/** A plain single-part text message (no URL when `body` has none). */
export function plainMessage(options: {
  from: string;
  to: readonly string[];
  subject: string;
  body: string;
}): { text: string; messageId: string } {
  const messageId = `<${randomUUID()}@url.integration.test>`;
  const text = [
    `From: ${options.from}`,
    `To: ${options.to.join(', ')}`,
    `Subject: ${options.subject}`,
    `Message-ID: ${messageId}`,
    `Date: ${new Date().toUTCString().replace('GMT', '+0000')}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    options.body,
    '',
  ].join(CRLF);
  return { text, messageId };
}

/**
 * An S/MIME-style `multipart/signed` message (RFC 8551 layout: the signed text part with a link,
 * then an `application/pkcs7-signature` part). The signature bytes are a fixed TEST-ONLY
 * placeholder: the gateway never verifies S/MIME, it only has to recognize the structure and
 * leave the whole message untouched (U11 `signed_smime`).
 */
export function smimeSignedMessage(options: {
  from: string;
  to: readonly string[];
  subject: string;
  link: string;
}): { text: string; messageId: string; signedBody: string } {
  const messageId = `<${randomUUID()}@url.integration.test>`;
  const boundary = `signed-${randomUUID()}`;
  const signature = Buffer.from(`TEST-ONLY placeholder signature ${randomUUID()}`)
    .toString('base64')
    .replace(/(.{76})/g, `$1${CRLF}`);
  const signedBody = [
    `--${boundary}`,
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    `Signed body of ${options.subject}.`,
    `Link: ${options.link}`,
    `--${boundary}`,
    'Content-Type: application/pkcs7-signature; name="smime.p7s"',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="smime.p7s"',
    '',
    signature,
    `--${boundary}--`,
    '',
  ].join(CRLF);
  const text = [
    `From: ${options.from}`,
    `To: ${options.to.join(', ')}`,
    `Subject: ${options.subject}`,
    `Message-ID: ${messageId}`,
    `Date: ${new Date().toUTCString().replace('GMT', '+0000')}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256; boundary="${boundary}"`,
    '',
    'This is an S/MIME signed message.',
    signedBody,
  ].join(CRLF);
  return { text, messageId, signedBody };
}

/** The body of a stored/delivered message (everything after the first empty line). */
export function bodyOf(raw: Buffer | string): string {
  // Line endings normalized to LF: the sinks store Maildir files with LF, SMTP data is CRLF.
  const text = (typeof raw === 'string' ? raw : raw.toString('utf8')).replace(/\r\n/g, '\n');
  const index = text.indexOf('\n\n');
  return index === -1 ? text : text.slice(index + 2);
}

/** The MIME part headers (`Content-Type` lines) between the boundaries of `body`. */
export function partContentTypes(body: string, boundary: string): string[] {
  return body
    .split(`--${boundary}`)
    .slice(1, -1)
    .map((part) => /^\r?\nContent-Type: ([^\r\n;]+)/i.exec(part)?.[1]?.toLowerCase() ?? '');
}

// --- Readers (MySQL writer) ---------------------------------------------------------------------

export function messageUrlsOf(prisma: PrismaClient, message: MessageKey) {
  return prisma.messageUrl.findMany({
    where: { messageId: message.id, receivedAt: message.receivedAt },
    orderBy: { urlSeq: 'asc' },
  });
}

export function urlResultsOf(prisma: PrismaClient, message: MessageKey) {
  return prisma.urlScanResult.findMany({
    where: { messageId: message.id, receivedAt: message.receivedAt },
    orderBy: [{ scanId: 'asc' }, { urlSeq: 'asc' }],
  });
}

export function urlRewritesOf(prisma: PrismaClient, message: MessageKey) {
  return prisma.urlRewrite.findMany({
    where: { messageId: message.id, receivedAt: message.receivedAt },
    orderBy: { lifecycleRound: 'asc' },
  });
}

export function clickEventsOf(prisma: PrismaClient, message: MessageKey) {
  return prisma.urlClickEvent.findMany({
    where: { messageId: message.id, messageReceivedAt: message.receivedAt },
    orderBy: { id: 'asc' },
  });
}

/** One GET of the click-service (no redirect following); the body as text. */
export async function click(
  path: string,
): Promise<{ status: number; location: string | null; body: string; headers: Headers }> {
  const res = await fetch(`${clickServiceUrl()}${path}`, {
    redirect: 'manual',
    signal: AbortSignal.timeout(15_000),
  });
  return {
    status: res.status,
    location: res.headers.get('location'),
    body: await res.text(),
    headers: res.headers,
  };
}

/** A metric value of the click-service admin listener (sum over matching series). */
export async function clickMetric(name: string, labels: Record<string, string>): Promise<number> {
  const res = await fetch(`${clickAdminUrl()}/metrics`, { signal: AbortSignal.timeout(5_000) });
  const text = await res.text();
  let total = 0;
  for (const line of text.split('\n')) {
    if (!line.startsWith(`${name}{`)) continue;
    if (Object.entries(labels).every(([k, v]) => line.includes(`${k}="${v}"`))) {
      total += Number(line.split(' ').pop());
    }
  }
  return total;
}

/**
 * Purges `scan.url.inspect` (step 4.3 U2): a lossy work queue by design (`drop-head`, consumer
 * kind `stateless`), filled with dynamic-inspection requests while the optional url-browser
 * profile is off; a dropped request is expired by the email-worker sweeper (U15). Never purges a
 * ledger work queue.
 */
export async function purgeInspectionQueue(
  api: ManagementApi = new ManagementApi(),
  vhost: string = stack.rabbitmqVhost(),
): Promise<number> {
  const depth = (await api.queue(vhost, 'scan.url.inspect').catch(() => ({ messages: 0 })))
    .messages;
  await api.purge(vhost, 'scan.url.inspect');
  return depth;
}

/** True when the click-service answers its admin readiness (apps profile). */
export async function clickServiceReady(): Promise<boolean> {
  try {
    const res = await fetch(`${clickAdminUrl()}/health/ready`, {
      signal: AbortSignal.timeout(3_000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/** True when url-test answers (smtp-test profile). */
export async function urlTestReady(): Promise<boolean> {
  try {
    const res = await fetch(`${urlTestHttpUrl()}/health`, { signal: AbortSignal.timeout(3_000) });
    return res.ok;
  } catch {
    return false;
  }
}

/** `/reset` of the url-test rebinding responder (`first=private`: 127.0.0.1 is answered first). */
export async function resetRebind(first: 'public' | 'private'): Promise<void> {
  const res = await fetch(
    `${urlTestHttpUrl()}/reset${first === 'private' ? '?first=private' : ''}`,
    { signal: AbortSignal.timeout(5_000) },
  );
  if (!res.ok) throw new Error(`url-test /reset answered ${res.status}`);
}

/**
 * Removes the shared chain-cache entries (U6 `eg:url:chain:v1:…`) of these URLs, so the next
 * scan fetches them again instead of reusing a chain of an earlier run (the suites assert the
 * fetch itself).
 */
export async function forgetChains(urls: readonly string[]): Promise<number> {
  const redis = new Redis(stack.redisUrl(), { lazyConnect: true, maxRetriesPerRequest: 2 });
  try {
    await redis.connect();
    const keys = urls.flatMap((url) => {
      const normalized = normalizeUrl(url);
      return normalized.ok ? [chainCacheKey(FETCHER_VERSION, normalized.url.identity)] : [];
    });
    return keys.length === 0 ? 0 : await redis.del(...keys);
  } finally {
    redis.disconnect();
  }
}
