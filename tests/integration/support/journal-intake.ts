import { randomBytes } from 'node:crypto';
import { GetObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import type { PrismaClient } from '@email-gateway/database';
import { idempotencyKey, type ApiResponse, type ApiSession } from './api-client';
import { compose, composeExec, composeOk, waitFor } from './compose';
import { stack } from './env';
import { listQueue, logsSince } from './postfix';
import { reply, swaks, type SwaksResult } from './smtp-tools';

/**
 * Pieces of the step 8.6 stack suite `journal-intake.test.ts`
 * (docs/plan/steps/27-journal-intake-and-archive-split.md §9.6): synthetic journal traffic (the
 * documented Exchange journal report shape, Google Workspace "Also deliver to" copies with the
 * header token, generic BCC copies), the intake senders (provider-sender-m365 / -google, counted
 * as provider egress by PROVIDER_EGRESS_EXTRA_RANGES; smtp-tools for on-premises sources), the
 * Compose overrides of the run and readers of the rows the mail path writes. Every domain is a
 * reserved test name; nothing reaches Microsoft or Google. Intake addresses come from the live
 * api (they are credentials: never printed).
 */

export const CRLF = '\r\n';
export const M365_SENDER = 'provider-sender-m365';
export const GOOGLE_SENDER = 'provider-sender-google';
export const TOOLS_SENDER = 'smtp-tools';

/** `JOURNAL_INTAKE_DOMAIN` of the stack (the api, Postfix and the adapter read the same key). */
export function intakeDomain(): string {
  const value = process.env.JOURNAL_INTAKE_DOMAIN;
  if (!value) throw new Error('JOURNAL_INTAKE_DOMAIN is not set in .env (step 8.6)');
  return value;
}

/**
 * Overrides of the run (shell environment over `.env`, LOCAL ONLY): the adapter's source cache and
 * counter flush are short so pause/disable and verification show within seconds; the
 * archive-worker's intake health loop runs every 5 s (D9); everything else is the archive suite's.
 */
export const INTAKE_ADAPTER_ENV: Record<string, string> = {
  JOURNAL_INTAKE_SOURCE_CACHE_SECONDS: '1',
  JOURNAL_INTAKE_COUNTER_FLUSH_SECONDS: '2',
};
export const INTAKE_WORKER_ENV: Record<string, string> = {
  JOURNAL_INTAKE_HEALTH_INTERVAL_MS: '5000',
};

export async function recreateAdapter(env: Record<string, string>): Promise<void> {
  await composeOk(['up', '-d', '--no-deps', '--force-recreate', '--wait', 'smtp-adapter'], {
    timeoutMs: 300_000,
    env,
  });
}

export async function restoreAdapter(): Promise<void> {
  await compose(['up', '-d', '--no-deps', '--force-recreate', '--wait', 'smtp-adapter'], {
    timeoutMs: 300_000,
  });
}

/** A small RFC 5322 message with CRLF line ends. */
export function originalMessage(o: {
  messageId: string;
  from: string;
  to: readonly string[];
  cc?: readonly string[];
  subject: string;
  body?: string;
  date?: string;
  extraHeaders?: readonly string[];
}): string {
  return [
    `Message-ID: ${o.messageId}`,
    `Date: ${o.date ?? new Date().toUTCString().replace('GMT', '+0000')}`,
    `From: ${o.from}`,
    `To: ${o.to.join(', ')}`,
    ...(o.cc?.length ? [`Cc: ${o.cc.join(', ')}`] : []),
    `Subject: ${o.subject}`,
    ...(o.extraHeaders ?? []),
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    o.body ?? 'Synthetic journal intake body.',
    '',
  ].join(CRLF);
}

export const newMessageId = (label: string) =>
  `<it-jrnl-${label}-${randomBytes(6).toString('hex')}@journal-source.test>`;

/**
 * An Exchange journal report (the documented shape: `X-MS-Journal-Report`, multipart/mixed with
 * the text/plain envelope part and the message/rfc822 part) addressed to `intakeAddress`.
 */
export function journalReport(o: {
  intakeAddress: string;
  original: string;
  sender: string;
  to?: readonly string[];
  cc?: readonly string[];
  bcc?: readonly string[];
  messageId?: string;
  tenantIds?: readonly string[];
}): string {
  const boundary = `b1_${randomBytes(6).toString('hex')}`;
  const envelope = [
    `Sender: ${o.sender}`,
    'Subject: journal',
    ...(o.messageId ? [`Message-Id: ${o.messageId}`] : []),
    ...(o.to ?? []).map((a) => `To: ${a}`),
    ...(o.cc ?? []).map((a) => `Cc: ${a}`),
    ...(o.bcc ?? []).map((a) => `Bcc: ${a}`),
  ].join(CRLF);
  return [
    'X-MS-Journal-Report:',
    ...(o.tenantIds ?? []).map((id) => `X-MS-Exchange-CrossTenant-Id: ${id}`),
    'From: Journal Agent <journal-agent@journal-source.test>',
    `To: ${o.intakeAddress}`,
    'Subject: journal report',
    `Message-ID: <report-${randomBytes(6).toString('hex')}@journal-source.test>`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/plain; charset="us-ascii"',
    '',
    envelope,
    '',
    `--${boundary}`,
    'Content-Type: message/rfc822',
    '',
    o.original,
    `--${boundary}--`,
    '',
  ].join(CRLF);
}

/** A Google Workspace "Also deliver to" copy with `X-Gm-Original-To` and the header token. */
export function googleCopy(o: {
  original: string;
  originalTo: readonly string[];
  tokens: readonly string[];
}): string {
  return [
    ...o.originalTo.map((a) => `X-Gm-Original-To: ${a}`),
    ...o.tokens.map((t) => `X-EG-Journal-Token: ${t}`),
    o.original,
  ].join(CRLF);
}

/** One SMTP transaction to the inbound Postfix (mailtest `postfix:25`, STARTTLS by default). */
export function sendIntake(options: {
  service: string;
  to: readonly string[];
  data?: string;
  from?: string;
  tls?: boolean;
  quitAfter?: 'RCPT';
}): Promise<SwaksResult> {
  return swaks({
    service: options.service,
    server: 'postfix',
    port: 25,
    tls: options.tls ?? true,
    helo:
      options.service === M365_SENDER
        ? 'journal.protection.example.test'
        : options.service === GOOGLE_SENDER
          ? 'mail-gateway.google.example.test'
          : 'exchange.onprem.example.test',
    from: options.from ?? 'journal-agent@journal-source.test',
    to: options.to,
    ...(options.data !== undefined ? { data: options.data } : {}),
    ...(options.quitAfter ? { quitAfter: options.quitAfter } : {}),
  });
}

export const replyCode = (result: SwaksResult, key: string): number | undefined =>
  result.replies.get(key)?.code;

export function expectAccepted(result: SwaksResult, what: string): void {
  const code = reply(result, 'DATA-END').code;
  if (code !== 250) throw new Error(`${what}: DATA answered ${code}\n${result.transcript}`);
}

/** The registry rows of intake messages of an organization (writer), newest first. */
export function intakeMessages(prisma: PrismaClient, organizationId: bigint) {
  return prisma.emailMessage.findMany({
    where: { organizationId, ingestSource: 'journal_intake' },
    orderBy: { receivedAt: 'desc' },
    select: {
      id: true,
      receivedAt: true,
      status: true,
      internetMessageId: true,
      emlObjectKey: true,
      emlSha256: true,
      direction: true,
    },
  });
}

/** Waits for the intake message with `internetMessageId` in `organizationId`. */
export function waitForIntakeMessage(
  prisma: PrismaClient,
  organizationId: bigint,
  internetMessageId: string,
  status?: string,
) {
  return waitFor(
    `intake message ${internetMessageId}${status ? ` in ${status}` : ''}`,
    async () => {
      const row = (await intakeMessages(prisma, organizationId)).find(
        (m) => m.internetMessageId === internetMessageId,
      );
      return row && (!status || row.status === status) ? row : undefined;
    },
    { timeoutMs: 180_000, intervalMs: 1_500 },
  );
}

/** Bytes of an object of the mail bucket (stored EML). */
export async function mailObject(s3: S3Client, key: string): Promise<Buffer> {
  const res = await s3.send(new GetObjectCommand({ Bucket: stack.s3().mailBucket, Key: key }));
  return Buffer.from(await res.Body!.transformToByteArray());
}

/** The first bytes of an object of the archive bucket (encryption header check). */
export async function archiveObjectHead(s3: S3Client, key: string, bytes = 16): Promise<Buffer> {
  const res = await s3.send(
    new GetObjectCommand({
      Bucket: stack.s3().archiveBucket,
      Key: key,
      Range: `bytes=0-${bytes - 1}`,
    }),
  );
  return Buffer.from(await res.Body!.transformToByteArray());
}

/** Inbound Postfix log lines since `since` (`docker compose logs`) that mention a needle. */
export async function postfixLogMentions(
  since: Date,
  needles: readonly string[],
): Promise<string[]> {
  return (await logsSince('postfix', since))
    .split('\n')
    .filter((line) => needles.some((n) => line.includes(n)));
}

/** Whether Postfix holds a bounce (DSN) for any of `senders` in its queue. */
export async function queuedBouncesTo(senders: readonly string[]): Promise<number> {
  const queue = await listQueue('postfix');
  return queue.filter(
    (m) =>
      m.sender === '' &&
      m.recipients.some((r) => senders.some((s) => r.address.toLowerCase() === s.toLowerCase())),
  ).length;
}

/** `PUT /journaling/settings` with CAS (organization admin, MFA). */
export async function putJournaling(
  admin: ApiSession,
  change: Record<string, unknown>,
): Promise<ApiResponse> {
  const current = await admin.get('/journaling/settings');
  if (current.status !== 200) return current;
  return admin.put(
    '/journaling/settings',
    { expectedRowVersion: (current.body as { rowVersion: number }).rowVersion, ...change },
    idempotencyKey(),
  );
}

/** A journal intake source through the api (journal:manage, MFA); returns the one-time address. */
export async function createSource(
  admin: ApiSession,
  body: Record<string, unknown>,
): Promise<{ id: string; address: string; headerToken: string | null }> {
  const res = await admin.post('/journaling/intake-sources', body, idempotencyKey());
  if (res.status !== 201) {
    throw new Error(
      `POST /journaling/intake-sources answered ${res.status}: ${JSON.stringify(res.body)}`,
    );
  }
  const created = res.body as {
    source: { id: string };
    address: string | null;
    headerToken: string | null;
  };
  if (!created.address) throw new Error('the created source carries no address');
  return { id: created.source.id, address: created.address, headerToken: created.headerToken };
}

/** PATCH a source (CAS on its row version). */
export async function patchSource(
  admin: ApiSession,
  id: string,
  change: Record<string, unknown>,
): Promise<ApiResponse> {
  const current = await admin.get(`/journaling/intake-sources/${id}`);
  if (current.status !== 200) return current;
  return admin.patch(
    `/journaling/intake-sources/${id}`,
    { expectedRowVersion: (current.body as { rowVersion: number }).rowVersion, ...change },
    idempotencyKey(),
  );
}

/**
 * The IPv4 addresses of the smtp-tools container (discovered at run time): it reaches Postfix over
 * whichever Compose network resolves `postfix`, so every address is registered as a /32 source
 * network (APP_ENV local allows private ranges).
 */
export async function toolsAddresses(): Promise<string[]> {
  const result = await composeExec(TOOLS_SENDER, ['hostname', '-i']);
  const ips = result.stdout
    .trim()
    .split(/\s+/)
    .filter((ip) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip));
  if (ips.length === 0) throw new Error('smtp-tools has no IPv4 address');
  return ips;
}

/**
 * Removes every step 8.6 row of the fixture organizations that `SmtpFixtures.cleanup` does not
 * know: intake messages, counters, sources, provider connections and their domain links, and the
 * adapter's Redis keys of the sources. Archive rows go with `purgeArchiveTenants`.
 */
export async function purgeIntakeRows(
  prisma: PrismaClient,
  redis: { scan: (...args: never[]) => unknown; del: (...keys: string[]) => Promise<number> },
  organizationIds: readonly bigint[],
): Promise<void> {
  if (organizationIds.length === 0) return;
  const where = { organizationId: { in: [...organizationIds] } };
  const sources = await prisma.journalIntakeSource.findMany({
    where,
    select: { id: true, addressHash: true, previousAddressHash: true },
  });
  await prisma.journalIntakeMessage.deleteMany({ where });
  await prisma.journalIntakeCounter.deleteMany({ where });
  await prisma.journalIntakeSource.deleteMany({ where });
  await prisma.providerConnectionDomain.deleteMany({ where });
  await prisma.providerConnection.deleteMany({ where });
  const keys = [
    ...sources.flatMap((s) => [
      `sa:jintake:src:${s.addressHash}`,
      ...(s.previousAddressHash ? [`sa:jintake:src:${s.previousAddressHash}`] : []),
    ]),
  ];
  if (keys.length > 0) await redis.del(...keys);
}

/** Webhook-receiver requests of a path that name one of `messagePublicIds`. */
export function mentions(requests: readonly { body: Buffer }[], ids: readonly string[]): number {
  return requests.filter((r) => ids.some((id) => r.body.toString('utf8').includes(id))).length;
}
