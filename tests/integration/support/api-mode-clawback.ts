import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { uuidv7 } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import {
  EventTypes,
  threatLateSignalV1,
  type ThreatLateSignalV1,
} from '@email-gateway/event-contracts';
import { waitFor } from './compose';
import { MAILBOX_WORKER_SUITE_ENV } from './api-mode';

/**
 * Pieces of the step API-3 stack suite `api-mode-clawback.test.ts` — the program acceptance run
 * of API-1..API-3 (docs/plan/steps/37-api-mode-clawback-reporting.md §9.6 and §13,
 * ADR-0103/0104): the mailbox-worker overrides of the run (short clawback, report and TI sweep
 * ticks, a one-minute `clawback.stalled` warning), readers and waits of the five step API-3
 * tables (MySQL writer), the late-signal outbox row of the §13 A3 fallback (the exact row
 * `writeLateSignalOutbox` of the email-worker writes, validated by the strict contract), synthetic
 * report e-mails (forward as attachment, inline forward) and the removal of the step API-3 rows in
 * the api purge's order (§3.4: targets, clawbacks and reports before the remediation actions,
 * mailboxes and connections; organization settings before the organization). Synthetic data only;
 * nothing reaches Microsoft, Google or the Internet; no credential is printed.
 */

/**
 * mailbox-worker overrides of the run (shell environment over `.env`, LOCAL ONLY): the API-1/API-2
 * suite values plus clawback and report ticks of 1 s, a threat-intelligence sweep every 5 s (the
 * config minimum) and the `clawback.stalled` warning after 1 minute (C13; the fail threshold keeps
 * its default).
 */
export const CLAWBACK_WORKER_SUITE_ENV: Record<string, string> = {
  ...MAILBOX_WORKER_SUITE_ENV,
  API_MODE_CLAWBACK_TICK_MS: '1000',
  API_MODE_REPORTS_TICK_MS: '1000',
  API_MODE_CLAWBACK_TI_INTERVAL_SECONDS: '5',
  API_MODE_CLAWBACK_STALLED_WARN_MINUTES: '1',
};

/** Terminal clawback statuses (C5.1). */
export const FINAL_CLAWBACK_STATUSES = [
  'completed',
  'completed_with_errors',
  'no_match',
  'too_broad',
  'denied',
  'expired',
  'cancelled',
  'failed',
] as const;

// --- rows ----------------------------------------------------------------------------------------

export type ClawbackRow = NonNullable<
  Awaited<ReturnType<PrismaClient['apiClawback']['findFirst']>>
>;

/** Clawbacks of an organization (writer), oldest first. */
export function clawbacksOf(prisma: PrismaClient, organizationId: bigint) {
  return prisma.apiClawback.findMany({ where: { organizationId }, orderBy: { id: 'asc' } });
}

/** Waits for a clawback of the organization that satisfies `predicate`. */
export function waitForClawback(
  prisma: PrismaClient,
  organizationId: bigint,
  what: string,
  predicate: (c: ClawbackRow) => boolean,
  timeoutMs = 180_000,
): Promise<ClawbackRow> {
  return waitFor(
    `clawback ${what}`,
    async () => (await clawbacksOf(prisma, organizationId)).find(predicate),
    { timeoutMs, intervalMs: 1_000 },
  );
}

/** Waits until the clawback (by public id) satisfies `predicate`. */
export function waitForClawbackState(
  prisma: PrismaClient,
  publicId: string,
  what: string,
  predicate: (c: ClawbackRow) => boolean,
  timeoutMs = 180_000,
): Promise<ClawbackRow> {
  return waitFor(
    `clawback ${what}`,
    async () => {
      const row = await prisma.apiClawback.findUnique({ where: { publicId } });
      return row && predicate(row) ? row : undefined;
    },
    { timeoutMs, intervalMs: 1_000 },
  );
}

/** The frozen targets of a clawback (writer), in materialization order. */
export function targetsOf(prisma: PrismaClient, clawbackId: bigint) {
  return prisma.apiClawbackTarget.findMany({ where: { clawbackId }, orderBy: { id: 'asc' } });
}

export type ReportRow = NonNullable<
  Awaited<ReturnType<PrismaClient['apiUserReport']['findFirst']>>
>;

/** Waits for a user report of the organization from `reporter` that satisfies `predicate`. */
export function waitForReport(
  prisma: PrismaClient,
  organizationId: bigint,
  reporter: string,
  what: string,
  predicate: (r: ReportRow) => boolean,
  timeoutMs = 180_000,
): Promise<ReportRow> {
  return waitFor(
    `user report ${what}`,
    async () =>
      (
        await prisma.apiUserReport.findMany({
          where: { organizationId, reporterAddress: reporter.toLowerCase() },
          orderBy: { id: 'asc' },
        })
      ).find(predicate),
    { timeoutMs, intervalMs: 1_000 },
  );
}

/** The step API-3 counters of an API-mode connection, summed over the hours (writer). */
export async function clawbackCounterSums(prisma: PrismaClient, apiConnectionId: bigint) {
  const rows = await prisma.apiModeCounter.findMany({ where: { apiConnectionId } });
  const sum = (
    k:
      | 'internalCopies'
      | 'clawbackTargetsQueued'
      | 'clawbackTargetsSucceeded'
      | 'clawbackTargetsFailed'
      | 'reportsReceived'
      | 'reportsResolved',
  ) => rows.reduce((n, r) => n + r[k], 0);
  return {
    internalCopies: sum('internalCopies'),
    targetsQueued: sum('clawbackTargetsQueued'),
    targetsSucceeded: sum('clawbackTargetsSucceeded'),
    targetsFailed: sum('clawbackTargetsFailed'),
    reportsReceived: sum('reportsReceived'),
    reportsResolved: sum('reportsResolved'),
  };
}

// --- late signal (§13 A3 fallback) ---------------------------------------------------------------

/**
 * Writes the `mail.threat.late_signal.v1` outbox row the email-worker's sandbox finalizer writes
 * for a raising risk revision 1 (`writeLateSignalOutbox`: strict contract parse, uuidv7 event id
 * at `signalAt`, `aggregate_type = 'message'`, `aggregate_id` = the decimal registry id). The live
 * event-relay publishes it to `email.security` (`org.<id>.mail.threat.late_signal.v1` → queue
 * `email.mailbox`, topology v18) and the live mailbox-worker's `copies` role consumes it. Returns
 * the event id and the payload.
 */
export async function writeSandboxLateSignal(
  prisma: PrismaClient,
  input: {
    organizationId: bigint;
    message: { id: bigint; receivedAt: Date };
    verdict: ThreatLateSignalV1['verdict'];
    level: ThreatLateSignalV1['level'];
    hardBlocks: readonly string[];
    attachmentSha256: readonly string[];
    signalAt?: Date;
  },
): Promise<{ eventId: string; payload: ThreatLateSignalV1 }> {
  const scan = await prisma.emailScan.findFirstOrThrow({
    where: {
      organizationId: input.organizationId,
      messageId: input.message.id,
      receivedAt: input.message.receivedAt,
    },
    orderBy: { lifecycleRound: 'desc' },
    select: { id: true },
  });
  const signalAt = input.signalAt ?? new Date();
  const payload = threatLateSignalV1.parse({
    kind: 'sandbox_revision',
    messageId: input.message.id.toString(),
    receivedAt: input.message.receivedAt.toISOString(),
    scanId: scan.id.toString(),
    revision: 1,
    verdict: input.verdict,
    level: input.level,
    hardBlocks: [...input.hardBlocks],
    attachmentSha256: [...input.attachmentSha256],
    urlSha256: [],
    signalAt: signalAt.toISOString(),
  });
  const eventId = uuidv7(signalAt.getTime());
  await prisma.messageOutbox.create({
    data: {
      eventId,
      organizationId: input.organizationId,
      eventType: EventTypes.ThreatLateSignal,
      aggregateType: 'message',
      aggregateId: payload.messageId,
      correlationId: randomUUID(),
      payload,
    },
    select: { id: true },
  });
  return { eventId, payload };
}

/** Waits until the relay published the outbox row of `eventId`. */
export function waitForPublished(prisma: PrismaClient, eventId: string, timeoutMs = 60_000) {
  return waitFor(
    `outbox row ${eventId} published`,
    async () => {
      const row = await prisma.messageOutbox.findFirst({
        where: { eventId },
        select: { publishedAt: true },
      });
      return row?.publishedAt ? row : undefined;
    },
    { timeoutMs, intervalMs: 500 },
  );
}

// --- synthetic messages --------------------------------------------------------------------------

const CRLF = '\r\n';
const rfc5322 = (d: Date) => d.toUTCString().replace('GMT', '+0000');

export const sha256Hex = (bytes: Buffer | string) =>
  createHash('sha256').update(bytes).digest('hex');

/** A benign synthetic attachment body (unique per call; never real content). */
export const benignAttachment = (label: string) =>
  Buffer.from(
    `EXAMPLE synthetic statement ${label} ${randomBytes(8).toString('hex')}\nNothing to see here.\n`,
    'utf8',
  );

/** Folds a long address list header (RFC 5322 lines stay below 998 octets). */
export const foldAddresses = (name: string, addresses: readonly string[]) =>
  `${name}: ${addresses.join(`,${CRLF} `)}`;

/**
 * A synthetic message for a journal report or a simulator delivery: plain text, or with one
 * base64 attachment; `to` folded over several lines.
 */
export function syntheticEml(o: {
  messageId: string;
  from: string;
  to: readonly string[];
  subject: string;
  body?: string;
  date?: Date;
  attachment?: { filename: string; contentType?: string; content: Buffer };
}): string {
  const head = [
    `Message-ID: <${o.messageId}>`,
    `Date: ${rfc5322(o.date ?? new Date())}`,
    `From: ${o.from}`,
    foldAddresses('To', o.to),
    `Subject: ${o.subject}`,
    'MIME-Version: 1.0',
  ];
  const body = o.body ?? 'EXAMPLE synthetic API-mode clawback copy body.';
  if (!o.attachment) {
    return [
      ...head,
      'Content-Type: text/plain; charset=utf-8',
      'Content-Transfer-Encoding: 7bit',
      '',
      body,
      '',
    ].join(CRLF);
  }
  const boundary = `b_${randomBytes(6).toString('hex')}`;
  const base64 = o.attachment.content
    .toString('base64')
    .replace(/.{1,76}/g, (line) => `${line}${CRLF}`);
  return [
    ...head,
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/plain; charset=utf-8',
    '',
    body,
    `--${boundary}`,
    `Content-Type: ${o.attachment.contentType ?? 'application/octet-stream'}; name="${o.attachment.filename}"`,
    `Content-Disposition: attachment; filename="${o.attachment.filename}"`,
    'Content-Transfer-Encoding: base64',
    '',
    base64,
    `--${boundary}--`,
    '',
  ].join(CRLF);
}

/**
 * A report e-mail forwarding `original` AS AN ATTACHMENT (`message/rfc822`, the Outlook/Gmail
 * "forward as attachment" shape) from `reporter` to the report mailbox.
 */
export function forwardAsAttachmentEml(o: {
  messageId: string;
  reporter: string;
  reportMailbox: string;
  original: string;
}): string {
  const boundary = `fwd_${randomBytes(6).toString('hex')}`;
  return [
    `Message-ID: <${o.messageId}>`,
    `Date: ${rfc5322(new Date())}`,
    `From: ${o.reporter}`,
    `To: ${o.reportMailbox}`,
    'Subject: FW: suspicious message',
    'MIME-Version: 1.0',
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/plain; charset=utf-8',
    '',
    'EXAMPLE: this looks like phishing, please check.',
    `--${boundary}`,
    'Content-Type: message/rfc822; name="suspicious.eml"',
    'Content-Disposition: attachment; filename="suspicious.eml"',
    '',
    o.original,
    `--${boundary}--`,
    '',
  ].join(CRLF);
}

/**
 * A report e-mail with an INLINE forward (Gmail's separator followed by From/Date/Subject/To of
 * the original, no Message-ID): matched by sender + subject in the reporter's mailbox (C10.3).
 */
export function inlineForwardEml(o: {
  messageId: string;
  reporter: string;
  reportMailbox: string;
  originalFrom: string;
  originalTo: string;
  originalSubject: string;
  originalDate: Date;
}): string {
  return [
    `Message-ID: <${o.messageId}>`,
    `Date: ${rfc5322(new Date())}`,
    `From: ${o.reporter}`,
    `To: ${o.reportMailbox}`,
    `Subject: Fwd: ${o.originalSubject}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    'EXAMPLE: reporting this one too.',
    '',
    '---------- Forwarded message ---------',
    `From: ${o.originalFrom}`,
    `Date: ${rfc5322(o.originalDate)}`,
    `Subject: ${o.originalSubject}`,
    `To: ${o.originalTo}`,
    '',
    'EXAMPLE forwarded text of the original.',
    '',
  ].join(CRLF);
}

// --- cleanup -------------------------------------------------------------------------------------

/**
 * Removes the step API-3 rows of the organizations in the api purge's order (§3.4,
 * `API_MODE_PURGE_ORDER`): clawback targets (they also cascade with their clawback), clawbacks and
 * user reports — before the remediation actions, mailboxes and connections they reference — and
 * the organization settings (RESTRICT to the organization). Run it before `purgeRemediationRows`
 * and `purgeApiModeRows` (both also apply this order), then the fixture cleanup.
 */
export async function purgeClawbackRows(
  prisma: PrismaClient,
  organizationIds: readonly bigint[],
): Promise<void> {
  if (organizationIds.length === 0) return;
  const where = { organizationId: { in: [...organizationIds] } };
  await prisma.apiClawbackTarget.deleteMany({ where });
  await prisma.apiClawback.deleteMany({ where });
  await prisma.apiUserReport.deleteMany({ where });
  await prisma.apiModeOrgSetting.deleteMany({ where });
}

/** Rows of the step API-3 tenant tables still referencing the organizations. */
export async function clawbackRowCounts(prisma: PrismaClient, organizationIds: readonly bigint[]) {
  const where = { organizationId: { in: [...organizationIds] } };
  return {
    clawbacks: await prisma.apiClawback.count({ where }),
    targets: await prisma.apiClawbackTarget.count({ where }),
    reports: await prisma.apiUserReport.count({ where }),
    orgSettings: await prisma.apiModeOrgSetting.count({ where }),
  };
}
