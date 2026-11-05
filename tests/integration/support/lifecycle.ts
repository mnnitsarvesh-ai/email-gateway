import { createHash, randomUUID } from 'node:crypto';
import { PutObjectCommand } from '@aws-sdk/client-s3';
import type {
  MessageDirection,
  MessageStatus,
  PrismaClient,
  RecipientStatus,
} from '@email-gateway/database';
import { expect } from 'vitest';
import { waitFor } from './compose';
import type { SmtpFixtures } from './smtp-fixtures';

/**
 * Readers of the step 3.3 message lifecycle (docs/plan/steps/08-message-lifecycle.md L2–L5) on
 * the MySQL WRITER, for the stack suites: the message's state columns and its applied
 * transitions (`email_message_status_history`, oldest first by version).
 */
export interface MessageKey {
  id: bigint;
  receivedAt: Date;
}

export interface LifecycleRow {
  status: MessageStatus;
  statusReason: string | null;
  version: number;
  lifecycleRound: number;
}

export async function lifecycleOf(
  prisma: PrismaClient,
  message: MessageKey,
): Promise<LifecycleRow> {
  return prisma.emailMessage.findUniqueOrThrow({
    where: { id_receivedAt: { id: message.id, receivedAt: message.receivedAt } },
    select: { status: true, statusReason: true, version: true, lifecycleRound: true },
  });
}

/** Applied transitions of one message, oldest first (version order). */
export function historyOf(prisma: PrismaClient, message: MessageKey) {
  return prisma.emailMessageStatusHistory.findMany({
    where: { messageId: message.id, receivedAt: message.receivedAt },
    orderBy: { version: 'asc' },
  });
}

/** `[from, to, reason]` of every applied transition, oldest first. */
export async function pathOf(
  prisma: PrismaClient,
  message: MessageKey,
): Promise<[MessageStatus | null, MessageStatus, string | null][]> {
  return (await historyOf(prisma, message)).map((h) => [h.fromStatus, h.toStatus, h.reasonCode]);
}

/**
 * Waits until the message is in `state` (and has `reason` when given); returns the row. The
 * failure message shows the last state and the path so far.
 */
export async function waitForLifecycle(
  prisma: PrismaClient,
  message: MessageKey,
  state: MessageStatus,
  reason?: string,
  timeoutMs = 120_000,
): Promise<LifecycleRow> {
  let last: LifecycleRow | undefined;
  try {
    return await waitFor(
      `message ${message.id} in ${state}${reason ? `/${reason}` : ''}`,
      async () => {
        last = await lifecycleOf(prisma, message);
        return last.status === state && (reason === undefined || last.statusReason === reason)
          ? last
          : undefined;
      },
      { timeoutMs, intervalMs: 500 },
    );
  } catch (err) {
    const path = await pathOf(prisma, message).catch(() => []);
    throw new Error(
      `${(err as Error).message}\n  last: ${last ? `${last.status}/${last.statusReason ?? '-'} v${last.version} r${last.lifecycleRound}` : 'none'}\n  path: ${JSON.stringify(path)}`,
    );
  }
}

/**
 * Asserts the invariants of every lifecycle: history versions 0..version contiguous (one row per
 * applied transition, none missing or repeated), each row starting where the previous ended,
 * the message's version equal to the last row's, and distinct transition keys.
 */
export async function expectConsistentHistory(
  prisma: PrismaClient,
  message: MessageKey,
): Promise<void> {
  const [row, history] = await Promise.all([
    lifecycleOf(prisma, message),
    historyOf(prisma, message),
  ]);
  expect(history.map((h) => h.version)).toEqual(history.map((_, i) => i));
  expect(history.at(-1)?.version).toBe(row.version);
  expect(history.at(-1)?.toStatus).toBe(row.status);
  expect(history[0]?.fromStatus).toBeNull();
  for (let i = 1; i < history.length; i++) {
    expect(history[i]!.fromStatus).toBe(history[i - 1]!.toStatus);
  }
  const keys = history.map((h) => h.transitionKey).filter((k): k is string => k !== null);
  expect(new Set(keys).size).toBe(keys.length);
}

/** The two creation rows of the SMTP commit (L5.2: E1 `NULL → received`, E2 `→ persisted`). */
export async function expectIngestionRows(
  prisma: PrismaClient,
  message: MessageKey,
): Promise<void> {
  const history = await historyOf(prisma, message);
  expect(
    history.slice(0, 2).map((h) => ({
      version: h.version,
      from: h.fromStatus,
      to: h.toStatus,
      reason: h.reasonCode,
      role: h.actorRole,
      service: h.actorService,
      type: h.actorType,
      round: h.lifecycleRound,
      stateEventId: h.stateEventId,
    })),
  ).toEqual([
    {
      version: 0,
      from: null,
      to: 'received',
      reason: 'smtp_accepted',
      role: 'ingestion',
      service: 'smtp-adapter',
      type: 'system',
      round: 0,
      stateEventId: null,
    },
    {
      version: 1,
      from: 'received',
      to: 'persisted',
      reason: 'committed',
      role: 'ingestion',
      service: 'smtp-adapter',
      type: 'system',
      round: 0,
      stateEventId: null,
    },
  ]);
  expect(history[0]!.correlationId).toMatch(/^lmtp:/);
  expect(history[0]!.eventId).toBe(history[1]!.eventId);
}

/**
 * The dev pass-through path of a delivered message: ingestion → scan (E3, E6; step 4.1) → E27
 * (the pass-through approves only scanned mail; E4 is retired) → E20 → derived final.
 */
export const DELIVERED_PATH = (
  finalState: MessageStatus,
  finalReason: string,
): [MessageStatus | null, MessageStatus, string | null][] => [
  [null, 'received', 'smtp_accepted'],
  ['received', 'persisted', 'committed'],
  ['persisted', 'scanning', 'scan_started'],
  ['scanning', 'scanned', 'scan_complete'],
  ['scanned', 'approved', 'dev_passthrough'],
  ['approved', 'delivery_pending', 'delivery_planned'],
  ['delivery_pending', finalState, finalReason],
];

/**
 * The path of an `approved` FIXTURE message (`insertFixtureMessage`, L8.6: inserted directly in
 * `approved`, so it was never scanned) once it is delivered: creation rows, the fixture's
 * `persisted → approved` row, then E20 and the derived final state.
 */
export const FIXTURE_APPROVED_DELIVERED_PATH = (
  finalState: MessageStatus,
  finalReason: string,
): [MessageStatus | null, MessageStatus, string | null][] => [
  [null, 'received', 'smtp_accepted'],
  ['received', 'persisted', 'committed'],
  ['persisted', 'approved', 'dev_passthrough'],
  ['approved', 'delivery_pending', 'delivery_planned'],
  ['delivery_pending', finalState, finalReason],
];

/**
 * Every applied transition after creation has one `mail.message.state_changed.v1` outbox row
 * (event id = history `state_event_id`) and one `lifecycle.<to>` email event (L5.1 steps 6–7).
 * Rows written by a suite fixture (`insertFixtureMessage`) are not transitions and are skipped.
 */
export async function expectStateChangedRows(
  prisma: PrismaClient,
  organizationId: bigint,
  message: MessageKey,
): Promise<void> {
  // Creation rows (v0, v1) and suite fixture rows (actor `fixture`) have no event.
  const history = (await historyOf(prisma, message)).filter(
    (h) => h.version >= 2 && h.actorRole !== 'fixture',
  );
  const ids = history.map((h) => h.stateEventId);
  expect(ids.every((id) => typeof id === 'string')).toBe(true);
  const outbox = await prisma.messageOutbox.findMany({
    where: { organizationId, eventId: { in: ids as string[] } },
    select: { eventId: true, eventType: true },
  });
  expect(outbox).toHaveLength(history.length);
  expect(outbox.every((o) => o.eventType === 'mail.message.state_changed.v1')).toBe(true);
  const events = await prisma.emailEvent.findMany({
    where: {
      organizationId,
      messageId: message.id,
      eventType: { startsWith: 'lifecycle.' },
      NOT: { eventType: 'lifecycle.ignored' },
    },
    select: { eventType: true },
    orderBy: { id: 'asc' },
  });
  expect(events.map((e) => e.eventType)).toEqual(history.map((h) => `lifecycle.${h.toStatus}`));
}

/**
 * Exactly-once check of the lifecycle over every message of the organizations (the stack chaos
 * suites): each message in `state`/`reason`, its history exactly `transitions + 1` rows with
 * versions 0..transitions (no gap, no repeat), distinct transition keys, and one
 * `mail.message.state_changed.v1` outbox row per applied transition after creation.
 */
export async function lifecycleProblems(
  prisma: PrismaClient,
  organizationIds: readonly bigint[],
  n: number,
  // Step 4.1: received, persisted, scanning, scanned, approved, delivery_pending, delivered.
  expected: { state: MessageStatus; reason: string; version: number } = {
    state: 'delivered',
    reason: 'delivery_complete',
    version: 6,
  },
): Promise<string[]> {
  const problems: string[] = [];
  const orgs = [...organizationIds];
  const states = await prisma.emailMessage.groupBy({
    by: ['status', 'statusReason', 'version'],
    where: { organizationId: { in: orgs } },
    _count: { _all: true },
  });
  const good = states.find(
    (s) =>
      s.status === expected.state &&
      s.statusReason === expected.reason &&
      s.version === expected.version,
  );
  if ((good?._count._all ?? 0) !== n) {
    problems.push(
      `messages in ${expected.state}/${expected.reason} v${expected.version}: ${good?._count._all ?? 0} of ${n} (${JSON.stringify(
        states.map((s) => [s.status, s.statusReason, s.version, s._count._all]),
      )})`,
    );
  }
  const history = await prisma.emailMessageStatusHistory.groupBy({
    by: ['messageId'],
    where: { organizationId: { in: orgs } },
    _count: { _all: true, transitionKey: true },
    _min: { version: true },
    _max: { version: true },
  });
  const bad = history.filter(
    (h) =>
      h._count._all !== expected.version + 1 ||
      h._min.version !== 0 ||
      h._max.version !== expected.version ||
      h._count.transitionKey !== h._count._all,
  );
  if (history.length !== n) problems.push(`messages with history: ${history.length} of ${n}`);
  if (bad.length > 0) {
    problems.push(
      `messages whose history is not ${expected.version + 1} contiguous rows: ${bad.length} (e.g. ${bad[0]!.messageId.toString()}: ${bad[0]!._count._all} rows)`,
    );
  }
  // Distinct versions per message: the unique key (message_id, version, received_at) makes
  // count = max + 1 with min 0 equivalent to "0..max without gaps or repeats".
  const stateChanged = await prisma.messageOutbox.count({
    where: { organizationId: { in: orgs }, eventType: 'mail.message.state_changed.v1' },
  });
  const transitionsAfterCreation = n * (expected.version - 1);
  if (stateChanged !== transitionsAfterCreation) {
    problems.push(
      `state_changed outbox rows: ${stateChanged}, expected ${transitionsAfterCreation}`,
    );
  }
  return problems;
}

export interface FixtureMessage extends MessageKey {
  publicId: string;
  organizationId: bigint;
  emlObjectKey: string;
  version: number;
  recipients: { id: bigint; address: string; rcptSeq: number }[];
}

/** Reason codes of the fixture's last history row (what that state's producer would write). */
const FIXTURE_REASON: Partial<Record<MessageStatus, string>> = {
  approved: 'dev_passthrough',
  scanning: 'scan_started',
  scanned: 'scan_complete',
  scan_failed: 'scan_error',
  policy_evaluated: 'policy_decided',
  quarantined: 'policy_quarantine',
  held_for_review: 'policy_hold',
};

const sha256hex = (text: string | Buffer) => createHash('sha256').update(text).digest('hex');

/**
 * A stored message of `organizationId` in `state`, as a stack-suite PRECONDITION (L8.6: fixtures
 * may insert rows in any state; no production path does): the EML in MinIO under the
 * organization's prefix, the registry row, `email_messages` in `state` with its version, the
 * recipients and a matching history (`NULL → received` v0, `received → persisted` v1 as the SMTP
 * commit writes them, then one `persisted → <state>` row v2 for any later state, actor
 * `fixture`). `statusChangedAt` lets a suite backdate the state (expiry). The message is not
 * ingested through SMTP, so the dev pass-through never approves it on its own.
 */
export async function insertFixtureMessage(
  fx: SmtpFixtures,
  options: {
    organizationId: bigint;
    state: MessageStatus;
    recipients: readonly string[];
    recipientStatus?: RecipientStatus;
    direction?: MessageDirection;
    domainId?: bigint | null;
    statusChangedAt?: Date;
    /** Default: one second ago. Rows that reference the message must not be older. */
    receivedAt?: Date;
    subject?: string;
  },
): Promise<FixtureMessage> {
  const org = options.organizationId;
  const receivedAt = options.receivedAt ?? new Date(Date.now() - 1_000);
  const statusChangedAt = options.statusChangedAt ?? receivedAt;
  const direction = options.direction ?? 'inbound';
  const eml = [
    'From: lifecycle-sender@example.org',
    `To: ${options.recipients.join(', ')}`,
    `Subject: ${options.subject ?? 'Lifecycle stack fixture'}`,
    `Message-ID: <${randomUUID()}@lifecycle.integration.test>`,
    `Date: ${receivedAt.toUTCString().replace('GMT', '+0000')}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Lifecycle stack fixture.',
    '',
  ].join('\r\n');
  const identity = await fx.prisma.messageIdentity.create({
    data: { organizationId: org, ingestKey: `it-${randomUUID()}`, receivedAt },
    select: { id: true, publicId: true },
  });
  const emlObjectKey = `org/${org.toString()}/eml/it/${randomUUID()}.eml`;
  await fx.s3.send(
    new PutObjectCommand({ Bucket: fx.bucket, Key: emlObjectKey, Body: Buffer.from(eml) }),
  );
  const steps: { from: MessageStatus | null; to: MessageStatus; reason: string | null }[] = [
    { from: null, to: 'received', reason: 'smtp_accepted' },
    { from: 'received', to: 'persisted', reason: 'committed' },
  ];
  if (options.state !== 'persisted') {
    steps.push({
      from: 'persisted',
      to: options.state,
      reason: FIXTURE_REASON[options.state] ?? null,
    });
  }
  const version = steps.length - 1;
  await fx.prisma.emailMessage.create({
    data: {
      id: identity.id,
      receivedAt,
      organizationId: org,
      domainId: options.domainId ?? null,
      direction,
      status: options.state,
      statusChangedAt,
      version,
      lifecycleRound: 0,
      statusReason: steps.at(-1)!.reason,
      envelopeFrom: 'lifecycle-sender@example.org',
      sizeBytes: Buffer.byteLength(eml),
      recipientCount: options.recipients.length,
      emlObjectKey,
      emlSha256: sha256hex(eml),
      clientIp: '203.0.113.9',
      clientHelo: 'mail.example.org',
    },
  });
  const recipients: FixtureMessage['recipients'] = [];
  for (const [rcptSeq, address] of options.recipients.entries()) {
    const row = await fx.prisma.emailRecipient.create({
      data: {
        receivedAt,
        messageId: identity.id,
        organizationId: org,
        rcptSeq,
        address,
        direction,
        status: options.recipientStatus ?? 'pending',
      },
      select: { id: true },
    });
    recipients.push({ id: row.id, address, rcptSeq });
  }
  await fx.prisma.emailMessageStatusHistory.createMany({
    data: steps.map((step, index) => ({
      receivedAt,
      messageId: identity.id,
      organizationId: org,
      version: index,
      fromStatus: step.from,
      toStatus: step.to,
      reasonCode: step.reason,
      changedAt: index < 2 ? receivedAt : statusChangedAt,
      actorRole: index < 2 ? 'ingestion' : 'fixture',
      actorService: index < 2 ? 'smtp-adapter' : 'integration-test',
      actorType: 'system' as const,
      transitionKey: sha256hex(`fixture:${identity.id.toString()}:${index}`),
      occurredAt: index < 2 ? receivedAt : statusChangedAt,
    })),
  });
  return {
    id: identity.id,
    publicId: identity.publicId,
    receivedAt,
    organizationId: org,
    emlObjectKey,
    version,
    recipients,
  };
}
