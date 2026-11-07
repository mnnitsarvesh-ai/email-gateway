import { AmqpConnection, ConfirmPublisher } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import { EventTypes, type EventEnvelope } from '@email-gateway/event-contracts';
import { ManagementApi } from './broker';
import { compose, composeOk, run, runningServices, waitFor } from './compose';
import { workerHealth } from './delivery-worker';
import { stack } from './env';
import { emailWorkerHealth, emailWorkerMetrics } from './mime-stack';
import { routingStackGate } from './routing-stack';
import type { SmtpStackGate } from './smtp-stack';

/**
 * Shared pieces of the step 3.2 stack messaging suites (tests/integration/messaging-*.test.ts,
 * docs/plan/steps/07-rabbitmq.md §10, WP5). They run against the LIVE containers of the apps
 * profile: smtp-tools → postfix:25 → smtp-adapter (EML in MinIO, `mail.message.received.v1` in
 * the outbox) → event-relay (confirmed publish) → `email.received` → email-worker (MIME parse,
 * `mail.message.parsed.v1`) → event-relay → `scan.spam` → email-worker scan role (Rspamd,
 * `mail.message.scanned.v1`, step 4.1) → the DEVELOPMENT-ONLY dev pass-through approval of
 * scanned mail (outbox feed) → event-relay → `email.delivery.pending` →
 * delivery-worker planner → reinjection → postfix-outbound → mail-sink. Chaos is applied to the
 * real containers (`docker compose restart|pause|kill`), so the suites need the containers, not
 * host processes.
 */
export const MIME_LEDGER = 'email-worker.mime-parser';
/** Ledger of the Rspamd engine consumer on `scan.spam` (step 4.1 S2). */
export const SCAN_LEDGER = 'email-worker.scan.rspamd';
/** Step 4.2: the attachment engine's ledger consumer (scan.attachment). */
export const ATTACHMENT_SCAN_LEDGER = 'email-worker.scan.attachment';
/** Step 4.3: the URL engine's ledger consumer (scan.url). */
export const URL_SCAN_LEDGER = 'email-worker.scan.url';
/** Step 4.4: the BEC engine's ledger consumer (scan.bec, stage-2: `scan_stage_ready.v1`). */
export const BEC_SCAN_LEDGER = 'email-worker.scan.bec';
/** Step 4.5: the DLP engine's ledger consumer (scan.dlp, stage 1: `parsed.v1`). */
export const DLP_SCAN_LEDGER = 'email-worker.scan.dlp';
/**
 * Step 4.2 A1, step 4.3 U1, step 4.4 B1, step 4.5 D1: every round requires Rspamd, the
 * attachment engine, the URL engine, the BEC engine and the DLP engine
 * (`SCAN_ENGINES=rspamd,attachment,url,bec,dlp`).
 */
export const REQUIRED_ENGINE_COUNT = 5;
export const PLANNER_LEDGER = 'delivery-worker.planner';
export const QUEUES = {
  received: 'email.received',
  pending: 'email.delivery.pending',
  deadLetter: 'email.dead-letter',
} as const;

type Logger = ConstructorParameters<typeof AmqpConnection>[0]['logger'];

/** A logger that discards everything (the library logs ids and codes only anyway). */
export function silentLogger(): Logger {
  const noop = () => undefined;
  const make = (): unknown => ({
    child: () => make(),
    trace: noop,
    debug: noop,
    info: noop,
    warn: noop,
    error: noop,
    fatal: noop,
  });
  return make() as Logger;
}

const silent = silentLogger();

const REQUIRED_CONTAINERS = ['event-relay', 'email-worker', 'delivery-worker', 'api', 'rabbitmq'];

const HOW_TO_START = [
  'The messaging stack suites need the apps profile as CONTAINERS built from this tree',
  '(images one at a time on an 8 GB Docker VM), the smtp-test profile and the dev pass-through:',
  '  docker compose --profile apps build <service>   (one at a time)',
  '  docker compose --profile apps up -d --wait',
  '  docker compose --profile smtp-test up -d --wait',
  '  DELIVERY_DEV_PASSTHROUGH_ENABLED=true in .env (local/CI only)',
].join('\n');

async function ready(service: 'event-relay' | 'api'): Promise<boolean> {
  try {
    const res = await fetch(`http://${stack.host}:${stack.ports.services[service]}/health/ready`, {
      signal: AbortSignal.timeout(3_000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

let cached: Promise<SmtpStackGate> | undefined;

/** The routing stack gate plus the step 3.2 containers (event-relay, RabbitMQ consumers). */
export function messagingStackGate(): Promise<SmtpStackGate> {
  cached ??= detect();
  return cached;
}

async function detect(): Promise<SmtpStackGate> {
  const base = await routingStackGate();
  if (base.skip) return base;
  const problems: string[] = base.problem ? [base.problem] : [];
  const services = await runningServices();
  const missing = REQUIRED_CONTAINERS.filter((s) => !services.has(s));
  if (missing.length > 0) problems.push(`apps containers not running: ${missing.join(', ')}`);
  if (!(await ready('event-relay'))) problems.push('event-relay is not ready (port 3070)');
  if (!(await ready('api'))) problems.push('api is not ready');
  if (!(await emailWorkerHealth('ready'))) problems.push('email-worker is not ready');
  const metrics = await emailWorkerMetrics();
  if (!metrics || !/^# TYPE amqp_consumer_messages_total /m.test(metrics)) {
    problems.push('the email-worker does not consume RabbitMQ (no amqp_consumer_messages_total)');
  }
  if (!(await workerHealth('ready'))) problems.push('delivery-worker is not ready');
  return {
    ...base,
    problem: problems.length > 0 ? `${problems.join('\n')}\n${HOW_TO_START}` : undefined,
  };
}

/** Administrator AMQP URL on the topology vhost (never logged). */
export function adminVhostUrl(): string {
  const url = new URL(stack.rabbitmqUrl());
  url.pathname = `/${encodeURIComponent(stack.rabbitmqVhost())}`;
  return url.toString();
}

/**
 * An administrator connection to the live topology vhost: passive queue depths (exact, unlike
 * the management statistics) and a confirm publisher (appId `event-relay`, like the relay).
 */
export class LiveBroker {
  readonly mgmt = new ManagementApi();

  private constructor(
    readonly connection: AmqpConnection,
    readonly publisher: ConfirmPublisher,
  ) {}

  static async connect(): Promise<LiveBroker> {
    const connection = new AmqpConnection({
      urls: [adminVhostUrl()],
      connectionName: 'it-messaging-stack',
      logger: silent,
      reconnect: { baseMs: 200, maxMs: 2_000 },
    });
    connection.start();
    await connection.waitUntilConnected(30_000);
    const publisher = new ConfirmPublisher({
      connection,
      logger: silent,
      appId: 'event-relay',
      confirmTimeoutMs: 15_000,
      maxMessageBytes: 131_072,
    });
    return new LiveBroker(connection, publisher);
  }

  /** Ready messages of a queue (passive declare; reconnects after a broker restart). */
  async depth(queue: string): Promise<number> {
    await this.connection.waitUntilConnected(60_000);
    const channel = await this.connection.createChannel();
    try {
      return (await channel.checkQueue(queue)).messageCount;
    } finally {
      await channel.close().catch(() => undefined);
    }
  }

  /** Publishes envelopes exactly as the relay does; throws unless every one is confirmed. */
  async publish(events: EventEnvelope[]): Promise<void> {
    const results = await this.publisher.publishBatch(events.map((envelope) => ({ envelope })));
    const failed = results.filter((r) => r.outcome !== 'confirmed');
    if (failed.length > 0) {
      throw new Error(`publish not confirmed: ${failed.map((f) => f.outcome).join(',')}`);
    }
  }

  async close(): Promise<void> {
    await this.publisher.close();
    await this.connection.close();
  }
}

/** What the relay publishes for an outbox row (envelope from the row, ADR-0023). */
export function envelopeOfRow(row: {
  eventId: string;
  eventType: string;
  createdAt: Date;
  correlationId: string;
  organizationId: bigint;
  payload: unknown;
}): EventEnvelope {
  return {
    eventId: row.eventId,
    eventType: row.eventType,
    occurredAt: row.createdAt.toISOString(),
    correlationId: row.correlationId,
    organizationId: row.organizationId.toString(),
    payload: row.payload,
  };
}

export interface PipelineCounts {
  messages: number;
  recipients: number;
  /** `email_message_parses` rows (one per message by a unique key). */
  parses: number;
  /** Parse rows in a final state. */
  parsesFinal: number;
  receivedEvents: number;
  /** `message_idempotency` rows of `email-worker.mime-parser` for the received events. */
  mimeLedger: number;
  /** `mail.message.parsed.v1` + `parse_failed.v1` outbox rows (one per handled parse). */
  parseEvents: number;
  /** Step 4.1: `email_scans` rows (one per message and round by a unique key). */
  scans: number;
  /** Final `scan_engine_results` rows (one per round and engine by a unique key). */
  scanFinals: number;
  /** `message_idempotency` rows of `email-worker.scan.rspamd` for the parsed events. */
  scanLedger: number;
  /** Step 4.2: `message_idempotency` rows of `email-worker.scan.attachment` (parsed events). */
  attachmentLedger: number;
  /** Step 4.3: `message_idempotency` rows of `email-worker.scan.url` (parsed events). */
  urlLedger: number;
  /** Step 4.4: `mail.message.scan_stage_ready.v1` outbox rows (one per round, B2). */
  stageEvents: number;
  /** Step 4.4: `message_idempotency` rows of `email-worker.scan.bec` (stage events). */
  becLedger: number;
  /** Step 4.4: `bec_scan_results` rows (one per round by a unique key). */
  becResults: number;
  /** Step 4.5: `message_idempotency` rows of `email-worker.scan.dlp` (parsed events). */
  dlpLedger: number;
  /**
   * Step 4.5: `dlp_scan_results` rows (one per round by a unique key; an inbound round's
   * `skipped` final writes one too, WP3 deviation 5).
   */
  dlpResults: number;
  /** `mail.message.scanned.v1` outbox rows (one per completed round). */
  scannedEvents: number;
  approvals: number;
  /** `message_idempotency` rows of `delivery-worker.planner` for the approvals. */
  plannerLedger: number;
  deliveries: number;
  delivered: number;
  /** Recipients with more than one delivery of the same delivery sequence. */
  duplicateDeliveries: number;
  reinjections: number;
  /** Outbox rows of the organizations with `published_at IS NULL`. */
  unpublished: number;
  outboxRows: number;
}

async function ledgerCount(prisma: PrismaClient, consumer: string, eventIds: string[]) {
  let total = 0;
  for (let i = 0; i < eventIds.length; i += 1000) {
    total += await prisma.messageIdempotency.count({
      where: { consumer, eventId: { in: eventIds.slice(i, i + 1000) } },
    });
  }
  return total;
}

/** Counts of every stage's rows for `organizationIds` on the MySQL writer. */
export async function pipelineCounts(
  prisma: PrismaClient,
  organizationIds: readonly bigint[],
): Promise<PipelineCounts> {
  const where = { organizationId: { in: [...organizationIds] } };
  const received = await prisma.messageOutbox.findMany({
    where: { ...where, eventType: EventTypes.MessageReceived },
    select: { eventId: true },
  });
  const approvals = await prisma.messageOutbox.findMany({
    where: { ...where, eventType: EventTypes.DeliveryApproved },
    select: { eventId: true },
  });
  const parsed = await prisma.messageOutbox.findMany({
    where: { ...where, eventType: EventTypes.MessageParsed },
    select: { eventId: true },
  });
  const stage = await prisma.messageOutbox.findMany({
    where: { ...where, eventType: EventTypes.MessageScanStageReady },
    select: { eventId: true },
  });
  const perRecipient = await prisma.emailDelivery.groupBy({
    by: ['recipientId', 'deliverySeq'],
    where,
    _count: { _all: true },
  });
  return {
    messages: await prisma.emailMessage.count({ where }),
    recipients: await prisma.emailRecipient.count({ where }),
    parses: await prisma.emailMessageParse.count({ where }),
    parsesFinal: await prisma.emailMessageParse.count({
      where: { ...where, status: { in: ['parsed', 'parsed_with_defects'] } },
    }),
    receivedEvents: received.length,
    mimeLedger: await ledgerCount(
      prisma,
      MIME_LEDGER,
      received.map((r) => r.eventId),
    ),
    parseEvents: await prisma.messageOutbox.count({
      where: {
        ...where,
        eventType: { in: [EventTypes.MessageParsed, EventTypes.MessageParseFailed] },
      },
    }),
    scans: await prisma.emailScan.count({ where }),
    scanFinals: await prisma.scanEngineResult.count({ where: { ...where, isFinal: true } }),
    scanLedger: await ledgerCount(
      prisma,
      SCAN_LEDGER,
      parsed.map((p) => p.eventId),
    ),
    attachmentLedger: await ledgerCount(
      prisma,
      ATTACHMENT_SCAN_LEDGER,
      parsed.map((p) => p.eventId),
    ),
    urlLedger: await ledgerCount(
      prisma,
      URL_SCAN_LEDGER,
      parsed.map((p) => p.eventId),
    ),
    stageEvents: stage.length,
    becLedger: await ledgerCount(
      prisma,
      BEC_SCAN_LEDGER,
      stage.map((e) => e.eventId),
    ),
    becResults: await prisma.becScanResult.count({ where }),
    dlpLedger: await ledgerCount(
      prisma,
      DLP_SCAN_LEDGER,
      parsed.map((p) => p.eventId),
    ),
    dlpResults: await prisma.dlpScanResult.count({ where }),
    scannedEvents: await prisma.messageOutbox.count({
      where: { ...where, eventType: EventTypes.MessageScanned },
    }),
    approvals: approvals.length,
    plannerLedger: await ledgerCount(
      prisma,
      PLANNER_LEDGER,
      approvals.map((a) => a.eventId),
    ),
    deliveries: await prisma.emailDelivery.count({ where }),
    delivered: await prisma.emailDelivery.count({ where: { ...where, status: 'delivered' } }),
    duplicateDeliveries: perRecipient.filter((g) => g._count._all > 1).length,
    reinjections: await prisma.deliveryReinjection.count({ where }),
    unpublished: await prisma.messageOutbox.count({ where: { ...where, publishedAt: null } }),
    outboxRows: await prisma.messageOutbox.count({ where }),
  };
}

/**
 * True once `n` single-recipient messages went the whole way: parsed, scanned (step 4.1),
 * planned, delivered.
 */
export function pipelineComplete(c: PipelineCounts, n: number): boolean {
  return (
    c.messages === n &&
    c.parsesFinal === n &&
    c.mimeLedger === n &&
    c.parseEvents === n &&
    c.scannedEvents === n &&
    c.scanLedger === n &&
    c.approvals === n &&
    c.plannerLedger === n &&
    c.delivered === n &&
    c.unpublished === 0
  );
}

/** Waits until `pipelineComplete`; the timeout error lists every count. */
export async function waitForPipeline(
  prisma: PrismaClient,
  organizationIds: readonly bigint[],
  n: number,
  timeoutMs: number,
): Promise<PipelineCounts> {
  let last: PipelineCounts | undefined;
  try {
    return await waitFor(
      `${n} messages parsed, planned and delivered`,
      async () => {
        last = await pipelineCounts(prisma, organizationIds);
        return pipelineComplete(last, n) ? last : undefined;
      },
      { timeoutMs, intervalMs: 3_000 },
    );
  } catch (err) {
    throw new Error(`${(err as Error).message}\n  counts: ${JSON.stringify(last)}`);
  }
}

/**
 * The exactly-once assertions of every chaos suite for `n` single-recipient messages: one parse
 * row, one MIME ledger row and one parse event per message; one scan round, one final result per
 * required engine (Rspamd, step 4.1, the attachment engine, step 4.2, the URL engine, step 4.3,
 * the BEC engine, step 4.4, and the DLP engine, step 4.5), one ledger row per engine consumer,
 * one stage trigger, one bec result, one dlp result and one `scanned.v1` per message; one approval, one
 * planner ledger row, one delivery and one reinjection group per message; nothing unpublished.
 */
export function exactlyOnceProblems(c: PipelineCounts, n: number): string[] {
  const expected: [keyof PipelineCounts, number][] = [
    ['messages', n],
    ['recipients', n],
    ['parses', n],
    ['parsesFinal', n],
    ['receivedEvents', n],
    ['mimeLedger', n],
    ['parseEvents', n],
    ['scans', n],
    ['scanFinals', n * REQUIRED_ENGINE_COUNT],
    ['scanLedger', n],
    ['attachmentLedger', n],
    ['urlLedger', n],
    ['stageEvents', n],
    ['becLedger', n],
    ['becResults', n],
    ['dlpLedger', n],
    ['dlpResults', n],
    ['scannedEvents', n],
    ['approvals', n],
    ['plannerLedger', n],
    ['deliveries', n],
    ['delivered', n],
    ['duplicateDeliveries', 0],
    ['reinjections', n],
    ['unpublished', 0],
  ];
  return expected
    .filter(([key, value]) => c[key] !== value)
    .map(([key, value]) => `${key}=${c[key]} (expected ${value})`);
}

/** `docker compose ps` health of one service (`healthy`, `starting`, … or '' when absent). */
export async function containerHealth(service: string): Promise<string> {
  const id = (await compose(['ps', '--all', '--quiet', service], { timeoutMs: 20_000 })).stdout
    .trim()
    .split('\n')[0];
  if (!id || !/^[0-9a-f]{12,64}$/.test(id)) return '';
  const inspect = await run(
    'docker',
    [
      'inspect',
      '--format',
      '{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{end}}',
      id,
    ],
    { timeoutMs: 20_000 },
  );
  return inspect.stdout.trim();
}

/** Waits until a container is running and (when it has a healthcheck) healthy. */
export async function waitForHealthy(service: string, timeoutMs = 180_000): Promise<void> {
  await waitFor(
    `${service} healthy`,
    async () => {
      const state = await containerHealth(service);
      return state === 'running/healthy' || state === 'running/';
    },
    { timeoutMs, intervalMs: 2_000 },
  );
}

/** The container id of a running service. */
export async function containerId(service: string): Promise<string> {
  const id = (await composeOk(['ps', '--all', '--quiet', service], { timeoutMs: 20_000 })).stdout
    .trim()
    .split('\n')[0];
  if (!id || !/^[0-9a-f]{12,64}$/.test(id)) throw new Error(`${service} container not found`);
  return id;
}

/** Every application series of `/metrics` of a service whose name starts with `prefix`. */
export async function metricLines(
  service: 'email-worker' | 'delivery-worker' | 'event-relay',
  prefix: string,
): Promise<string[]> {
  const res = await fetch(`http://${stack.host}:${stack.ports.services[service]}/metrics`, {
    signal: AbortSignal.timeout(5_000),
  });
  if (!res.ok) return [];
  return (await res.text()).split('\n').filter((l) => l.startsWith(prefix));
}

/**
 * Event-relay steady state: every shard held by the live relay and its lag ~0 (the gauges of
 * §5.3, `outbox_relay_shards_held`, `outbox_relay_lag_seconds{shard}`).
 */
export async function relayState(): Promise<{ shardsHeld: number; maxLagSeconds: number }> {
  const held = await metricLines('event-relay', 'outbox_relay_shards_held');
  const lag = await metricLines('event-relay', 'outbox_relay_lag_seconds');
  const value = (line: string) => Number(line.split(' ').at(-1));
  return {
    shardsHeld: held.reduce((sum, l) => sum + value(l), 0),
    maxLagSeconds: lag.reduce((max, l) => Math.max(max, value(l)), 0),
  };
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Prints a line for the step's verification record (§13). */
export function record(suite: string, fields: Record<string, unknown>): void {
  const parts = Object.entries(fields).map(([k, v]) => `${k}=${String(v)}`);
  process.stdout.write(`[${suite}] ${parts.join(' ')}\n`);
}
