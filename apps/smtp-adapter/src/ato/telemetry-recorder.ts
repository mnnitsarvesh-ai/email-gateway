import {
  Inject,
  Injectable,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
} from '@nestjs/common';
import {
  type Counter,
  type Gauge,
  MetricsService,
  PrismaService,
  uuidv7,
} from '@email-gateway/common';
import {
  EventTypes,
  SMTP_TELEMETRY_MAX_ENTRIES,
  smtpAuthRecordedV1,
  smtpSubmissionRecordedV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import { createHmac } from 'node:crypto';
import { hostname } from 'node:os';
import { ADAPTER_CONFIG, ADAPTER_LOGGER, type SmtpAdapterConfig } from '../config';
import { parseIpKey } from '../connectors/addresses';

/** Outbox aggregate of every telemetry batch (D2): the organization id as `aggregate_id`. */
export const SMTP_TELEMETRY_AGGREGATE_TYPE = 'smtp_telemetry';
/** Bound of the shutdown flush (D4). */
export const TELEMETRY_SHUTDOWN_FLUSH_MS = 5000;
/** How long a missing platform organization is remembered before it is looked up again. */
const PLATFORM_NEGATIVE_CACHE_MS = 60_000;
const WARN_INTERVAL_MS = 60_000;

/** Generated connector usernames (`egc-` + 20 lower-case base32; api `SASL_USERNAME_PATTERN`). */
const GENERATED_USERNAME = /^egc-[a-z2-7]{20}$/;
const QUEUE_ID = /^[0-9A-Za-z]{1,32}$/;
const HELO = /^[\x21-\x7e]{1,255}$/;
const TLS_PROTOCOL = /^[A-Za-z0-9._-]{1,16}$/;
const SENDER = /^[^\s@A-Z]+@[^\s@A-Z]+$/;
const INSTANCE_UNSAFE = /[^A-Za-z0-9._-]/g;

export type TelemetryKind = 'auth' | 'submission';
export type TelemetryAuthResult = 'ok' | 'fail' | 'throttled' | 'blocked';
export type TelemetryAuthFailureReason =
  | 'bad_credentials'
  | 'connector_inactive'
  | 'organization_inactive'
  | 'malformed'
  | 'ato_blocked'
  | 'ip_throttled';

/**
 * One AUTH decision as the SASL server knows it after its reply. A resolved connector carries
 * its id and organization; an unresolved username (unknown, malformed or not looked up because
 * the IP was throttled) carries the raw username, which the recorder turns into a keyed hash
 * immediately and never keeps.
 */
export interface AuthTelemetry {
  occurredAt: Date;
  result: TelemetryAuthResult;
  mechanism: 'plain' | 'login' | 'unknown';
  clientIp: string | null;
  connector: { id: bigint; organizationId: bigint } | null;
  username: string | null;
  failureReason: TelemetryAuthFailureReason | null;
}

/** One message the policy service passed at END-OF-MESSAGE (`submission` / `relay`). */
export interface SubmissionTelemetry {
  occurredAt: Date;
  organizationId: bigint;
  context: 'submission' | 'relay';
  connectorId: bigint;
  connectorAuthType: 'sasl' | 'source_ip' | 'client_certificate';
  queueId: string | undefined;
  clientIp: string | undefined;
  heloName: string | undefined;
  tlsProtocol: string | undefined;
  senderAddress: string | undefined;
  recipientCount: number;
  sizeBytes: number;
}

interface Buffered {
  kind: TelemetryKind;
  /** null: the platform organization (unknown usernames). */
  organizationId: bigint | null;
  /** Epoch ms when buffered (expiry). */
  bufferedAt: number;
  entry: Record<string, unknown>;
}

export type AtoTelemetryConfig = Pick<
  SmtpAdapterConfig,
  | 'SMTP_ATO_TELEMETRY_ENABLED'
  | 'SMTP_ATO_TELEMETRY_FLUSH_MS'
  | 'SMTP_ATO_TELEMETRY_BATCH_MAX'
  | 'SMTP_ATO_TELEMETRY_BUFFER_MAX'
  | 'SMTP_ATO_TELEMETRY_MAX_AGE_MS'
  | 'SMTP_ATO_USERNAME_HASH_KEY'
>;

/** `producer.instance` of the batches: host name and pid, reduced to the contract's charset. */
export function telemetryInstanceName(
  host: string = hostname(),
  pid: number = process.pid,
): string {
  const base = host.replace(INSTANCE_UNSAFE, '-').slice(0, 50) || 'smtp-adapter';
  return `${base}.${pid}`.slice(0, 64);
}

/**
 * Account takeover telemetry of the smtp-adapter (step 8.4 D4, ADR-0073). AUTH decisions and
 * accepted submissions are pushed synchronously into one bounded in-process buffer **after** the
 * SMTP reply was sent (never awaited by a reply path). A flusher every
 * SMTP_ATO_TELEMETRY_FLUSH_MS groups the entries by (organization, kind) into batches of at most
 * SMTP_ATO_TELEMETRY_BATCH_MAX and inserts one `message_outbox` row per batch, all in one
 * multi-row insert on the writer (`smtp.auth.recorded.v1` / `smtp.submission.recorded.v1`,
 * aggregate `smtp_telemetry`).
 *
 * Loss model (documented, D4): a full buffer drops the newest entry (`dropped`); on a database
 * error entries stay buffered and are retried until SMTP_ATO_TELEMETRY_MAX_AGE_MS, then dropped
 * (`expired`); a crash loses at most one flush interval. Unknown usernames are represented only
 * by the first 16 hex characters of HMAC-SHA256(SMTP_ATO_USERNAME_HASH_KEY, username) and go
 * into batches of the platform organization (`organizations.kind = 'platform'`, resolved once;
 * when it does not exist those entries are dropped and counted). Nothing here ever looks up a
 * feature flag: the ato-worker drops events of organizations without ATO.
 */
@Injectable()
export class AtoTelemetryRecorder implements OnApplicationBootstrap, OnModuleDestroy {
  readonly instance = telemetryInstanceName();
  private readonly logger: Logger;
  private readonly total: Counter<'kind' | 'result'>;
  private readonly bufferGauge: Gauge;
  private buffer: Buffered[] = [];
  private timer: NodeJS.Timeout | undefined;
  private stopped = false;
  private flushing: Promise<void> | undefined;
  private platformId: bigint | undefined;
  private platformMissingUntil = 0;
  private lastWarnAt = 0;

  constructor(
    private readonly prisma: PrismaService,
    metrics: MetricsService,
    @Inject(ADAPTER_CONFIG) private readonly config: AtoTelemetryConfig,
    @Inject(ADAPTER_LOGGER) logger: Logger,
  ) {
    this.logger = logger.child({ component: 'ato-telemetry' });
    this.total = metrics.counter(
      'smtp_ato_telemetry_total',
      'ATO telemetry entries by kind and result (recorded, flushed, dropped, expired, error)',
      ['kind', 'result'],
    );
    this.bufferGauge = metrics.gauge(
      'smtp_ato_telemetry_buffer_entries',
      'ATO telemetry entries waiting in the in-process buffer',
    );
  }

  get enabled(): boolean {
    return this.config.SMTP_ATO_TELEMETRY_ENABLED;
  }

  /** Entries currently buffered (tests, the gauge). */
  get size(): number {
    return this.buffer.length;
  }

  onApplicationBootstrap(): void {
    if (!this.enabled) {
      this.logger.info('ATO telemetry disabled (SMTP_ATO_TELEMETRY_ENABLED=false)');
      return;
    }
    this.schedule();
  }

  async onModuleDestroy(): Promise<void> {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    if (!this.enabled) return;
    // One final flush, bounded: shutdown never hangs on a slow database.
    await Promise.race([
      this.flush().catch(() => undefined),
      new Promise<void>((resolve) => setTimeout(resolve, TELEMETRY_SHUTDOWN_FLUSH_MS).unref()),
    ]);
  }

  /** Records one AUTH decision (synchronous; call after the reply was written). */
  recordAuth(input: AuthTelemetry): void {
    if (!this.enabled) return;
    const known = input.connector !== null;
    const username = input.username;
    const entry = {
      occurredAt: input.occurredAt.toISOString(),
      result: input.result,
      mechanism: input.mechanism,
      connectorId: known ? input.connector!.id.toString() : null,
      clientIp: parseIpKey(input.clientIp ?? undefined)?.text ?? null,
      usernameClass: known
        ? 'connector'
        : username !== null && GENERATED_USERNAME.test(username)
          ? 'unknown_generated_format'
          : 'unknown_other',
      usernameHash: known || username === null || username === '' ? null : this.hash(username),
      failureReason: input.result === 'ok' ? null : input.failureReason,
    };
    this.push('auth', known ? input.connector!.organizationId : null, entry);
  }

  /** Records one accepted submission (synchronous; call after the END-OF-MESSAGE answer). */
  recordSubmission(input: SubmissionTelemetry): void {
    if (!this.enabled) return;
    const sender = input.senderAddress?.toLowerCase() ?? '';
    if (sender.length > 320 || !SENDER.test(sender)) {
      // Null sender (or not an address): no mailbox account to attribute; not an entry.
      return;
    }
    const entry = {
      occurredAt: input.occurredAt.toISOString(),
      context: input.context,
      connectorId: input.connectorId.toString(),
      connectorAuthType: input.connectorAuthType,
      queueId: input.queueId !== undefined && QUEUE_ID.test(input.queueId) ? input.queueId : null,
      clientIp: parseIpKey(input.clientIp)?.text ?? null,
      heloName: input.heloName !== undefined && HELO.test(input.heloName) ? input.heloName : null,
      tlsProtocol:
        input.tlsProtocol !== undefined && TLS_PROTOCOL.test(input.tlsProtocol)
          ? input.tlsProtocol
          : null,
      senderAddress: sender,
      recipientCount: Math.min(10_000, Math.max(0, Math.trunc(input.recipientCount))),
      sizeBytes: Math.max(0, Math.trunc(input.sizeBytes)),
    };
    this.push('submission', input.organizationId, entry);
  }

  /**
   * Flushes the buffer once (the timer, shutdown and tests call it). Concurrent calls share one
   * run. Never throws: failures are counted and the entries stay buffered until they expire.
   */
  flush(): Promise<void> {
    this.flushing ??= this.flushOnce().finally(() => {
      this.flushing = undefined;
    });
    return this.flushing;
  }

  private push(kind: TelemetryKind, organizationId: bigint | null, entry: Buffered['entry']) {
    if (this.buffer.length >= this.config.SMTP_ATO_TELEMETRY_BUFFER_MAX) {
      this.total.inc({ kind, result: 'dropped' });
      this.warn('ATO telemetry buffer full; dropping the newest entry');
      return;
    }
    this.buffer.push({ kind, organizationId, bufferedAt: Date.now(), entry });
    this.total.inc({ kind, result: 'recorded' });
    this.bufferGauge.set(this.buffer.length);
  }

  private hash(username: string): string {
    return createHmac('sha256', this.config.SMTP_ATO_USERNAME_HASH_KEY ?? '')
      .update(username, 'utf8')
      .digest('hex')
      .slice(0, 16);
  }

  private async flushOnce(): Promise<void> {
    const now = Date.now();
    const taken = this.buffer;
    this.buffer = [];
    const fresh: Buffered[] = [];
    for (const item of taken) {
      if (now - item.bufferedAt > this.config.SMTP_ATO_TELEMETRY_MAX_AGE_MS) {
        this.total.inc({ kind: item.kind, result: 'expired' });
      } else {
        fresh.push(item);
      }
    }
    if (fresh.length === 0) {
      this.bufferGauge.set(this.buffer.length);
      return;
    }

    let platformId: bigint | null = null;
    if (fresh.some((item) => item.organizationId === null)) {
      try {
        platformId = await this.platformOrganizationId(now);
      } catch (err) {
        this.requeue(fresh, err, 'platform organization lookup failed; telemetry kept');
        return;
      }
    }
    const routable: Buffered[] = [];
    for (const item of fresh) {
      if (item.organizationId === null && platformId === null) {
        this.total.inc({ kind: item.kind, result: 'dropped' });
        this.warn('no platform organization; unknown-username telemetry dropped');
      } else {
        routable.push(item);
      }
    }

    const rows = this.batches(routable, platformId);
    if (rows.length === 0) {
      this.bufferGauge.set(this.buffer.length);
      return;
    }
    try {
      await this.prisma.messageOutbox.createMany({ data: rows.map((row) => row.data) });
    } catch (err) {
      this.requeue(
        rows.flatMap((row) => row.items),
        err,
        'telemetry flush failed; entries kept until they expire',
      );
      return;
    }
    for (const row of rows) {
      this.total.inc({ kind: row.kind, result: 'flushed' }, row.items.length);
    }
    this.bufferGauge.set(this.buffer.length);
  }

  /** Groups by (organization, kind) in arrival order, chunks, validates against the contract. */
  private batches(items: readonly Buffered[], platformId: bigint | null) {
    const groups = new Map<string, { kind: TelemetryKind; org: bigint; items: Buffered[] }>();
    for (const item of items) {
      const org = item.organizationId ?? platformId!;
      const key = `${org}:${item.kind}`;
      let group = groups.get(key);
      if (!group) {
        group = { kind: item.kind, org, items: [] };
        groups.set(key, group);
      }
      group.items.push(item);
    }
    const size = Math.min(this.config.SMTP_ATO_TELEMETRY_BATCH_MAX, SMTP_TELEMETRY_MAX_ENTRIES);
    const rows: {
      kind: TelemetryKind;
      items: Buffered[];
      data: {
        eventId: string;
        organizationId: bigint;
        eventType: string;
        aggregateType: string;
        aggregateId: string;
        correlationId: string;
        payload: object;
      };
    }[] = [];
    for (const group of groups.values()) {
      for (let start = 0; start < group.items.length; start += size) {
        const chunk = group.items.slice(start, start + size);
        const candidate = {
          producer: { instance: this.instance },
          entries: chunk.map((item, seq) => ({ seq, ...item.entry })),
        };
        const schema = group.kind === 'auth' ? smtpAuthRecordedV1 : smtpSubmissionRecordedV1;
        const parsed = schema.safeParse(candidate);
        if (!parsed.success) {
          // A recorder bug, never input data: count and drop rather than poison the outbox.
          this.total.inc({ kind: group.kind, result: 'error' }, chunk.length);
          this.logger.error(
            { kind: group.kind, issues: parsed.error.issues.slice(0, 3).map((i) => i.path) },
            'telemetry batch failed its contract; dropped',
          );
          continue;
        }
        const eventId = uuidv7();
        rows.push({
          kind: group.kind,
          items: chunk,
          data: {
            eventId,
            organizationId: group.org,
            eventType:
              group.kind === 'auth'
                ? EventTypes.SmtpAuthRecorded
                : EventTypes.SmtpSubmissionRecorded,
            aggregateType: SMTP_TELEMETRY_AGGREGATE_TYPE,
            aggregateId: group.org.toString(),
            correlationId: `smtp-telemetry:${eventId}`,
            payload: parsed.data,
          },
        });
      }
    }
    return rows;
  }

  /** Puts unflushed entries back in front (oldest first); overflow beyond the bound is dropped. */
  private requeue(items: Buffered[], err: unknown, message: string): void {
    for (const item of items) this.total.inc({ kind: item.kind, result: 'error' });
    const merged = [...items, ...this.buffer];
    const max = this.config.SMTP_ATO_TELEMETRY_BUFFER_MAX;
    for (const item of merged.slice(max)) this.total.inc({ kind: item.kind, result: 'dropped' });
    this.buffer = merged.slice(0, max);
    this.bufferGauge.set(this.buffer.length);
    this.warn(message, err);
  }

  private async platformOrganizationId(now: number): Promise<bigint | null> {
    if (this.platformId !== undefined) return this.platformId;
    if (now < this.platformMissingUntil) return null;
    const row = await this.prisma.organization.findFirst({
      where: { kind: 'platform' },
      select: { id: true },
      orderBy: { id: 'asc' },
    });
    if (!row) {
      this.platformMissingUntil = now + PLATFORM_NEGATIVE_CACHE_MS;
      return null;
    }
    this.platformId = row.id;
    return row.id;
  }

  private schedule(): void {
    if (this.stopped) return;
    this.timer = setTimeout(() => {
      void this.flush().finally(() => this.schedule());
    }, this.config.SMTP_ATO_TELEMETRY_FLUSH_MS);
    this.timer.unref();
  }

  private warn(message: string, err?: unknown): void {
    const now = Date.now();
    if (now - this.lastWarnAt < WARN_INTERVAL_MS) return;
    this.lastWarnAt = now;
    this.logger.warn(err === undefined ? {} : { err }, message);
  }
}
