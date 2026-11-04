import { MetricsService, type PublishItem, type PublishResult } from '@email-gateway/common';
import { EXAMPLE_EVENT_PAYLOADS } from '@email-gateway/event-contracts';
import { createLogger, type Logger } from '@email-gateway/logger';
import { RelayMetrics } from '../metrics/relay-metrics';
import { shardOf } from '../relay/envelope';
import type { ReconcilerLocks } from '../reconciler/outbox-reconciler';
import type {
  FailedRow,
  OutboxKey,
  OutboxRow,
  PoisonRow,
  ReadOptions,
  RelayStore,
} from '../relay/relay-store';
import type { ShardLocks } from '../relay/outbox-relay';

/** Unit-test fakes of the relay's and reconciler's collaborators (not used by production code). */

export const silentLogger: Logger = createLogger({ service: 'event-relay-test', level: 'silent' });

export function newMetrics(): { metrics: RelayMetrics; service: MetricsService } {
  const service = new MetricsService({ service: 'event-relay-test' });
  return { metrics: new RelayMetrics(service), service };
}

/** Value of a series (labels must match exactly), 0 when absent. */
export async function metricValue(
  service: MetricsService,
  name: string,
  labels: Record<string, string> = {},
): Promise<number> {
  const metric = service.registry.getSingleMetric(name);
  if (!metric) return 0;
  const data = await metric.get();
  const sample = data.values.find(
    (v) =>
      !('metricName' in v && v.metricName !== undefined && v.metricName !== name) &&
      Object.entries(labels).every(([k, value]) => String(v.labels[k]) === value) &&
      Object.keys(v.labels).filter((k) => k !== 'service').length === Object.keys(labels).length,
  );
  return sample?.value ?? 0;
}

export interface StoredRow extends OutboxRow {
  publishedAt: Date | null;
  lastError: string | null;
}

let nextId = 1n;
export const T0 = new Date('2026-11-04T10:00:00.000Z');

export function outboxRow(overrides: Partial<StoredRow> = {}): StoredRow {
  const id = overrides.id ?? nextId++;
  return {
    id,
    createdAt: new Date(T0.getTime() - 60_000),
    eventId: `0190f0a0-0000-7000-8000-${id.toString().padStart(12, '0')}`,
    organizationId: 42n,
    eventType: 'mail.message.received.v1',
    aggregateType: 'message',
    aggregateId: `m${id.toString()}`,
    correlationId: `smtp:${id.toString().padStart(8, '0')}`,
    payload: EXAMPLE_EVENT_PAYLOADS['mail.message.received.v1'],
    availableAt: new Date(T0.getTime() - 60_000),
    attempts: 0,
    publishedAt: null,
    lastError: null,
    ...overrides,
  };
}

/** In-memory `message_outbox` with the relay store's semantics. */
export class FakeRelayStore implements RelayStore {
  readonly rows: StoredRow[] = [];
  readonly reads: ReadOptions[] = [];
  oldestCalls = 0;
  failOn: Partial<
    Record<'read' | 'markPublished' | 'markFailed' | 'markPoison' | 'oldest', Error>
  > = {};
  /** Clock of `NOW(3)`. */
  now = () => T0;

  add(...rows: StoredRow[]): this {
    this.rows.push(...rows);
    this.rows.sort((a, b) => (a.id < b.id ? -1 : 1));
    return this;
  }

  get(id: bigint): StoredRow {
    const row = this.rows.find((r) => r.id === id);
    if (!row) throw new Error('no such row');
    return row;
  }

  private matches(row: StoredRow, options: Omit<ReadOptions, 'limit'>): boolean {
    return (
      row.publishedAt === null &&
      row.attempts < options.maxAttempts &&
      shardOf(row.aggregateType, row.aggregateId, options.shard.count) === options.shard.index &&
      (options.organizationIds === undefined ||
        options.organizationIds.includes(row.organizationId))
    );
  }

  readUnpublished(options: ReadOptions): Promise<OutboxRow[]> {
    this.reads.push(options);
    if (this.failOn.read) return Promise.reject(this.failOn.read);
    return Promise.resolve(
      this.rows
        .filter((r) => this.matches(r, options))
        .slice(0, options.limit)
        .map((r) => ({ ...r })),
    );
  }

  oldestUnpublished(options: Omit<ReadOptions, 'limit'>): Promise<Date | null> {
    this.oldestCalls += 1;
    if (this.failOn.oldest) return Promise.reject(this.failOn.oldest);
    const dates = this.rows
      .filter((r) => this.matches(r, options))
      .map((r) => r.createdAt.getTime());
    return Promise.resolve(dates.length === 0 ? null : new Date(Math.min(...dates)));
  }

  markPublished(rows: readonly OutboxKey[]): Promise<number> {
    if (this.failOn.markPublished) return Promise.reject(this.failOn.markPublished);
    let changed = 0;
    for (const key of rows) {
      const row = this.get(key.id);
      if (row.publishedAt === null) {
        row.publishedAt = this.now();
        changed += 1;
      }
    }
    return Promise.resolve(changed);
  }

  markFailed(rows: readonly FailedRow[]): Promise<void> {
    if (this.failOn.markFailed) return Promise.reject(this.failOn.markFailed);
    for (const failed of rows) {
      const row = this.get(failed.id);
      if (row.publishedAt !== null) continue;
      if (failed.countsAttempt) row.attempts += 1;
      row.availableAt = failed.availableAt;
      row.lastError = failed.code;
    }
    return Promise.resolve();
  }

  markPoison(rows: readonly PoisonRow[], maxAttempts: number): Promise<void> {
    if (this.failOn.markPoison) return Promise.reject(this.failOn.markPoison);
    for (const poison of rows) {
      const row = this.get(poison.id);
      if (row.publishedAt !== null) continue;
      row.attempts = maxAttempts;
      row.lastError = poison.code;
    }
    return Promise.resolve();
  }
}

/** Advisory locks: names in `elsewhere` are held by another process. */
export class FakeLocks implements ShardLocks, ReconcilerLocks {
  readonly held = new Set<string>();
  readonly elsewhere = new Set<string>();
  readonly ensured: string[] = [];
  fail: Error | undefined;

  ensure(name: string): Promise<boolean> {
    this.ensured.push(name);
    if (this.fail) return Promise.reject(this.fail);
    if (this.elsewhere.has(name)) {
      this.held.delete(name);
      return Promise.resolve(false);
    }
    this.held.add(name);
    return Promise.resolve(true);
  }

  isHeld(name: string): boolean {
    return this.held.has(name);
  }

  heldCount(prefix: string): number {
    return [...this.held].filter((n) => n.startsWith(prefix)).length;
  }

  release(name: string): Promise<void> {
    this.held.delete(name);
    return Promise.resolve();
  }
}

/** A publisher whose verdict per item comes from `decide` (default: every item confirmed). */
export class FakePublisher {
  readonly batches: PublishItem[][] = [];
  decide: (item: PublishItem, index: number) => PublishResult = () => ({ outcome: 'confirmed' });
  throws: Error | undefined;

  publishBatch(items: PublishItem[]): Promise<PublishResult[]> {
    this.batches.push(items);
    if (this.throws) return Promise.reject(this.throws);
    return Promise.resolve(items.map((item, i) => this.decide(item, i)));
  }

  get published(): PublishItem[] {
    return this.batches.flat();
  }
}

export class FakeBroker {
  connected = true;
  blocked = false;
}

export const noSleep = (): Promise<boolean> => Promise.resolve(true);
