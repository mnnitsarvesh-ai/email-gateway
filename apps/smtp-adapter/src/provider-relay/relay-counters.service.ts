import { Inject, Injectable, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import { ADAPTER_CONFIG, ADAPTER_LOGGER } from '../config';
import type { ProviderRelayConfig } from './provider-relay.config';
import { ProviderRelayMetrics } from './provider-relay.metrics';

export type RelayCounterName = 'accepted' | 'proofFailed' | 'tempFailed' | 'probes';

/** Counts are health evidence, not mail data: dropped after this many failed flushes. */
export const MAX_FLUSH_FAILURES = 3;

interface Bucket {
  organizationId: bigint;
  connectionId: bigint;
  hourStart: Date;
  accepted: number;
  proofFailed: number;
  tempFailed: number;
  probes: number;
  lastAcceptedAt: Date | null;
  failures: number;
}

/** UTC hour of an instant (minutes, seconds and milliseconds zero). */
export function utcHour(at: Date): Date {
  const hour = new Date(at.getTime());
  hour.setUTCMinutes(0, 0, 0);
  return hour;
}

/**
 * Hourly provider relay counters per connection (step 8.2 D8.2, D11 `outbound.relay_activity`):
 * aggregated in memory and flushed every PROVIDER_RELAY_COUNTER_FLUSH_SECONDS with an additive
 * `INSERT … ON DUPLICATE KEY UPDATE col = col + ?` into `provider_relay_counters` (writer, outside
 * any mail transaction), plus `provider_connections.last_relay_accepted_at` (never `row_version`,
 * which binds impact tokens). Best effort: a failed flush is logged and counted and the bucket is
 * retried; it is dropped after 3 failed flushes. Recording never throws and never waits on I/O.
 */
@Injectable()
export class RelayCountersService implements OnModuleInit, OnModuleDestroy {
  private readonly logger: Logger;
  private readonly buckets = new Map<string, Bucket>();
  private timer: NodeJS.Timeout | undefined;
  private flushing: Promise<void> | null = null;

  constructor(
    private readonly prisma: PrismaService,
    private readonly metrics: ProviderRelayMetrics,
    @Inject(ADAPTER_CONFIG)
    private readonly config: Pick<ProviderRelayConfig, 'PROVIDER_RELAY_COUNTER_FLUSH_SECONDS'>,
    @Inject(ADAPTER_LOGGER) logger: Logger,
  ) {
    this.logger = logger.child({ component: 'provider-relay-counters' });
  }

  onModuleInit(): void {
    this.timer = setInterval(() => {
      void this.flush();
    }, this.config.PROVIDER_RELAY_COUNTER_FLUSH_SECONDS * 1000);
    this.timer.unref();
  }

  async onModuleDestroy(): Promise<void> {
    clearInterval(this.timer);
    await this.flush();
  }

  record(
    organizationId: bigint,
    connectionId: bigint,
    counter: RelayCounterName,
    at: Date,
    by = 1,
  ): void {
    if (by <= 0) return;
    const hourStart = utcHour(at);
    const key = `${connectionId}:${hourStart.getTime()}`;
    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = {
        organizationId,
        connectionId,
        hourStart,
        accepted: 0,
        proofFailed: 0,
        tempFailed: 0,
        probes: 0,
        lastAcceptedAt: null,
        failures: 0,
      };
      this.buckets.set(key, bucket);
    }
    bucket[counter] += by;
    if (counter === 'accepted' && (bucket.lastAcceptedAt === null || bucket.lastAcceptedAt < at)) {
      bucket.lastAcceptedAt = at;
    }
  }

  /** Buckets not yet flushed (tests and shutdown). */
  get pending(): number {
    return this.buckets.size;
  }

  /** Writes every pending bucket; concurrent calls share one flush. Never throws. */
  flush(): Promise<void> {
    this.flushing ??= this.flushAll().finally(() => {
      this.flushing = null;
    });
    return this.flushing;
  }

  private async flushAll(): Promise<void> {
    for (const [key, bucket] of [...this.buckets]) {
      // Detach first: counts recorded during the write go to a fresh bucket.
      this.buckets.delete(key);
      try {
        await this.write(bucket);
      } catch (err) {
        this.metrics.counterFlushFailed();
        bucket.failures += 1;
        if (bucket.failures >= MAX_FLUSH_FAILURES) {
          this.logger.error(
            { err, connectionId: bucket.connectionId.toString(), failures: bucket.failures },
            'provider relay counters dropped after repeated flush failures',
          );
          continue;
        }
        this.logger.warn(
          { err, connectionId: bucket.connectionId.toString(), failures: bucket.failures },
          'provider relay counter flush failed; retrying later',
        );
        this.merge(key, bucket);
      }
    }
  }

  private merge(key: string, failed: Bucket): void {
    const current = this.buckets.get(key);
    if (!current) {
      this.buckets.set(key, failed);
      return;
    }
    current.accepted += failed.accepted;
    current.proofFailed += failed.proofFailed;
    current.tempFailed += failed.tempFailed;
    current.probes += failed.probes;
    current.failures = Math.max(current.failures, failed.failures);
    if (
      failed.lastAcceptedAt !== null &&
      (current.lastAcceptedAt === null || current.lastAcceptedAt < failed.lastAcceptedAt)
    ) {
      current.lastAcceptedAt = failed.lastAcceptedAt;
    }
  }

  private async write(bucket: Bucket): Promise<void> {
    await this.prisma.$executeRaw`
      INSERT INTO provider_relay_counters
        (organization_id, connection_id, hour_start, accepted, proof_failed, temp_failed, probes,
         updated_at)
      VALUES (${bucket.organizationId}, ${bucket.connectionId}, ${bucket.hourStart},
              ${bucket.accepted}, ${bucket.proofFailed}, ${bucket.tempFailed}, ${bucket.probes},
              CURRENT_TIMESTAMP(3))
      ON DUPLICATE KEY UPDATE
        accepted = accepted + ${bucket.accepted},
        proof_failed = proof_failed + ${bucket.proofFailed},
        temp_failed = temp_failed + ${bucket.tempFailed},
        probes = probes + ${bucket.probes},
        updated_at = CURRENT_TIMESTAMP(3)`;
    if (bucket.lastAcceptedAt === null) return;
    // Separate from the counts: a failure here must not re-add counts that were written.
    try {
      await this.prisma.$executeRaw`
        UPDATE provider_connections
        SET last_relay_accepted_at = ${bucket.lastAcceptedAt}
        WHERE id = ${bucket.connectionId}
          AND (last_relay_accepted_at IS NULL OR last_relay_accepted_at < ${bucket.lastAcceptedAt})`;
    } catch (err) {
      this.metrics.counterFlushFailed();
      this.logger.warn(
        { err, connectionId: bucket.connectionId.toString() },
        'could not update the last accepted provider relay time',
      );
    }
  }
}
