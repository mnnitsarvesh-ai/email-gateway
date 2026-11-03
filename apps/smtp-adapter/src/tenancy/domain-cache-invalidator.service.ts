import {
  Inject,
  Injectable,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
} from '@nestjs/common';
import { type Counter, MetricsService, PrismaService } from '@email-gateway/common';
import { EventTypes } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import { ADAPTER_CONFIG, ADAPTER_LOGGER, type SmtpAdapterConfig } from '../config';
import { DomainPolicyService } from './domain-policy.service';

/** Rows per poll (D5). */
export const INVALIDATION_BATCH_SIZE = 500;

interface OutboxRow {
  id: bigint;
  payload: unknown;
}

/**
 * Fast-path invalidation of the domain cache (step 2.2 D5): tails `message_outbox` on the
 * writer for `domain.status.changed.v1` rows every SMTP_CACHE_INVALIDATION_POLL_MS and deletes
 * the cached view (`sa:dom:{name}`) plus the socketmap keys derived from the name.
 *
 * Starts at `MAX(id)` (the TTL already bounds anything older). Ids committed out of order may
 * be skipped; the TTL is the guarantee, the tail only makes changes visible within seconds.
 * Errors are logged and retried on the next tick; the timer is unref'd and stops on shutdown.
 * When the outbox relay exists (step 3.2) this becomes a RabbitMQ subscription.
 */
@Injectable()
export class DomainCacheInvalidator implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger: Logger;
  private readonly invalidations: Counter;
  private timer: NodeJS.Timeout | undefined;
  private stopped = false;
  private running: Promise<void> | undefined;
  /** Last processed outbox id; null until the starting point is known. */
  private lastId: bigint | null = null;

  constructor(
    private readonly prisma: PrismaService,
    private readonly domains: DomainPolicyService,
    metrics: MetricsService,
    @Inject(ADAPTER_CONFIG)
    private readonly config: Pick<SmtpAdapterConfig, 'SMTP_CACHE_INVALIDATION_POLL_MS'>,
    @Inject(ADAPTER_LOGGER) logger: Logger,
  ) {
    this.logger = logger.child({ component: 'domain-cache-invalidator' });
    this.invalidations = metrics.counter(
      'smtp_cache_invalidations_total',
      'Domain cache entries invalidated from domain.status.changed outbox events',
    );
  }

  onApplicationBootstrap(): void {
    if (this.config.SMTP_CACHE_INVALIDATION_POLL_MS === 0) {
      this.logger.info('domain cache invalidation disabled (TTL only)');
      return;
    }
    this.schedule(0);
  }

  async onModuleDestroy(): Promise<void> {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    await this.running;
  }

  /** One poll. Public for tests; returns the number of invalidated names. */
  async poll(): Promise<number> {
    if (this.lastId === null) {
      const [row] = await this.prisma.$queryRaw<{ maxId: bigint | null }[]>`
        SELECT MAX(id) AS maxId FROM message_outbox`;
      this.lastId = row?.maxId === null || row?.maxId === undefined ? 0n : BigInt(row.maxId);
      return 0;
    }
    const rows = await this.prisma.$queryRaw<OutboxRow[]>`
      SELECT id, payload FROM message_outbox
      WHERE id > ${this.lastId} AND event_type = ${EventTypes.DomainStatusChanged}
      ORDER BY id LIMIT ${INVALIDATION_BATCH_SIZE}`;
    let count = 0;
    for (const row of rows) {
      const name = payloadName(row.payload);
      if (name !== null) {
        await this.domains.invalidate(name);
        this.invalidations.inc();
        count += 1;
      } else {
        this.logger.warn({ outboxId: String(row.id) }, 'domain event without a name; skipped');
      }
      this.lastId = BigInt(row.id);
    }
    return count;
  }

  private schedule(delayMs: number): void {
    if (this.stopped) return;
    this.timer = setTimeout(() => {
      this.running = this.poll()
        .then((count) => {
          if (count > 0) this.logger.debug({ count }, 'domain cache entries invalidated');
        })
        .catch((err: unknown) => this.logger.warn({ err }, 'outbox tail failed; retrying'))
        .finally(() => {
          this.running = undefined;
          this.schedule(this.config.SMTP_CACHE_INVALIDATION_POLL_MS);
        });
    }, delayMs);
    this.timer.unref();
  }
}

function payloadName(payload: unknown): string | null {
  const value: unknown = typeof payload === 'string' ? safeJson(payload) : payload;
  if (typeof value !== 'object' || value === null) return null;
  const name = (value as { name?: unknown }).name;
  return typeof name === 'string' && name.length > 0 && name.length <= 253 ? name : null;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}
