import { randomUUID } from 'node:crypto';
import {
  Inject,
  Injectable,
  Logger,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
} from '@nestjs/common';
import { runWithContext } from '@email-gateway/logger';
import { API_CONFIG } from '../../../api-config.token';
import { SYSTEM_ACTOR } from '../../../audit/audit.service';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../../config';
import { KeyValueStore } from '../../../kv/key-value-store';
import { CLAIM_SECONDS, domainKvKeys } from '../domains.constants';
import { type DueDomain, DomainJobsRepository } from '../repositories/domain-jobs.repository';
import { acquireCheckLock, releaseCheckLock } from './check-lock';
import { DkimRotationService } from './dkim-rotation.service';
import { DomainVerificationService } from './domain-verification.service';

export type DomainSchedulerConfig = Pick<
  ApiConfig,
  | 'DOMAIN_BACKGROUND_JOBS_ENABLED'
  | 'DOMAIN_JOBS_INTERVAL_SECONDS'
  | 'DOMAIN_CHECK_BATCH_SIZE'
  | 'DOMAIN_CHECK_CONCURRENCY'
  | 'DOMAIN_RECHECK_INTERVAL_SECONDS'
>;

/** Counts of one scheduler tick (logged once per tick, returned by `runOnce`). */
export interface DomainJobSummary {
  /** Due domains found. */
  due: number;
  /** Domains this tick won with the conditional claim. */
  claimed: number;
  /** Checks that ran to completion (any outcome). */
  checked: number;
  verified: number;
  failed: number;
  indeterminate: number;
  /** Not checked: organization not active, per-domain lock held, or domain not checkable. */
  skipped: number;
  /** Checks that threw (logged with the domain id; retried after the claim expires). */
  errors: number;
  /** Rotating DKIM keys retired. */
  retired: number;
}

const emptySummary = (): DomainJobSummary => ({
  due: 0,
  claimed: 0,
  checked: 0,
  verified: 0,
  failed: 0,
  indeterminate: 0,
  skipped: 0,
  errors: 0,
  retired: 0,
});

/** Runs `fn` over `items` with at most `limit` calls in flight. */
export async function forEachWithConcurrency<T>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(Math.max(limit, 1), items.length) }, async () => {
    while (next < items.length) {
      const item = items[next++]!;
      await fn(item);
    }
  });
  await Promise.all(workers);
}

/**
 * Background verification and re-verification (D11), in the api process like the session
 * purge. Each tick: KV tick lock (one replica per tick) → due domains → conditional claim per
 * domain (`next_check_at` moves 5 minutes ahead, so a crashed check is retried later) →
 * per-domain KV lock → check with bounded concurrency → DKIM retirement → one log line.
 * Domains of organizations that are not active are postponed by the healthy recheck interval.
 * Safe with any number of replicas; disabled with DOMAIN_BACKGROUND_JOBS_ENABLED=false.
 */
@Injectable()
export class DomainCheckScheduler implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger(DomainCheckScheduler.name);
  private readonly instanceId = randomUUID();
  private timer: NodeJS.Timeout | undefined;
  private running: Promise<unknown> | undefined;

  constructor(
    @Inject(API_CONFIG) private readonly config: DomainSchedulerConfig,
    private readonly kv: KeyValueStore,
    private readonly jobs: DomainJobsRepository,
    private readonly verification: DomainVerificationService,
    private readonly rotation: DkimRotationService,
  ) {}

  onApplicationBootstrap(): void {
    if (!this.config.DOMAIN_BACKGROUND_JOBS_ENABLED) return;
    this.timer = setInterval(() => this.tick(), this.config.DOMAIN_JOBS_INTERVAL_SECONDS * 1000);
    this.timer.unref();
  }

  async onModuleDestroy(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.running;
  }

  /** True when a timer is scheduled. */
  get scheduled(): boolean {
    return this.timer !== undefined;
  }

  private tick(): void {
    if (this.running) return; // the previous tick is still running
    this.running = this.runOnce()
      .catch((err: unknown) => this.logger.error({ message: 'Domain checks failed', err }))
      .finally(() => {
        this.running = undefined;
      });
  }

  /** One tick; null when another replica holds the tick lock or the KV store is unavailable. */
  async runOnce(now: Date = new Date()): Promise<DomainJobSummary | null> {
    const lockSeconds = Math.max(this.config.DOMAIN_JOBS_INTERVAL_SECONDS - 1, 5);
    let acquired: boolean;
    try {
      acquired = await this.kv.setIfAbsent(domainKvKeys.tickLock, this.instanceId, lockSeconds);
    } catch (err) {
      this.logger.warn({ message: 'Domain checks skipped: key-value store unavailable', err });
      return null;
    }
    if (!acquired) return null;
    return runWithContext({ correlationId: `domain-job:${randomUUID()}` }, () => this.execute(now));
  }

  private async execute(now: Date): Promise<DomainJobSummary> {
    const summary = emptySummary();
    const due = await this.jobs.findDue(now, this.config.DOMAIN_CHECK_BATCH_SIZE);
    summary.due = due.length;
    const claimed: DueDomain[] = [];
    const claimUntil = new Date(now.getTime() + CLAIM_SECONDS * 1000);
    for (const domain of due) {
      if (domain.organizationStatus !== 'active') {
        const later = new Date(now.getTime() + this.config.DOMAIN_RECHECK_INTERVAL_SECONDS * 1000);
        await this.jobs.claim(domain.id, domain.nextCheckAt, later);
        summary.skipped++;
        continue;
      }
      if (await this.jobs.claim(domain.id, domain.nextCheckAt, claimUntil)) claimed.push(domain);
    }
    summary.claimed = claimed.length;

    await forEachWithConcurrency(claimed, this.config.DOMAIN_CHECK_CONCURRENCY, (domain) =>
      this.checkOne(domain, now, summary),
    );

    try {
      summary.retired = await this.rotation.retireDue(now);
    } catch (err) {
      this.logger.error({ message: 'DKIM key retirement failed', err });
    }
    this.logger.log({ message: 'Domain checks completed', ...summary });
    return summary;
  }

  private async checkOne(domain: DueDomain, now: Date, summary: DomainJobSummary): Promise<void> {
    let lock;
    try {
      lock = await acquireCheckLock(this.kv, domain.id);
    } catch (err) {
      this.logger.warn({
        message: 'Domain check skipped: key-value store unavailable',
        domainId: domain.id.toString(),
        err,
      });
      summary.skipped++;
      return;
    }
    if (!lock) {
      summary.skipped++; // a manual verification is running; the claim retries it later
      return;
    }
    try {
      const result = await this.verification.runCheck(
        systemScope(domain.organizationId),
        domain.id,
        {
          bypassCache: false,
          actor: SYSTEM_ACTOR,
          sourceIp: null,
          now,
        },
      );
      if (result === 'skipped') {
        summary.skipped++;
        return;
      }
      summary.checked++;
      if (result === 'verified') summary.verified++;
      else if (result === 'failed') summary.failed++;
      else if (result === 'indeterminate') summary.indeterminate++;
    } catch (err) {
      summary.errors++;
      this.logger.error({ message: 'Domain check failed', domainId: domain.id.toString(), err });
    } finally {
      await releaseCheckLock(this.kv, lock);
    }
  }
}
