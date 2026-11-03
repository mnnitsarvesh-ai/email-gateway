import { Inject, Injectable, Logger, type OnModuleDestroy } from '@nestjs/common';
import { Redis } from 'ioredis';
import { API_CONFIG } from '../../../api-config.token';
import type { ApiConfig } from '../../../config';
import {
  DKIM_KEYS_HASH,
  DKIM_SELECTORS_HASH,
  isEmptyPlan,
  type PublishedSigningState,
  type SigningPlan,
} from '../domain/dkim-signing-plan';
import { DkimKeyStore } from './dkim-key-store';

export type RedisDkimStoreConfig = Pick<ApiConfig, 'REDIS_DKIM_URL'>;

/**
 * redis-dkim (step 2.2 D12, ADR-0020) as the `dkim-writer` ACL user, which may only use
 * PING, HGET, HGETALL, HKEYS, HSET, HDEL, HEXISTS, MULTI, EXEC and DEL on the two hashes.
 * Connects lazily on first use (never when `REDIS_DKIM_URL` is empty). The ready check is off
 * because it needs `INFO`, which the ACL does not grant. Errors propagate to the caller; the
 * URL (it carries the password) is never logged.
 */
@Injectable()
export class RedisDkimStore extends DkimKeyStore implements OnModuleDestroy {
  private readonly logger = new Logger(RedisDkimStore.name);
  private readonly client: Redis | undefined;
  private lastError: string | undefined;

  constructor(@Inject(API_CONFIG) config: RedisDkimStoreConfig) {
    super();
    if (config.REDIS_DKIM_URL) {
      this.client = new Redis(config.REDIS_DKIM_URL, {
        lazyConnect: true,
        enableReadyCheck: false,
        maxRetriesPerRequest: 1,
        connectTimeout: 5_000,
        retryStrategy: (times) => Math.min(times * 500, 5_000),
      });
      this.client.on('error', (err: Error) => {
        // One line per distinct failure instead of one per reconnect attempt.
        if (err.message === this.lastError) return;
        this.lastError = err.message;
        this.logger.warn({ message: 'redis-dkim connection error', error: err.message });
      });
      this.client.on('ready', () => {
        this.lastError = undefined;
      });
    }
  }

  get configured(): boolean {
    return this.client !== undefined;
  }

  async readState(): Promise<PublishedSigningState> {
    const client = this.require();
    const [selectors, keyFields] = await Promise.all([
      client.hgetall(DKIM_SELECTORS_HASH),
      client.hkeys(DKIM_KEYS_HASH),
    ]);
    return { selectors, keyFields };
  }

  async apply(plan: SigningPlan): Promise<void> {
    if (isEmptyPlan(plan)) return;
    const multi = this.require().multi();
    // Order (D12): keys before the selectors that reference them; selectors removed before
    // their keys. MULTI/EXEC makes the whole change atomic for readers anyway.
    if (plan.keysToWrite.length > 0) {
      multi.hset(DKIM_KEYS_HASH, Object.fromEntries(plan.keysToWrite));
    }
    if (plan.selectorsToWrite.length > 0) {
      multi.hset(DKIM_SELECTORS_HASH, Object.fromEntries(plan.selectorsToWrite));
    }
    if (plan.selectorsToDelete.length > 0) {
      multi.hdel(DKIM_SELECTORS_HASH, ...plan.selectorsToDelete);
    }
    if (plan.keysToDelete.length > 0) multi.hdel(DKIM_KEYS_HASH, ...plan.keysToDelete);
    const results = await multi.exec();
    if (results === null) throw new Error('redis-dkim transaction was aborted');
    const failed = results.find(([err]) => err !== null);
    if (failed) throw new Error(`redis-dkim transaction failed: ${failed[0]!.message}`);
  }

  async onModuleDestroy(): Promise<void> {
    if (!this.client) return;
    if (this.client.status === 'wait' || this.client.status === 'end') {
      this.client.disconnect();
      return;
    }
    try {
      await this.client.quit();
    } catch {
      this.client.disconnect();
    }
  }

  private require(): Redis {
    if (!this.client) throw new Error('redis-dkim is not configured');
    return this.client;
  }
}
