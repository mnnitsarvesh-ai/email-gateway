import { Inject, Injectable } from '@nestjs/common';
import { ADAPTER_CONFIG } from '../config';
import { RedisJsonCache } from '../tenancy/redis-json-cache';
import type { JournalIntakeConfig } from './journal-intake.config';
import {
  type IntakeSourceSnapshot,
  intakeSourceSnapshotSchema,
  JournalIntakeSourceRepository,
} from './source-snapshot';

/** `sa:jintake:src:<addressHash>` (contracts §34). */
export const intakeSourceCacheKey = (addressHash: string): string =>
  `sa:jintake:src:${addressHash}`;

/**
 * Read-through cache of intake sources for the RCPT policy (D2.2.8): positive and negative
 * entries live JOURNAL_INTAKE_SOURCE_CACHE_SECONDS (default 30), so a pause, disable, rotation or
 * entitlement change takes effect within that bound; the LMTP stage re-checks on the writer
 * without the cache. Cache errors fall back to the writer; writer errors propagate (tempfail).
 */
@Injectable()
export class JournalIntakeSourceCache {
  constructor(
    private readonly cache: RedisJsonCache,
    private readonly repository: JournalIntakeSourceRepository,
    @Inject(ADAPTER_CONFIG)
    private readonly config: Pick<JournalIntakeConfig, 'JOURNAL_INTAKE_SOURCE_CACHE_SECONDS'>,
  ) {}

  get(addressHash: string): Promise<IntakeSourceSnapshot | null> {
    const ttl = this.config.JOURNAL_INTAKE_SOURCE_CACHE_SECONDS;
    return this.cache.getOrLoad({
      cache: 'journal_intake',
      key: intakeSourceCacheKey(addressHash),
      ttlSeconds: ttl,
      negativeTtlSeconds: ttl,
      schema: intakeSourceSnapshotSchema,
      load: () => this.repository.loadByAddressHash(addressHash),
    });
  }
}
