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
import type { ApiConfig } from '../../../config';
import { SecretBox } from '../../../crypto/secret-box';
import { KeyValueStore } from '../../../kv/key-value-store';
import {
  type DesiredSigningKey,
  planSigningSync,
  type SigningSyncCounts,
} from '../domain/dkim-signing-plan';
import { domainKvKeys } from '../domains.constants';
import { DkimSigningRepository, type SignableKey } from '../repositories/dkim-signing.repository';
import { DkimKeyStore, DkimSigningDisabledError } from '../signing/dkim-key-store';
import { dkimKeyAad } from './domain-configuration.service';

export type DkimSigningPublisherConfig = Pick<
  ApiConfig,
  'DKIM_SIGNING_SYNC_ENABLED' | 'DKIM_SIGNING_SYNC_INTERVAL_SECONDS'
>;

/** Delay of the first reconciliation after startup (keys come back quickly after a restart). */
const FIRST_SYNC_DELAY_MS = 1_000;

/**
 * Publishes the DKIM signing keys to redis-dkim (step 2.2 D12, ADR-0020). The api is the only
 * holder of `DATA_ENCRYPTION_KEY`; it decrypts the active RSA-2048 key of every domain that may
 * sign (domain active and outbound-enabled, organization active) and reconciles the two hashes
 * rspamd-outbound reads. Runs every `DKIM_SIGNING_SYNC_INTERVAL_SECONDS` in one replica per tick
 * (KV lock, like the domain checks) and on demand (`pnpm --filter @email-gateway/api dkim:sync`).
 * Private keys are never logged: logs carry domain public ids and counts only.
 */
@Injectable()
export class DkimSigningPublisher implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger(DkimSigningPublisher.name);
  private readonly instanceId = randomUUID();
  private timer: NodeJS.Timeout | undefined;
  private firstRun: NodeJS.Timeout | undefined;
  private running: Promise<unknown> | undefined;

  constructor(
    @Inject(API_CONFIG) private readonly config: DkimSigningPublisherConfig,
    private readonly kv: KeyValueStore,
    private readonly keys: DkimSigningRepository,
    private readonly secretBox: SecretBox,
    private readonly store: DkimKeyStore,
  ) {}

  onApplicationBootstrap(): void {
    if (!this.store.configured) {
      this.logger.warn(
        'DKIM signing publisher disabled: REDIS_DKIM_URL is not set (outbound mail cannot be signed)',
      );
      return;
    }
    if (!this.config.DKIM_SIGNING_SYNC_ENABLED) return;
    const intervalMs = this.config.DKIM_SIGNING_SYNC_INTERVAL_SECONDS * 1000;
    this.firstRun = setTimeout(() => this.tick(), FIRST_SYNC_DELAY_MS);
    this.firstRun.unref();
    this.timer = setInterval(() => this.tick(), intervalMs);
    this.timer.unref();
  }

  async onModuleDestroy(): Promise<void> {
    if (this.firstRun) clearTimeout(this.firstRun);
    if (this.timer) clearInterval(this.timer);
    this.firstRun = undefined;
    this.timer = undefined;
    await this.running;
  }

  /** True when the periodic sync is scheduled. */
  get scheduled(): boolean {
    return this.timer !== undefined;
  }

  private tick(): void {
    if (this.running) return;
    this.running = this.runOnce()
      .catch((err: unknown) =>
        this.logger.error({ message: 'DKIM signing key sync failed', error: errorText(err) }),
      )
      .finally(() => {
        this.running = undefined;
      });
  }

  /** One scheduled tick; null when another replica holds the tick lock or KV is unavailable. */
  async runOnce(): Promise<SigningSyncCounts | null> {
    const lockSeconds = Math.max(this.config.DKIM_SIGNING_SYNC_INTERVAL_SECONDS - 1, 5);
    let acquired: boolean;
    try {
      acquired = await this.kv.setIfAbsent(domainKvKeys.dkimSyncLock, this.instanceId, lockSeconds);
    } catch (err) {
      this.logger.warn({
        message: 'DKIM signing key sync skipped: key-value store unavailable',
        error: errorText(err),
      });
      return null;
    }
    if (!acquired) return null;
    return runWithContext({ correlationId: `dkim-sync:${randomUUID()}` }, () => this.reconcile());
  }

  /**
   * Makes redis-dkim hold exactly the signable keys: reads the desired keys (writer), decrypts
   * them (a domain whose key cannot be decrypted is logged by public id and left as it is),
   * reads the published selectors and key fields, and applies the difference in one
   * `MULTI`/`EXEC`. Throws `DkimSigningDisabledError` when no store is configured.
   */
  async reconcile(): Promise<SigningSyncCounts> {
    if (!this.store.configured) throw new DkimSigningDisabledError();
    const desired: DesiredSigningKey[] = [];
    const keep = new Set<string>();
    for (const key of newestPerDomain(await this.keys.findSignableKeys())) {
      try {
        const { plaintext } = this.secretBox.decrypt(
          key.ciphertext,
          dkimKeyAad(key.domainPublicId, key.selector),
        );
        desired.push({ domain: key.domainName, selector: key.selector, pem: plaintext });
      } catch {
        keep.add(key.domainName);
        this.logger.error({
          message: 'DKIM signing key could not be decrypted; domain skipped',
          domainId: key.domainPublicId,
        });
      }
    }
    const plan = planSigningSync(desired, await this.store.readState(), keep);
    await this.store.apply(plan);
    const level = plan.counts.published + plan.counts.removed + plan.counts.pruned > 0;
    const entry = { message: 'DKIM signing keys reconciled', ...plan.counts };
    if (level) this.logger.log(entry);
    else this.logger.debug(entry);
    return plan.counts;
  }
}

/** One key per domain: the newest (highest id) when several are active. */
function newestPerDomain(keys: readonly SignableKey[]): SignableKey[] {
  const byDomain = new Map<string, SignableKey>();
  for (const key of keys) {
    const seen = byDomain.get(key.domainName);
    if (!seen || key.keyId > seen.keyId) byDomain.set(key.domainName, key);
  }
  return [...byDomain.values()];
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : 'unknown error';
}
