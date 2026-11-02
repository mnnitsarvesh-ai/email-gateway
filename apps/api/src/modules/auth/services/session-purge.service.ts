import {
  Inject,
  Injectable,
  Logger,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
} from '@nestjs/common';
import { API_CONFIG } from '../../../api-config.token';
import type { ApiConfig } from '../../../config';
import { KeyValueStore } from '../../../kv/key-value-store';
import {
  kvKeys,
  SESSION_PURGE_BATCH,
  SESSION_PURGE_GRACE_MS,
  SESSION_PURGE_INTERVAL_MS,
  SESSION_PURGE_LOCK_SECONDS,
  TOKEN_PURGE_GRACE_MS,
} from '../auth.constants';
import { LoginAuditRepository } from '../repositories/login-audit.repository';
import { SessionsRepository } from '../repositories/sessions.repository';
import { UserTokensRepository } from '../repositories/user-tokens.repository';

export type SessionPurgeConfig = Pick<
  ApiConfig,
  'AUTH_BACKGROUND_JOBS_ENABLED' | 'AUTH_LOGIN_AUDIT_RETENTION_DAYS'
>;

export interface PurgeResult {
  sessions: number;
  tokens: number;
  loginAudit: number;
}

/** Deletes in batches until a batch comes back short. */
export async function purgeInBatches(
  deleteBatch: (limit: number) => Promise<number>,
  batchSize = SESSION_PURGE_BATCH,
  maxBatches = 10_000,
): Promise<number> {
  let total = 0;
  for (let i = 0; i < maxBatches; i += 1) {
    const deleted = await deleteBatch(batchSize);
    total += deleted;
    if (deleted < batchSize) break;
  }
  return total;
}

/**
 * Hourly purge (D5) of expired sessions (idle expiry + 1 day), expired single-use tokens
 * (+ 7 days) and login audit rows past AUTH_LOGIN_AUDIT_RETENTION_DAYS. One replica at a time
 * (KV lock `jobs:auth-purge`, 55 min). Disabled with AUTH_BACKGROUND_JOBS_ENABLED=false.
 */
@Injectable()
export class SessionPurgeService implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger(SessionPurgeService.name);
  private timer: NodeJS.Timeout | undefined;
  private running: Promise<unknown> | undefined;

  constructor(
    @Inject(API_CONFIG) private readonly config: SessionPurgeConfig,
    private readonly kv: KeyValueStore,
    private readonly sessions: SessionsRepository,
    private readonly tokens: UserTokensRepository,
    private readonly loginAudit: LoginAuditRepository,
  ) {}

  onApplicationBootstrap(): void {
    if (!this.config.AUTH_BACKGROUND_JOBS_ENABLED) return;
    this.timer = setInterval(() => this.tick(), SESSION_PURGE_INTERVAL_MS);
    this.timer.unref();
  }

  async onModuleDestroy(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.running;
  }

  /** True when a timer is scheduled (tests). */
  get scheduled(): boolean {
    return this.timer !== undefined;
  }

  private tick(): void {
    this.running = this.runOnce().catch((err: unknown) =>
      this.logger.error({ message: 'Auth purge failed', err }),
    );
  }

  /** One purge run; null when another instance holds the lock. */
  async runOnce(now: Date = new Date()): Promise<PurgeResult | null> {
    const acquired = await this.kv.setIfAbsent(
      kvKeys.purgeLock,
      now.toISOString(),
      SESSION_PURGE_LOCK_SECONDS,
    );
    if (!acquired) return null;
    const sessionsBefore = new Date(now.getTime() - SESSION_PURGE_GRACE_MS);
    const tokensBefore = new Date(now.getTime() - TOKEN_PURGE_GRACE_MS);
    const auditBefore = new Date(
      now.getTime() - this.config.AUTH_LOGIN_AUDIT_RETENTION_DAYS * 86_400_000,
    );
    const result: PurgeResult = {
      sessions: await purgeInBatches((n) => this.sessions.purgeExpired(sessionsBefore, n)),
      tokens: await purgeInBatches((n) => this.tokens.purgeExpired(tokensBefore, n)),
      loginAudit: await purgeInBatches((n) => this.loginAudit.purgeOlderThan(auditBefore, n)),
    };
    this.logger.log({ message: 'Auth purge completed', ...result });
    return result;
  }
}
