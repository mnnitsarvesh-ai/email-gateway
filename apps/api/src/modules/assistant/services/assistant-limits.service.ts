import { Inject, Injectable } from '@nestjs/common';
import { API_CONFIG } from '../../../api-config.token';
import { KeyValueStore } from '../../../kv/key-value-store';
import {
  type AssistantConfig,
  assistantKeys,
  TOKEN_COUNTER_TTL_SECONDS,
  TURN_LOCK_GRACE_SECONDS,
  utcDayKey,
  utcDayStart,
} from '../assistant.constants';
import { assistantBusy, assistantUserRateLimited } from '../assistant.errors';
import { UsageRepository } from '../repositories/usage.repository';
import { AssistantMetrics } from './assistant-metrics';

/** Seconds until the next UTC midnight (Retry-After of an exhausted daily budget). */
export function secondsUntilUtcMidnight(now: Date): number {
  const next = utcDayStart(now).getTime() + 86_400_000;
  return Math.max(1, Math.ceil((next - now.getTime()) / 1000));
}

/** The per-user daily budget of a turn start (step AI-6 D1). */
export interface UserBudget {
  userId: bigint;
  userPublicId: string;
  budget: number;
}

/**
 * Budgets, limits and locks of the assistant (design D7, D11; Redis keys of contracts §35):
 * turns per user per minute (`as:rl:u`), the tenant and platform daily token counters
 * (`as:tok:o`, `as:tok:p`; seeded from the usage tables on a miss, TTL 48 h; step AI-6 D6: the
 * platform counter counts platform-key turns only), the per-user daily token counter of step
 * AI-6 D1 (`as:tok:u`, seeded from `ai_chat_usage_user_daily`), the
 * per-process concurrency semaphore and the per-conversation turn lock (`as:turn`). Store
 * errors propagate: callers fail closed.
 */
@Injectable()
export class AssistantLimitsService {
  private active = 0;

  constructor(
    @Inject(API_CONFIG) private readonly config: AssistantConfig,
    private readonly kv: KeyValueStore,
    private readonly usage: UsageRepository,
    private readonly metrics: AssistantMetrics,
  ) {}

  /** The organization's effective daily token budget. */
  tenantBudget(dailyTokenBudget: number | null): number {
    const wanted = dailyTokenBudget ?? this.config.ASSISTANT_TENANT_DAILY_TOKENS_DEFAULT;
    return Math.min(wanted, this.config.ASSISTANT_TENANT_DAILY_TOKENS_MAX);
  }

  /** Tokens the organization used today (UTC). */
  async tenantUsedToday(organizationId: bigint, now: Date): Promise<number> {
    const key = assistantKeys.tenantTokens(organizationId, utcDayKey(now));
    return this.counter(key, () => this.usage.tenantDayTokens(organizationId, utcDayStart(now)));
  }

  /** Tokens the platform used today (UTC). */
  async platformUsedToday(now: Date): Promise<number> {
    const key = assistantKeys.platformTokens(utcDayKey(now));
    return this.counter(key, () => this.usage.platformDayTokens(utcDayStart(now)));
  }

  /** Tokens one user used today (UTC; step AI-6 D1). */
  async userUsedToday(
    organizationId: bigint,
    user: { userId: bigint; userPublicId: string },
    now: Date,
  ): Promise<number> {
    const key = assistantKeys.userTokens(user.userPublicId, utcDayKey(now));
    return this.counter(key, () =>
      this.usage.userDayTokens(organizationId, user.userId, utcDayStart(now)),
    );
  }

  /**
   * Which budget is exhausted at turn start, if any (a running turn may finish): the tenant's,
   * the caller's per-user budget (step AI-6 D1), then the platform cap, which counts only turns on
   * the platform's keys (step AI-6 D6, A6-7: a tenant-key turn is not refused by it).
   */
  async exhaustedScope(
    organizationId: bigint,
    dailyTokenBudget: number | null,
    now: Date,
    options: { keySource?: 'platform' | 'tenant'; user?: UserBudget | null } = {},
  ): Promise<'tenant' | 'platform' | 'user' | null> {
    const used = await this.tenantUsedToday(organizationId, now);
    if (used >= this.tenantBudget(dailyTokenBudget)) return 'tenant';
    if (
      options.user &&
      (await this.userUsedToday(organizationId, options.user, now)) >= options.user.budget
    ) {
      return 'user';
    }
    const cap = this.config.ASSISTANT_PLATFORM_DAILY_TOKENS;
    if (
      cap > 0 &&
      (options.keySource ?? 'platform') === 'platform' &&
      (await this.platformUsedToday(now)) >= cap
    ) {
      return 'platform';
    }
    return null;
  }

  /** Counts a turn against the user's per-minute window; `429 rate_limited` beyond it. */
  async consumeUserWindow(userPublicId: string, now: Date): Promise<void> {
    const minute = Math.floor(now.getTime() / 60_000);
    const count = await this.kv.incrWithTtl(assistantKeys.userWindow(userPublicId, minute), 60);
    if (count > this.config.ASSISTANT_TURNS_PER_USER_PER_MINUTE) {
      this.metrics.budgetRefusals.inc({ scope: 'user' });
      const retryAfter = Math.max(1, 60 - Math.floor((now.getTime() % 60_000) / 1000));
      throw assistantUserRateLimited(retryAfter);
    }
  }

  /**
   * Adds a finished turn's tokens to today's counters (after its usage rows committed): the
   * tenant's, the user's (step AI-6 D1) and, for a platform-key turn, the platform's (D6).
   */
  async recordTokens(
    organizationId: bigint,
    tokens: number,
    now: Date,
    options: { userPublicId?: string; keySource?: 'platform' | 'tenant' } = {},
  ): Promise<void> {
    if (!Number.isSafeInteger(tokens) || tokens < 1) return;
    const day = utcDayKey(now);
    const keys = [assistantKeys.tenantTokens(organizationId, day)];
    if ((options.keySource ?? 'platform') === 'platform')
      keys.push(assistantKeys.platformTokens(day));
    if (options.userPublicId) keys.push(assistantKeys.userTokens(options.userPublicId, day));
    for (const key of keys) {
      // A missing counter is seeded from the table on its next read (which includes this turn).
      if ((await this.kv.get(key)) !== null) {
        await this.kv.incrByWithTtl(key, tokens, TOKEN_COUNTER_TTL_SECONDS);
      }
    }
  }

  /** One slot of the per-process concurrency limit; `503 assistant_busy` when full. */
  acquireSlot(): () => void {
    if (this.active >= this.config.ASSISTANT_MAX_CONCURRENT_TURNS) {
      this.metrics.budgetRefusals.inc({ scope: 'concurrency' });
      throw assistantBusy();
    }
    this.active += 1;
    this.metrics.activeTurns.set(this.active);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.active -= 1;
      this.metrics.activeTurns.set(this.active);
    };
  }

  get activeTurns(): number {
    return this.active;
  }

  /** TTL of a turn lock: the turn deadline plus a grace. */
  get lockTtlSeconds(): number {
    return Math.ceil(this.config.ASSISTANT_TURN_DEADLINE_MS / 1000) + TURN_LOCK_GRACE_SECONDS;
  }

  /** The conversation's turn lock; false when another turn (or "more" page) holds it. */
  acquireLock(conversationPublicId: string, token: string): Promise<boolean> {
    return this.kv.setIfAbsent(
      assistantKeys.turnLock(conversationPublicId),
      token,
      this.lockTtlSeconds,
    );
  }

  /** Releases the lock only when this holder still owns it. */
  async releaseLock(conversationPublicId: string, token: string): Promise<void> {
    const key = assistantKeys.turnLock(conversationPublicId);
    if ((await this.kv.get(key)) === token) await this.kv.del(key);
  }

  /** Cross-pod cancellation flag of a running turn. */
  async requestCancel(turnPublicId: string): Promise<void> {
    await this.kv.set(assistantKeys.turnCancel(turnPublicId), '1', this.lockTtlSeconds);
  }

  async cancelRequested(turnPublicId: string): Promise<boolean> {
    return this.kv.exists(assistantKeys.turnCancel(turnPublicId));
  }

  /**
   * The assistant re-authentication window of a session family (step AI-2 D2 step 9): true
   * when the session re-authenticated an assistant confirmation within
   * ASSISTANT_REAUTH_WINDOW_SECONDS (0 = never fresh, always ask).
   */
  async reauthFresh(sessionFamilyId: string): Promise<boolean> {
    if (this.config.ASSISTANT_REAUTH_WINDOW_SECONDS <= 0) return false;
    return this.kv.exists(assistantKeys.reauthWindow(sessionFamilyId));
  }

  /** Opens (or renews) the window after a successful assistant re-authentication. */
  async markReauthenticated(sessionFamilyId: string): Promise<void> {
    const ttl = this.config.ASSISTANT_REAUTH_WINDOW_SECONDS;
    if (ttl <= 0) return;
    await this.kv.set(assistantKeys.reauthWindow(sessionFamilyId), '1', ttl);
  }

  private async counter(key: string, seed: () => Promise<number>): Promise<number> {
    const cached = await this.kv.get(key);
    if (cached !== null) {
      const value = Number.parseInt(cached, 10);
      if (Number.isSafeInteger(value) && value >= 0) return value;
    }
    const value = await seed();
    if (await this.kv.setIfAbsent(key, String(value), TOKEN_COUNTER_TTL_SECONDS)) return value;
    const raced = Number.parseInt((await this.kv.get(key)) ?? String(value), 10);
    return Number.isSafeInteger(raced) ? raced : value;
  }
}
