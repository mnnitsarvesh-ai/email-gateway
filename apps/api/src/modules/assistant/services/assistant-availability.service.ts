import { Inject, Injectable } from '@nestjs/common';
import { API_CONFIG } from '../../../api-config.token';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { CodedHttpException } from '../../../http/coded-exception';
import { OrganizationFeaturesService } from '../../../tenancy/organization-features.service';
import { ASSISTANT_FEATURE, type AssistantConfig } from '../assistant.constants';
import {
  assistantBudgetExhausted,
  assistantDisabled,
  assistantNotEnabled,
  assistantProviderUnavailable,
  assistantTenantDisabled,
} from '../assistant.errors';
import type { AssistantStatusView, StatusReason } from '../dto/assistant.schemas';
import {
  AssistantSettingsRepository,
  type SettingsRow,
} from '../repositories/assistant-settings.repository';
import { AssistantLimitsService, secondsUntilUtcMidnight } from './assistant-limits.service';
import { AssistantMetrics } from './assistant-metrics';
import { AssistantProviderService } from './assistant-provider.service';

export interface Availability {
  available: boolean;
  reason: StatusReason | null;
  /** `budget_exhausted`: which budget. */
  budgetScope: 'tenant' | 'platform' | null;
  settings: SettingsRow | null;
  dailyTokens: number;
  usedToday: number;
}

/**
 * Whether the assistant may run for the caller's organization (design D11, §4.1 status), in this
 * order: the platform switch `ASSISTANT_ENABLED` (`platform_disabled`), the organization feature
 * `ai_assistant` with the plan fallback (`feature_disabled`), the tenant setting `enabled` with the
 * external-processing acknowledgement (`tenant_disabled`), the provider breaker
 * (`provider_unavailable`) and the daily token budgets (`budget_exhausted`). Writer reads only.
 */
@Injectable()
export class AssistantAvailabilityService {
  constructor(
    @Inject(API_CONFIG) private readonly config: AssistantConfig,
    private readonly settings: AssistantSettingsRepository,
    private readonly features: OrganizationFeaturesService,
    private readonly provider: AssistantProviderService,
    private readonly limits: AssistantLimitsService,
    private readonly metrics: AssistantMetrics,
  ) {}

  /**
   * The gates up to the tenant setting; `full` adds the breaker and the budgets (turns). The
   * first failing gate is the reason.
   */
  async evaluate(scope: TenantScope, now: Date, full = true): Promise<Availability> {
    const settings = await this.settings.get(scope);
    const dailyTokens = this.limits.tenantBudget(settings?.dailyTokenBudget ?? null);
    const result = (
      reason: StatusReason | null,
      usedToday = 0,
      budgetScope: 'tenant' | 'platform' | null = null,
    ): Availability => ({
      available: reason === null,
      reason,
      budgetScope,
      settings,
      dailyTokens,
      usedToday,
    });
    if (!this.config.ASSISTANT_ENABLED) return result('platform_disabled');
    if (!(await this.features.isEffectivelyEnabled(scope.organizationId, ASSISTANT_FEATURE))) {
      return result('feature_disabled');
    }
    if (!settings?.enabled || settings.externalProcessingAckAt === null) {
      return result('tenant_disabled');
    }
    if (!full) return result(null);
    if (await this.provider.isOpen()) return result('provider_unavailable');
    const usedToday = await this.limits.tenantUsedToday(scope.organizationId, now);
    const exhausted = await this.limits.exhaustedScope(
      scope.organizationId,
      settings.dailyTokenBudget,
      now,
    );
    return exhausted ? result('budget_exhausted', usedToday, exhausted) : result(null, usedToday);
  }

  /** `GET /assistant/status`. */
  async status(scope: TenantScope, now: Date = new Date()): Promise<AssistantStatusView> {
    const availability = await this.evaluate(scope, now);
    const usedToday =
      availability.reason === null || availability.reason === 'budget_exhausted'
        ? availability.usedToday
        : this.config.ASSISTANT_ENABLED
          ? await this.limits.tenantUsedToday(scope.organizationId, now)
          : 0;
    return {
      available: availability.available,
      ...(availability.reason !== null && { reason: availability.reason }),
      provider: this.provider.providerId,
      model: this.provider.model,
      limits: {
        messageMaxChars: this.config.ASSISTANT_USER_MESSAGE_MAX_CHARS,
        turnsPerMinute: this.config.ASSISTANT_TURNS_PER_USER_PER_MINUTE,
      },
      budget: { dailyTokens: availability.dailyTokens, usedToday },
    };
  }

  /** Throws the coded error of the first failing gate (turns: `full`; "more" and new chats: not). */
  async assertAvailable(scope: TenantScope, now: Date, full: boolean): Promise<Availability> {
    const availability = await this.evaluate(scope, now, full);
    if (availability.reason === null) return availability;
    if (availability.reason === 'budget_exhausted') {
      this.metrics.budgetRefusals.inc({ scope: availability.budgetScope ?? 'tenant' });
    }
    throw errorOf(availability, now);
  }
}

export function errorOf(availability: Availability, now: Date): CodedHttpException {
  switch (availability.reason) {
    case 'platform_disabled':
      return assistantDisabled();
    case 'feature_disabled':
      return assistantNotEnabled();
    case 'tenant_disabled':
      return assistantTenantDisabled();
    case 'provider_unavailable':
      return assistantProviderUnavailable();
    default:
      return assistantBudgetExhausted(
        availability.budgetScope ?? 'tenant',
        secondsUntilUtcMidnight(now),
      );
  }
}
