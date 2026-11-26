import { Inject, Injectable } from '@nestjs/common';
import { API_CONFIG } from '../../../api-config.token';
import type { UserPrincipal } from '../../../auth-contracts/principal';
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
  assistantTenantKeyInvalid,
} from '../assistant.errors';
import { scopeOrganizationPublicId } from '../domain/tool-catalog';
import type { AssistantStatusView, StatusReason } from '../dto/assistant.schemas';
import {
  AssistantSettingsRepository,
  type SettingsRow,
} from '../repositories/assistant-settings.repository';
import { AssistantLimitsService, secondsUntilUtcMidnight } from './assistant-limits.service';
import { AssistantMetrics } from './assistant-metrics';
import { AssistantProviderService, type TurnRoute } from './assistant-provider.service';

export interface Availability {
  available: boolean;
  reason: StatusReason | null;
  /** `budget_exhausted`: which budget (step AI-6 D1: `user` = the per-user daily budget). */
  budgetScope: 'tenant' | 'platform' | 'user' | null;
  settings: SettingsRow | null;
  dailyTokens: number;
  usedToday: number;
  /** Step AI-6 D6: the selected provider route (full evaluations that passed the breakers). */
  route: TurnRoute | null;
  /** `provider_unavailable` because `useTenantKey` has no usable key and no platform fallback. */
  tenantKeyInvalid: boolean;
}

/** Who asks (step AI-6: the tenant key's breaker and the per-user budget). */
export interface AvailabilityCaller {
  principal: UserPrincipal;
}

/**
 * Whether the assistant may run for the caller's organization (design D11, §4.1 status), in this
 * order: the platform switch `ASSISTANT_ENABLED` (`platform_disabled`), the organization feature
 * `ai_assistant` with the plan fallback (`feature_disabled`), the tenant setting `enabled` with the
 * external-processing acknowledgement (`tenant_disabled`), the provider route
 * (`provider_unavailable`: step AI-6 D6, every candidate's breaker open, or `useTenantKey` without
 * a usable key → `503 assistant_tenant_key_invalid`) and the daily token budgets
 * (`budget_exhausted`: the tenant, the caller's per-user budget of step AI-6 D1, then the platform
 * cap, which counts platform-key turns only). Writer reads only.
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
  async evaluate(
    scope: TenantScope,
    now: Date,
    full = true,
    caller: AvailabilityCaller | null = null,
  ): Promise<Availability> {
    const settings = await this.settings.get(scope);
    const dailyTokens = this.limits.tenantBudget(settings?.dailyTokenBudget ?? null);
    let route: TurnRoute | null = null;
    let tenantKeyInvalid = false;
    const result = (
      reason: StatusReason | null,
      usedToday = 0,
      budgetScope: Availability['budgetScope'] = null,
    ): Availability => ({
      available: reason === null,
      reason,
      budgetScope,
      settings,
      dailyTokens,
      usedToday,
      route,
      tenantKeyInvalid,
    });
    if (!this.config.ASSISTANT_ENABLED) return result('platform_disabled');
    if (!(await this.features.isEffectivelyEnabled(scope.organizationId, ASSISTANT_FEATURE))) {
      return result('feature_disabled');
    }
    if (!settings?.enabled || settings.externalProcessingAckAt === null) {
      return result('tenant_disabled');
    }
    if (!full) return result(null);
    const selection = await this.provider.select(
      scope,
      settings,
      caller ? { organizationPublicId: scopeOrganizationPublicId(caller.principal) } : null,
    );
    if (selection.kind !== 'route') {
      tenantKeyInvalid = selection.kind === 'tenant_key_invalid';
      return result('provider_unavailable');
    }
    route = selection.route;
    const usedToday = await this.limits.tenantUsedToday(scope.organizationId, now);
    const exhausted = await this.limits.exhaustedScope(
      scope.organizationId,
      settings.dailyTokenBudget,
      now,
      {
        keySource: route.current.keySource,
        user:
          caller && settings.userDailyTokenBudget != null
            ? {
                userId: caller.principal.userId,
                userPublicId: caller.principal.userPublicId,
                budget: settings.userDailyTokenBudget,
              }
            : null,
      },
    );
    return exhausted ? result('budget_exhausted', usedToday, exhausted) : result(null, usedToday);
  }

  /** `GET /assistant/status` (step AI-6: `keySource`, `fallbackActive`, `dataSharing`). */
  async status(
    scope: TenantScope,
    now: Date = new Date(),
    principal: UserPrincipal | null = null,
  ): Promise<AssistantStatusView> {
    const availability = await this.evaluate(scope, now, true, principal ? { principal } : null);
    if (this.config.ASSISTANT_ENABLED) {
      await this.provider.refreshBreakerGauges().catch(() => undefined);
    }
    const route = availability.route;
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
      keySource: route?.current.keySource ?? 'platform',
      fallbackActive: route !== null && route.current.role === 'fallback',
      dataSharing: availability.settings?.dataSharing ?? 'metadata',
    };
  }

  /** Throws the coded error of the first failing gate (turns: `full`; "more" and new chats: not). */
  async assertAvailable(
    scope: TenantScope,
    now: Date,
    full: boolean,
    caller: AvailabilityCaller | null = null,
  ): Promise<Availability> {
    const availability = await this.evaluate(scope, now, full, caller);
    if (availability.reason === null) return availability;
    if (availability.reason === 'budget_exhausted') {
      const budget = availability.budgetScope ?? 'tenant';
      this.metrics.budgetRefusals.inc({ scope: budget === 'user' ? 'user_tokens' : budget });
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
      return availability.tenantKeyInvalid
        ? assistantTenantKeyInvalid()
        : assistantProviderUnavailable();
    default:
      return assistantBudgetExhausted(
        availability.budgetScope ?? 'tenant',
        secondsUntilUtcMidnight(now),
      );
  }
}
