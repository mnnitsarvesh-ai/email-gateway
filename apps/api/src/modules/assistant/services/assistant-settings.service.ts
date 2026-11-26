import { BadRequestException, Inject, Injectable, Optional } from '@nestjs/common';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { TransactionRunner } from '../../../database/transaction-runner';
import { OrganizationFeaturesService } from '../../../tenancy/organization-features.service';
import {
  ASSISTANT_AUDIT,
  ASSISTANT_FEATURE,
  AUDIT_RESOURCE,
  type AssistantConfig,
} from '../assistant.constants';
import {
  assistantNotEnabled,
  assistantSettingsConflict,
  assistantTenantKeyNotFound,
  assistantTenantKeyRejected,
  assistantTenantKeysDisabled,
} from '../assistant.errors';
import { scopeOrganizationPublicId } from '../domain/tool-catalog';
import type { AssistantSettingsView, UpdateAssistantSettingsBody } from '../dto/assistant.schemas';
import {
  AssistantSettingsRepository,
  type SettingsRow,
  type SettingsWrite,
} from '../repositories/assistant-settings.repository';
import { ConversationsRepository } from '../repositories/conversations.repository';
import { ProviderKeysRepository } from '../repositories/provider-keys.repository';
import { AssistantLimitsService } from './assistant-limits.service';
import { TenantKeyService } from './tenant-key.service';

/**
 * The organization's assistant settings `assistant-settings/1` (design D13, §4.1): one row per
 * organization (no row = disabled with the platform defaults), CAS on `rowVersion`
 * (`409 assistant_settings_conflict`), enabling needs `externalProcessingAcknowledged: true`
 * (recording who and when) and the feature `ai_assistant` (`403 assistant_not_enabled`); the
 * budget is capped by ASSISTANT_TENANT_DAILY_TOKENS_MAX. Audited `assistant.settings_updated`
 * (changed field names and the new switches, never other values). Lowering `retentionDays`
 * moves the purge date of the organization's existing conversations earlier (D12).
 *
 * Step AI-6 (D1, D3, D7): `dataSharing` (`metadata` | `pseudonymized`), the per-user daily
 * budget (1 … the effective tenant budget), `useTenantKey` (only with the platform gate on —
 * `403 assistant_tenant_keys_disabled` — and a stored key: `404 assistant_tenant_key_not_found`,
 * one with status `valid`: `422 assistant_tenant_key_rejected`) and `tenantKeyFallbackToPlatform`
 * (absent in the body = unchanged); the view adds `tenantKey`, `tenantKeysOffered` and the
 * read-only `effectiveLimits`.
 */
@Injectable()
export class AssistantSettingsService {
  constructor(
    @Inject(API_CONFIG) private readonly config: AssistantConfig,
    private readonly repo: AssistantSettingsRepository,
    private readonly features: OrganizationFeaturesService,
    private readonly limits: AssistantLimitsService,
    private readonly runner: TransactionRunner,
    private readonly audit: AuditService,
    private readonly conversations: ConversationsRepository,
    @Optional() private readonly keys?: ProviderKeysRepository,
    @Optional() private readonly tenantKeys?: TenantKeyService,
  ) {}

  now(): Date {
    return new Date();
  }

  async get(scope: TenantScope): Promise<AssistantSettingsView> {
    const [row, featureEnabled] = await Promise.all([
      this.repo.get(scope),
      this.features.isEffectivelyEnabled(scope.organizationId, ASSISTANT_FEATURE),
    ]);
    return this.view(row, featureEnabled);
  }

  async update(
    principal: UserPrincipal,
    scope: TenantScope,
    body: UpdateAssistantSettingsBody,
    sourceIp: string | null,
  ): Promise<AssistantSettingsView> {
    const issues: string[] = [];
    if (body.enabled && !body.externalProcessingAcknowledged) {
      issues.push('externalProcessingAcknowledged: must be true to enable the assistant');
    }
    if (
      body.dailyTokenBudget !== null &&
      body.dailyTokenBudget > this.config.ASSISTANT_TENANT_DAILY_TOKENS_MAX
    ) {
      issues.push(
        `dailyTokenBudget: must be at most ${this.config.ASSISTANT_TENANT_DAILY_TOKENS_MAX}`,
      );
    }
    const effectiveBudget = this.limits.tenantBudget(body.dailyTokenBudget);
    if (
      body.userDailyTokenBudget !== undefined &&
      body.userDailyTokenBudget !== null &&
      body.userDailyTokenBudget > effectiveBudget
    ) {
      issues.push(
        `userDailyTokenBudget: must be at most the effective daily budget (${effectiveBudget})`,
      );
    }
    if (issues.length > 0) throw new BadRequestException(issues);
    const featureEnabled = await this.features.isEffectivelyEnabled(
      scope.organizationId,
      ASSISTANT_FEATURE,
    );
    if (body.enabled && !featureEnabled) throw assistantNotEnabled();
    if (body.useTenantKey === true) await this.assertTenantKeyUsable(scope);

    const now = this.now();
    await this.runner.run(async (tx) => {
      const current = await this.repo.get(scope, tx);
      const currentVersion = current?.rowVersion ?? 0;
      if (currentVersion !== body.expectedRowVersion) {
        throw assistantSettingsConflict(currentVersion);
      }
      const keepAck = body.externalProcessingAcknowledged && current?.externalProcessingAckAt;
      const data: SettingsWrite = {
        enabled: body.enabled,
        externalProcessingAckAt: body.externalProcessingAcknowledged
          ? keepAck
            ? current.externalProcessingAckAt
            : now
          : null,
        externalProcessingAckByUserId: body.externalProcessingAcknowledged
          ? keepAck
            ? current.externalProcessingAckByUserId
            : principal.userId
          : null,
        dailyTokenBudget: body.dailyTokenBudget,
        retentionDays: body.retentionDays,
        updatedByUserId: principal.userId,
        ...(body.dataSharing !== undefined && { dataSharing: body.dataSharing }),
        ...(body.userDailyTokenBudget !== undefined && {
          userDailyTokenBudget: body.userDailyTokenBudget,
        }),
        ...(body.useTenantKey !== undefined && { useTenantKey: body.useTenantKey }),
        ...(body.tenantKeyFallbackToPlatform !== undefined && {
          tenantKeyFallbackToPlatform: body.tenantKeyFallbackToPlatform,
        }),
      };
      const written = current
        ? await this.repo.update(scope, body.expectedRowVersion, data, tx)
        : await this.repo.create(scope, data, tx);
      if (!written) {
        const latest = await this.repo.get(scope, tx);
        throw assistantSettingsConflict(latest?.rowVersion ?? 0);
      }
      // A lowered retention applies to the existing conversations too (D12): their purge date
      // moves earlier in the same transaction. A raised one applies from each next turn.
      const previousRetention =
        current?.retentionDays ?? this.config.ASSISTANT_RETENTION_DEFAULT_DAYS;
      if (data.retentionDays < previousRetention) {
        await this.conversations.shortenRetention(scope.organizationId, data.retentionDays, tx);
      }
      const changed = changedFields(current, data);
      await this.audit.record(
        {
          organizationId: scope.organizationId,
          actor: this.audit.actorFrom(principal),
          action: ASSISTANT_AUDIT.settingsUpdated,
          resourceType: AUDIT_RESOURCE.settings,
          resourceId: scopeOrganizationPublicId(principal),
          sourceIp,
          metadata: {
            changed,
            enabled: data.enabled,
            externalProcessingAcknowledged: data.externalProcessingAckAt !== null,
            dataSharing: data.dataSharing ?? current?.dataSharing ?? 'metadata',
            useTenantKey: data.useTenantKey ?? current?.useTenantKey ?? false,
            rowVersion: currentVersion + 1,
          },
        },
        tx,
      );
    });
    return this.view(await this.repo.get(scope), featureEnabled);
  }

  /** `useTenantKey: true` needs the platform gate and a stored key with status `valid` (D7). */
  private async assertTenantKeyUsable(scope: TenantScope): Promise<void> {
    if (!this.tenantKeys?.enabled) throw assistantTenantKeysDisabled();
    const key = await this.keys?.find(scope.organizationId);
    if (!key) throw assistantTenantKeyNotFound();
    if (key.status !== 'valid') throw assistantTenantKeyRejected({ keyStatus: key.status });
  }

  private async view(
    row: SettingsRow | null,
    featureEnabled: boolean,
  ): Promise<AssistantSettingsView> {
    const ackBy =
      row?.externalProcessingAckByUserId != null
        ? await this.repo.userPublicId(row.externalProcessingAckByUserId)
        : null;
    const tenantKey =
      row && this.tenantKeys ? await this.tenantKeys.view(row.organizationId) : null;
    const c = this.config;
    return {
      version: 'assistant-settings/1',
      enabled: row?.enabled ?? false,
      externalProcessingAcknowledged: row?.externalProcessingAckAt != null,
      externalProcessingAcknowledgedAt: row?.externalProcessingAckAt?.toISOString() ?? null,
      externalProcessingAcknowledgedBy: ackBy,
      dailyTokenBudget: row?.dailyTokenBudget ?? null,
      effectiveDailyTokenBudget: this.limits.tenantBudget(row?.dailyTokenBudget ?? null),
      retentionDays: row?.retentionDays ?? this.config.ASSISTANT_RETENTION_DEFAULT_DAYS,
      dataSharing: row?.dataSharing ?? 'metadata',
      userDailyTokenBudget: row?.userDailyTokenBudget ?? null,
      useTenantKey: row?.useTenantKey ?? false,
      tenantKeyFallbackToPlatform: row?.tenantKeyFallbackToPlatform ?? false,
      tenantKey,
      tenantKeysOffered: this.tenantKeys?.offered() ?? {
        enabled: false,
        providers: [...c.ASSISTANT_TENANT_KEY_PROVIDERS],
        models: [...c.ASSISTANT_TENANT_KEY_MODELS],
      },
      effectiveLimits: {
        turnsPerUserPerMinute: c.ASSISTANT_TURNS_PER_USER_PER_MINUTE,
        messageMaxChars: c.ASSISTANT_USER_MESSAGE_MAX_CHARS,
        toolRoundsPerTurn: c.ASSISTANT_MAX_TOOL_ROUNDS,
        toolCallsPerTurn: c.ASSISTANT_MAX_TOOL_CALLS_PER_TURN,
        turnDeadlineSeconds: Math.ceil(c.ASSISTANT_TURN_DEADLINE_MS / 1000),
        platformDailyCapSet: c.ASSISTANT_PLATFORM_DAILY_TOKENS > 0,
        tenantDailyTokensMax: c.ASSISTANT_TENANT_DAILY_TOKENS_MAX,
        reportsPerUserPerDay: c.ASSISTANT_REPORTS_PER_USER_PER_DAY,
        reportEmailsPerUserPerDay: c.ASSISTANT_REPORT_EMAILS_PER_USER_PER_DAY,
        reportEmailsPerTenantPerDay: c.ASSISTANT_REPORT_EMAILS_PER_TENANT_PER_DAY,
        confirmationTtlSeconds: c.ASSISTANT_CONFIRMATION_TTL_SECONDS,
        retentionDays: { min: 1, max: 365 },
      },
      featureEnabled,
      rowVersion: row?.rowVersion ?? 0,
      updatedAt: row?.updatedAt.toISOString() ?? null,
    };
  }
}

/** Names of the fields a write changes (audit metadata; never the values). */
export function changedFields(current: SettingsRow | null, next: SettingsWrite): string[] {
  const before = {
    enabled: current?.enabled ?? false,
    externalProcessingAcknowledged: current?.externalProcessingAckAt != null,
    dailyTokenBudget: current?.dailyTokenBudget ?? null,
    retentionDays: current?.retentionDays ?? null,
    dataSharing: current?.dataSharing ?? 'metadata',
    userDailyTokenBudget: current?.userDailyTokenBudget ?? null,
    useTenantKey: current?.useTenantKey ?? false,
    tenantKeyFallbackToPlatform: current?.tenantKeyFallbackToPlatform ?? false,
  };
  // Step AI-6: an absent field keeps its value (unchanged).
  const after = {
    enabled: next.enabled,
    externalProcessingAcknowledged: next.externalProcessingAckAt !== null,
    dailyTokenBudget: next.dailyTokenBudget,
    retentionDays: next.retentionDays,
    dataSharing: next.dataSharing ?? before.dataSharing,
    userDailyTokenBudget:
      next.userDailyTokenBudget === undefined
        ? before.userDailyTokenBudget
        : next.userDailyTokenBudget,
    useTenantKey: next.useTenantKey ?? before.useTenantKey,
    tenantKeyFallbackToPlatform:
      next.tenantKeyFallbackToPlatform ?? before.tenantKeyFallbackToPlatform,
  };
  return (Object.keys(after) as Array<keyof typeof after>).filter((k) => before[k] !== after[k]);
}
