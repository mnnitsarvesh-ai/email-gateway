import { BadRequestException, Inject, Injectable } from '@nestjs/common';
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
import { assistantNotEnabled, assistantSettingsConflict } from '../assistant.errors';
import { scopeOrganizationPublicId } from '../domain/tool-catalog';
import type { AssistantSettingsView, UpdateAssistantSettingsBody } from '../dto/assistant.schemas';
import {
  AssistantSettingsRepository,
  type SettingsRow,
  type SettingsWrite,
} from '../repositories/assistant-settings.repository';
import { ConversationsRepository } from '../repositories/conversations.repository';
import { AssistantLimitsService } from './assistant-limits.service';

/**
 * The organization's assistant settings `assistant-settings/1` (design D13, §4.1): one row per
 * organization (no row = disabled with the platform defaults), CAS on `rowVersion`
 * (`409 assistant_settings_conflict`), enabling needs `externalProcessingAcknowledged: true`
 * (recording who and when) and the feature `ai_assistant` (`403 assistant_not_enabled`); the
 * budget is capped by ASSISTANT_TENANT_DAILY_TOKENS_MAX. Audited `assistant.settings_updated`
 * (changed field names and the new switches, never other values). Lowering `retentionDays`
 * moves the purge date of the organization's existing conversations earlier (D12).
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
    if (issues.length > 0) throw new BadRequestException(issues);
    const featureEnabled = await this.features.isEffectivelyEnabled(
      scope.organizationId,
      ASSISTANT_FEATURE,
    );
    if (body.enabled && !featureEnabled) throw assistantNotEnabled();

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
            rowVersion: currentVersion + 1,
          },
        },
        tx,
      );
    });
    return this.view(await this.repo.get(scope), featureEnabled);
  }

  private async view(
    row: SettingsRow | null,
    featureEnabled: boolean,
  ): Promise<AssistantSettingsView> {
    const ackBy =
      row?.externalProcessingAckByUserId != null
        ? await this.repo.userPublicId(row.externalProcessingAckByUserId)
        : null;
    return {
      version: 'assistant-settings/1',
      enabled: row?.enabled ?? false,
      externalProcessingAcknowledged: row?.externalProcessingAckAt != null,
      externalProcessingAcknowledgedAt: row?.externalProcessingAckAt?.toISOString() ?? null,
      externalProcessingAcknowledgedBy: ackBy,
      dailyTokenBudget: row?.dailyTokenBudget ?? null,
      effectiveDailyTokenBudget: this.limits.tenantBudget(row?.dailyTokenBudget ?? null),
      retentionDays: row?.retentionDays ?? this.config.ASSISTANT_RETENTION_DEFAULT_DAYS,
      dataSharing: 'metadata',
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
  };
  const after = {
    enabled: next.enabled,
    externalProcessingAcknowledged: next.externalProcessingAckAt !== null,
    dailyTokenBudget: next.dailyTokenBudget,
    retentionDays: next.retentionDays,
  };
  return (Object.keys(after) as Array<keyof typeof after>).filter((k) => before[k] !== after[k]);
}
