import { Inject, Injectable, Logger } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import {
  attachmentPlatformSettingsOf,
  becPlatformSettingsOf,
  dlpPlatformSettingsOf,
  rspamdPlatformSettingsOf,
  type SandboxExpectedBackend,
  sandboxPlatformSettingsOf,
  urlPlatformSettingsOf,
} from '../../../config';
import { TransactionRunner } from '../../../database/transaction-runner';
import { OrganizationFeaturesService } from '../../../tenancy/organization-features.service';
import type { ClientContext } from '../../auth/services/session.service';
import { isUniqueViolation } from '../../domains/repositories/domains.repository';
import {
  type EngineSettingsDefinition,
  engineSettingsDefinitions,
  type EngineViewContext,
  holdsOverride,
  SANDBOX_FEATURE_KEY,
} from '../domain/engine-settings';
import {
  type EngineSettingsView,
  type SandboxExecutionMode,
  SETTINGS_APPLY_NOTE,
  type ScanSettingsList,
  type ScanSettingsPut,
  type ScanSettingsResponse,
} from '../dto/scan-settings.schemas';
import {
  featureNotEnabled,
  scanEngineNotFound,
  scanSettingsInvalid,
  versionConflict,
} from '../scans.errors';
import {
  type ScanSettingsRow,
  ScanSettingsRepository,
} from '../repositories/scan-settings.repository';

/** `audit_logs.action` of the settings changes (D14 `<resource>.<verb>`). */
export const SCAN_SETTINGS_AUDIT = {
  updated: 'scan_settings.updated',
  reset: 'scan_settings.reset',
} as const;
export const SCAN_SETTINGS_RESOURCE = 'scan_engine_settings';

type ScanConfig = Parameters<typeof rspamdPlatformSettingsOf>[0] &
  Parameters<typeof attachmentPlatformSettingsOf>[0] &
  Parameters<typeof urlPlatformSettingsOf>[0] &
  Parameters<typeof becPlatformSettingsOf>[0] &
  Parameters<typeof dlpPlatformSettingsOf>[0] &
  Parameters<typeof sandboxPlatformSettingsOf>[0] & {
    SANDBOX_EXPECTED_BACKEND?: SandboxExpectedBackend;
  };

/** How the settings view describes the configured controller backend (X17). */
export const SANDBOX_EXECUTION_OF: Record<SandboxExpectedBackend, SandboxExecutionMode> = {
  disabled: 'disabled',
  static: 'static_only',
  'hardened-container': 'local_test_runner',
};

const stored = (row: ScanSettingsRow | null) =>
  row === null ? null : { settings: row.settings, version: row.version, updatedAt: row.updatedAt };

const userIdOf = (principal: Principal): bigint | null =>
  principal.kind === 'user' ? principal.userId : null;

/**
 * Per-organization scan settings (step 4.1 S8, S16; step 4.2 A8: `attachment`; step 4.3 U13:
 * `url`, domains normalized through `@email-gateway/url-security`). Reads list every
 * catalog engine with tenant settings, its platform settings, bounds, the organization's override
 * and the effective settings (replica). Changes validate the override against the platform
 * settings (`resolveRspamdSettings` / `resolveAttachmentSettings` / `resolveUrlSettings`: bounds, threshold order,
 * raise-only severities and verdicts, tighten-only size, platform-denied types never allowed,
 * no unknown keys; `422 scan_settings_invalid`), compare
 * and set the row version (`409 version_conflict`) and write the `audit_logs` row with the
 * before/after settings in the same writer transaction. The organization comes from the
 * authenticated scope only. A reset keeps the row with an empty override and a new version, so
 * versions never repeat (no lost update after a reset).
 *
 * Step 4.6 X17: an override with `sandbox.enabled = true` needs the organization's plan feature
 * `attachment_sandbox` (read on the writer inside the change transaction; `409
 * feature_not_enabled`); every view states that feature.
 */
@Injectable()
export class ScanSettingsService {
  private readonly logger = new Logger(ScanSettingsService.name);
  private readonly definitions: ReadonlyMap<string, EngineSettingsDefinition>;

  constructor(
    @Inject(API_CONFIG) config: ScanConfig,
    private readonly repository: ScanSettingsRepository,
    private readonly transactions: TransactionRunner,
    private readonly audit: AuditService,
    private readonly features: OrganizationFeaturesService,
  ) {
    this.definitions = engineSettingsDefinitions({
      rspamd: rspamdPlatformSettingsOf(config),
      attachment: attachmentPlatformSettingsOf(config),
      url: urlPlatformSettingsOf(config),
      bec: becPlatformSettingsOf(config),
      dlp: dlpPlatformSettingsOf(config),
      sandbox: {
        settings: sandboxPlatformSettingsOf(config),
        execution: SANDBOX_EXECUTION_OF[config.SANDBOX_EXPECTED_BACKEND ?? 'disabled'],
      },
    });
  }

  /** The organization facts the views show (plan features are read on the writer). */
  private async context(
    scope: TenantScope,
    tx?: Prisma.TransactionClient,
  ): Promise<EngineViewContext> {
    return {
      attachmentSandbox: await this.features.isEnabled(
        scope.organizationId,
        SANDBOX_FEATURE_KEY,
        tx,
      ),
    };
  }

  /** `GET /scan-settings`. */
  async list(scope: TenantScope): Promise<ScanSettingsList> {
    const [list, context] = await Promise.all([this.repository.list(scope), this.context(scope)]);
    const rows = new Map(list.map((row) => [row.engine, row]));
    return {
      data: [...this.definitions.values()].map((definition) =>
        definition.view(stored(rows.get(definition.catalog.name) ?? null), context),
      ),
      note: SETTINGS_APPLY_NOTE,
    };
  }

  /** `PUT /scan-settings/{engine}`: replaces the override (compare-and-set on `version`). */
  async replace(
    principal: Principal,
    scope: TenantScope,
    engine: string,
    body: ScanSettingsPut,
    client: ClientContext,
  ): Promise<ScanSettingsResponse> {
    const definition = this.definition(engine);
    const checked = definition.check(body.settings);
    if (!checked.ok) throw scanSettingsInvalid(checked.violations);
    const settings = checked.settings as Prisma.InputJsonValue;
    try {
      const view = await this.transactions.run(async (tx) => {
        const current = await this.repository.find(tx, scope, engine);
        const currentVersion = current?.version ?? 0;
        if (currentVersion !== body.expectedVersion) throw versionConflict(currentVersion);
        const feature = definition.requiredFeature?.(checked.settings) ?? null;
        if (
          feature !== null &&
          !(await this.features.isEnabled(scope.organizationId, feature, tx))
        ) {
          throw featureNotEnabled(feature);
        }
        const context = await this.context(scope, tx);
        const updatedByUserId = userIdOf(principal);
        if (current === null) {
          await this.repository.create(tx, scope, { engine, settings, updatedByUserId });
        } else if (
          !(await this.repository.replaceIfVersion(tx, scope, {
            engine,
            expectedVersion: body.expectedVersion,
            settings,
            updatedByUserId,
          }))
        ) {
          const now = await this.repository.find(tx, scope, engine);
          throw versionConflict(now?.version ?? 0);
        }
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: SCAN_SETTINGS_AUDIT.updated,
            resourceType: SCAN_SETTINGS_RESOURCE,
            resourceId: engine,
            sourceIp: client.ip,
            metadata: {
              engine,
              fromVersion: currentVersion,
              toVersion: currentVersion + 1,
              before: holdsOverride(stored(current)) ? current!.settings : null,
              after: checked.settings,
            },
          },
          tx,
        );
        return definition.view(stored(await this.repository.find(tx, scope, engine)), context);
      });
      this.logChange('updated', scope, view);
      return { ...view, note: SETTINGS_APPLY_NOTE };
    } catch (error) {
      // Two first writes raced on the (organization, engine) key: the loser is a conflict.
      if (isUniqueViolation(error)) {
        const now = await this.transactions.run((tx) => this.repository.find(tx, scope, engine));
        throw versionConflict(now?.version ?? 0);
      }
      throw error;
    }
  }

  /**
   * `DELETE /scan-settings/{engine}?expectedVersion=n`: back to the platform settings. The row
   * keeps an empty override and gets a new version; without an override nothing changes (no
   * audit row) when `expectedVersion` is the current version.
   */
  async reset(
    principal: Principal,
    scope: TenantScope,
    engine: string,
    expectedVersion: number,
    client: ClientContext,
  ): Promise<ScanSettingsResponse> {
    const definition = this.definition(engine);
    const { view, changed } = await this.transactions.run(async (tx) => {
      const current = await this.repository.find(tx, scope, engine);
      const currentVersion = current?.version ?? 0;
      if (currentVersion !== expectedVersion) throw versionConflict(currentVersion);
      const context = await this.context(scope, tx);
      if (!holdsOverride(stored(current))) {
        return { view: definition.view(stored(current), context), changed: false };
      }
      const changed = await this.repository.replaceIfVersion(tx, scope, {
        engine,
        expectedVersion,
        settings: {},
        updatedByUserId: userIdOf(principal),
      });
      if (!changed) {
        const now = await this.repository.find(tx, scope, engine);
        throw versionConflict(now?.version ?? 0);
      }
      await this.audit.record(
        {
          organizationId: scope.organizationId,
          actor: this.audit.actorFrom(principal),
          action: SCAN_SETTINGS_AUDIT.reset,
          resourceType: SCAN_SETTINGS_RESOURCE,
          resourceId: engine,
          sourceIp: client.ip,
          metadata: {
            engine,
            fromVersion: currentVersion,
            toVersion: currentVersion + 1,
            before: current!.settings,
            after: null,
          },
        },
        tx,
      );
      return {
        view: definition.view(stored(await this.repository.find(tx, scope, engine)), context),
        changed: true,
      };
    });
    if (changed) this.logChange('reset', scope, view);
    return { ...view, note: SETTINGS_APPLY_NOTE };
  }

  private definition(engine: string): EngineSettingsDefinition {
    const definition = this.definitions.get(engine);
    if (!definition) throw scanEngineNotFound();
    return definition;
  }

  private logChange(change: 'updated' | 'reset', scope: TenantScope, view: EngineSettingsView) {
    this.logger.log({
      message: 'scan settings changed',
      change,
      engine: view.engine,
      organizationId: scope.organizationId.toString(),
      version: view.version,
      overrideApplied: view.overrideApplied,
    });
  }
}
