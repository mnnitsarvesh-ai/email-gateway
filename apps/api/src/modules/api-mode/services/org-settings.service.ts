import { Inject, Injectable } from '@nestjs/common';
import {
  ORG_SETTINGS_BOUNDS,
  ORG_SETTINGS_DEFAULTS,
  resolveOrgSettings,
  type ResolvedOrgSettings,
} from '@email-gateway/mailbox-api';
import type { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import {
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  type IdempotentResult,
  IdempotencyService,
} from '../../../http/idempotency/idempotency.service';
import {
  API_MODE_AUDIT,
  API_MODE_OPERATIONS,
  API_MODE_RESOURCES,
  API_MODE_TX_TIMEOUT_MS,
  type ApiModeConfig,
} from '../api-mode.constants';
import { organizationNotFound, settingsConflict } from '../api-mode.errors';
import {
  effectivePurgeThreshold,
  nextPurgeThresholdRaise,
  settingsCasOk,
} from '../domain/clawback-rules';
import {
  type OrgSettingsChangeView,
  type OrgSettingsView,
  PutOrgSettingsBodySchema,
} from '../dto/api-mode-clawback.schemas';
import {
  ApiClawbackRepository,
  type OrgSettingsRow,
} from '../repositories/api-clawback.repository';
import { parseBody } from './protection-mode.service';

type Tx = Prisma.TransactionClient;

/** The eight settings of C14 #19 and the two of step API-4 (A12), in their stable order. */
export const ORG_SETTING_KEYS = [
  'internalMailEnabled',
  'autoClawback',
  'autoMaxMailboxes',
  'purgeApprovalMailboxes',
  'clawbackLookbackDays',
  'tiMinConfidence',
  'reportAckEnabled',
  'reportFeedbackEnabled',
  'policyEvaluationEnabled',
  'outboundDetectionEnabled',
] as const;
type SettingKey = (typeof ORG_SETTING_KEYS)[number];

const isUniqueViolation = (error: unknown): boolean =>
  (error as { code?: unknown } | null)?.code === 'P2002';

/** The effective settings of a row (or the defaults). */
export function effectiveSettings(row: OrgSettingsRow | null): ResolvedOrgSettings {
  return resolveOrgSettings(row);
}

/**
 * The organization's API-mode settings (step API-3 §3.1 `api_mode_org_settings`, C14 #18, #19,
 * C17): the effective values (the row, else `ORG_SETTINGS_DEFAULTS`, resolved by the pure
 * `resolveOrgSettings` the mailbox-worker shares), the bounds and the platform facts; the PUT
 * replaces all eight values with CAS on `row_version` (`expectedRowVersion: null` creates the
 * row; the organization row is locked first so concurrent creations serialize) and writes the
 * `api_mode.settings_org_updated` audit row with the from/to values in the same transaction.
 */
@Injectable()
export class OrgSettingsService {
  constructor(
    @Inject(API_CONFIG)
    private readonly config: Pick<
      ApiModeConfig,
      | 'API_MODE_HARD_DELETE_ENABLED'
      | 'API_MODE_CLAWBACK_MAX_WINDOW_DAYS'
      | 'API_MODE_PURGE_APPROVAL_TTL_HOURS'
      | 'API_MODE_REPORT_MAILBOXES_MAX'
    >,
    private readonly repository: ApiClawbackRepository,
    private readonly idempotency: IdempotencyService,
    private readonly audit: AuditService,
  ) {}

  /** The effective settings (replica unless a transaction is given). */
  async resolve(scope: TenantScope, tx?: Tx): Promise<ResolvedOrgSettings> {
    return effectiveSettings(await this.repository.orgSettings(scope, tx));
  }

  /**
   * The settings a purge submit by `principal` is decided with (in the caller's transaction):
   * the effective settings and the purge approval threshold that applies to that principal —
   * the value before their own raise when they raised it (P2 separation of duties).
   */
  async resolveForSubmit(
    scope: TenantScope,
    principal: Principal,
    tx: Tx,
  ): Promise<{
    settings: ResolvedOrgSettings;
    purgeThreshold: { threshold: number; selfRaised: boolean };
  }> {
    const row = await this.repository.orgSettings(scope, tx);
    const settings = effectiveSettings(row);
    return {
      settings,
      purgeThreshold: effectivePurgeThreshold({
        threshold: settings.purgeApprovalMailboxes,
        raise: {
          raisedBy: row?.purgeApprovalRaisedBy ?? null,
          beforeRaise: row?.purgeApprovalBeforeRaise ?? null,
        },
        submitter: principalKey(principal),
      }),
    };
  }

  view(row: OrgSettingsRow | null): OrgSettingsView {
    const resolved = effectiveSettings(row);
    const settings = Object.fromEntries(
      ORG_SETTING_KEYS.map((k) => [k, resolved[k]]),
    ) as OrgSettingsView['settings'];
    return {
      settings,
      source: resolved.source,
      rowVersion: resolved.rowVersion,
      updatedAt: row === null ? null : row.updatedAt.toISOString(),
      defaults: { ...ORG_SETTINGS_DEFAULTS },
      bounds: {
        autoMaxMailboxes: { ...ORG_SETTINGS_BOUNDS.autoMaxMailboxes },
        purgeApprovalMailboxes: { ...ORG_SETTINGS_BOUNDS.purgeApprovalMailboxes },
        clawbackLookbackDays: { ...ORG_SETTINGS_BOUNDS.clawbackLookbackDays },
        tiMinConfidence: { ...ORG_SETTINGS_BOUNDS.tiMinConfidence },
      },
      platform: {
        hardDeleteAvailable: this.config.API_MODE_HARD_DELETE_ENABLED,
        clawbackMaxWindowDays: this.config.API_MODE_CLAWBACK_MAX_WINDOW_DAYS,
        purgeApprovalTtlHours: this.config.API_MODE_PURGE_APPROVAL_TTL_HOURS,
        reportMailboxesMax: this.config.API_MODE_REPORT_MAILBOXES_MAX,
      },
    };
  }

  /** `GET /api-mode/settings` (C14 #18). */
  async get(scope: TenantScope): Promise<OrgSettingsView> {
    return this.view(await this.repository.orgSettings(scope));
  }

  /** `PUT /api-mode/settings` (C14 #19; keyed; CAS). */
  async put(
    principal: Principal,
    scope: TenantScope,
    input: { idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<OrgSettingsChangeView>> {
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(PutOrgSettingsBodySchema, input.body);
    const operation = API_MODE_OPERATIONS.orgSettingsPut;
    return this.idempotency.execute<OrgSettingsChangeView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: 'organization',
        fingerprint: requestFingerprint({ operation, resourceId: 'organization', body }),
      },
      async (tx) => {
        try {
          if (!(await this.repository.lockOrganization(tx, scope))) throw organizationNotFound();
          const current = await this.repository.lockOrgSettings(tx, scope);
          if (!settingsCasOk(current?.rowVersion ?? null, body.expectedRowVersion)) {
            throw settingsConflict(current?.rowVersion ?? null);
          }
          const before = effectiveSettings(current);
          // P2 separation of duties: remember who raised the purge threshold and from what.
          const raise = nextPurgeThresholdRaise({
            before: before.purgeApprovalMailboxes,
            next: body.purgeApprovalMailboxes,
            current: {
              raisedBy: current?.purgeApprovalRaisedBy ?? null,
              beforeRaise: current?.purgeApprovalBeforeRaise ?? null,
            },
            actor: principalKey(principal),
          });
          const write = {
            internalMailEnabled: body.internalMailEnabled,
            autoClawback: body.autoClawback,
            autoMaxMailboxes: body.autoMaxMailboxes,
            purgeApprovalMailboxes: body.purgeApprovalMailboxes,
            clawbackLookbackDays: body.clawbackLookbackDays,
            tiMinConfidence: body.tiMinConfidence,
            reportAckEnabled: body.reportAckEnabled,
            reportFeedbackEnabled: body.reportFeedbackEnabled,
            // Step API-4 (A12): absent = keep the current effective value (API-3 bodies).
            policyEvaluationEnabled: body.policyEvaluationEnabled ?? before.policyEvaluationEnabled,
            outboundDetectionEnabled:
              body.outboundDetectionEnabled ?? before.outboundDetectionEnabled,
            updatedByUserId: principal.kind === 'user' ? principal.userId : null,
            purgeApprovalRaisedBy: raise.raisedBy,
            purgeApprovalBeforeRaise: raise.beforeRaise,
          };
          if (current === null) await this.repository.createOrgSettings(tx, scope, write);
          else if (
            !(await this.repository.updateOrgSettings(tx, scope, current.rowVersion, write))
          ) {
            throw settingsConflict(current.rowVersion);
          }
          const after = await this.repository.orgSettings(scope, tx);
          if (after === null) throw settingsConflict(null);
          const resolvedAfter = effectiveSettings(after);
          const changed: SettingKey[] = ORG_SETTING_KEYS.filter(
            (k) => before[k] !== resolvedAfter[k],
          );
          const pick = (s: Record<SettingKey, unknown>) =>
            Object.fromEntries(changed.map((k) => [k, s[k]]));
          await this.audit.record(
            {
              organizationId: scope.organizationId,
              actor: this.audit.actorFrom(principal),
              action: API_MODE_AUDIT.settingsOrgUpdated,
              resourceType: API_MODE_RESOURCES.orgSettings,
              resourceId: 'organization',
              sourceIp,
              metadata: {
                changed,
                from: pick(before),
                to: pick(resolvedAfter),
                created: current === null,
                rowVersion: after.rowVersion,
                reason: body.reason,
                ...(changed.includes('purgeApprovalMailboxes') && {
                  purgeApprovalSelfCheck:
                    raise.raisedBy === null ? null : { beforeRaise: raise.beforeRaise },
                }),
              },
            },
            tx,
          );
          return {
            statusCode: 200,
            body: { ...this.view(after), changed: [...changed], created: current === null },
          };
        } catch (error) {
          // A concurrent creation of the row won the primary key: a CAS conflict.
          if (isUniqueViolation(error)) throw settingsConflict(null);
          throw error;
        }
      },
      { timeoutMs: API_MODE_TX_TIMEOUT_MS },
    );
  }
}
