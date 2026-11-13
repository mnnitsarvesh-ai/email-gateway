import { BadRequestException, ForbiddenException, Injectable } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import {
  canonicalSettings,
  NOTIFICATION_SETTINGS_BOUNDS,
  NOTIFICATION_SETTINGS_DEFAULTS,
  notificationSettingsSchema,
  PREFERENCE_KINDS,
  resolveNotificationPreferences,
  resolveNotificationSettings,
} from '@email-gateway/webhooks';
import { AuditService } from '../../audit/audit.service';
import type { Principal, UserPrincipal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { TransactionRunner } from '../../database/transaction-runner';
import { formatZodIssues } from '../../validation/zod-validation.pipe';
import type { ClientContext } from '../auth/services/session.service';
import { QuarantineContext } from '../quarantine/services/quarantine-context';
import { changedPaths } from '../quarantine/services/quarantine-settings.service';
import { notificationSettingsConflict, notificationSettingsInvalid } from './notifications.errors';
import { NotificationsRepository, type StoredSettings } from './notifications.repository';
import {
  type PreferencesBody,
  type PreferencesResponse,
  SettingsEnvelopeSchema,
  type SettingsResponse,
} from './notifications.schemas';

/** Writer transaction budget of the notification writes (D15). */
export const NOTIFICATIONS_TX_TIMEOUT_MS = 30_000;

export const NOTIFICATION_AUDIT = {
  settingsUpdated: 'notification.settings_updated',
  preferencesUpdated: 'notification.preferences_updated',
} as const;

const plain = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

/** The settings view of a stored row (or none). */
export function toSettingsView(row: StoredSettings | null): SettingsResponse {
  const resolution = resolveNotificationSettings(row?.settings ?? null);
  const stored = row === null ? null : notificationSettingsSchema.safeParse(row.settings);
  return {
    settings: resolution.settings,
    stored: stored?.success ? stored.data : null,
    invalidStored: row !== null && resolution.invalidStored,
    rowVersion: row?.rowVersion ?? 0,
    updatedAt: row?.updatedAt.toISOString() ?? null,
    defaults: plain(NOTIFICATION_SETTINGS_DEFAULTS),
    bounds: plain(NOTIFICATION_SETTINGS_BOUNDS),
  };
}

/**
 * Tenant security-alert settings and the personal preference center (step 6.2 N3): `GET`
 * resolves the stored document over the defaults (an invalid stored document → defaults and
 * `invalidStored`); `PUT` validates the whole document strictly (`400
 * notification_settings_invalid` with the violating paths), compares `expectedRowVersion` (0 =
 * none stored; `409 notification_settings_conflict`) and is audited with the changed paths
 * only. Preferences are the caller's own (users who are members of the organization; API keys
 * and platform overrides are refused): opt-outs in `notification_user_preferences`, the
 * quarantine digest opt-out in `quarantine_user_preferences.digest_opt_out` (one source of
 * truth with `/quarantine/me/preferences`; opting out needs `digest.allowOptOut`).
 */
@Injectable()
export class NotificationsService {
  constructor(
    private readonly repository: NotificationsRepository,
    private readonly runner: TransactionRunner,
    private readonly audit: AuditService,
    private readonly quarantine: QuarantineContext,
  ) {}

  async settings(scope: TenantScope): Promise<SettingsResponse> {
    return toSettingsView(await this.repository.settings(scope));
  }

  async putSettings(
    principal: Principal,
    scope: TenantScope,
    rawBody: unknown,
    client: ClientContext,
  ): Promise<SettingsResponse> {
    const envelope = SettingsEnvelopeSchema.safeParse(rawBody ?? {});
    if (!envelope.success) throw new BadRequestException(formatZodIssues(envelope.error));
    const parsed = notificationSettingsSchema.safeParse(envelope.data.settings);
    if (!parsed.success) {
      throw notificationSettingsInvalid(
        parsed.error.issues.map((issue) => ({
          path: ['settings', ...issue.path.map(String)].join('.'),
          message: issue.message,
        })),
      );
    }
    const canonical = canonicalSettings(parsed.data);
    const document = JSON.parse(canonical.json) as Prisma.InputJsonValue;
    const userId = principal.kind === 'user' ? principal.userId : null;
    const expected = envelope.data.expectedRowVersion;
    const row = await this.runner.run(
      async (tx) => {
        const current = await this.repository.lockSettings(tx, scope);
        const currentVersion = current?.rowVersion ?? 0;
        if (currentVersion !== expected) throw notificationSettingsConflict(currentVersion);
        const data = { settings: document, sha256: canonical.sha256, userId };
        if (current === null) {
          await this.repository.insertSettings(tx, scope, data);
        } else if (!(await this.repository.updateSettings(tx, scope, currentVersion, data))) {
          throw notificationSettingsConflict(currentVersion);
        }
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: NOTIFICATION_AUDIT.settingsUpdated,
            resourceType: 'notification_settings',
            resourceId: null,
            sourceIp: client.ip,
            metadata: {
              changedPaths: changedPaths(current?.settings ?? {}, document).slice(0, 64),
              settingsSha256: canonical.sha256,
              rowVersion: currentVersion + 1,
            },
          },
          tx,
        );
        // Read-after-write on the writer (the replica may lag behind this write).
        return this.repository.reloadSettings(tx, scope);
      },
      { timeoutMs: NOTIFICATIONS_TX_TIMEOUT_MS },
    );
    return toSettingsView(row);
  }

  async preferences(principal: Principal, scope: TenantScope): Promise<PreferencesResponse> {
    const user = this.member(principal, scope);
    const [stored, digestOptOut, quarantine] = await Promise.all([
      this.repository.preferences(scope, user.userId),
      this.repository.digestOptOut(scope, user.userId),
      this.quarantine.settings(scope),
    ]);
    const resolved = resolveNotificationPreferences(stored);
    return {
      optOut: resolved.optOut,
      quarantineDigestOptOut: digestOptOut,
      quarantineDigestOptOutAllowed: quarantine.digest.allowOptOut,
      kinds: [...PREFERENCE_KINDS],
      invalidStored: resolved.invalidStored,
    };
  }

  async putPreferences(
    principal: Principal,
    scope: TenantScope,
    body: PreferencesBody,
    client: ClientContext,
  ): Promise<PreferencesResponse> {
    const user = this.member(principal, scope);
    const optOut = PREFERENCE_KINDS.filter((kind) => body.optOut.includes(kind));
    const result = await this.runner.run(
      async (tx) => {
        const current = await this.repository.lockPreferences(tx, scope, user.userId);
        const quarantine = await this.quarantine.settingsTx(tx, scope);
        const allowed = quarantine.digest.allowOptOut;
        if (body.quarantineDigestOptOut && !current.digestOptOut && !allowed) {
          throw new BadRequestException([
            'quarantineDigestOptOut: the organization does not allow opting out of the quarantine digest',
          ]);
        }
        const before = resolveNotificationPreferences(current.preferences).optOut;
        await this.repository.upsertPreferences(tx, scope, user.userId, { optOut });
        if (body.quarantineDigestOptOut !== current.digestOptOut) {
          await this.repository.upsertDigestOptOut(
            tx,
            scope,
            user.userId,
            body.quarantineDigestOptOut,
          );
        }
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: NOTIFICATION_AUDIT.preferencesUpdated,
            resourceType: 'notification_preferences',
            resourceId: user.userPublicId,
            sourceIp: client.ip,
            metadata: {
              optOut,
              added: optOut.filter((k) => !before.includes(k)),
              removed: before.filter((k) => !optOut.includes(k)),
              quarantineDigestOptOut: body.quarantineDigestOptOut,
            },
          },
          tx,
        );
        return { allowed };
      },
      { timeoutMs: NOTIFICATIONS_TX_TIMEOUT_MS },
    );
    return {
      optOut,
      quarantineDigestOptOut: body.quarantineDigestOptOut,
      quarantineDigestOptOutAllowed: result.allowed,
      kinds: [...PREFERENCE_KINDS],
      invalidStored: false,
    };
  }

  /** A user who is a member of the organization (not an API key, not a platform override). */
  private member(principal: Principal, scope: TenantScope): UserPrincipal {
    if (principal.kind !== 'user' || scope.via !== 'member') {
      throw new ForbiddenException('Notification preferences are for members of the organization');
    }
    return principal;
  }
}
