import { Inject, Injectable } from '@nestjs/common';
import {
  type ArchiveSettingsDocument,
  canonicalSha256,
  parseExportSigningPublicKey,
  parsePreviousSigningPublicKeys,
  resolveArchiveSettings,
  type ResolvedArchiveSettings,
  validateArchiveSettingsChange,
} from '@email-gateway/archive';
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
import { OrganizationFeaturesService } from '../../../tenancy/organization-features.service';
import { OrganizationLimitsService } from '../../../tenancy/organization-limits.service';
import {
  ARCHIVE_AUDIT,
  ARCHIVE_OPERATIONS,
  ARCHIVE_RESOURCE,
  ARCHIVE_TX_TIMEOUT_MS,
  ARCHIVING_FEATURE,
  type ArchiveConfig,
} from '../archive.constants';
import { changedSettingsPaths, forbiddenSettingsPaths } from '../domain/settings-paths';
import {
  archiveSettingsConflict,
  archiveSettingsForbiddenPath,
  archivingNotEnabled,
  defaultRetentionRequired,
  immutabilityDowngradeForbidden,
  objectLockUnavailable,
  retentionPolicyNotFound,
  scopeReferenceInvalid,
} from '../archive.errors';
import type {
  ArchiveSettingsView,
  ArchiveStatusView,
  SigningKeysView,
  UpdateArchiveSettingsBody,
} from '../dto/archive.schemas';
import {
  ArchiveConfigRepository,
  type SettingsRow,
} from '../repositories/archive-config.repository';
import { ArchiveRecordsRepository } from '../repositories/archive-records.repository';
import { secondsBetween, userIdOf } from './archive-common';
import { ArchiveObjectStore } from './archive-object-store';
import { ArchiveSearchClient } from './archive-search.client';

type Tx = Prisma.TransactionClient;

/** Top-level fields of the PUT body (audit `changedPaths`). */
type SettingsField = 'enabled' | 'immutability' | 'defaultRetentionPolicyId' | 'settings';

/** The stored document resolved with defaults; an unparsable stored document reads as defaults. */
export function effectiveSettings(raw: unknown): ResolvedArchiveSettings {
  try {
    return resolveArchiveSettings(raw);
  } catch {
    return resolveArchiveSettings(null);
  }
}

/** Dotted paths of the scope ids that did not resolve (first one reported). */
function firstUnresolved(
  doc: ResolvedArchiveSettings['scope'],
  unresolved: { domainIds: string[]; departmentIds: string[]; userIds: string[] },
): string | null {
  for (const field of ['domainIds', 'departmentIds', 'userIds'] as const) {
    const missing = new Set(unresolved[field].map((id) => id.toLowerCase()));
    const index = doc[field].findIndex((id) => missing.has(id.toLowerCase()));
    if (index >= 0) return `settings.scope.${field}.${index}`;
  }
  return null;
}

/**
 * Archive settings, status and the published export signing keys (step 8.1 §4.4 #1, #2, #10,
 * #14; A10, A22). `PUT /archive/settings` runs in one writer transaction under the organization
 * and settings row locks with the transactional Idempotency-Key: CAS on `rowVersion`, scope ids
 * resolved inside the organization, the library rules of `validateArchiveSettingsChange`
 * (entitlement when enabling, a live default retention policy while enabled, no compliance
 * downgrade, Object Lock availability for a new mode), `generation + 1`, `journal_enabled_at`
 * when enabling, the "apply lock" signal for a stronger mode and the audit row with the changed
 * paths (never values).
 */
@Injectable()
export class ArchiveSettingsService {
  private readonly signingKeys: SigningKeysView;

  constructor(
    @Inject(API_CONFIG)
    config: Pick<
      ArchiveConfig,
      | 'ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY'
      | 'ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY_ID'
      | 'ARCHIVE_EXPORT_SIGNING_PREVIOUS_PUBLIC_KEYS'
    >,
    private readonly configs: ArchiveConfigRepository,
    private readonly records: ArchiveRecordsRepository,
    private readonly objects: ArchiveObjectStore,
    private readonly search: ArchiveSearchClient,
    private readonly features: OrganizationFeaturesService,
    private readonly limits: OrganizationLimitsService,
    private readonly idempotency: IdempotencyService,
    private readonly audit: AuditService,
  ) {
    // Validated at start (config schema); parsed again so a bad key never reaches a response.
    parseExportSigningPublicKey(config.ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY);
    const previous = parsePreviousSigningPublicKeys(
      config.ARCHIVE_EXPORT_SIGNING_PREVIOUS_PUBLIC_KEYS,
    );
    this.signingKeys = {
      data: [
        {
          id: config.ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY_ID,
          algorithm: 'Ed25519',
          format: 'spki-der-base64url',
          publicKey: config.ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY,
          current: true,
        },
        ...previous.map((k) => ({
          id: k.id,
          algorithm: 'Ed25519' as const,
          format: 'spki-der-base64url' as const,
          publicKey: k.publicKey,
          current: false,
        })),
      ],
    };
  }

  now(): Date {
    return new Date();
  }

  /** `GET /archive/settings` (#1): replica row, writer entitlement, cached lock probe. */
  async get(scope: TenantScope): Promise<ArchiveSettingsView> {
    const [row, entitled, lockAvailable] = await Promise.all([
      this.configs.settings(scope),
      this.features.isEnabled(scope.organizationId, ARCHIVING_FEATURE),
      this.objects.objectLockAvailable(),
    ]);
    return this.view(row, entitled, lockAvailable);
  }

  view(row: SettingsRow | null, entitled: boolean, lockAvailable: boolean): ArchiveSettingsView {
    return {
      enabled: row?.enabled ?? false,
      entitled,
      immutability: row?.objectLockMode ?? 'none',
      objectLockAvailable: lockAvailable,
      defaultRetentionPolicyId: row?.defaultRetentionPolicyPublicId ?? null,
      settings: effectiveSettings(row?.settings ?? null),
      generation: Number(row?.generation ?? 0n),
      journalEnabledAt: row?.journalEnabledAt?.toISOString() ?? null,
      rowVersion: row?.rowVersion ?? 0,
      updatedAt: row?.updatedAt.toISOString() ?? null,
    };
  }

  /** `PUT /archive/settings` (#2; A10, A22; step 8.6 per-path authorization). */
  update(
    principal: Principal,
    scope: TenantScope,
    idempotencyKey: unknown,
    body: UpdateArchiveSettingsBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<ArchiveSettingsView>> {
    return this.applyUpdate(principal, scope, idempotencyKey, sourceIp, {
      area: 'archive',
      operation: ARCHIVE_OPERATIONS.settingsUpdate,
      fingerprintBody: body,
      change: () => body,
      viewOf: (row, entitled, lockAvailable) => this.view(row, entitled, lockAvailable),
    });
  }

  /**
   * The shared settings update (step 8.6 D11): `PUT /archive/settings` and
   * `PUT /journaling/settings` write the same row with the same `row_version`, rules and audit
   * action. In one writer transaction under the organization and settings locks: CAS on
   * `rowVersion`, the change built from the stored row (`change`), the changed paths authorized
   * one by one (`403 archive_settings_forbidden_path`), then the 8.1 rules.
   */
  async applyUpdate<T>(
    principal: Principal,
    scope: TenantScope,
    idempotencyKey: unknown,
    sourceIp: string | null,
    request: {
      area: 'archive' | 'journaling';
      operation: string;
      fingerprintBody: unknown;
      /** The full PUT body against the locked stored row (journaling merges `access` in). */
      change: (current: SettingsRow | null) => UpdateArchiveSettingsBody;
      viewOf: (row: SettingsRow | null, entitled: boolean, lockAvailable: boolean) => T;
    },
  ): Promise<IdempotentResult<T>> {
    const key = parseIdempotencyKey(idempotencyKey);
    const lockAvailable = await this.objects.objectLockAvailable();
    const operation = request.operation;
    return this.idempotency.execute<T>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: '-',
        fingerprint: requestFingerprint({
          operation,
          resourceId: '-',
          body: request.fingerprintBody,
        }),
      },
      async (tx) => {
        await this.limits.lockOrganization(tx, scope.organizationId);
        const current = await this.configs.lockSettings(tx, scope);
        const currentVersion = current?.rowVersion ?? 0;
        const body = request.change(current);
        if (currentVersion !== body.expectedRowVersion) {
          throw archiveSettingsConflict(currentVersion);
        }
        // Step 8.6 D11: every changed path needs its own permission (before any other rule).
        const paths = changedSettingsPaths(
          {
            enabled: current?.enabled ?? false,
            immutability: current?.objectLockMode ?? 'none',
            defaultRetentionPolicyId: current?.defaultRetentionPolicyPublicId ?? null,
            document: current?.settings ?? null,
          },
          {
            enabled: body.enabled,
            immutability: body.immutability,
            defaultRetentionPolicyId: body.defaultRetentionPolicyId,
            document: body.settings,
          },
        );
        const forbidden = forbiddenSettingsPaths(paths, principal.permissions);
        if (forbidden.length > 0) throw archiveSettingsForbiddenPath(forbidden);
        const entitled = await this.features.isEnabled(scope.organizationId, ARCHIVING_FEATURE, tx);
        const next = await this.nextState(tx, scope, current, body);
        const decision = validateArchiveSettingsChange(
          current === null
            ? null
            : { enabled: current.enabled, immutability: current.objectLockMode },
          { enabled: next.enabled, immutability: next.immutability },
          {
            objectLockAvailable: lockAvailable,
            entitled,
            defaultRetentionLive: next.defaultLive,
          },
        );
        if (!decision.ok) {
          switch (decision.code) {
            case 'archiving_not_enabled':
              throw archivingNotEnabled();
            case 'archive_default_retention_required':
              throw defaultRetentionRequired();
            case 'archive_immutability_downgrade_forbidden':
              throw immutabilityDowngradeForbidden();
            case 'archive_object_lock_unavailable':
              throw objectLockUnavailable();
          }
        }
        const changed: SettingsField[] = [];
        if (next.enabled !== (current?.enabled ?? false)) changed.push('enabled');
        if (next.immutability !== (current?.objectLockMode ?? 'none')) changed.push('immutability');
        if (next.defaultPolicyId !== (current?.defaultRetentionPolicyId ?? null)) {
          changed.push('defaultRetentionPolicyId');
        }
        const nextSha = next.document === null ? null : canonicalSha256(next.document);
        const currentSha =
          current?.settings === null || current?.settings === undefined
            ? null
            : canonicalSha256(current.settings);
        if (body.settings !== undefined && nextSha !== currentSha) changed.push('settings');
        if (changed.length === 0) {
          return { statusCode: 200, body: request.viewOf(current, entitled, lockAvailable) };
        }
        const now = this.now();
        const written = await this.configs.writeSettings(tx, scope, current, {
          enabled: next.enabled,
          objectLockMode: next.immutability,
          defaultRetentionPolicyId: next.defaultPolicyId,
          settings: next.document,
          settingsSha256: nextSha,
          journalEnabledAt: decision.enabling ? now : (current?.journalEnabledAt ?? null),
          updatedByUserId: userIdOf(principal),
        });
        if (!written) throw archiveSettingsConflict(currentVersion);
        if (decision.applyLockPass) await this.configs.requestLockPass(tx, scope);
        const after = await this.configs.settingsOnWriter(scope, tx);
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: ARCHIVE_AUDIT.settingsUpdated,
            resourceType: ARCHIVE_RESOURCE.settings,
            resourceId: '-',
            sourceIp,
            metadata: {
              area: request.area,
              changedPaths: changed.sort(),
              settingsPaths: [...paths].sort(),
              enabled: next.enabled,
              immutability: next.immutability,
              enabling: decision.enabling,
              applyLockPass: decision.applyLockPass,
              generation: Number(after?.generation ?? 0n),
              rowVersion: after?.rowVersion ?? currentVersion + 1,
              ...(nextSha !== null && { settingsSha256: nextSha }),
            },
          },
          tx,
        );
        return { statusCode: 200, body: request.viewOf(after, entitled, lockAvailable) };
      },
      { timeoutMs: ARCHIVE_TX_TIMEOUT_MS },
    );
  }

  /** The next typed values and document of a PUT, with the scope ids resolved (writer). */
  private async nextState(
    tx: Tx,
    scope: TenantScope,
    current: SettingsRow | null,
    body: UpdateArchiveSettingsBody,
  ): Promise<{
    enabled: boolean;
    immutability: 'none' | 'governance' | 'compliance';
    defaultPolicyId: bigint | null;
    defaultLive: boolean;
    document: ArchiveSettingsDocument | null;
  }> {
    let defaultPolicyId = current?.defaultRetentionPolicyId ?? null;
    if (body.defaultRetentionPolicyId !== undefined) {
      if (body.defaultRetentionPolicyId === null) {
        defaultPolicyId = null;
      } else {
        const policy = await this.configs.lockPolicy(
          tx,
          scope,
          body.defaultRetentionPolicyId.toLowerCase(),
        );
        if (policy === null) throw retentionPolicyNotFound();
        defaultPolicyId = policy.id;
      }
    }
    let defaultLive = false;
    if (defaultPolicyId !== null) {
      const policy = await this.configs.policyById(tx, scope, defaultPolicyId);
      defaultLive = policy !== null && policy.deletedAt === null;
    }
    const document = body.settings !== undefined ? body.settings : (current?.settings ?? null);
    if (body.settings !== undefined) {
      const resolved = resolveArchiveSettings(body.settings);
      const resolution = await this.configs.resolveScope(tx, scope, resolved.scope);
      const path = firstUnresolved(resolved.scope, resolution.unresolved);
      if (path !== null) throw scopeReferenceInvalid(path);
    }
    return {
      enabled: body.enabled ?? current?.enabled ?? false,
      immutability: body.immutability ?? current?.objectLockMode ?? 'none',
      defaultPolicyId,
      defaultLive,
      document,
    };
  }

  /** `GET /archive/status` (#10): counts of the organization, lock and search availability. */
  async status(scope: TenantScope): Promise<ArchiveStatusView> {
    const now = this.now();
    const [row, entitled, counts, lockAvailable, searchAvailable] = await Promise.all([
      this.configs.settings(scope),
      this.features.isEnabled(scope.organizationId, ARCHIVING_FEATURE),
      this.records.statusCounts(scope),
      this.objects.objectLockAvailable(),
      this.search.available(),
    ]);
    return {
      generatedAt: now.toISOString(),
      settings: {
        enabled: row?.enabled ?? false,
        entitled,
        immutability: row?.objectLockMode ?? 'none',
        generation: Number(row?.generation ?? 0n),
      },
      capture: {
        pending: counts.intents.pending ?? 0,
        capturedOpen: counts.intents.captured_open ?? 0,
        failed: counts.intents.failed ?? 0,
        lost: counts.intents.lost ?? 0,
        oldestPendingAt: counts.oldestPendingAt?.toISOString() ?? null,
      },
      records: counts.records,
      index: {
        queued: counts.indexQueued,
        oldestQueuedAt: counts.oldestQueuedAt?.toISOString() ?? null,
        lagSeconds: secondsBetween(counts.oldestQueuedAt, now),
      },
      disposals: { inProgress: counts.disposalsInProgress, failed: counts.disposalsFailed },
      keys: counts.keys,
      objectLock: { available: lockAvailable },
      search: { configured: this.search.configured, available: searchAvailable },
    };
  }

  /** `GET /archive/export-signing-keys` (#14): the current and previous public keys. */
  exportSigningKeys(): SigningKeysView {
    return this.signingKeys;
  }
}
