import { Injectable } from '@nestjs/common';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { IdempotentResult } from '../../../http/idempotency/idempotency.service';
import { OrganizationFeaturesService } from '../../../tenancy/organization-features.service';
import { journalingDocument } from '../../archive/domain/settings-paths';
import {
  ArchiveConfigRepository,
  type SettingsRow,
} from '../../archive/repositories/archive-config.repository';
import {
  ArchiveSettingsService,
  effectiveSettings,
} from '../../archive/services/archive-settings.service';
import type {
  JournalingSettingsView,
  JournalingStatusView,
  UpdateJournalingSettingsBody,
} from '../dto/journaling.schemas';
import {
  ARCHIVING_FEATURE,
  INTAKE_HEALTH_KEYS,
  INTAKE_STATUS_KEYS,
  JOURNAL_INTAKE_FEATURE,
  JOURNAL_OPERATIONS,
} from '../journaling.constants';
import { JournalingRepository } from '../repositories/journaling.repository';
import { IntakeAddressService } from './intake-address.service';

/** The UTC day of an instant (a `DATE` column value). */
export const utcDay = (at: Date): Date =>
  new Date(Date.UTC(at.getUTCFullYear(), at.getUTCMonth(), at.getUTCDate()));

/**
 * The Journaling half of the archive settings and the journaling status (step 8.6 D8, D11):
 * `GET/PUT /journaling/settings` read and write the SAME `archive_settings` row and `row_version`
 * as `/archive/settings` through `ArchiveSettingsService.applyUpdate` (one implementation of the
 * 8.1 A22 rules, the per-path authorization and the audit action `archive.settings_updated`, here
 * with `area: 'journaling'`). The journaling body carries only the journaling sections; the stored
 * Archive-area section (`access`) is kept as stored, so this route can never change an Archive
 * path.
 */
@Injectable()
export class JournalingSettingsService {
  constructor(
    private readonly archiveSettings: ArchiveSettingsService,
    private readonly configs: ArchiveConfigRepository,
    private readonly features: OrganizationFeaturesService,
    private readonly repository: JournalingRepository,
    private readonly addresses: IntakeAddressService,
  ) {}

  now(): Date {
    return new Date();
  }

  private view(
    row: SettingsRow | null,
    entitled: boolean,
    intakeEntitled: boolean,
  ): JournalingSettingsView {
    const s = effectiveSettings(row?.settings ?? null);
    return {
      enabled: row?.enabled ?? false,
      entitled,
      intakeEntitled,
      intakeAvailable: this.addresses.available,
      journalEnabledAt: row?.journalEnabledAt?.toISOString() ?? null,
      settings: {
        directions: s.directions,
        include: s.include,
        scope: s.scope,
        policyArchive: s.policyArchive,
        intake: s.intake,
      },
      generation: Number(row?.generation ?? 0n),
      rowVersion: row?.rowVersion ?? 0,
      updatedAt: row?.updatedAt.toISOString() ?? null,
    };
  }

  private async entitlements(scope: TenantScope): Promise<[boolean, boolean]> {
    const f = await this.features.effective(scope.organizationId, [
      ARCHIVING_FEATURE,
      JOURNAL_INTAKE_FEATURE,
    ]);
    return [f[ARCHIVING_FEATURE] === true, f[JOURNAL_INTAKE_FEATURE] === true];
  }

  /** `GET /journaling/settings`. */
  async get(scope: TenantScope): Promise<JournalingSettingsView> {
    const [row, [entitled, intakeEntitled]] = await Promise.all([
      this.configs.settings(scope),
      this.entitlements(scope),
    ]);
    return this.view(row, entitled, intakeEntitled);
  }

  /** `PUT /journaling/settings`: the shared update with only journaling paths. */
  async update(
    principal: Principal,
    scope: TenantScope,
    idempotencyKey: unknown,
    body: UpdateJournalingSettingsBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<JournalingSettingsView>> {
    const [, intakeEntitled] = await this.entitlements(scope);
    return this.archiveSettings.applyUpdate(principal, scope, idempotencyKey, sourceIp, {
      area: 'journaling',
      operation: JOURNAL_OPERATIONS.settingsUpdate,
      fingerprintBody: body,
      change: (current) => ({
        expectedRowVersion: body.expectedRowVersion,
        ...(body.enabled !== undefined && { enabled: body.enabled }),
        ...(body.settings !== undefined && {
          settings: journalingDocument(current?.settings ?? null, body.settings),
        }),
      }),
      viewOf: (row, entitled) => this.view(row, entitled, intakeEntitled),
    });
  }

  /** `GET /journaling/status`: capture backlog, sources by status and health, today's intake. */
  async status(scope: TenantScope): Promise<JournalingStatusView> {
    const now = this.now();
    const day = utcDay(now);
    const [row, [entitled, intakeEntitled], intents, sources, today] = await Promise.all([
      this.configs.settings(scope),
      this.entitlements(scope),
      this.repository.intentCounts(scope),
      this.repository.sourceCounts(scope),
      this.repository.dayTotals(scope, day),
    ]);
    const i = intents.byStatus;
    const byStatus = Object.fromEntries(
      INTAKE_STATUS_KEYS.map((k) => [k, sources.byStatus[k] ?? 0]),
    ) as JournalingStatusView['sources']['byStatus'];
    const byHealth = Object.fromEntries(
      INTAKE_HEALTH_KEYS.map((k) => [k, sources.byHealth[k] ?? 0]),
    ) as JournalingStatusView['sources']['byHealth'];
    return {
      generatedAt: now.toISOString(),
      settings: {
        enabled: row?.enabled ?? false,
        entitled,
        intakeEntitled,
        intakeAvailable: this.addresses.available,
        generation: Number(row?.generation ?? 0n),
      },
      capture: {
        pending: i.pending ?? 0,
        capturedOpen: i.captured_open ?? 0,
        closed: i.closed ?? 0,
        failed: i.failed ?? 0,
        lost: i.lost ?? 0,
        skipped: i.skipped ?? 0,
        oldestPendingAt: intents.oldestPendingAt?.toISOString() ?? null,
      },
      sources: {
        total: Object.entries(byStatus)
          .filter(([k]) => k !== 'disabled')
          .reduce((n, [, v]) => n + v, 0),
        byStatus,
        byHealth,
      },
      intakeToday: {
        day: day.toISOString().slice(0, 10),
        accepted: today.accepted,
        duplicates: today.duplicates,
        bytes: Number(today.bytes),
        refused:
          today.refusedAddress +
          today.refusedNetwork +
          today.refusedTls +
          today.refusedSize +
          today.refusedRate +
          today.refusedUnavailable,
        droppedProof: today.droppedProof,
        unwrapFailed: today.unwrapFailed,
      },
    };
  }
}
