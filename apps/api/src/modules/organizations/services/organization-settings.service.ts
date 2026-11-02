import { BadRequestException, ConflictException, Injectable } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import { AuditService } from '../../../audit/audit.service';
import { TransactionRunner } from '../../../database/transaction-runner';
import { PrincipalCacheService } from '../../auth/services/principal-cache.service';
import { assertCanManage, type OrganizationAccess } from '../domain/organization-access';
import { maxQuarantineRetentionDays } from '../domain/settings-validation';
import type { SettingsUpdate } from '../dto/organizations.schemas';
import { type SettingsResponse, toSettingsResponse } from '../organization.mapper';
import {
  OrganizationsRepository,
  type SettingsRecord,
  type SettingsWrite,
  type VisibleOrganization,
} from '../organizations.repository';
import { assertMutable, type RequestOrigin, requireVisible } from './organization-guards';

export const SYSTEM_QUARANTINE_MAX = 'quarantine.max_retention_days';
export const SYSTEM_QUARANTINE_DEFAULT = 'quarantine.default_retention_days';

/** Column defaults of `organization_settings` (used when a row is missing). */
const DEFAULT_SETTINGS: Omit<SettingsRecord, 'updatedAt'> = {
  timezone: 'UTC',
  locale: 'en',
  quarantineRetentionDays: 30,
  digestEnabled: true,
  digestSchedule: '0 8 * * *',
  notificationEmail: null,
  mfaRequired: false,
  preferences: null,
};

const SETTING_FIELDS = [
  'timezone',
  'locale',
  'quarantineRetentionDays',
  'digestEnabled',
  'digestSchedule',
  'notificationEmail',
  'mfaRequired',
  'preferences',
] as const satisfies ReadonlyArray<keyof SettingsUpdate>;

function sameValue(a: unknown, b: unknown): boolean {
  return JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
}

/** Copies the given fields of a validated update (no `undefined` keys). */
function toWrite(update: SettingsUpdate): SettingsWrite {
  const write: SettingsWrite = {};
  for (const field of SETTING_FIELDS) {
    if (update[field] !== undefined) Object.assign(write, { [field]: update[field] });
  }
  return write;
}

/**
 * `organization_settings` (D12). Reads need `organization:read` or the catalog; writes need
 * `organization:manage` (own organization) or the catalog. Quarantine retention is bounded by the
 * organization's `quarantine_retention_days` limit and the platform maximum; MFA stays mandatory
 * for the platform organization.
 */
@Injectable()
export class OrganizationSettingsService {
  constructor(
    private readonly repository: OrganizationsRepository,
    private readonly transactions: TransactionRunner,
    private readonly audit: AuditService,
    private readonly principalCache: PrincipalCacheService,
  ) {}

  async get(access: OrganizationAccess, publicId: string): Promise<SettingsResponse> {
    const org = await requireVisible(this.repository, access, publicId);
    const settings = await this.repository.findSettings(org);
    return toSettingsResponse(
      org,
      settings ?? { ...DEFAULT_SETTINGS, updatedAt: org.updatedAt },
      await this.retentionBound(org),
    );
  }

  async update(
    access: OrganizationAccess,
    publicId: string,
    input: SettingsUpdate,
    origin: RequestOrigin,
  ): Promise<SettingsResponse> {
    assertCanManage(access);
    const { org, settings, bound, mfaChanged } = await this.transactions.run(async (tx) => {
      const found = await requireVisible(this.repository, access, publicId, tx);
      const current = await this.repository.lockAndReload(tx, found);
      assertMutable(current);
      if (current.kind === 'platform' && input.mfaRequired === false) {
        throw new ConflictException('MFA is mandatory for the platform organization');
      }
      const max = await this.retentionBound(current, tx);
      this.assertRetention(input.quarantineRetentionDays, max);

      const before = (await this.repository.findSettings(current, tx)) ?? DEFAULT_SETTINGS;
      const write = toWrite(input);
      const changedFields = SETTING_FIELDS.filter(
        (field) => field in write && !sameValue(write[field], before[field]),
      );
      if (changedFields.length > 0) {
        await this.repository.upsertSettings(tx, current, write);
        await this.audit.record(
          {
            organizationId: current.id,
            actor: this.audit.actorFrom(access.principal),
            action: 'organization.settings_updated',
            resourceType: 'organization',
            resourceId: current.publicId,
            sourceIp: origin.ip,
            // Field names only: preferences and addresses stay out of the audit trail.
            metadata: {
              changedFields,
              ...(changedFields.includes('mfaRequired') && { mfaRequired: write.mfaRequired }),
            },
          },
          tx,
        );
      }
      const after = await this.repository.findSettings(current, tx);
      return {
        org: current,
        settings: after ?? { ...DEFAULT_SETTINGS, updatedAt: current.updatedAt },
        bound: max,
        mfaChanged: changedFields.includes('mfaRequired'),
      };
    });
    // `mfa_required` is part of every cached principal of the organization.
    if (mfaChanged) await this.principalCache.invalidateOrganization(org.id);
    return toSettingsResponse(org, settings, bound);
  }

  /**
   * Settings of a new organization (D12): defaults, then the caller's values. Without an explicit
   * value, quarantine retention is the platform default capped by the plan's limit.
   */
  async initialSettings(
    planRetentionLimit: bigint | null,
    input: SettingsUpdate | undefined,
  ): Promise<SettingsWrite> {
    const bound = maxQuarantineRetentionDays(
      planRetentionLimit,
      await this.repository.systemSettingNumber(SYSTEM_QUARANTINE_MAX),
    );
    const write = input ? toWrite(input) : {};
    if (write.quarantineRetentionDays !== undefined) {
      this.assertRetention(write.quarantineRetentionDays, bound, 'settings.');
      return write;
    }
    const platformDefault =
      (await this.repository.systemSettingNumber(SYSTEM_QUARANTINE_DEFAULT)) ??
      DEFAULT_SETTINGS.quarantineRetentionDays;
    return {
      ...write,
      quarantineRetentionDays: Math.max(
        1,
        bound === null ? platformDefault : Math.min(platformDefault, bound),
      ),
    };
  }

  /** Upper bound of `quarantineRetentionDays` for the organization (null = unbounded). */
  private async retentionBound(
    org: VisibleOrganization,
    client?: Prisma.TransactionClient,
  ): Promise<number | null> {
    const limit = await this.repository.findLimit(org, 'quarantine_retention_days', client);
    return maxQuarantineRetentionDays(
      limit?.limitValue ?? null,
      await this.repository.systemSettingNumber(SYSTEM_QUARANTINE_MAX, client),
    );
  }

  private assertRetention(days: number | undefined, max: number | null, path = ''): void {
    if (days !== undefined && max !== null && days > max) {
      throw new BadRequestException([`${path}quarantineRetentionDays: must be at most ${max}`]);
    }
  }
}
