import type { Prisma } from '@email-gateway/database';
import {
  type QuarantinePlatformBounds,
  type QuarantineSettings,
  resolveQuarantineSettings,
} from '@email-gateway/quarantine';
import { type QuarantineInconsistencySink, quarantineWrongRead } from './errors';

/**
 * The effective quarantine settings of one organization (step 5.3 Q24), read on the writer in the
 * caller's transaction: `quarantine_settings.settings` (strict schema; invalid → defaults and
 * `quarantine_settings_invalid_total`) merged with `organization_settings` (hold days, digest
 * on/off, schedule, time zone) and clamped to the platform bounds. Both rows are echo-checked on
 * `organization_id` (§6).
 */
export class QuarantineSettingsRepository {
  constructor(
    private readonly bounds: QuarantinePlatformBounds,
    private readonly sink: QuarantineInconsistencySink,
    private readonly onInvalid: () => void,
  ) {}

  async resolve(tx: Prisma.TransactionClient, organizationId: bigint): Promise<QuarantineSettings> {
    const stored = await tx.quarantineSettings.findFirst({
      where: { organizationId },
      select: { organizationId: true, settings: true },
    });
    if (stored !== null && stored.organizationId !== organizationId) {
      quarantineWrongRead(this.sink, 'quarantine_settings', 'organization echo');
    }
    const org = await tx.organizationSetting.findFirst({
      where: { organizationId },
      select: {
        organizationId: true,
        quarantineRetentionDays: true,
        digestEnabled: true,
        digestSchedule: true,
        timezone: true,
      },
    });
    if (org !== null && org.organizationId !== organizationId) {
      quarantineWrongRead(this.sink, 'organization_settings', 'organization echo');
    }
    const resolved = resolveQuarantineSettings(
      stored?.settings ?? null,
      this.bounds,
      org === null
        ? null
        : {
            quarantineRetentionDays: org.quarantineRetentionDays,
            digestEnabled: org.digestEnabled,
            digestSchedule: org.digestSchedule,
            timezone: org.timezone,
          },
    );
    if (resolved.violations.length > 0) this.onInvalid();
    return resolved.settings;
  }
}
