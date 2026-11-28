import { resolveOrgSettings, type ResolvedOrgSettings } from '@email-gateway/mailbox-api';
import type { Db } from '../shared/db';
import { InconsistentReadError } from '../shared/errors';

/**
 * Step API-3 (note 37 §3.1, C17): the organization's API-mode settings — the
 * `api_mode_org_settings` row, else the platform defaults — resolved exactly as the api resolves
 * them (`resolveOrgSettings` of `@email-gateway/mailbox-api`). Organization echo-checked.
 */
export async function loadOrgSettings(
  db: Db,
  organizationId: bigint,
): Promise<ResolvedOrgSettings> {
  const row = await db.apiModeOrgSetting.findUnique({
    where: { organizationId },
    select: {
      organizationId: true,
      internalMailEnabled: true,
      autoClawback: true,
      autoMaxMailboxes: true,
      purgeApprovalMailboxes: true,
      clawbackLookbackDays: true,
      tiMinConfidence: true,
      reportAckEnabled: true,
      reportFeedbackEnabled: true,
      policyEvaluationEnabled: true,
      outboundDetectionEnabled: true,
      rowVersion: true,
    },
  });
  if (row && row.organizationId !== organizationId) {
    throw new InconsistentReadError('api_mode_org_settings');
  }
  return resolveOrgSettings(row);
}

/** A per-pass memo of organization settings (one read per organization). */
export class OrgSettingsMemo {
  private readonly cache = new Map<bigint, ResolvedOrgSettings>();

  async get(db: Db, organizationId: bigint): Promise<ResolvedOrgSettings> {
    const known = this.cache.get(organizationId);
    if (known) return known;
    const settings = await loadOrgSettings(db, organizationId);
    this.cache.set(organizationId, settings);
    return settings;
  }
}
