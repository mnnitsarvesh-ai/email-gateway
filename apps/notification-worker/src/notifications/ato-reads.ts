import type { Prisma } from '@email-gateway/database';
import { z } from 'zod';
import {
  findPermissionHolders,
  InconsistentNotificationReadError,
  type NoticeUser,
} from './notification-reads';

type Tx = Prisma.TransactionClient;

/** The plan feature that enables account takeover detection per organization (D21). */
export const ATO_FEATURE_KEY = 'ato_detection';
/** The incident category of account takeover (shared incident model, ADR-0075). */
export const ATO_INCIDENT_CATEGORY = 'account_takeover';

export const ATO_SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;
export type AtoSeverity = (typeof ATO_SEVERITIES)[number];
export const atoSeverityRank = (severity: AtoSeverity): number => ATO_SEVERITIES.indexOf(severity);

/**
 * The part of the tenant's ATO settings (`ato_settings.settings`, `ato-settings/1`, §4.3) the
 * notification-worker needs at send time. Read leniently (the api and the ato-worker validate the
 * whole document with `atoSettingsSchema`): a missing or malformed key takes the documented
 * default, exactly the defaults of `DEFAULT_ATO_SETTINGS`.
 */
export interface AtoNotificationSettings {
  mode: 'monitor' | 'enforce' | 'off';
  incidentMinSeverity: AtoSeverity;
  socEmails: string[];
  includeOrganizationContact: boolean;
  digest: { daily: boolean; weekly: boolean };
}

export const ATO_NOTIFICATION_DEFAULTS: Readonly<AtoNotificationSettings> = Object.freeze({
  mode: 'monitor',
  incidentMinSeverity: 'high',
  socEmails: [],
  includeOrganizationContact: true,
  digest: Object.freeze({ daily: true, weekly: true }),
});

const lenient = <T extends z.ZodType>(schema: T) => schema.optional().catch(undefined);

const storedSettingsSchema = z.object({
  mode: lenient(z.enum(['monitor', 'enforce', 'off'])),
  notifications: lenient(
    z.object({
      incidentMinSeverity: lenient(z.enum(ATO_SEVERITIES)),
      socEmails: lenient(z.array(z.email()).max(5)),
      includeOrganizationContact: lenient(z.boolean()),
      digest: lenient(z.object({ daily: lenient(z.boolean()), weekly: lenient(z.boolean()) })),
    }),
  ),
});

/** The notification settings of a stored document (null/invalid → defaults per key). */
export function resolveAtoNotificationSettings(stored: unknown): AtoNotificationSettings {
  const d = ATO_NOTIFICATION_DEFAULTS;
  const parsed = storedSettingsSchema.safeParse(stored ?? {});
  const s = parsed.success ? parsed.data : {};
  const n = s.notifications ?? {};
  return {
    mode: s.mode ?? d.mode,
    incidentMinSeverity: n.incidentMinSeverity ?? d.incidentMinSeverity,
    socEmails: [...new Set((n.socEmails ?? d.socEmails).map((e) => e.toLowerCase()))],
    includeOrganizationContact: n.includeOrganizationContact ?? d.includeOrganizationContact,
    digest: {
      daily: n.digest?.daily ?? d.digest.daily,
      weekly: n.digest?.weekly ?? d.digest.weekly,
    },
  };
}

export interface AtoOrganization {
  id: bigint;
  publicId: string;
  slug: string;
  name: string;
  /** `organization_settings.notification_email` (raw; validated by the handler). */
  notificationEmail: string | null;
}

export interface AtoNoticeIncident {
  id: bigint;
  publicId: string;
  status: string;
  severity: AtoSeverity;
  titleCode: string | null;
  reasonCodes: string[];
  subjectRefId: bigint;
  detectedAt: Date;
}

export interface AtoNoticeAccount {
  publicId: string;
  kind: 'mailbox' | 'gateway_user' | 'smtp_connector';
  /** The tenant's own mailbox address (masked by the template, ADR-0062). */
  address: string | null;
  /** Connector name or user display name (sanitized by the template). */
  name: string | null;
}

export interface AtoNoticeAction {
  publicId: string;
  actionType: string;
  status: string;
  impact: string;
  provider: string;
  resultCode: string | null;
  approvalExpiresAt: Date | null;
  incidentId: bigint | null;
  accountId: bigint;
}

/** An ATO identity-provider integration as the `provider_unhealthy` notice shows it (step 8.5). */
export interface AtoNoticeIntegration {
  publicId: string;
  provider: string;
  displayName: string | null;
  status: string;
  healthStatus: string;
  /** Stream codes whose last probe was not available (≤ 7). */
  failingStreams: string[];
  /** Permission names the last probe found missing (≤ 10). */
  missingPermissions: string[];
}

const STREAM_CODE = /^[a-z][a-z_]{0,31}$/;
const PERMISSION_NAME = /^[A-Za-z0-9._:/-]{1,128}$/;

/**
 * Failing streams and missing permission names of a stored probe report
 * (`ato_provider_integrations.health_detail`, untrusted JSON), bounded, codes and names only.
 */
export function probeFacts(detail: unknown): {
  failingStreams: string[];
  missingPermissions: string[];
} {
  const out = { failingStreams: [] as string[], missingPermissions: [] as string[] };
  if (!detail || typeof detail !== 'object' || Array.isArray(detail)) return out;
  const d = detail as { streams?: unknown; grants?: unknown };
  if (d.streams && typeof d.streams === 'object' && !Array.isArray(d.streams)) {
    for (const [name, value] of Object.entries(d.streams as Record<string, unknown>)) {
      const availability = (value as { availability?: unknown } | null)?.availability;
      if (
        STREAM_CODE.test(name) &&
        typeof availability === 'string' &&
        availability !== 'available' &&
        availability !== 'not_offered'
      ) {
        out.failingStreams.push(name);
      }
    }
  }
  const missing = new Set<string>();
  if (Array.isArray(d.grants)) {
    for (const grant of d.grants) {
      const names = (grant as { missingPermissions?: unknown } | null)?.missingPermissions;
      if (!Array.isArray(names)) continue;
      for (const name of names) {
        if (typeof name === 'string' && PERMISSION_NAME.test(name)) missing.add(name);
      }
    }
  }
  out.failingStreams = out.failingStreams.sort().slice(0, 7);
  out.missingPermissions = [...missing].sort().slice(0, 10);
  return out;
}

export interface AtoDigestCounts {
  openedBySeverity: Record<AtoSeverity, number>;
  resolvedByResolution: Record<string, number>;
  falsePositives: number;
  activeCritical: number;
  pendingApprovals: number;
  restrictedAccounts: number;
  /** Most frequent rule codes of the period's signals (≤ 5, most frequent first). */
  topRuleCodes: Array<{ code: string; count: number }>;
}

const RESOLUTION_CODES = ['remediated', 'false_positive', 'benign_activity', 'duplicate', 'other'];

/**
 * The writer reads of the account takeover notices (step 8.4 D16), inside the consumer's
 * idempotency transaction, each scoped to the envelope's organization and echo-checked (4.2 §6):
 * the organization (name, slug, contact), the feature and the tenant's notification settings,
 * the incident (category `account_takeover` only), the monitored account and its display name,
 * the response action, the digest counts of a period and the throttle window's event count.
 * Never an IP address, a token, a subject or a recipient address.
 */
export class AtoNotificationReads {
  async organization(tx: Tx, organizationId: bigint): Promise<AtoOrganization | null> {
    const org = await tx.organization.findFirst({
      where: { id: organizationId },
      select: { id: true, publicId: true, slug: true, name: true },
    });
    if (org === null) return null;
    if (org.id !== organizationId) throw new InconsistentNotificationReadError('organization');
    const settings = await tx.organizationSetting.findFirst({
      where: { organizationId },
      select: { organizationId: true, notificationEmail: true },
    });
    if (settings !== null && settings.organizationId !== organizationId) {
      throw new InconsistentNotificationReadError('organization_settings');
    }
    return { ...org, notificationEmail: settings?.notificationEmail ?? null };
  }

  /** Whether `ato_detection` is enabled and the tenant's notification settings. */
  async state(
    tx: Tx,
    organizationId: bigint,
  ): Promise<{ featureEnabled: boolean; settings: AtoNotificationSettings }> {
    const feature = await tx.organizationFeature.findFirst({
      where: { organizationId, featureKey: ATO_FEATURE_KEY },
      select: { organizationId: true, featureKey: true, enabled: true },
    });
    if (
      feature !== null &&
      (feature.organizationId !== organizationId || feature.featureKey !== ATO_FEATURE_KEY)
    ) {
      throw new InconsistentNotificationReadError('organization_feature');
    }
    const row = await tx.atoSetting.findFirst({
      where: { organizationId },
      select: { organizationId: true, settings: true },
    });
    if (row !== null && row.organizationId !== organizationId) {
      throw new InconsistentNotificationReadError('ato_settings');
    }
    return {
      featureEnabled: feature?.enabled ?? false,
      settings: resolveAtoNotificationSettings(row?.settings ?? null),
    };
  }

  /** An `account_takeover` incident of the organization by public id (null otherwise). */
  async incident(
    tx: Tx,
    organizationId: bigint,
    publicId: string,
  ): Promise<AtoNoticeIncident | null> {
    const row = await tx.securityIncident.findFirst({
      where: { organizationId, publicId, category: ATO_INCIDENT_CATEGORY },
      select: {
        id: true,
        publicId: true,
        organizationId: true,
        category: true,
        status: true,
        severity: true,
        titleCode: true,
        reasonCodes: true,
        subjectRefId: true,
        detectedAt: true,
      },
    });
    if (row === null) return null;
    if (
      row.organizationId !== organizationId ||
      row.publicId !== publicId ||
      row.category !== ATO_INCIDENT_CATEGORY
    ) {
      throw new InconsistentNotificationReadError('security_incident');
    }
    return {
      id: row.id,
      publicId: row.publicId,
      status: row.status,
      severity: row.severity,
      titleCode: row.titleCode,
      reasonCodes: Array.isArray(row.reasonCodes)
        ? row.reasonCodes.filter((c): c is string => typeof c === 'string')
        : [],
      subjectRefId: row.subjectRefId,
      detectedAt: row.detectedAt,
    };
  }

  /** A monitored account of the organization (by internal id or public id) with its name. */
  async account(
    tx: Tx,
    organizationId: bigint,
    ref: { id: bigint } | { publicId: string },
  ): Promise<AtoNoticeAccount | null> {
    const row = await tx.atoAccount.findFirst({
      where: { organizationId, ...ref },
      select: {
        id: true,
        publicId: true,
        organizationId: true,
        kind: true,
        address: true,
        userId: true,
        connectorId: true,
      },
    });
    if (row === null) return null;
    if (
      row.organizationId !== organizationId ||
      ('id' in ref ? row.id !== ref.id : row.publicId !== ref.publicId)
    ) {
      throw new InconsistentNotificationReadError('ato_account');
    }
    let name: string | null = null;
    if (row.kind === 'smtp_connector' && row.connectorId !== null) {
      const connector = await tx.smtpConnector.findFirst({
        where: { id: row.connectorId, organizationId },
        select: { id: true, organizationId: true, name: true },
      });
      if (connector !== null && connector.organizationId !== organizationId) {
        throw new InconsistentNotificationReadError('smtp_connector');
      }
      name = connector?.name ?? null;
    } else if (row.kind === 'gateway_user' && row.userId !== null) {
      const user = await tx.user.findFirst({
        where: { id: row.userId, organizationId },
        select: { id: true, organizationId: true, displayName: true },
      });
      if (user !== null && user.organizationId !== organizationId) {
        throw new InconsistentNotificationReadError('user');
      }
      name = user?.displayName ?? null;
    }
    return { publicId: row.publicId, kind: row.kind, address: row.address, name };
  }

  /** A response action of the organization by public id. */
  async action(tx: Tx, organizationId: bigint, publicId: string): Promise<AtoNoticeAction | null> {
    const row = await tx.atoResponseAction.findFirst({
      where: { organizationId, publicId },
      select: {
        organizationId: true,
        publicId: true,
        actionType: true,
        status: true,
        impact: true,
        provider: true,
        resultCode: true,
        approvalExpiresAt: true,
        incidentId: true,
        accountId: true,
      },
    });
    if (row === null) return null;
    if (row.organizationId !== organizationId || row.publicId !== publicId) {
      throw new InconsistentNotificationReadError('ato_response_action');
    }
    const { organizationId: _org, ...rest } = row;
    return rest;
  }

  /** Step 8.5: an identity-provider integration of the organization by public id. */
  async integration(
    tx: Tx,
    organizationId: bigint,
    publicId: string,
  ): Promise<AtoNoticeIntegration | null> {
    const row = await tx.atoProviderIntegration.findFirst({
      where: { organizationId, publicId },
      select: {
        organizationId: true,
        publicId: true,
        provider: true,
        displayName: true,
        status: true,
        healthStatus: true,
        healthDetail: true,
      },
    });
    if (row === null) return null;
    if (row.organizationId !== organizationId || row.publicId !== publicId) {
      throw new InconsistentNotificationReadError('ato_provider_integration');
    }
    return {
      publicId: row.publicId,
      provider: row.provider,
      displayName: row.displayName,
      status: row.status,
      healthStatus: row.healthStatus,
      ...probeFacts(row.healthDetail),
    };
  }

  /** One page of the users holding `permission`, sorted by id, after `afterId`, ≤ `take`. */
  holders(
    tx: Tx,
    organizationId: bigint,
    permission: string,
    take: number,
    afterId: bigint | null,
  ): Promise<NoticeUser[]> {
    return findPermissionHolders(tx, organizationId, permission, { take, afterId });
  }

  /** `event_count` of the throttle window so far, or null when the row is gone. */
  async windowEventCount(
    tx: Tx,
    organizationId: bigint,
    kind: string,
    scopeKey: string,
    windowStart: Date,
  ): Promise<number | null> {
    const row = await tx.notificationAlertWindow.findFirst({
      where: { organizationId, kind, scopeKey, windowStart },
      select: { organizationId: true, kind: true, scopeKey: true, eventCount: true },
    });
    if (row === null) return null;
    if (row.organizationId !== organizationId || row.kind !== kind || row.scopeKey !== scopeKey) {
      throw new InconsistentNotificationReadError('notification_alert_window');
    }
    return row.eventCount;
  }

  /**
   * The digest counts of `[from, to)` (D16): ATO incidents opened by severity, resolved by
   * resolution (false positives separately), active critical incidents, pending approvals,
   * accounts with an active SMTP restriction and the top rule codes of the period's signals.
   * Indexed reads on `(organization_id, category, …)`, `(organization_id, status, …)` and the
   * monthly `detected_at` partitions of `ato_risk_signals`.
   */
  async digest(tx: Tx, organizationId: bigint, from: Date, to: Date): Promise<AtoDigestCounts> {
    const where = { organizationId, category: ATO_INCIDENT_CATEGORY } as const;
    const [opened, resolved, activeCritical, pendingApprovals, restricted, top] = await Promise.all(
      [
        tx.securityIncident.groupBy({
          by: ['severity'],
          where: { ...where, detectedAt: { gte: from, lt: to } },
          _count: { _all: true },
        }),
        tx.securityIncident.groupBy({
          by: ['resolutionCode'],
          where: {
            ...where,
            status: { in: ['false_positive', 'resolved'] },
            resolvedAt: { gte: from, lt: to },
          },
          _count: { _all: true },
        }),
        tx.securityIncident.count({
          where: {
            ...where,
            severity: 'critical',
            status: { in: ['open', 'investigating', 'confirmed', 'mitigated'] },
          },
        }),
        tx.atoResponseAction.count({ where: { organizationId, status: 'pending_approval' } }),
        tx.atoSmtpRestriction.count({
          where: { organizationId, status: 'active', expiresAt: { gt: to } },
        }),
        tx.$queryRaw<Array<{ rule_code: string; n: bigint | number }>>`
          SELECT rule_code, COUNT(*) AS n FROM ato_risk_signals
          WHERE organization_id = ${organizationId} AND detected_at >= ${from}
            AND detected_at < ${to} AND status <> 'informational'
          GROUP BY rule_code ORDER BY n DESC, rule_code ASC LIMIT 5`,
      ],
    );
    const openedBySeverity: Record<AtoSeverity, number> = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    };
    for (const g of opened) openedBySeverity[g.severity] += g._count._all;
    const resolvedByResolution: Record<string, number> = {};
    for (const code of RESOLUTION_CODES) resolvedByResolution[code] = 0;
    for (const g of resolved) {
      const code = g.resolutionCode ?? 'other';
      resolvedByResolution[code] = (resolvedByResolution[code] ?? 0) + g._count._all;
    }
    return {
      openedBySeverity,
      resolvedByResolution,
      falsePositives: resolvedByResolution.false_positive ?? 0,
      activeCritical,
      pendingApprovals,
      restrictedAccounts: restricted,
      topRuleCodes: top.map((r) => ({ code: r.rule_code, count: Number(r.n) })),
    };
  }
}
