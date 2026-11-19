import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { AtoPolicyFactsRow } from '@email-gateway/policy-dsl';
import { atoSubjectHash } from '@email-gateway/security-contracts';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';

/** The feature that enables account takeover detection (step 8.4 D21). */
const ATO_FEATURE_KEY = 'ato_detection';

interface FeatureRow {
  organizationId: bigint;
  featureKey: string;
  enabled: number | boolean;
  settingsOrganizationId: bigint | null;
  mode: string | null;
}

interface AccountRow {
  accountId: bigint;
  organizationId: bigint;
  kind: string;
  subjectHash: string;
  riskScore: number;
  riskLevel: string;
  incidentId: bigint | null;
  incidentOrganizationId: bigint | null;
  incidentCategory: string | null;
  incidentSubjectRefId: bigint | null;
  incidentSeverity: string | null;
  incidentStatus: string | null;
}

/** A replica row of another organization or key: a read defect (500, never a wrong answer). */
export class InconsistentAtoFactsReadError extends Error {
  override readonly name = 'InconsistentAtoFactsReadError';
}

const same = (a: bigint | number | null, b: bigint): boolean => a !== null && BigInt(a) === b;

/**
 * The **current** ATO facts of a sender for a dry-run of a round without a stored evaluation
 * (step 8.4 D23, §5.3): the same two point reads and rules as the policy-engine's
 * `AtoFactsRepository` (feature `ato_detection` enabled and ATO mode not `off`; the `mailbox`
 * account by `(organization_id, kind, subject_hash)` with its active `account_takeover`
 * incident), on the replica, organization from the principal's scope, echo-checked. Null when
 * ATO is not enabled for the organization. Never writes.
 */
@Injectable()
export class AtoPolicyFactsRepository {
  constructor(private readonly reader: PrismaReadService) {}

  async current(scope: TenantScope, senderAddress: string): Promise<AtoPolicyFactsRow | null> {
    const organizationId = scope.organizationId;
    const db = this.reader.client;
    const features = await db.$queryRaw<FeatureRow[]>`
      SELECT f.organization_id AS organizationId, f.feature_key AS featureKey, f.enabled AS enabled,
             s.organization_id AS settingsOrganizationId,
             JSON_UNQUOTE(JSON_EXTRACT(s.settings, '$.mode')) AS mode
      FROM organization_features f
      LEFT JOIN ato_settings s ON s.organization_id = f.organization_id
      WHERE f.organization_id = ${organizationId} AND f.feature_key = ${ATO_FEATURE_KEY}`;
    const feature = features[0];
    if (feature === undefined) return null;
    if (
      features.length > 1 ||
      !same(feature.organizationId, organizationId) ||
      feature.featureKey !== ATO_FEATURE_KEY ||
      (feature.settingsOrganizationId !== null &&
        !same(feature.settingsOrganizationId, organizationId))
    ) {
      throw new InconsistentAtoFactsReadError('ATO feature echo');
    }
    if (!(feature.enabled === true || Number(feature.enabled) === 1) || feature.mode === 'off') {
      return null;
    }
    let subjectHash: string;
    try {
      subjectHash = atoSubjectHash('mailbox', senderAddress);
    } catch {
      return null;
    }
    const rows = await db.$queryRaw<AccountRow[]>`
      SELECT a.id AS accountId, a.organization_id AS organizationId, a.kind AS kind,
             a.subject_hash AS subjectHash, a.risk_score AS riskScore, a.risk_level AS riskLevel,
             i.id AS incidentId, i.organization_id AS incidentOrganizationId,
             i.category AS incidentCategory, i.subject_ref_id AS incidentSubjectRefId,
             i.severity AS incidentSeverity, i.status AS incidentStatus
      FROM ato_accounts a
      LEFT JOIN security_incidents i
        ON i.id = a.active_incident_id AND i.organization_id = ${organizationId}
       AND i.category = 'account_takeover' AND i.subject_type = 'ato_account'
       AND i.active_marker = 1
      WHERE a.organization_id = ${organizationId} AND a.kind = 'mailbox'
        AND a.subject_hash = ${subjectHash}`;
    const row = rows[0];
    if (row === undefined) {
      return {
        accountKnown: false,
        riskScore: 0,
        riskLevel: 'low',
        incidentSeverity: null,
        incidentStatus: null,
      };
    }
    if (
      rows.length > 1 ||
      !same(row.organizationId, organizationId) ||
      row.kind !== 'mailbox' ||
      row.subjectHash !== subjectHash ||
      (row.incidentId !== null &&
        (!same(row.incidentOrganizationId, organizationId) ||
          row.incidentCategory !== 'account_takeover'))
    ) {
      throw new InconsistentAtoFactsReadError('ATO account echo');
    }
    const incident =
      row.incidentId !== null && same(row.incidentSubjectRefId, BigInt(row.accountId));
    return {
      accountKnown: true,
      riskScore: Number(row.riskScore),
      riskLevel: row.riskLevel,
      incidentSeverity: incident ? row.incidentSeverity : null,
      incidentStatus: incident ? row.incidentStatus : null,
    };
  }
}
