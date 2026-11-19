import type { Prisma } from '@email-gateway/database';
import type { PolicyMetrics } from '../metrics/policy-metrics';
import type { AtoPolicyFactsRow } from '@email-gateway/policy-dsl';
import { atoSubjectHash } from '@email-gateway/security-contracts';
import { type InconsistencySink, wrongRead } from './errors';

/** The organization feature that enables account takeover detection (step 8.4 D21). */
export const ATO_FEATURE_KEY = 'ato_detection';

/** `policy_ato_facts_total{result}` (step 8.4 D19). */
export type AtoFactsResult =
  'resolved' | 'unknown_account' | 'disabled' | 'not_applicable' | 'error';

export interface AtoFactsObserver {
  /** One resolution (or skip) of one evaluation. */
  observe(result: AtoFactsResult, seconds: number | null): void;
}

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

const UNKNOWN_ACCOUNT: AtoPolicyFactsRow = Object.freeze({
  accountKnown: false,
  riskScore: 0,
  riskLevel: 'low',
  incidentSeverity: null,
  incidentStatus: null,
});

const same = (a: bigint | number | null, b: bigint): boolean => a !== null && BigInt(a) === b;

/**
 * The ATO policy facts of one outbound or internal evaluation (step 8.4 D23, ADR-0073): two
 * indexed point reads **inside the evaluation transaction** on the writer, echo-checked like
 * every other read of the engine (a shifted read throws `InconsistentPolicyReadError`, retryable):
 *
 * 1. `organization_features` (`ato_detection`) LEFT JOIN `ato_settings` by their unique
 *    organization keys: no row, disabled, or settings `mode` = `off` → no facts (`disabled`);
 * 2. `ato_accounts` by the unique key `(organization_id, kind = 'mailbox', subject_hash)` LEFT JOIN
 *    the account's active `account_takeover` incident of the same organization
 *    (`active_marker = 1`): no account → `accountKnown: false`, score 0, level `low`, no incident.
 *
 * A database error propagates and fails the evaluation transaction like any other read (retried
 * by the consumer policy); the ato-worker is never involved. Pre-existing organizations have the
 * feature off (D21), so their mail never gets facts.
 */
export class AtoFactsRepository {
  constructor(
    private readonly sink: InconsistencySink,
    private readonly observer: AtoFactsObserver = { observe: () => undefined },
    private readonly hrtime: () => bigint = () => process.hrtime.bigint(),
  ) {}

  /** Counts an evaluation that cannot have facts (inbound, no authenticated sender). */
  notApplicable(): void {
    this.observer.observe('not_applicable', null);
  }

  /**
   * Facts of the authenticated sender `senderAddress` (already normalized by the input builder),
   * or null when ATO is not enabled for the organization or the address cannot be an account.
   */
  async read(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    senderAddress: string,
  ): Promise<AtoPolicyFactsRow | null> {
    const started = this.hrtime();
    const elapsed = () => Number(this.hrtime() - started) / 1e9;
    try {
      const enabled = await this.enabled(tx, organizationId);
      if (!enabled) {
        this.observer.observe('disabled', elapsed());
        return null;
      }
      let subjectHash: string;
      try {
        subjectHash = atoSubjectHash('mailbox', senderAddress);
      } catch {
        this.observer.observe('not_applicable', elapsed());
        return null;
      }
      const facts = await this.account(tx, organizationId, subjectHash);
      this.observer.observe(facts.accountKnown ? 'resolved' : 'unknown_account', elapsed());
      return facts;
    } catch (error) {
      this.observer.observe('error', elapsed());
      throw error;
    }
  }

  private async enabled(tx: Prisma.TransactionClient, organizationId: bigint): Promise<boolean> {
    const rows = await tx.$queryRaw<FeatureRow[]>`
      SELECT f.organization_id AS organizationId, f.feature_key AS featureKey, f.enabled AS enabled,
             s.organization_id AS settingsOrganizationId,
             JSON_UNQUOTE(JSON_EXTRACT(s.settings, '$.mode')) AS mode
      FROM organization_features f
      LEFT JOIN ato_settings s ON s.organization_id = f.organization_id
      WHERE f.organization_id = ${organizationId} AND f.feature_key = ${ATO_FEATURE_KEY}`;
    if (rows.length > 1) wrongRead(this.sink, 'ato_settings', 'feature row count');
    const row = rows[0];
    if (row === undefined) return false;
    if (!same(row.organizationId, organizationId) || row.featureKey !== ATO_FEATURE_KEY) {
      wrongRead(this.sink, 'ato_settings', 'feature echo');
    }
    if (row.settingsOrganizationId !== null && !same(row.settingsOrganizationId, organizationId)) {
      wrongRead(this.sink, 'ato_settings', 'settings echo');
    }
    return (row.enabled === true || Number(row.enabled) === 1) && row.mode !== 'off';
  }

  private async account(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    subjectHash: string,
  ): Promise<AtoPolicyFactsRow> {
    const rows = await tx.$queryRaw<AccountRow[]>`
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
    if (rows.length > 1) wrongRead(this.sink, 'ato_accounts', 'account row count');
    const row = rows[0];
    if (row === undefined) return UNKNOWN_ACCOUNT;
    if (
      !same(row.organizationId, organizationId) ||
      row.kind !== 'mailbox' ||
      row.subjectHash !== subjectHash
    ) {
      wrongRead(this.sink, 'ato_accounts', 'account echo');
    }
    if (
      row.incidentId !== null &&
      (!same(row.incidentOrganizationId, organizationId) ||
        row.incidentCategory !== 'account_takeover')
    ) {
      // The join constrained both: a different value is a shifted read.
      wrongRead(this.sink, 'ato_accounts', 'incident echo');
    }
    // An active incident about another subject is not this account's (ignored, never a match).
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

/** The repository with the engine's series (`policy_ato_facts_total`, `policy_ato_facts_seconds`). */
export function atoFactsRepositoryFor(
  metrics: Pick<PolicyMetrics, 'atoFacts' | 'atoFactsSeconds' | 'inconsistentReads'>,
): AtoFactsRepository {
  return new AtoFactsRepository((read) => metrics.inconsistentReads.inc({ read }), {
    observe: (result, seconds) => {
      metrics.atoFacts.inc({ result });
      if (seconds !== null) metrics.atoFactsSeconds.observe(seconds);
    },
  });
}
