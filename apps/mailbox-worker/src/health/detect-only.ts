import { Prisma, type PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { DETECT_ONLY_THEN_VALUES, detectOnlyDue } from '@email-gateway/mailbox-api';
import type { MailboxMetrics } from '../metrics/mailbox-metrics';
import type { RemediationPolicyLoader } from '../remediation/policy-loader';
import { requestThrottledAlert } from '../shared/alerts';
import { systemAudit, TX_OPTIONS } from '../shared/db';
import { errorFields } from '../shared/errors';

/** The alert kind of an ended detect-only period (B7, A9.2). */
export const DETECT_ONLY_ALERT_KIND = 'api_mode_detect_only_ended';
/** `simulatedSinceStart` counts at most this many actions (B7). */
export const SIMULATED_COUNT_CAP = 10_000;
const BATCH = 100;

export interface DetectOnlyDeps {
  prisma: PrismaClient;
  metrics: MailboxMetrics | null;
  logger: Logger;
  now: () => Date;
  /** The remediation policy cache (keyed on row version; invalidated for the organization). */
  policies: RemediationPolicyLoader;
  config: { alertMinIntervalHours: number };
  organizationIds?: readonly bigint[];
}

export interface DetectOnlyReport {
  enforced: number;
  reminded: number;
  alerts: number;
  failed: number;
}

interface DueRow {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  domainId: bigint | null;
  mode: 'detect_only' | 'enforce';
  rowVersion: number;
  detectOnlyUntil: Date | null;
  detectOnlyThen: 'remind' | 'enforce' | null;
  detectOnlyStartedAt: Date | null;
  detectOnlyNotifiedAt: Date | null;
}

/**
 * The detect-only start period's expiry (step API-4 B7, ADR-0107), run by the health leader each
 * tick: remediation policies in `detect_only` whose `detect_only_until` has passed and whose
 * period was not notified yet (`detectOnlyDue`). In one writer transaction per policy (CAS on
 * `row_version` and `detect_only_notified_at IS NULL`):
 *
 * - `then = enforce` → `mode = enforce`, `row_version + 1`, the period columns cleared except
 *   `detect_only_notified_at = now`, system audit `api_mode.remediation_policy_auto_enforced`,
 *   alert `api_mode_detect_only_ended` (severity medium);
 * - `then = remind` → `detect_only_notified_at = now` (mode kept), system audit
 *   `api_mode.detect_only_period_ended`, alert (severity low).
 *
 * Alerts go through `notification_alert_windows` (scope = the policy public id), exactly like
 * `api_mode_unhealthy`. The organization's cached policy rows are dropped, and the loader's cache
 * keys parsed documents on `row_version`, so the next decision uses the new mode. Metadata: ids,
 * enums and counts only.
 */
export class DetectOnlyExpiry {
  constructor(private readonly deps: DetectOnlyDeps) {}

  async runOnce(): Promise<DetectOnlyReport> {
    const now = this.deps.now();
    const report: DetectOnlyReport = { enforced: 0, reminded: 0, alerts: 0, failed: 0 };
    const rows: DueRow[] = await this.deps.prisma.apiRemediationPolicy.findMany({
      where: {
        mode: 'detect_only',
        detectOnlyUntil: { lte: now },
        detectOnlyNotifiedAt: null,
        detectOnlyThen: { not: null },
        ...(this.deps.organizationIds
          ? { organizationId: { in: [...this.deps.organizationIds] } }
          : {}),
      },
      orderBy: { detectOnlyUntil: 'asc' },
      take: BATCH,
      select: {
        id: true,
        publicId: true,
        organizationId: true,
        domainId: true,
        mode: true,
        rowVersion: true,
        detectOnlyUntil: true,
        detectOnlyThen: true,
        detectOnlyStartedAt: true,
        detectOnlyNotifiedAt: true,
      },
    });
    for (const row of rows) {
      const due = detectOnlyDue(row, now);
      if (!due) continue;
      try {
        const outcome = await this.expire(row, due.then, due.severity, now);
        if (outcome === 'raced') continue;
        if (due.then === 'enforce') report.enforced += 1;
        else report.reminded += 1;
        if (outcome === 'alerted') report.alerts += 1;
        this.deps.metrics?.alerts.inc({
          result: outcome === 'alerted' ? 'requested' : 'throttled',
        });
        this.deps.policies.invalidate(row.organizationId);
        this.deps.logger.info(
          {
            policyId: row.publicId,
            organizationId: row.organizationId.toString(),
            then: due.then,
            alert: outcome,
          },
          due.then === 'enforce'
            ? 'detect-only period ended; remediation policy switched to enforce'
            : 'detect-only period ended; reminder requested',
        );
      } catch (error) {
        report.failed += 1;
        this.deps.logger.warn(
          { policyId: row.publicId, ...errorFields(error) },
          'detect-only period expiry failed; retried next run',
        );
      }
    }
    await this.gauge();
    return report;
  }

  private async expire(
    row: DueRow,
    then: 'remind' | 'enforce',
    severity: 'low' | 'medium',
    now: Date,
  ): Promise<'alerted' | 'throttled' | 'raced'> {
    const simulatedSinceStart = await this.simulatedSinceStart(row);
    const scope = row.domainId === null ? 'organization' : 'domain';
    return this.deps.prisma.$transaction(async (tx) => {
      const changed =
        then === 'enforce'
          ? await tx.$executeRaw`
              UPDATE api_remediation_policies
              SET mode = 'enforce', row_version = row_version + 1, detect_only_until = NULL,
                  detect_only_then = NULL, detect_only_started_at = NULL,
                  detect_only_notified_at = ${now}, updated_at = ${now}
              WHERE id = ${row.id} AND organization_id = ${row.organizationId}
                AND row_version = ${row.rowVersion} AND mode = 'detect_only'
                AND detect_only_notified_at IS NULL`
          : await tx.$executeRaw`
              UPDATE api_remediation_policies
              SET detect_only_notified_at = ${now}, updated_at = ${now}
              WHERE id = ${row.id} AND organization_id = ${row.organizationId}
                AND row_version = ${row.rowVersion} AND mode = 'detect_only'
                AND detect_only_notified_at IS NULL`;
      if (changed !== 1) return 'raced' as const;
      await systemAudit(tx, {
        organizationId: row.organizationId,
        action:
          then === 'enforce'
            ? 'api_mode.remediation_policy_auto_enforced'
            : 'api_mode.detect_only_period_ended',
        resourceType: 'api_remediation_policy',
        resourceId: row.publicId,
        correlationId: `api-mode-detect-only:${row.publicId}`,
        metadata: { policyId: row.publicId, scope, simulatedSinceStart },
      });
      const requested = await requestThrottledAlert(tx, {
        organizationId: row.organizationId,
        kind: DETECT_ONLY_ALERT_KIND,
        scopeKey: row.publicId,
        windowMinutes: this.deps.config.alertMinIntervalHours * 60,
        severity,
        refs: { remediationPolicyId: row.publicId },
        correlationId: `api-mode-detect-only:${row.publicId}`,
        now,
      });
      return requested ? ('alerted' as const) : ('throttled' as const);
    }, TX_OPTIONS);
  }

  /**
   * B7 `simulatedSinceStart`: `simulated` remediation actions of the policy's scope since the
   * period started (a domain policy: the domain's mailboxes; the organization policy: the
   * organization), capped at 10 000.
   */
  private async simulatedSinceStart(row: DueRow): Promise<number> {
    const since = row.detectOnlyStartedAt ?? new Date(0);
    const domainFilter =
      row.domainId === null
        ? Prisma.empty
        : Prisma.sql`AND EXISTS (SELECT 1 FROM api_mailboxes m
                                WHERE m.id = a.mailbox_id AND m.organization_id = a.organization_id
                                  AND m.domain_id = ${row.domainId})`;
    const rows = await this.deps.prisma.$queryRaw<Array<{ n: bigint | number }>>`
      SELECT COUNT(*) AS n FROM (
        SELECT 1 FROM api_remediation_actions a
        WHERE a.organization_id = ${row.organizationId} AND a.status = 'simulated'
          AND a.created_at >= ${since} ${domainFilter}
        LIMIT ${SIMULATED_COUNT_CAP}) AS capped`;
    return Number(rows[0]?.n ?? 0);
  }

  /** `api_mode_detect_only_policies{then}`: running periods by what follows them. */
  async gauge(): Promise<void> {
    const m = this.deps.metrics;
    if (!m) return;
    const orgs = this.deps.organizationIds;
    const rows = await this.deps.prisma.$queryRaw<Array<{ then: string; n: bigint | number }>>`
      SELECT detect_only_then AS \`then\`, COUNT(*) AS n FROM api_remediation_policies
      WHERE mode = 'detect_only' AND detect_only_then IS NOT NULL
        AND detect_only_notified_at IS NULL
        ${orgs ? Prisma.sql`AND organization_id IN (${Prisma.join(orgs)})` : Prisma.empty}
      GROUP BY detect_only_then`;
    const counts = new Map<string, number>(DETECT_ONLY_THEN_VALUES.map((t) => [t, 0]));
    for (const r of rows) counts.set(r.then, Number(r.n));
    for (const [then, n] of counts) m.detectOnlyPolicies.set({ then }, n);
  }
}
