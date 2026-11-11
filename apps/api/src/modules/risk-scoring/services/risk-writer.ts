import { Injectable, Logger } from '@nestjs/common';
import { type Counter, MetricsService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { TransactionRunner } from '../../../database/transaction-runner';
import type { ClientContext } from '../../auth/services/session.service';
import { InconsistentRiskReadError, inconsistentRead } from '../risk-scoring.errors';

/**
 * Budget of every risk profile write (step 5.1 §6, the 4.2 §6 mitigation): an interactive
 * transaction is never abandoned by a short timeout; 120 s budget, 10 s to obtain a connection.
 */
export const RISK_TX = { timeoutMs: 120_000, maxWaitMs: 10_000 } as const;

/**
 * `audit_logs.action` of the risk profile changes (R15). Metadata = ids, version numbers, hashes
 * and the changed override paths only; no key matches `/code|key$/i` (AuditService drops those).
 */
export const RISK_AUDIT = {
  draftCreated: 'risk_profile.draft_created',
  draftUpdated: 'risk_profile.draft_updated',
  draftDeleted: 'risk_profile.draft_deleted',
  published: 'risk_profile.published',
  activated: 'risk_profile.activated',
  reset: 'risk_profile.reset',
} as const;

export const RISK_RESOURCE = {
  version: 'risk_scoring_profile_version',
  profile: 'risk_scoring_profile',
} as const;

export const userIdOf = (principal: Principal): bigint | null =>
  principal.kind === 'user' ? principal.userId : null;

/**
 * Runs a risk profile writer transaction (120 s budget, 10 s `maxWait`); an echo-check mismatch
 * (`InconsistentRiskReadError`) retries the whole transaction once, a second mismatch is
 * `503 inconsistent_read` (step 5.1 §6).
 */
@Injectable()
export class RiskWriter {
  private readonly logger = new Logger(RiskWriter.name);

  constructor(private readonly transactions: TransactionRunner) {}

  async run<T>(fn: (tx: Prisma.TransactionClient) => Promise<T>): Promise<T> {
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await this.transactions.run(fn, RISK_TX);
      } catch (error) {
        if (!(error instanceof InconsistentRiskReadError)) throw error;
        this.logger.warn({ message: 'inconsistent writer read', read: error.read, attempt });
        if (attempt >= 2) throw inconsistentRead();
      }
    }
  }
}

/** Writes one audit row inside the change's transaction. */
@Injectable()
export class RiskAuditor {
  constructor(private readonly audit: AuditService) {}

  record(
    tx: Prisma.TransactionClient,
    entry: {
      principal: Principal;
      scope: TenantScope;
      client: ClientContext;
      action: (typeof RISK_AUDIT)[keyof typeof RISK_AUDIT];
      resourceType: (typeof RISK_RESOURCE)[keyof typeof RISK_RESOURCE];
      resourceId: string;
      metadata: Record<string, unknown>;
    },
  ): Promise<void> {
    return this.audit.record(
      {
        organizationId: entry.scope.organizationId,
        actor: this.audit.actorFrom(entry.principal),
        action: entry.action,
        resourceType: entry.resourceType,
        resourceId: entry.resourceId,
        sourceIp: entry.client.ip,
        metadata: entry.metadata,
      },
      tx,
    );
  }
}

/** Operations of `risk_profile_changes_total`. */
export type RiskProfileOperation =
  'draft_created' | 'draft_updated' | 'draft_deleted' | 'published' | 'activated' | 'reset';

/** Results of `risk_dry_runs_total` (R19). */
export type RiskDryRunResult = 'ok' | 'not_complete' | 'not_found' | 'invalid_profile';

/**
 * The api's risk scoring series (R19): `risk_profile_changes_total{operation}` and
 * `risk_dry_runs_total{result}`. Bounded labels; never a tenant, an id or a value.
 */
@Injectable()
export class RiskMetrics {
  readonly profileChanges: Counter<'operation'>;
  readonly dryRuns: Counter<'result'>;

  constructor(metrics: MetricsService) {
    this.profileChanges = metrics.counter(
      'risk_profile_changes_total',
      'Committed risk scoring profile changes, by operation (draft_created, draft_updated, draft_deleted, published, activated, reset)',
      ['operation'],
    );
    this.dryRuns = metrics.counter(
      'risk_dry_runs_total',
      'Risk scoring dry-runs of a stored scan round (no write), by result (ok, not_complete, not_found, invalid_profile)',
      ['result'],
    );
  }
}
