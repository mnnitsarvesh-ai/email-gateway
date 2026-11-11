import { Injectable, Logger } from '@nestjs/common';
import { type Counter, MetricsService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { TransactionRunner } from '../../../database/transaction-runner';
import type { ClientContext } from '../../auth/services/session.service';
import { InconsistentPolicyReadError, inconsistentRead } from '../policies.errors';

/**
 * Budget of every policy write (step 5.2 P17, §6, the 4.2 §6 mitigation): an interactive
 * transaction is never abandoned by a short timeout; 120 s budget, 10 s to obtain a connection.
 */
export const POLICY_TX = { timeoutMs: 120_000, maxWaitMs: 10_000 } as const;

/**
 * `audit_logs.action` of the policy changes (P22). Metadata = public ids, version numbers, row
 * versions, hashes, rule counts, override rule ids and changed paths only (never definition
 * values or change notes); no key matches `/code|key$/i` (AuditService drops those).
 */
export const POLICY_AUDIT = {
  created: 'policy.created',
  updated: 'policy.updated',
  enabled: 'policy.enabled',
  disabled: 'policy.disabled',
  deleted: 'policy.deleted',
  draftCreated: 'policy.version_draft_created',
  draftUpdated: 'policy.version_draft_updated',
  draftDeleted: 'policy.version_draft_deleted',
  published: 'policy.version_published',
  activated: 'policy.version_activated',
  overrideRulesPublished: 'policy.override_rules_published',
  settingsUpdated: 'policy.settings_updated',
  settingsOverridesEnabled: 'policy.settings_overrides_enabled',
} as const;
export type PolicyAuditAction = (typeof POLICY_AUDIT)[keyof typeof POLICY_AUDIT];

export const POLICY_RESOURCE = {
  policy: 'email_policy',
  version: 'policy_version',
  settings: 'policy_settings',
} as const;
export type PolicyResource = (typeof POLICY_RESOURCE)[keyof typeof POLICY_RESOURCE];

export const userIdOf = (principal: Principal): bigint | null =>
  principal.kind === 'user' ? principal.userId : null;

/**
 * Runs a policy writer transaction (120 s budget, 10 s `maxWait`); an echo-check mismatch
 * (`InconsistentPolicyReadError`) retries the whole transaction once, a second mismatch is
 * `503 inconsistent_read` (step 5.2 §6, the 5.1 `RiskWriter` pattern).
 */
@Injectable()
export class PolicyWriter {
  private readonly logger = new Logger(PolicyWriter.name);

  constructor(private readonly transactions: TransactionRunner) {}

  async run<T>(fn: (tx: Prisma.TransactionClient) => Promise<T>): Promise<T> {
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await this.transactions.run(fn, POLICY_TX);
      } catch (error) {
        if (!(error instanceof InconsistentPolicyReadError)) throw error;
        this.logger.warn({ message: 'inconsistent writer read', read: error.read, attempt });
        if (attempt >= 2) throw inconsistentRead();
      }
    }
  }
}

export interface PolicyAuditEntry<A extends string = string, R extends string = string> {
  principal: Principal;
  scope: TenantScope;
  client: ClientContext;
  action: A;
  resourceType: R;
  resourceId: string;
  metadata: Record<string, unknown>;
}

/** Writes one audit row inside the change's transaction (policies and departments). */
@Injectable()
export class PolicyAuditor {
  constructor(private readonly audit: AuditService) {}

  record(tx: Prisma.TransactionClient, entry: PolicyAuditEntry): Promise<void> {
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

/** Operations of `policy_changes_total` (bounded). */
export const POLICY_OPERATIONS = [
  'created',
  'updated',
  'enabled',
  'disabled',
  'deleted',
  'draft_created',
  'draft_updated',
  'draft_deleted',
  'published',
  'activated',
  'settings_updated',
  'department_created',
  'department_updated',
  'department_deleted',
  'member_added',
  'member_removed',
] as const;
export type PolicyOperation = (typeof POLICY_OPERATIONS)[number];

/** `kind` and `result` of `policy_dry_runs_total` (P24). */
export type PolicyDryRunKind = 'test' | 'message';
export type PolicyDryRunResult = 'ok' | 'invalid' | 'not_found' | 'not_complete';

/**
 * The api's policy series (P24): `policy_changes_total{operation}` and
 * `policy_dry_runs_total{kind, result}`. Bounded labels; never a tenant, an id or a value.
 */
@Injectable()
export class PolicyMetrics {
  readonly changes: Counter<'operation'>;
  readonly dryRuns: Counter<'kind' | 'result'>;

  constructor(metrics: MetricsService) {
    this.changes = metrics.counter(
      'policy_changes_total',
      'Committed policy, policy settings and department changes, by operation',
      ['operation'],
    );
    this.dryRuns = metrics.counter(
      'policy_dry_runs_total',
      'Policy tests (synthetic facts) and message dry-runs (no write), by kind (test, message) and result (ok, invalid, not_found, not_complete)',
      ['kind', 'result'],
    );
  }
}
