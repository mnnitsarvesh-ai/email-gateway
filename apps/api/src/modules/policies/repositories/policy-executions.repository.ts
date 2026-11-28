import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { type EvaluationRow, evaluationSelect } from './policy-facts.repository';

const historySelect = {
  id: true,
  receivedAt: true,
  messageId: true,
  evaluationSeq: true,
  scanId: true,
  trigger: true,
  direction: true,
  disposition: true,
  decisionSource: true,
  decisivePolicyPublicId: true,
  decisiveRuleId: true,
  action: true,
  overrideApplied: true,
  actions: true,
  matchedRules: true,
  policyGeneration: true,
  policyVersions: true,
  inputSha256: true,
  durationUs: true,
  evaluatedAt: true,
  // Step 8.4 D23: shown with the input hash.
  atoFacts: true,
  // Step API-4 (A12): inline (gateway) or detect (API-mode copy) evaluation.
  evaluationMode: true,
} satisfies Prisma.PolicyExecutionLogSelect;
export type HistoryRow = Prisma.PolicyExecutionLogGetPayload<{ select: typeof historySelect }>;

export interface HistoryFilter {
  from: Date;
  to: Date;
  direction?: 'inbound' | 'outbound' | 'internal';
  disposition?: 'allow' | 'require_approval' | 'quarantine' | 'reject';
  source?: 'tenant_rule' | 'platform_default' | 'floor';
  policyId?: string;
  ruleId?: string;
  overrideApplied?: boolean;
  trigger?: 'scanned' | 'scan_failed' | 'parse_failed';
  /** Step API-4 (A12): `inline` (default), `detect` or both (`undefined`). */
  evaluationMode?: 'inline' | 'detect';
  /** Exclusive `(received_at, id)` upper bound of the previous page. */
  before?: { receivedAt: Date; id: bigint };
  take: number;
}

/** Most evaluations one message lists (one per lifecycle round). */
const MAX_MESSAGE_EVALUATIONS = 100;

/** The stored evaluation columns the sample dry-run compares against (step 7.3 §4.3). */
const sampleSelect = {
  id: true,
  receivedAt: true,
  messageId: true,
  evaluationSeq: true,
  scanId: true,
  trigger: true,
  direction: true,
  disposition: true,
  decisionSource: true,
  decisivePolicyPublicId: true,
  decisiveRuleId: true,
  policyVersions: true,
  evaluatedAt: true,
  // Step 8.4 D23: the ATO facts the stored evaluation used (reused by the sample dry-run).
  atoFacts: true,
} satisfies Prisma.PolicyExecutionLogSelect;
export type SampleRoundRow = Prisma.PolicyExecutionLogGetPayload<{ select: typeof sampleSelect }>;

export interface SampleFilter {
  from: Date;
  to: Date;
  direction?: 'inbound' | 'outbound' | 'internal';
  /** Most rows read (the caller passes `limit × 4`). */
  take: number;
}

/**
 * Read-only, tenant-scoped reads of `policy_execution_logs` (step 5.2 P16, P22) on the replica:
 * the execution history (a required, bounded `received_at` range prunes the monthly partitions;
 * newest first by `(received_at, id)`), the rounds of a sample dry-run (step 7.3) and every
 * evaluation of one message, plus the message public ids of a page. Every query matches the
 * scope's organization; no write method.
 */
@Injectable()
export class PolicyExecutionsRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db() {
    return this.reader.client;
  }

  history(scope: TenantScope, f: HistoryFilter): Promise<HistoryRow[]> {
    const where: Prisma.PolicyExecutionLogWhereInput = tenantWhere(scope, {
      receivedAt: { gte: f.from, lt: f.to },
      ...(f.direction !== undefined && { direction: f.direction }),
      ...(f.disposition !== undefined && { disposition: f.disposition }),
      ...(f.source !== undefined && { decisionSource: f.source }),
      ...(f.policyId !== undefined && { decisivePolicyPublicId: f.policyId }),
      ...(f.ruleId !== undefined && { decisiveRuleId: f.ruleId }),
      ...(f.overrideApplied !== undefined && { overrideApplied: f.overrideApplied }),
      ...(f.trigger !== undefined && { trigger: f.trigger }),
      ...(f.evaluationMode !== undefined && { evaluationMode: f.evaluationMode }),
      ...(f.before !== undefined && {
        OR: [
          { receivedAt: { lt: f.before.receivedAt } },
          { receivedAt: f.before.receivedAt, id: { lt: f.before.id } },
        ],
      }),
    });
    return this.db.policyExecutionLog.findMany({
      where,
      select: historySelect,
      orderBy: [{ receivedAt: 'desc' }, { id: 'desc' }],
      take: f.take,
    });
  }

  /**
   * The newest stored evaluations of scanned rounds in `[from, to)` (step 7.3 §4.3): newest first
   * by `(received_at, id)` through `(organization_id, received_at)`, or through
   * `(organization_id, direction, received_at)` when a direction is given (step 7.3 §14.8: the
   * entries read stay about `take` even when the tenant has little traffic in that direction;
   * the bounded range prunes the monthly partitions), at most `take` rows; parse-failure
   * evaluations (no scan) are excluded.
   */
  sampleRounds(scope: TenantScope, f: SampleFilter): Promise<SampleRoundRow[]> {
    return this.db.policyExecutionLog.findMany({
      where: tenantWhere(scope, {
        receivedAt: { gte: f.from, lt: f.to },
        scanId: { not: null },
        // Step API-4: detect rows of API-mode copies are not gateway rounds.
        evaluationMode: 'inline' as const,
        ...(f.direction !== undefined && { direction: f.direction }),
      }),
      select: sampleSelect,
      orderBy: [{ receivedAt: 'desc' }, { id: 'desc' }],
      take: f.take,
    });
  }

  /** Public ids of the messages of a page (`message_identities.id` = the message id). */
  async messagePublicIds(scope: TenantScope, ids: readonly bigint[]): Promise<Map<bigint, string>> {
    if (ids.length === 0) return new Map();
    const rows = await this.db.messageIdentity.findMany({
      where: tenantWhere(scope, { id: { in: [...new Set(ids)] } }),
      select: { id: true, publicId: true },
    });
    return new Map(rows.map((r) => [r.id, r.publicId]));
  }

  /** Every stored evaluation of the message, newest round first. */
  forMessage(
    scope: TenantScope,
    message: { id: bigint; receivedAt: Date },
  ): Promise<Array<EvaluationRow & { atoFacts: Prisma.JsonValue }>> {
    return this.db.policyExecutionLog.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        evaluationMode: 'inline' as const,
      }),
      select: { ...evaluationSelect, atoFacts: true },
      orderBy: [{ evaluationSeq: 'desc' }, { id: 'desc' }],
      take: MAX_MESSAGE_EVALUATIONS,
    });
  }

  /** The evaluations of the given scans of the message (the scans read API `policy`). */
  forScans(
    scope: TenantScope,
    message: { id: bigint; receivedAt: Date },
    scanIds: readonly bigint[],
  ): Promise<EvaluationRow[]> {
    if (scanIds.length === 0) return Promise.resolve([]);
    return this.db.policyExecutionLog.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        scanId: { in: [...scanIds] },
        evaluationMode: 'inline' as const,
      }),
      select: evaluationSelect,
      orderBy: [{ evaluationSeq: 'desc' }, { id: 'desc' }],
      take: MAX_MESSAGE_EVALUATIONS,
    });
  }
}
