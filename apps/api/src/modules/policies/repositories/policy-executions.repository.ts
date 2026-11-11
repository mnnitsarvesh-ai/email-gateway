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
  /** Exclusive `(received_at, id)` upper bound of the previous page. */
  before?: { receivedAt: Date; id: bigint };
  take: number;
}

/** Most evaluations one message lists (one per lifecycle round). */
const MAX_MESSAGE_EVALUATIONS = 100;

/**
 * Read-only, tenant-scoped reads of `policy_execution_logs` (step 5.2 P16, P22) on the replica:
 * the execution history (a required, bounded `received_at` range prunes the monthly partitions;
 * newest first by `(received_at, id)`) and every evaluation of one message, plus the message
 * public ids of a page. Every query matches the scope's organization; no write method.
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
  ): Promise<EvaluationRow[]> {
    return this.db.policyExecutionLog.findMany({
      where: tenantWhere(scope, { messageId: message.id, receivedAt: message.receivedAt }),
      select: evaluationSelect,
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
      }),
      select: evaluationSelect,
      orderBy: [{ evaluationSeq: 'desc' }, { id: 'desc' }],
      take: MAX_MESSAGE_EVALUATIONS,
    });
  }
}
