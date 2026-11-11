import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { API_CONFIG } from '../../../api-config.token';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { messageNotFound } from '../../messages/messages.errors';
import { evaluationViewOf } from '../domain/evaluation-view';
import type {
  MessagePolicyEvaluations,
  PolicyExecution,
  PolicyExecutionPage,
  PolicyExecutionQuery,
} from '../dto/policies.schemas';
import {
  type HistoryRow,
  PolicyExecutionsRepository,
} from '../repositories/policy-executions.repository';
import { PolicyFactsRepository } from '../repositories/policy-facts.repository';

type Settings = { POLICY_HISTORY_MAX_RANGE_DAYS: number };

const DAY_MS = 86_400_000;

/** History cursor: base64url of `<received_at ms>.<id>` of the last row of the page. */
export function encodeHistoryCursor(row: { receivedAt: Date; id: bigint }): string {
  return Buffer.from(`${row.receivedAt.getTime()}.${row.id.toString()}`, 'utf8').toString(
    'base64url',
  );
}

export function decodeHistoryCursor(cursor: string): { receivedAt: Date; id: bigint } {
  const text = Buffer.from(cursor, 'base64url').toString('utf8');
  const match = /^(0|[1-9][0-9]{0,15})\.([1-9][0-9]{0,19})$/.exec(text);
  if (match) {
    const receivedAt = new Date(Number(match[1]));
    const id = BigInt(match[2]!);
    if (
      !Number.isNaN(receivedAt.getTime()) &&
      id <= 18_446_744_073_709_551_615n &&
      encodeHistoryCursor({ receivedAt, id }) === cursor
    ) {
      return { receivedAt, id };
    }
  }
  throw new BadRequestException(['cursor: Invalid cursor']);
}

/** One history row (P22): ids, enums, counts and hashes only. */
export function executionOf(row: HistoryRow, messageId: string | null): PolicyExecution {
  const actions = Array.isArray(row.actions) ? (row.actions as Array<Record<string, unknown>>) : [];
  const versions = Array.isArray(row.policyVersions)
    ? (row.policyVersions as Array<{ policyPublicId?: unknown; versionNo?: unknown }>)
    : [];
  const decisiveVersion =
    row.decisivePolicyPublicId === null
      ? null
      : versions.find((v) => v.policyPublicId === row.decisivePolicyPublicId)?.versionNo;
  return {
    messageId,
    receivedAt: row.receivedAt.toISOString(),
    lifecycleRound: row.evaluationSeq,
    scanId: row.scanId === null ? null : row.scanId.toString(),
    trigger: row.trigger,
    direction: row.direction,
    disposition: row.disposition,
    finalAction: row.action,
    decisive: {
      source: row.decisionSource,
      policyId: row.decisivePolicyPublicId,
      versionNo: typeof decisiveVersion === 'number' ? decisiveVersion : null,
      ruleId: row.decisiveRuleId,
    },
    actions: actions.map((a) => ({
      type: a.type as PolicyExecution['actions'][number]['type'],
      status: a.status as PolicyExecution['actions'][number]['status'],
    })),
    matchedRuleCount: Array.isArray(row.matchedRules) ? row.matchedRules.length : 0,
    overrideApplied: row.overrideApplied,
    generation: row.policyGeneration.toString(),
    inputSha256: row.inputSha256,
    durationUs: row.durationUs,
    evaluatedAt: row.evaluatedAt.toISOString(),
  };
}

/**
 * The policy execution history and the evaluations of a message (step 5.2 P16, P22), from the
 * read replica, tenant-scoped. The history needs a `from`–`to` range of at most
 * POLICY_HISTORY_MAX_RANGE_DAYS (it prunes the monthly partitions) and pages by
 * `(received_at, id)`. Views carry ids, codes, enums, counts and hashes, never addresses.
 */
@Injectable()
export class PolicyHistoryService {
  constructor(
    @Inject(API_CONFIG) private readonly settings: Settings,
    private readonly executions: PolicyExecutionsRepository,
    private readonly facts: PolicyFactsRepository,
  ) {}

  async history(scope: TenantScope, query: PolicyExecutionQuery): Promise<PolicyExecutionPage> {
    const from = new Date(query.from);
    const to = new Date(query.to);
    const maxDays = this.settings.POLICY_HISTORY_MAX_RANGE_DAYS;
    if (to.getTime() - from.getTime() > maxDays * DAY_MS) {
      throw new BadRequestException([`to: The range must not exceed ${maxDays} days`]);
    }
    const before = query.cursor === undefined ? undefined : decodeHistoryCursor(query.cursor);
    const rows = await this.executions.history(scope, {
      from,
      to,
      take: query.limit + 1,
      ...(before !== undefined && { before }),
      ...(query.direction !== undefined && { direction: query.direction }),
      ...(query.disposition !== undefined && { disposition: query.disposition }),
      ...(query.source !== undefined && { source: query.source }),
      ...(query.policyId !== undefined && { policyId: query.policyId }),
      ...(query.ruleId !== undefined && { ruleId: query.ruleId }),
      ...(query.overrideApplied !== undefined && { overrideApplied: query.overrideApplied }),
      ...(query.trigger !== undefined && { trigger: query.trigger }),
    });
    const page = rows.slice(0, query.limit);
    const ids = await this.executions.messagePublicIds(
      scope,
      page.map((r) => r.messageId),
    );
    const last = page.at(-1);
    return {
      data: page.map((r) => executionOf(r, ids.get(r.messageId) ?? null)),
      nextCursor: rows.length > query.limit && last ? encodeHistoryCursor(last) : null,
    };
  }

  async forMessage(scope: TenantScope, messageId: string): Promise<MessagePolicyEvaluations> {
    const message = await this.facts.message(scope, messageId);
    if (!message) throw messageNotFound();
    const rows = await this.executions.forMessage(scope, message);
    const data: MessagePolicyEvaluations['data'] = [];
    for (const row of rows) {
      const view = evaluationViewOf(row);
      if (view !== null) data.push(view); // Malformed stored JSON is left out.
    }
    return { messageId: message.publicId, data };
  }
}
