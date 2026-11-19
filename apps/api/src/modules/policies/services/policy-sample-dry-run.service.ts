import { performance } from 'node:perf_hooks';
import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { type CompiledSnapshot, referencedDirectoryIds } from '@email-gateway/policy-dsl';
import { API_CONFIG } from '../../../api-config.token';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CodedHttpException } from '../../../http/coded-exception';
import {
  SAMPLE_ROWS_PER_ROUND,
  sampleItem,
  sampleSummary,
  sampleTarget,
  sampleWindow,
  selectSampleRounds,
  windowTooWide,
} from '../domain/policy-sample';
import {
  POLICY_SAMPLE_DEFAULT_DAYS,
  POLICY_SAMPLE_LIMIT_DEFAULT,
  type PolicySampleDryRun,
  type PolicySampleDryRunResponse,
  type PolicySampleItem,
} from '../dto/policies.schemas';
import { POLICY_INPUT_INVALID } from '../policies.errors';
import {
  PolicyExecutionsRepository,
  type SampleRoundRow,
} from '../repositories/policy-executions.repository';
import { PolicyFactsRepository } from '../repositories/policy-facts.repository';
import {
  countDryRun,
  invalidVersions,
  isOpenRound,
  PolicyEvaluationService,
} from './policy-evaluation.service';
import { PolicyMetrics } from './policy-writer';

type Settings = {
  POLICY_DRY_RUN_SAMPLE_MAX: number;
  POLICY_DRY_RUN_DEADLINE_MS: number;
  POLICY_HISTORY_MAX_RANGE_DAYS: number;
};

export interface SampleRunOptions {
  /** The request time (`to` defaults to it). */
  now?: Date;
  /** Monotonic milliseconds for the deadline (tests pass a fake clock). */
  clock?: () => number;
}

/**
 * `POST /policies/dry-run` (step 7.3 §4.3, B8, ADR-0063 decision 4): re-evaluates the newest
 * stored round per message of the organization in a bounded window against a target snapshot
 * **compiled once** for the request, reading each round's facts from the replica exactly as the
 * per-round dry-run does (`PolicyEvaluationService.evaluateRound`), sequentially, at most
 * `limit ≤ POLICY_DRY_RUN_SAMPLE_MAX` rounds (selection reads at most `limit × 4` rows) and until
 * POLICY_DRY_RUN_DEADLINE_MS. Returns stored versus recomputed decisions with message public ids,
 * times, enums, rule ids and counts only. **Writes nothing** (no evaluation row, audit, outbox or
 * idempotency record; no writer dependency). Counted `policy_dry_runs_total{kind="sample"}` and
 * `policy_sample_dry_run_rounds_total{outcome}`.
 */
@Injectable()
export class PolicySampleDryRunService {
  constructor(
    @Inject(API_CONFIG) private readonly settings: Settings,
    private readonly evaluation: PolicyEvaluationService,
    private readonly executions: PolicyExecutionsRepository,
    private readonly facts: PolicyFactsRepository,
    private readonly metrics: PolicyMetrics,
  ) {}

  sampleDryRun(
    scope: TenantScope,
    body: PolicySampleDryRun,
    options: SampleRunOptions = {},
  ): Promise<PolicySampleDryRunResponse> {
    const clock = options.clock ?? (() => performance.now());
    const started = clock();
    return countDryRun(this.metrics, 'sample', () =>
      this.run(scope, body, options.now ?? new Date(), clock, started),
    );
  }

  private async run(
    scope: TenantScope,
    body: PolicySampleDryRun,
    now: Date,
    clock: () => number,
    started: number,
  ): Promise<PolicySampleDryRunResponse> {
    const maxLimit = this.settings.POLICY_DRY_RUN_SAMPLE_MAX;
    const limit = body.sample.limit ?? Math.min(POLICY_SAMPLE_LIMIT_DEFAULT, maxLimit);
    if (limit > maxLimit) {
      throw new BadRequestException([
        `sample.limit: Must be at most ${maxLimit} (POLICY_DRY_RUN_SAMPLE_MAX)`,
      ]);
    }
    const maxDays = this.settings.POLICY_HISTORY_MAX_RANGE_DAYS;
    const window = sampleWindow(body.sample, now, POLICY_SAMPLE_DEFAULT_DAYS, maxDays);
    if (window.from.getTime() >= window.to.getTime()) {
      throw new BadRequestException(['sample.from: Must be before sample.to']);
    }
    if (windowTooWide(window, maxDays)) {
      throw new BadRequestException([`sample.from: The range must not exceed ${maxDays} days`]);
    }
    // An inline document is checked before any database access; the snapshot compiles once.
    const inline = this.evaluation.inlineOf(body.target);
    const compiled = await this.evaluation.compile(scope, body.target, inline);
    const rows = await this.executions.sampleRounds(scope, {
      from: window.from,
      to: window.to,
      take: limit * SAMPLE_ROWS_PER_ROUND,
      ...(body.sample.direction !== undefined && { direction: body.sample.direction }),
    });
    const selected = selectSampleRounds(rows, limit);
    const publicIds = await this.executions.messagePublicIds(
      scope,
      selected.map((r) => r.messageId),
    );
    const refs = referencedDirectoryIds(compiled);
    const deadline = started + this.settings.POLICY_DRY_RUN_DEADLINE_MS;
    const items: PolicySampleItem[] = [];
    let truncated = false;
    for (const [index, row] of selected.entries()) {
      if (clock() >= deadline) {
        truncated = true;
        this.metrics.sampleRounds.inc({ outcome: 'deadline' }, selected.length - index);
        break;
      }
      const item = await this.round(
        scope,
        row,
        publicIds.get(row.messageId) ?? null,
        compiled,
        refs,
      );
      this.metrics.sampleRounds.inc({ outcome: item.outcome });
      items.push(item);
    }
    const evaluated = items.filter((i) => i.outcome === 'evaluated').length;
    return {
      target: sampleTarget(body.target),
      window: { from: window.from.toISOString(), to: window.to.toISOString() },
      limit,
      evaluated,
      skipped: items.length - evaluated,
      truncated,
      exhausted: rows.length < limit * SAMPLE_ROWS_PER_ROUND && selected.length < limit,
      summary: sampleSummary(items),
      items,
      invalidVersions: invalidVersions(compiled),
    };
  }

  /** One selected round: its message and scan, then the shared round evaluation. */
  private async round(
    scope: TenantScope,
    row: SampleRoundRow,
    messageId: string | null,
    compiled: CompiledSnapshot,
    refs: { departmentIds: readonly string[]; userIds: readonly string[] },
  ): Promise<PolicySampleItem> {
    if (messageId === null || row.scanId === null)
      return sampleItem(row, messageId, 'not_found', null);
    const message = await this.facts.message(scope, messageId);
    if (!message || message.id !== row.messageId) {
      return sampleItem(row, messageId, 'not_found', null);
    }
    const scan = await this.facts.scan(scope, message, row.scanId);
    if (!scan) return sampleItem(row, messageId, 'not_found', null);
    if (isOpenRound(scan)) return sampleItem(row, messageId, 'not_complete', null);
    try {
      // Step 8.4 D23: the sampled round has a stored evaluation; its ATO facts are reused.
      const { evaluation, atoFactsSource } = await this.evaluation.evaluateRound(
        scope,
        message,
        scan,
        compiled,
        refs,
        { kind: 'stored', atoFacts: row.atoFacts },
      );
      return sampleItem(row, messageId, 'evaluated', evaluation, atoFactsSource);
    } catch (error) {
      if (error instanceof CodedHttpException && error.code === POLICY_INPUT_INVALID) {
        return sampleItem(row, messageId, 'input_invalid', null);
      }
      throw error;
    }
  }
}
