import type { Counter, Gauge, Histogram, MetricsService } from '@email-gateway/common';
import { BEC_AI_STATUSES, BEC_REASON_CODES, BEC_VERDICTS } from '@email-gateway/security-contracts';
import { CIRCUIT_STATE_VALUE, type CircuitState } from '../../circuit-breaker';

/**
 * The bec engine's series of the email-worker (step 4.4 B19; a contract for
 * `infrastructure/monitoring/rules/bec-scanning.rules.yml` and docs/runbooks/bec-detection.md),
 * registered once per worker registry. Labels are bounded enums only: verdicts, reason codes of
 * `BEC_REASON_CODES` (anything else → `other`), input names and states, AI layers, modes,
 * statuses and effects, budget results, read names, model ids/versions of the packaged manifest
 * and the configured LLM model; never an address, a domain, a name, a hash or an id.
 */

export const BEC_READS = [
  'scan',
  'finals',
  'auth',
  'urls',
  'headers',
  'parse',
  'message',
  'tenant',
  'history',
] as const;
export type BecRead = (typeof BEC_READS)[number];

export const BEC_INPUTS = {
  auth: ['available', 'failed', 'missing', 'not_in_round'],
  url: ['available', 'failed', 'not_in_round'],
  text: ['complete', 'incomplete', 'absent'],
  history: ['enabled', 'disabled', 'error'],
} as const;
export type BecInputName = keyof typeof BEC_INPUTS;

/** `scan_bec_ai_total{status}`: the AI statuses plus `gated` (the LLM was not asked, B10). */
export const AI_METRIC_STATUSES = [...BEC_AI_STATUSES, 'gated'] as const;
export type AiMetricStatus = (typeof AI_METRIC_STATUSES)[number];

export const BUDGET_RESULTS = [
  'allowed',
  'tenant_exhausted',
  'platform_exhausted',
  'unavailable',
] as const;
export type BudgetResult = (typeof BUDGET_RESULTS)[number];

export const HISTORY_UPDATE_RESULTS = ['inserted', 'updated'] as const;

const LLM_BUCKETS = [0.1, 0.25, 0.5, 1, 2, 5, 10, 15, 20, 30, 60];
const CODES: ReadonlySet<string> = new Set(BEC_REASON_CODES);
const STATUSES: ReadonlySet<string> = new Set(AI_METRIC_STATUSES);

const registries = new WeakMap<MetricsService, BecMetrics>();

export class BecMetrics {
  readonly results: Counter<'verdict' | 'deterministic_verdict'>;
  readonly rules: Counter<'code'>;
  readonly inputs: Counter<'input' | 'state'>;
  readonly ai: Counter<'layer' | 'mode' | 'status' | 'effect'>;
  readonly llmDuration: Histogram<'status'>;
  readonly llmTokens: Counter<'direction'>;
  readonly llmBudget: Counter<'result'>;
  readonly llmBreakerState: Gauge;
  readonly modelInfo: Gauge<'layer' | 'model' | 'version' | 'mode'>;
  readonly inconsistentReads: Counter<'read'>;
  readonly historyUpdates: Counter<'result'>;
  readonly historyRowsDeleted: Counter;
  readonly historySweeperErrors: Counter;

  /** One instance per registry (the engine, the repository hook and the sweeper share it). */
  static for(registry: MetricsService): BecMetrics {
    let metrics = registries.get(registry);
    if (!metrics) {
      metrics = new BecMetrics(registry);
      registries.set(registry, metrics);
    }
    return metrics;
  }

  private constructor(metrics: MetricsService) {
    this.results = metrics.counter(
      'scan_bec_results_total',
      'bec engine definite results by final verdict and deterministic verdict (before the AI layer)',
      ['verdict', 'deterministic_verdict'],
    );
    this.rules = metrics.counter(
      'scan_bec_rules_total',
      'Reason codes of bec results (fired, non-suppressed rules, engine and AI codes), by code',
      ['code'],
    );
    this.inputs = metrics.counter(
      'scan_bec_inputs_total',
      'Input states of bec results (auth, url, text, history), by input and state',
      ['input', 'state'],
    );
    this.ai = metrics.counter(
      'scan_bec_ai_total',
      'AI layer assessments of the bec engine by layer (local, llm), mode (active, shadow), status (ok, timeout, error, refused, invalid_output, budget_exceeded, skipped, circuit_open, gated) and effect',
      ['layer', 'mode', 'status', 'effect'],
    );
    this.llmDuration = metrics.histogram(
      'bec_llm_request_duration_seconds',
      'Duration of one LLM request of the bec engine, by status',
      ['status'],
      LLM_BUCKETS,
    );
    this.llmTokens = metrics.counter(
      'bec_llm_tokens_total',
      'LLM tokens reported by the provider, by direction (input, output)',
      ['direction'],
    );
    this.llmBudget = metrics.counter(
      'bec_llm_budget_total',
      'LLM budget checks by result (allowed, tenant_exhausted, platform_exhausted, unavailable)',
      ['result'],
    );
    this.llmBreakerState = metrics.gauge(
      'bec_llm_breaker_state',
      'LLM circuit breaker state in this worker (0 closed, 1 half-open, 2 open)',
    );
    this.modelInfo = metrics.gauge(
      'bec_model_info',
      'AI models configured in this worker (value 1), by layer, model id, version and platform mode',
      ['layer', 'model', 'version', 'mode'],
    );
    this.inconsistentReads = metrics.counter(
      'scan_bec_inconsistent_reads_total',
      'Writer reads of the bec engine whose identifying columns did not echo the request (Prisma wrong-read guard), by read',
      ['read'],
    );
    this.historyUpdates = metrics.counter(
      'bec_history_updates_total',
      'Communication history rows upserted with a bec final (round 0), by result (inserted, updated)',
      ['result'],
    );
    this.historyRowsDeleted = metrics.counter(
      'bec_history_rows_deleted_total',
      'Communication history rows deleted by the retention sweeper',
    );
    this.historySweeperErrors = metrics.counter(
      'bec_history_sweeper_errors_total',
      'Database errors of the communication history retention sweeper (it backs off and continues)',
    );
    // Zero series so the alert rules see them before the first event.
    for (const result of BUDGET_RESULTS) this.llmBudget.inc({ result }, 0);
    for (const read of BEC_READS) this.inconsistentReads.inc({ read }, 0);
    for (const result of HISTORY_UPDATE_RESULTS) this.historyUpdates.inc({ result }, 0);
    for (const verdict of BEC_VERDICTS) {
      this.results.inc({ verdict, deterministic_verdict: verdict }, 0);
    }
    for (const [input, states] of Object.entries(BEC_INPUTS)) {
      for (const state of states) this.inputs.inc({ input, state }, 0);
    }
    this.llmTokens.inc({ direction: 'input' }, 0);
    this.llmTokens.inc({ direction: 'output' }, 0);
    this.historyRowsDeleted.inc(0);
    this.historySweeperErrors.inc(0);
    this.llmBreakerState.set(0);
  }

  result(verdict: string, deterministicVerdict: string, codes: readonly string[]): void {
    this.results.inc({ verdict, deterministic_verdict: deterministicVerdict });
    for (const code of codes) this.rules.inc({ code: CODES.has(code) ? code : 'other' });
  }

  input(input: BecInputName, state: string): void {
    this.inputs.inc({ input, state });
  }

  assessment(layer: 'local' | 'llm', mode: 'active' | 'shadow', status: string, effect: string) {
    this.ai.inc({ layer, mode, status: STATUSES.has(status) ? status : 'error', effect });
  }

  llmRequest(status: string, seconds: number): void {
    this.llmDuration.observe({ status: STATUSES.has(status) ? status : 'error' }, seconds);
  }

  /** Token counts reported by the provider (`onResult` hook of the Anthropic provider). */
  tokens(inputTokens: number | null, outputTokens: number | null): void {
    if (inputTokens !== null && inputTokens > 0) {
      this.llmTokens.inc({ direction: 'input' }, inputTokens);
    }
    if (outputTokens !== null && outputTokens > 0) {
      this.llmTokens.inc({ direction: 'output' }, outputTokens);
    }
  }

  budget(result: BudgetResult): void {
    this.llmBudget.inc({ result });
  }

  breaker(state: CircuitState): void {
    this.llmBreakerState.set(CIRCUIT_STATE_VALUE[state]);
  }

  model(layer: 'local' | 'llm', model: string, version: string, mode: string): void {
    this.modelInfo.set({ layer, model, version, mode }, 1);
  }

  inconsistent(read: BecRead): void {
    this.inconsistentReads.inc({ read });
  }

  historyUpdate(result: 'inserted' | 'updated'): void {
    this.historyUpdates.inc({ result });
  }
}
