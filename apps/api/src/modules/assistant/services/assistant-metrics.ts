import { Injectable } from '@nestjs/common';
import { type Counter, type Gauge, type Histogram, MetricsService } from '@email-gateway/common';

/** Seconds; a turn runs up to ASSISTANT_TURN_DEADLINE_MS (≤ 300 s). */
const TURN_BUCKETS = [0.5, 1, 2.5, 5, 10, 20, 30, 60, 90, 120, 300];
/** Seconds; one loopback tool call (≤ ASSISTANT_TOOL_TIMEOUT_MS). */
const TOOL_BUCKETS = [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 15, 60];
/** Seconds from a proposal to the user's decision (≤ ASSISTANT_CONFIRMATION_TTL_SECONDS). */
const CONFIRMATION_BUCKETS = [1, 2.5, 5, 10, 20, 30, 60, 120, 300, 600, 900];

/** Outcomes of `assistant_confirmations_total` (step AI-2 D11). */
export type ConfirmationOutcome =
  | 'proposed'
  | 'executed'
  | 'failed'
  | 'cancelled'
  | 'expired'
  | 'refused_session'
  | 'refused_token'
  | 'refused_digest'
  | 'refused_state'
  | 'reauth_required'
  | 'reauth_failed'
  | 'outcome_unknown';

/**
 * The assistant series of design D11 on the api registry (`GET /metrics`). Labels are provider,
 * model, outcome, module, access, decision, kind, reason and budget scope only: never an
 * organization, user, conversation, tool argument or text.
 */
@Injectable()
export class AssistantMetrics {
  readonly turns: Counter<'provider' | 'model' | 'outcome'>;
  readonly turnSeconds: Histogram;
  readonly llmTokens: Counter<'provider' | 'model' | 'kind'>;
  readonly llmErrors: Counter<'provider' | 'reason'>;
  readonly toolCalls: Counter<'module' | 'access' | 'decision' | 'outcome'>;
  readonly toolSeconds: Histogram<'module'>;
  readonly budgetRefusals: Counter<'scope'>;
  readonly activeTurns: Gauge;
  readonly confirmations: Counter<'risk' | 'outcome'>;
  readonly confirmationSeconds: Histogram;

  constructor(metrics: MetricsService) {
    this.turns = metrics.counter(
      'assistant_turns_total',
      'Assistant turns by provider, model and outcome (completed, failed, cancelled, refused)',
      ['provider', 'model', 'outcome'],
    );
    this.turnSeconds = metrics.histogram(
      'assistant_turn_seconds',
      'Duration of assistant turns',
      [],
      TURN_BUCKETS,
    );
    this.llmTokens = metrics.counter(
      'assistant_llm_tokens_total',
      'LLM tokens by provider, model and kind (input, output, cache_read, cache_write)',
      ['provider', 'model', 'kind'],
    );
    this.llmErrors = metrics.counter(
      'assistant_llm_errors_total',
      'LLM provider call failures by provider and reason code',
      ['provider', 'reason'],
    );
    this.toolCalls = metrics.counter(
      'assistant_tool_calls_total',
      'Assistant tool calls by module, access, executor decision and outcome',
      ['module', 'access', 'decision', 'outcome'],
    );
    this.toolSeconds = metrics.histogram(
      'assistant_tool_seconds',
      'Duration of assistant loopback tool calls by module',
      ['module'],
      TOOL_BUCKETS,
    );
    this.budgetRefusals = metrics.counter(
      'assistant_budget_refusals_total',
      'Turns refused at start by budget scope (tenant, platform, user, concurrency)',
      ['scope'],
    );
    this.activeTurns = metrics.gauge(
      'assistant_active_turns',
      'Assistant turns running in this api process',
    );
    this.confirmations = metrics.counter(
      'assistant_confirmations_total',
      'Assistant write confirmations by risk and outcome (proposed, executed, failed, cancelled, ' +
        'expired, refused_*, reauth_required, reauth_failed, outcome_unknown)',
      ['risk', 'outcome'],
    );
    this.confirmationSeconds = metrics.histogram(
      'assistant_confirmation_seconds',
      'Time from an assistant write proposal to the user’s decision',
      [],
      CONFIRMATION_BUCKETS,
    );
  }
}
