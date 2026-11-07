import { performance } from 'node:perf_hooks';
import {
  type AiAssessment,
  type AiInput,
  type AiMode,
  type BecAiProvider,
  type BecRulesResult,
  type BecTenantData,
  buildAiInput,
  combineVerdict,
  type CombineResult,
  failedAssessment,
} from '@email-gateway/bec';
import type { Logger } from '@email-gateway/logger';
import type { BecEffectiveSettings } from '@email-gateway/security-contracts';
import { errorFields } from '../../../mime-ingestion/error-fields';
import type { CircuitBreaker } from '../../circuit-breaker';
import type { BecMetrics } from './bec-metrics';
import type { LlmBudgetCheck } from './llm-budget';

/**
 * The AI layer of the bec engine at runtime (step 4.4 B9, B10, ADR-0034): which providers run
 * in which mode, the LLM gating, budgets, concurrency, breaker and timeout, and the aggregation
 * with the invariant (`combineVerdict` of `@email-gateway/bec`).
 *
 * - **Local model** (in-process): the tenant's effective `ai.localModel` (capped by
 *   BEC_LOCAL_MODEL_MODE) runs BEC_LOCAL_MODEL in that mode; BEC_LOCAL_MODEL_SHADOW, when set,
 *   runs next to it in shadow.
 * - **LLM**: the tenant's effective `ai.llm` (capped by BEC_LLM_MODE, default off) runs
 *   BEC_LLM_MODEL in that mode and BEC_LLM_SHADOW_MODEL in shadow, only when the gate passes:
 *   inbound (the engine only asks for inbound mail), not every input missing, the deterministic
 *   verdict is not already `malicious`, and the deterministic score is in
 *   [BEC_LLM_MIN_SCORE, maliciousScore) or an intent rule fired. Each call: breaker permit
 *   (`circuit_open`), a slot of BEC_LLM_CONCURRENCY (waiting is bounded by the engine call's
 *   signal → `timeout`), a **passed** Redis budget check (exhausted → `budget_exceeded`, Redis
 *   unavailable → `skipped`; never a call without it), then the provider with
 *   BEC_LLM_TIMEOUT_MS.
 * - At most 2 applied and 3 shadow assessments (B14); a fourth planned shadow call is not made.
 *
 * Nothing here throws: a provider exception is recorded as status `error` (B4: AI problems are
 * never an attempt failure). Logs carry statuses and model ids only.
 */

export type AiProviderName = 'local' | 'anthropic' | 'fake';

export interface AiEntry {
  layer: 'local' | 'llm';
  mode: 'active' | 'shadow';
  provider: AiProviderName;
  assessment: AiAssessment;
}

export interface AiRunResult {
  entries: AiEntry[];
  combined: CombineResult;
}

/** A counting semaphore whose waits end with the caller's signal. */
export class Semaphore {
  private active = 0;
  private readonly waiters: Array<() => void> = [];

  constructor(private readonly capacity: number) {}

  get inUse(): number {
    return this.active;
  }

  /** Resolves to a release function, or null when `signal` aborted while waiting. */
  acquire(signal: AbortSignal): Promise<(() => void) | null> {
    if (signal.aborted) return Promise.resolve(null);
    const grant = (): (() => void) => {
      let released = false;
      return () => {
        if (released) return;
        released = true;
        this.active -= 1;
        this.waiters.shift()?.();
      };
    };
    if (this.active < this.capacity) {
      this.active += 1;
      return Promise.resolve(grant());
    }
    return new Promise((resolve) => {
      const wake = (): void => {
        signal.removeEventListener('abort', onAbort);
        this.active += 1;
        resolve(grant());
      };
      const onAbort = (): void => {
        const index = this.waiters.indexOf(wake);
        if (index >= 0) this.waiters.splice(index, 1);
        resolve(null);
      };
      this.waiters.push(wake);
      signal.addEventListener('abort', onAbort, { once: true });
    });
  }
}

export interface BecAiLayerOptions {
  local: { active: BecAiProvider; shadow: BecAiProvider | null };
  llm: {
    provider: 'anthropic' | 'fake';
    /** Null when no LLM can run in this worker (no key, or BEC_LLM_MODE=off). */
    active: BecAiProvider | null;
    shadow: BecAiProvider | null;
  };
  budget: LlmBudgetCheck;
  breaker: CircuitBreaker;
  /** BEC_LLM_CONCURRENCY. */
  concurrency: number;
  /** BEC_LLM_TIMEOUT_MS. */
  timeoutMs: number;
  /** BEC_LLM_MIN_SCORE. */
  minScore: number;
  /** BEC_LLM_MAX_EXCERPT_CHARS. */
  maxExcerptChars: number;
  metrics: BecMetrics;
  logger: Logger;
}

export interface AiRunInput {
  organizationId: bigint;
  rules: BecRulesResult;
  tenant: Pick<BecTenantData, 'executives' | 'vendors' | 'tenantDomains'>;
  settings: BecEffectiveSettings;
}

/** Whether the LLM is asked for this deterministic result (B10 gating). Pure. */
export function llmGatePasses(
  rules: Pick<BecRulesResult, 'verdict' | 'score' | 'inputs' | 'firedRules'>,
  minScore: number,
  maliciousScore: number,
): boolean {
  if (rules.verdict === 'skipped' || rules.verdict === 'malicious') return false;
  const { inputs } = rules;
  if (inputs.auth !== 'available' && inputs.url !== 'available' && inputs.text === 'absent') {
    return false;
  }
  const inBand = rules.score >= minScore && rules.score < maliciousScore;
  const intent = rules.firedRules.some((r) => r.category === 'intent' && r.suppressed === null);
  return inBand || intent;
}

interface Planned {
  layer: 'local' | 'llm';
  mode: 'active' | 'shadow';
  provider: BecAiProvider;
}

export const MAX_APPLIED_ASSESSMENTS = 2;
export const MAX_SHADOW_ASSESSMENTS = 3;

export class BecAiLayer {
  private readonly semaphore: Semaphore;
  private readonly logger: Logger;

  constructor(private readonly options: BecAiLayerOptions) {
    this.semaphore = new Semaphore(options.concurrency);
    this.logger = options.logger.child({ component: 'bec-ai' });
  }

  get llmProvider(): 'anthropic' | 'fake' {
    return this.options.llm.provider;
  }

  /** The assessments to run for a tenant and a deterministic result (bounded; see the class). */
  plan(input: AiRunInput): { planned: Planned[]; llmGated: AiMode | null } {
    const { local, llm } = this.options;
    const localMode = input.settings.ai.localModel;
    const llmMode = input.settings.ai.llm;
    const active: Planned[] = [];
    const shadow: Planned[] = [];
    if (localMode !== 'off') {
      (localMode === 'active' ? active : shadow).push({
        layer: 'local',
        mode: localMode,
        provider: local.active,
      });
      if (local.shadow) shadow.push({ layer: 'local', mode: 'shadow', provider: local.shadow });
    }
    let llmGated: AiMode | null = null;
    if (llmMode !== 'off' && llm.active) {
      if (llmGatePasses(input.rules, this.options.minScore, input.settings.maliciousScore)) {
        (llmMode === 'active' ? active : shadow).push({
          layer: 'llm',
          mode: llmMode,
          provider: llm.active,
        });
        if (llm.shadow) shadow.push({ layer: 'llm', mode: 'shadow', provider: llm.shadow });
      } else {
        llmGated = llmMode;
      }
    }
    return {
      planned: [
        ...active.slice(0, MAX_APPLIED_ASSESSMENTS),
        ...shadow.slice(0, MAX_SHADOW_ASSESSMENTS),
      ],
      llmGated,
    };
  }

  async run(input: AiRunInput, signal: AbortSignal): Promise<AiRunResult> {
    const { metrics } = this.options;
    const { planned, llmGated } = this.plan(input);
    if (llmGated !== null)
      metrics.assessment('llm', llmGated === 'active' ? 'active' : 'shadow', 'gated', 'none');
    const localInput = planned.some((p) => p.layer === 'local')
      ? buildAiInput(input.rules, input.tenant)
      : null;
    const llmInput = planned.some((p) => p.layer === 'llm')
      ? buildAiInput(input.rules, input.tenant, { maxExcerptChars: this.options.maxExcerptChars })
      : null;
    const assessments = await Promise.all(
      planned.map((p) =>
        p.layer === 'local'
          ? this.runLocal(p.provider, localInput!, signal)
          : this.runLlm(p.provider, llmInput!, input, signal),
      ),
    );
    const entries: AiEntry[] = planned.map((p, i) => ({
      layer: p.layer,
      mode: p.mode,
      provider: p.layer === 'local' ? 'local' : this.options.llm.provider,
      assessment: assessments[i]!,
    }));
    const { settings, rules } = input;
    const combined = combineVerdict(
      rules.verdict,
      rules.score,
      { identity: rules.identityEvidence, intent: rules.intentEvidence },
      entries.map((e) => ({ layer: e.layer, mode: e.mode, assessment: e.assessment })),
      {
        suspiciousScore: settings.suspiciousScore,
        maliciousScore: settings.maliciousScore,
        aiMaliciousBand: settings.ai.maliciousBand,
        corroborateConfidence: settings.ai.corroborateConfidence,
        raiseConfidence: settings.ai.raiseConfidence,
      },
    );
    entries.forEach((e, i) => {
      metrics.assessment(e.layer, e.mode, e.assessment.status, combined.effects[i] ?? 'none');
    });
    return { entries, combined };
  }

  private async runLocal(
    provider: BecAiProvider,
    input: AiInput,
    signal: AbortSignal,
  ): Promise<AiAssessment> {
    const started = performance.now();
    try {
      return await provider.assess(input, signal);
    } catch (error) {
      this.logger.warn(
        { model: provider.modelVersion, ...errorFields(error) },
        'bec local model failed; recorded as error',
      );
      return failedAssessment('error', provider, Math.round(performance.now() - started));
    }
  }

  private async runLlm(
    provider: BecAiProvider,
    aiInput: AiInput,
    input: AiRunInput,
    signal: AbortSignal,
  ): Promise<AiAssessment> {
    const { breaker, budget, metrics, timeoutMs } = this.options;
    const started = performance.now();
    const elapsed = (): number => Math.round(performance.now() - started);
    const failed = (status: Exclude<AiAssessment['status'], 'ok'>): AiAssessment =>
      failedAssessment(status, provider, elapsed(), 'bec-llm-prompt/1');
    const permit = breaker.tryAcquire();
    if (!permit) return failed('circuit_open');
    const release = await this.semaphore.acquire(signal);
    if (!release) {
      permit.release();
      return failed('timeout');
    }
    try {
      const allowed = await budget.check(input.organizationId, input.settings.ai.llmDailyCallLimit);
      metrics.budget(allowed);
      if (allowed !== 'allowed') {
        permit.release();
        return failed(allowed === 'unavailable' ? 'skipped' : 'budget_exceeded');
      }
      let assessment: AiAssessment;
      try {
        assessment = await provider.assess(
          aiInput,
          AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]),
        );
      } catch (error) {
        this.logger.warn(
          { model: provider.modelId, ...errorFields(error) },
          'bec llm provider threw; recorded as error',
        );
        assessment = failed('error');
      }
      if (assessment.status === 'error' || assessment.status === 'timeout') permit.failure();
      else permit.success();
      metrics.llmRequest(assessment.status, elapsed() / 1000);
      if (assessment.status !== 'ok') {
        this.logger.info(
          { model: provider.modelId, status: assessment.status },
          'bec llm assessment not ok; the deterministic verdict stands',
        );
      }
      return assessment;
    } finally {
      release();
    }
  }
}
