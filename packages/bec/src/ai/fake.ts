import { sha256Hex } from '../data';
import { type AI_INDICATORS } from '../rules/codes';
import { canonicalJson } from './llm-schema';
import { PROMPT_TEMPLATE_VERSION } from './prompt';
import {
  failedAssessment,
  type AiAssessment,
  type AiInput,
  type AiStatus,
  type BecAiProvider,
} from './types';

/**
 * Deterministic in-process LLM stand-in (`BEC_LLM_PROVIDER=fake`, B10) for integration and stack
 * runs: no network, no randomness. It is refused when `NODE_ENV=production` (the constructor
 * throws; the email-worker config refuses it too).
 *
 * Keyed by the features:
 * - identity evidence (rule_x1|rule_x3|rule_v1|rule_l1|rule_l2|rule_r3|rule_a1|rule_a6|rule_d1|
 *   rule_d2) **and** intent (any lex_* except authority, or rule_k1) → `bec` 0.95;
 * - intent only → `bec` 0.85; identity only → `phishing` 0.6;
 * - nothing → `benign` 0.9.
 * Indicators are derived from the fired rules / lexicon features. Test directive: an excerpt
 * text containing `bec-fake-status-<status>` (e.g. `bec-fake-status-timeout`) returns that
 * status (any AiStatus except ok), so suites can exercise failure handling.
 */

const IDENTITY = [
  'rule_x1',
  'rule_x3',
  'rule_v1',
  'rule_l1',
  'rule_l2',
  'rule_r3',
  'rule_a1',
  'rule_a6',
  'rule_d1',
  'rule_d2',
];
const INTENT = [
  'lex_payment_request',
  'lex_bank_change',
  'lex_gift_card',
  'lex_wire_transfer',
  'lex_invoice_change',
  'lex_payroll_change',
  'lex_urgency',
  'lex_secrecy',
  'lex_credential_request',
  'rule_k1',
];
const INDICATOR_OF: Readonly<Record<string, (typeof AI_INDICATORS)[number]>> = {
  rule_x1: 'executive_impersonation',
  rule_x3: 'executive_impersonation',
  rule_v1: 'vendor_impersonation',
  rule_l1: 'lookalike_sender',
  rule_l2: 'lookalike_sender',
  rule_r1: 'reply_to_redirection',
  rule_r2: 'reply_to_redirection',
  lex_bank_change: 'payment_redirection',
  lex_invoice_change: 'payment_redirection',
  lex_gift_card: 'gift_card_request',
  lex_wire_transfer: 'wire_request',
  lex_payroll_change: 'payroll_change',
  lex_urgency: 'urgency',
  lex_secrecy: 'secrecy',
  lex_credential_request: 'credential_request',
  rule_k1: 'credential_request',
};
const STATUSES: readonly AiStatus[] = [
  'timeout',
  'error',
  'refused',
  'invalid_output',
  'budget_exceeded',
  'skipped',
  'circuit_open',
];

const on = (features: AiInput['features'], name: string): boolean => {
  const value = features[name];
  return value === true || (typeof value === 'number' && value > 0);
};

export class FakeBecLlmProvider implements BecAiProvider {
  readonly kind = 'llm' as const;
  readonly modelId = 'fake';
  readonly modelVersion = 'fake/1';

  constructor(options: { nodeEnv: string | undefined }) {
    if (options.nodeEnv === 'production') {
      throw new Error('BEC_LLM_PROVIDER=fake is refused when NODE_ENV=production');
    }
  }

  assess(input: AiInput, signal: AbortSignal): Promise<AiAssessment> {
    if (signal.aborted)
      return Promise.resolve(failedAssessment('timeout', this, 0, PROMPT_TEMPLATE_VERSION));
    const directive = /bec-fake-status-([a-z_]+)/.exec(input.excerpt?.text ?? '')?.[1];
    const forced = STATUSES.find((s) => s === directive);
    if (forced)
      return Promise.resolve(
        failedAssessment(forced as Exclude<AiStatus, 'ok'>, this, 0, PROMPT_TEMPLATE_VERSION),
      );

    const identity = IDENTITY.filter((f) => on(input.features, f));
    const intent = INTENT.filter((f) => on(input.features, f));
    const [label, confidence] =
      identity.length > 0 && intent.length > 0
        ? (['bec', 0.95] as const)
        : intent.length > 0
          ? (['bec', 0.85] as const)
          : identity.length > 0
            ? (['phishing', 0.6] as const)
            : (['benign', 0.9] as const);
    const indicators = [
      ...new Set(
        Object.keys(INDICATOR_OF)
          .filter((f) => on(input.features, f))
          .map((f) => INDICATOR_OF[f]!),
      ),
    ].slice(0, 8);
    if (indicators.length === 0) indicators.push('benign_business');
    const cited = [...identity, ...intent]
      .slice(0, 8)
      .map((feature) => ({ feature, contribution: 1 }));
    const output = {
      labels: [
        { label, confidence },
        {
          label: label === 'benign' ? 'bec' : 'benign',
          confidence: Math.round((1 - confidence) * 100) / 100,
        },
      ],
      indicators,
      citedFeatures: cited.map((c) => ({ feature: c.feature, weight: c.contribution })),
      spans: [],
    };
    return Promise.resolve({
      status: 'ok',
      labels: output.labels as AiAssessment['labels'],
      confidence,
      citedFeatures: cited,
      spans: [],
      indicators,
      modelId: this.modelId,
      modelVersion: this.modelVersion,
      promptTemplateVersion: PROMPT_TEMPLATE_VERSION,
      responseSha256: sha256Hex(canonicalJson(output)),
      durationMs: 0,
    });
  }
}
