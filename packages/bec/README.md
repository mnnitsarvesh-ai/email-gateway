# @email-gateway/bec

Phishing and BEC detection library of step 4.4 ([design](../../docs/plan/steps/12-phishing-bec.md),
[ADR-0033](../../docs/architecture/adr/0033-bec-engine-and-stage-dependencies.md),
[ADR-0034](../../docs/architecture/adr/0034-bec-ai-layer-invariant.md),
[ADR-0035](../../docs/architecture/adr/0035-bec-communication-context-privacy.md)). CommonJS, no
Nest, no Prisma, no Redis: the email-worker's `bec` engine reads and echo-checks every row, the
S3 parts and the budgets, and passes plain structural inputs in. The deterministic path never
touches the network.

| Module      | Contents                                                                                                                                                                                                                                                        |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `identity/` | Bounded RFC 5322 mailbox-list parser (B5), display-name normalization and profile matching (token set / exact / UTS #39 confusable), free-mail list (`data/freemail.txt`), DKIM/SPF/DMARC alignment from `email_auth_results`, lookalikes through url-security. |
| `text/`     | HTML → text (parse5), normalization with an exact offset map (`bec-text/1`), lexicon token trie (`data/lexicon/{en,hi,hi-Latn}.json`), IBAN/SWIFT/IFSC/amount scanners, bounds and time budget, LLM excerpt + redaction with a window map (B8, B10).            |
| `rules/`    | `evaluateBecRules` = verdict map `bec-map/1` (B6): rules P1…S1, category caps, evidence classes, E0/E1/C0, trusted senders (B7), feedback suppression (B11), the AI feature vector, and the shared lists (`BEC_MAPPER_CODES`, `AI_FEATURE_NAMES`, …).           |
| `history/`  | Keyed hashes of the communication context (B12): `contextKeyHash`, canonical pairs, infrastructure fingerprint, read keys and the round-0 update list.                                                                                                          |
| `ai/`       | `BecAiProvider` / `AiAssessment` (B9), `combineVerdict` (aggregation invariant P1–P6), local model `bec-lr/1`, the Anthropic provider (`@anthropic-ai/sdk` 1.1.0, B10), the deterministic `fake` provider, `buildAiInput`.                                      |
| `training/` | Seeded generator of `training/bec-train-1.jsonl` from the fixture corpus, deterministic trainer, `model:check`.                                                                                                                                                 |

## Usage (worker side)

```ts
import {
  Deadline,
  evaluateBecRules,
  loadBecStaticData,
  loadLocalModel,
  buildAiInput,
  combineVerdict,
} from '@email-gateway/bec';

const data = loadBecStaticData({ brandsFile: process.env.URL_PROTECTED_BRANDS_FILE || null }); // once
const local = loadLocalModel(process.env.BEC_LOCAL_MODEL ?? 'bec-lr/1'); // throws if not in the manifest
const rules = evaluateBecRules(input, settings, data, { deadline: Deadline.after(textTimeoutMs) });
const assessment = await local.assess(buildAiInput(rules, input.tenant), signal);
const final = combineVerdict(
  rules.verdict,
  rules.score,
  { identity: rules.identityEvidence, intent: rules.intentEvidence },
  [{ layer: 'local', mode, assessment }],
  combineSettings,
);
```

`BecTextTimeoutError` (text budget exceeded) maps to the retryable attempt failure
`timeout`/`extract_timeout`; AI failures never fail an attempt (status recorded).

## Model versioning

`models/manifest.json` lists the available local models with the SHA-256 of their files;
`loadLocalModel` refuses a model that is missing or whose hash differs. Weights are reproducible:

```sh
pnpm --filter @email-gateway/bec model:train   # regenerate training/bec-train-1.jsonl (seeded), retrain, write models/*
pnpm --filter @email-gateway/bec model:check   # also run by `test`: same JSONL, weights within 1e-9, manifest hash, held-out metrics ≥ 0.9
```

The training set is synthetic (variants of the fixture corpus templates, no real mail); its
held-out metrics say the model reproduces the deterministic templates, not how it performs on real
traffic. Retraining from tenant feedback exports (B11) is an offline procedure producing
`bec-lr/2`.

## LLM provider

`AnthropicBecProvider` sends only the feature vector, categorical identity facts and a redacted
excerpt (≤ `BEC_LLM_MAX_EXCERPT_CHARS`); structured output with a strict JSON schema (no free
text), `effort: 'low'`, the server-side refusal fallback (`BEC_LLM_REFUSAL_FALLBACK=default`),
`maxRetries: 0`, per-request timeout, typed SDK errors. The client is built with OpenTelemetry
spans and SDK logging off so no request content reaches traces or logs. Prompt template:
`prompts/bec-llm-prompt-1.txt` (`bec-llm-prompt/1`, SHA-256 via `loadPromptTemplate()`).
Budgets, breaker and concurrency are the worker's. Tests use an injected `fetch`; stack runs use
`FakeBecLlmProvider` (`BEC_LLM_PROVIDER=fake`, refused in production; the excerpt directive
`bec-fake-status-<status>` forces a status).

## Tests

`pnpm --filter @email-gateway/bec test`: unit tests for every module, every rule with firing and
non-firing cases, the fixture corpus (`fixtures/corpus/*.json`, §9 scenarios), the exhaustive and
seeded-random aggregation invariant, the provider against recorded fake-transport responses
(request shape, marker strings never sent, refusal, `max_tokens`, schema violations, 429/5xx,
network, timeout), and `model:check`. No infrastructure is needed (`test:integration` is empty).
