# @email-gateway/risk-scoring

The pure risk scorer of step 5.1 ([design](../../docs/plan/steps/15-risk-scoring.md) R1–R12, [ADR-0041](../../docs/architecture/adr/0041-risk-scoring-model.md)): it turns one scan round's stored engine results into a score (0–1000), a level, a `MessageVerdict`, a recommended action, hard blocks, reason codes, per-signal contributions and an explanation. The email-worker scores every round at completion (revision 0, and revision 1 with a late sandbox final) and the api's dry-run reproduces a stored result from the same rows (ADR-0042). 5.1 recommends; policy (5.2) decides.

> **The default weights and thresholds (`rsk-default/1`) are engineering defaults calibrated on a synthetic, self-constructed dataset. They are not validated detection accuracy, and no accuracy, precision or recall figure is claimed.** See the [calibration report](../../docs/performance/risk-scoring-calibration.md).

## Invariants

- **Pure and deterministic.** No I/O, no clock, no randomness, no logger; integer arithmetic only (weights are integer points on 0–1000, factors are permille, floor after every multiplication). The same input and profile give byte-identical output; `inputSha256` hashes the canonical input, `versions.profile.sha256` the canonical effective profile.
- **Never clean by accident.** `unknown`, `timeout`, `error`, a missing final, a missing BEC/DLP/authentication row, an unmapped code and a scoring error are never `clean`; failures (including a missing BEC/DLP/authentication row) add points and the floors `failures.minLevel` / `failures.action` (a `scan_failed` round never recommends `deliver` or `tag`); an `unknown` result adds points and the floors `failures.unknownMinLevel` / `failures.unknownAction` (default `low` / `tag`), so it is never recommended for plain `deliver`.
- **No double counting.** Engine codes map to signals (one fact, raised once however many engines assert it); signals combine in `max` or capped-sum groups.
- **Hard blocks cannot be outweighed.** A fired indicator sets `critical`, its verdict and a non-delivery action regardless of score, trust and profile; malware and DLP-block indicators cannot be disabled.
- **Trust only on authenticated identity.** BEC T1 + DMARC `pass` + no authentication-failure signal + inbound; reduces trust-reducible signals only; always recorded.
- **AI never decides alone.** BEC enters through its deterministic, non-suppressed rule codes; an AI-only raise adds at most `tag`.
- **No message content.** Inputs, results and explanations carry engine names, outcomes, codes, signal ids, integers and versions only.
- `scoreRisk` never throws for a schema-valid input and profile (property-tested on 10 000 seeded random inputs).

## API (names fixed by R1)

| Area         | Exports                                                                                                                                                                                                                                                                                                                                              |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Versions     | `RISK_SCORER_VERSION` (`risk-score/1`), `RISK_SIGNAL_MAP_VERSION` (`risk-signals/1`), `RISK_INPUT_VERSION` (`risk-input/1`), `RISK_PLATFORM_PROFILES`, `RISK_DEFAULT_PLATFORM_PROFILE_ID` (`rsk-default/1`), `isPlatformProfileId`                                                                                                                   |
| Vocabularies | `RISK_LEVELS`, `RISK_ACTIONS` (strictness order), `RISK_VERDICTS` (= Prisma `MessageVerdict`), `RISK_SIGNAL_GROUPS`, `RISK_GROUP_DEFINITIONS`, `RISK_SIGNALS` (the R3 table as data), `RISK_HARD_BLOCKS` (R5), `RISK_INFORMATIONAL_CODES`, `RISK_REASON_CODES`                                                                                       |
| Schemas      | `scoringInputSchema` (R2), `riskProfileOverridesSchema` (R10, strict), `effectiveProfileSchema`, `riskResultSchema` (R11), `riskScoreViewSchema` (alias `riskResultViewSchema`), `RoundRows` (R12 type)                                                                                                                                              |
| Functions    | `buildScoringInput(rows, revision)` (throws `RiskInputError`), `resolveProfile(platformId, version)`, `platformProfile(platformId, fallback?)`, `validateOverrides(doc)`, `scoreRisk(input, resolved)`, `scoringErrorResult(input, resolved, reason)`, `renderExplanation`, `canonicalJson`, `sha256Hex`, `riskResultToRowJson`, `rowJsonToRiskView` |

Layout: `src/vocabulary.ts`, `src/signals.ts` (signal map, groups, informational codes), `src/hard-blocks.ts`, `src/reason-codes.ts`, `src/input.ts` (input schema and builder), `src/profile-schema.ts`, `src/profile.ts` (bounds, validation, resolution), `src/profiles/rsk-default-1.ts`, `src/score.ts`, `src/explanation.ts`, `src/result.ts` (result/view schemas, row mapping), `src/canonical.ts`.

## Synthetic dataset and calibration (§9.2)

- `pnpm --filter @email-gateway/risk-scoring dataset` regenerates `fixtures/calibration/risk-calibration-1.jsonl` (1 050 fixtures in nine classes, seeded PRNG, built through `buildScoringInput` from codes and outcomes the real verdict maps can produce; no addresses, domains or text). `dataset:check` compares byte for byte.
- `pnpm --filter @email-gateway/risk-scoring calibrate` scores every fixture with `rsk-default/1` and writes `docs/performance/risk-scoring-calibration.md`; `calibrate:check` compares.
- Both checks also run inside `pnpm --filter @email-gateway/risk-scoring test`, so neither artifact can drift from the code.

## Tests

`pnpm --filter @email-gateway/risk-scoring test` (no infrastructure): every R3 row fires its signal in its directions only; exhaustiveness over every engine code list; groups, caps, multipliers and the named overlaps; failures per engine and status, floors, missing rows; every hard block, locked indicators, `hb.dmarc_reject` off by default; trust conditions; thresholds and actions, DLP binding, AI-only raise; override bounds and resolution fallbacks; determinism (seeded property test, raw-row permutations); explanation bounds and content; row mapping round trip; the dataset and report checks. `test:integration` has no suites (pure library).
