# ADR-0071: Account takeover detection, scoring and incidents

**Status:** Proposed (step 8.4; architect 2026-11-16, file created by step 8.4 WP1 on 2026-11-18, not yet implemented end to end). Supersedes nothing. Builds on [ADR-0075](0075-security-incident-model-shared-ato-atp.md) for incidents. Design: [docs/plan/steps/24-account-takeover-core.md](../../plan/steps/24-account-takeover-core.md) §7 (placeholder ADR-ATO-2 before numbering).

**Context.** The brief asks for rule-based, baseline, anomaly, threat-intelligence and correlation detection that is explainable, an account score 0–100 with configurable weights and bands, decay, deduplication, history, analyst overrides, and incidents with six states and an audit trail; it forbids treating a VPN or new location alone as proof and forbids an LLM as the sole authority. Step 5.1 established integer, versioned, explainable scoring for messages.

**Decision.**

1. A versioned rule catalogue (`ato-rules/1`, about 50 rules in eleven categories with strengths `weak`, `moderate`, `strong`) in the pure library `@email-gateway/ato-detection`; every rule has a code, evidence, an explanation template, a dedupe key, bounded parameters and declared capabilities. Correlation rules run under the account lock over persisted signals.
2. Short-term windows live in Redis with idempotent updates; daily aggregates and baselines (`ato-baseline/1`, robust median/MAD statistics, rebuilt daily) live in MySQL; immature accounts and the tenant's learning period suppress baseline-relative signals.
3. The account score (`ato-score/1`) is integer arithmetic: weight × category multiplier × a committed half-life decay table, per-category groups (largest plus a quarter of the next three, capped), a weak-only cap below the incident threshold and a strong floor above it, overrides (`compromised` ≥ 90, `benign` capped unless contradicted by a later strong signal), per-tenant bands. Every change is a history row with its explanation and the rules and settings versions.
4. A signal is deduplicated under the account row lock; repetitions increase its occurrence count, never the score.
5. One active `account_takeover` incident per account on the shared security incident model ([ADR-0075](0075-security-incident-model-shared-ato-atp.md)), opened at the tenant's threshold, escalating automatically, closed only by analysts through the six-state machine; ATO detail in `ato_incident_details`; false-positive resolutions dismiss signals and may add trusted contexts. No LLM and no learned model decides anything; a future model must be evidence-driven (labels from incident resolutions) and shadowed first.

**Alternatives considered.** Summing raw signal weights (floods inflate scores). Floating-point decay (platform-dependent rounding). Redis-only baselines (lost on flush). Tenant-defined rules (executing tenant logic; unbounded). A learned anomaly model (no validated data; not explainable). Re-opening closed incidents (breaks the audit trail). ATO-specific incident tables (a second incident system once ATP-4 arrives; rejected by the product owner, ATP gap analysis §5 D15).

**Consequences.** Scores are reproducible from stored signals; defaults are engineering defaults without an accuracy claim; calibration needs real data and the false-positive metric; changing group caps or the decay table needs a new scorer version.
