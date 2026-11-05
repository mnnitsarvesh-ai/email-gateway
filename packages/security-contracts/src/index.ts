/**
 * Contracts of the security scan pipeline (docs/plan/steps/09-rspamd.md S4, S6–S9; ADR-0026,
 * which supersedes ADR-0007's engine contract): the standardized verdicts and reason codes, the
 * engine registry catalog, normalized engine and authentication results, and the Rspamd
 * platform/tenant settings with their pure resolver.
 *
 * Engines classify, policy decides (§2.0 invariant 8): nothing here rejects, quarantines or
 * delivers. The adapter interface itself lives with the adapters (email-worker
 * `scanning/engine.ts`).
 */
export * from './verdicts';
export * from './engines';
export * from './results';
export * from './settings';
