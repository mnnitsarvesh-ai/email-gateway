/**
 * Contracts of the security scan pipeline (docs/plan/steps/09-rspamd.md S4, S6–S9; ADR-0026,
 * which supersedes ADR-0007's engine contract; step 4.2 docs/plan/steps/10-attachment-scanning.md
 * §4, ADR-0028; step 4.3 docs/plan/steps/11-url-protection.md §4, ADR-0029): the standardized
 * verdicts and reason codes, the engine registry catalog, normalized engine and authentication
 * results, the Rspamd platform/tenant settings with their pure resolver, the attachment engine's
 * file-type vocabulary, reason codes, settings and per-attachment result, and the URL engine's
 * verdicts, reason codes, click decisions, rewrite skip reasons, settings and per-URL result.
 *
 * Engines classify, policy decides (§2.0 invariant 8): nothing here rejects, quarantines or
 * delivers. The adapter interface itself lives with the adapters (email-worker
 * `scanning/engine.ts`).
 */
export * from './verdicts';
export * from './engines';
export * from './results';
export * from './settings';
export * from './file-types';
export * from './attachment';
export * from './url';
