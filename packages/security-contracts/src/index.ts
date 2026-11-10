/**
 * Contracts of the security scan pipeline (docs/plan/steps/09-rspamd.md S4, S6–S9; ADR-0026,
 * which supersedes ADR-0007's engine contract; step 4.2 docs/plan/steps/10-attachment-scanning.md
 * §4, ADR-0028; step 4.3 docs/plan/steps/11-url-protection.md §4, ADR-0029): the standardized
 * verdicts and reason codes, the engine registry catalog, normalized engine and authentication
 * results, the Rspamd platform/tenant settings with their pure resolver, the attachment engine's
 * file-type vocabulary, reason codes, settings and per-attachment result, and the URL engine's
 * verdicts, reason codes, click decisions, rewrite skip reasons, settings and per-URL result, and
 * (step 4.4 docs/plan/steps/12-phishing-bec.md B6, B9, B13, B15, ADR-0033–0035) the BEC engine's
 * rule ids, reason codes, AI vocabularies, settings and read-view sub-schemas, and (step 4.5
 * docs/plan/steps/13-dlp.md, ADR-0036..0038) the DLP detector vocabulary, reason codes,
 * policy and rule-condition contracts, settings, read-view and evidence-document schemas, and
 * (step 4.6 docs/plan/steps/14-sandbox.md §4, X10, X14, X17, ADR-0039/0040) the sandbox
 * vocabularies (verdicts, backends, isolation classes, profiles, not-executed reasons, error
 * codes, skip reasons, finding codes with fixed severities, reason codes of `sandbox-map/1`),
 * artifact kinds, the observation and stored report schemas, the task limits and the settings.
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
export * from './bec';
export * from './dlp';
export * from './sandbox';
