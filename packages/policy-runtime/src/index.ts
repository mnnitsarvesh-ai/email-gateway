/**
 * `@email-gateway/policy-runtime` (step API-4 A2, ADR-0105): the runtime of a policy evaluation
 * shared by the policy-engine (inline rounds) and the mailbox-worker (detect-mode evaluation of
 * API-mode copies), so both evaluate with the same facts, snapshot and evaluator (P-I2):
 *
 * - the echo-checked writer reads of one round (`FactsRepository`), the organization's snapshot
 *   of the current generation with its LRU cache (`SnapshotRepository`, `SnapshotCache`), the
 *   directory of the snapshot's references (`DirectoryRepository`), the sender's ATO facts
 *   (`AtoFactsRepository`) and the input builder (`buildInputWithDirectory`) — moved unchanged
 *   from `apps/policy-engine/src/evaluation`;
 * - the inconsistent-read error and sink (`errors.ts`), the Q5 lifecycle mapping
 *   (`roundOutcome`) and the shared `policy_execution_logs` row mapping
 *   (`policyExecutionLogData`);
 * - the copy-round runner: `evaluateCopyRound`, `policyOutcomeOf` (the remediation decision's
 *   policy lane facts) and `detectRowData` (the detect row).
 *
 * No Nest, no RabbitMQ, no logger: callers wire metrics through the sinks and observers.
 */
export * from './errors';
export * from './facts.repository';
export * from './snapshot-cache';
export * from './snapshot.repository';
export * from './directory.repository';
export * from './ato-facts.repository';
export * from './input-builder';
export * from './round-outcome';
export * from './execution-log';
export * from './copy-round';
