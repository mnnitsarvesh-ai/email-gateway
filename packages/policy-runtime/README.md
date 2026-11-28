# @email-gateway/policy-runtime

The runtime of one policy evaluation, shared by the **policy-engine** (inline rounds) and the
**mailbox-worker** (detect-mode evaluation of API-mode copies), so both evaluate with the same
facts, snapshot rule and evaluator (step API-4,
[design note 38](../../docs/plan/steps/38-api-mode-parity-onboarding.md) A2, invariant P-I2;
ADR-0105). The evaluator itself is `@email-gateway/policy-dsl` (pure); this package holds the
writer reads around it and the row mapping. No Nest, no RabbitMQ, no logger: callers pass
metric sinks and observers.

## Moved from `apps/policy-engine/src/evaluation` (unchanged in behaviour)

| Module                    | What                                                                                                                                                                                                                                                                                                                       |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `facts.repository.ts`     | `FactsRepository.read(tx, ref)`: the P8 rows of one round, every read echo-checked (message, organization, `received_at`, scan, round, revision); lists capped at the P4 limit + 1. `RoundRef`, `RoundFacts`                                                                                                               |
| `snapshot.repository.ts`  | `SnapshotRepository.get(tx, organizationId)`: `policy_settings.generation` (absent = 0) and the compiled snapshot of that generation from the LRU (`SnapshotCache`, keyed `<organization>:<generation>`); a miss reads the active policies' published versions in the same transaction. `LoadedSnapshot`, `SnapshotLookup` |
| `directory.repository.ts` | `DirectoryRepository.resolve`: only the referenced departments and users, only for the message's addresses (P5). `EMPTY_DIRECTORY`, `DirectoryMaps`                                                                                                                                                                        |
| `ato-facts.repository.ts` | `AtoFactsRepository` (step 8.4 D23: two indexed point reads, echo-checked), `atoFactsRepositoryFor(metrics)` (structural `AtoFactsMetrics`), `ATO_FEATURE_KEY`                                                                                                                                                             |
| `input-builder.ts`        | `buildInputWithDirectory(tx, directory, organizationId, facts, compiled, guard?, ato?)` and `AtoFactsSource`                                                                                                                                                                                                               |
| `errors.ts`               | `InconsistentPolicyReadError` (retryable), `InconsistencySink`, `wrongRead`, `PolicyRead` (the `read` label), `POLICY_INPUT_INVALID`                                                                                                                                                                                       |
| `round-outcome.ts`        | `roundOutcome(evaluation, direction)` (the Q5 lifecycle mapping, `RoundOutcome`)                                                                                                                                                                                                                                           |
| `execution-log.ts`        | `policyExecutionLogData(args)`: the one `policy_execution_logs` create mapping (row columns, Q4 per-recipient columns, `ato_facts`), `durationUsOf`                                                                                                                                                                        |

`@email-gateway/policy-runtime/testing` exports the synthetic round fixtures (`cleanFacts`,
`cleanRiskRow`, `definition`, `RULES`, `POLICY_A`, `POLICY_B`) used by the policy-engine, this
package and the mailbox-worker suites.

## Copy rounds (detect mode, A2)

- `evaluateCopyRound(tx, deps, ref)` — `deps = { facts, snapshots, directory, atoFacts?, hrtime? }`,
  `ref = { messageId, receivedAt, organizationId, round, trigger: 'scanned'|'scan_failed', scanId }`
  (never an older round). Returns `{ status: 'evaluated', input, perRecipient, meta: { generation,
snapshotSha256, platformDefaultId, policyVersions, policyVersionIds, invalidVersions, cache },
durationUs }` or `{ status: 'failed', code: 'policy_input_invalid' | 'evaluator_error' }`
  (`PolicyInputError` from the reads or the builder, evaluator exceptions). An
  `InconsistentPolicyReadError` or a database error **throws** (the caller's ledger transaction
  rolls back and the event is redelivered).
- `policyOutcomeOf(evaluated, rcptSeq | null)` → `PolicyOutcomeFacts` of `@email-gateway/mailbox-api`
  (the remediation decision's policy lane): with a recipient its decision exactly as the
  policy-engine decides recipients (Q5), with `null` the message-level result; `tagged` = TAG/WARN
  applies with allow; `recommendationOnly` via `recommendationOnlyOf` (with `tagOriginsOf`; note 38
  §15.8); `decisiveRuleRef` `<policyPublicId>#<versionNo>/<ruleId>`; `floorReasons`
  ≤ 8; `dlpAction` from the input's DLP block when the DLP final is definite; applying
  `actionTypes`.
- `detectRowData(evaluated, ref, now)` → the `policy_execution_logs` create data with
  `evaluationMode: 'detect'`, `deliveredObject: 'none'`, `delivery` and `objectKey` null, `action`
  = the round's lifecycle final action (recorded, never applied) and action statuses from the
  post-delivery table of mailbox-api (`detectActionStatus`: not applicable stays so; ALERT without
  tenant alerts `recorded`). `DetectRowData` types `evaluationMode` loosely until the regenerated
  Prisma client is in place.

Config the callers read (unchanged): `POLICY_PLATFORM_DEFAULT`, `POLICY_SNAPSHOT_CACHE_MAX_ENTRIES`.

## Tests

```sh
pnpm --filter @email-gateway/policy-runtime build typecheck lint test
```

Unit suites against transaction doubles (no infrastructure): the moved repository, snapshot-cache
and ATO tests, and `copy-round.test.ts` (evaluated, failed on `PolicyInputError` and evaluator
exceptions, inconsistent reads and database errors throw, `policyOutcomeOf` per recipient and
message level incl. a split, `detectRowData`). The **parity test** of design §10.1 lives in
`apps/policy-engine/src/evaluation/evaluation.service.test.ts` (`API-4 parity`), where the inline
path exists: golden rounds give the same disposition, decisive rule, snapshot and `input_sha256`
inline and as a copy. The MySQL suites that exercise these reads are the policy-engine's
`test:integration` and the mailbox-worker's.
