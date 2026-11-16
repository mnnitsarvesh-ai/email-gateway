import { Inject, Injectable } from '@nestjs/common';
import {
  buildPolicyInput,
  buildSyntheticInput,
  compileSnapshot,
  type CompiledSnapshot,
  evaluatePolicyPerRecipient,
  type PerRecipientEvaluation,
  type PolicyEvaluationResult,
  type PolicyInput,
  PolicyInputError,
  type PolicySnapshotSource,
  referencedDirectoryIds,
  type SyntheticFacts,
} from '@email-gateway/policy-dsl';
import { API_CONFIG } from '../../../api-config.token';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CodedHttpException } from '../../../http/coded-exception';
import { MESSAGE_NOT_FOUND, messageNotFound } from '../../messages/messages.errors';
import { evaluationViewOf } from '../domain/evaluation-view';
import { checkDefinition } from '../domain/policy-definition';
import {
  addressKey,
  directoryMaps,
  inlinePolicy,
  OPEN_SCAN_STATUSES,
  policyRoundRowsOf,
  roundAddresses,
  type SnapshotPolicy,
  snapshotSource,
} from '../domain/policy-round';
import type {
  PolicyDryRun,
  PolicyDryRunResponse,
  PolicyTarget,
  PolicyTest,
  PolicyTestResponse,
} from '../dto/policies.schemas';
import {
  POLICY_DEFINITION_INVALID,
  POLICY_INPUT_INVALID,
  POLICY_SCAN_NOT_FOUND,
  POLICY_TEST_FACTS_INVALID,
  POLICY_VERSION_NOT_FOUND,
  policyDefinitionInvalid,
  policyInputInvalid,
  policyScanNotFound,
  policyTestFactsInvalid,
  policyVersionNotFound,
  SCAN_ROUND_NOT_COMPLETE,
  scanRoundNotComplete,
} from '../policies.errors';
import {
  type FactsMessageRow,
  type FactsScanRow,
  PolicyFactsRepository,
} from '../repositories/policy-facts.repository';
import { type PolicyDryRunKind, type PolicyDryRunResult, PolicyMetrics } from './policy-writer';

type Settings = { POLICY_PLATFORM_DEFAULT: string };

const RESULT_OF_CODE: Readonly<Record<string, PolicyDryRunResult>> = {
  [MESSAGE_NOT_FOUND]: 'not_found',
  [POLICY_SCAN_NOT_FOUND]: 'not_found',
  [POLICY_VERSION_NOT_FOUND]: 'not_found',
  [SCAN_ROUND_NOT_COMPLETE]: 'not_complete',
  [POLICY_DEFINITION_INVALID]: 'invalid',
  [POLICY_TEST_FACTS_INVALID]: 'invalid',
  [POLICY_INPUT_INVALID]: 'invalid',
};

/** The versions of a snapshot the current DSL no longer accepts (as every response lists them). */
export const invalidVersions = (
  compiled: CompiledSnapshot,
): PolicyTestResponse['invalidVersions'] =>
  compiled.invalid.map((i) => ({
    policyId: i.publicId,
    versionNo: i.versionNo,
    violations: i.violations.map((v) => ({ path: v.path, code: v.code, message: v.message })),
  }));

/** A round the dry-runs refuse: pending or running on the replica, or not replicated yet. */
export const isOpenRound = (scan: Pick<FactsScanRow, 'status' | 'completedAt'>): boolean =>
  OPEN_SCAN_STATUSES.has(scan.status) || scan.completedAt === null;

/**
 * Runs a test or dry-run and counts it in `policy_dry_runs_total{kind, result}`: `ok`, or the
 * result of a coded refusal (404s `not_found`, `scan_round_not_complete` `not_complete`,
 * definition/facts/input errors `invalid`); other errors are not counted.
 */
export async function countDryRun<T>(
  metrics: PolicyMetrics,
  kind: PolicyDryRunKind,
  fn: () => Promise<T>,
): Promise<T> {
  try {
    const out = await fn();
    metrics.dryRuns.inc({ kind, result: 'ok' });
    return out;
  } catch (error) {
    const result = error instanceof CodedHttpException ? RESULT_OF_CODE[error.code] : undefined;
    if (result !== undefined) metrics.dryRuns.inc({ kind, result });
    throw error;
  }
}

/**
 * The per-recipient evaluation (step 5.3 Q4) as the test and dry-run responses show it: the
 * message-level decision record, whether the recipients split, their decisions and the
 * lifecycle disposition of the message.
 */
export function perRecipientView(e: PerRecipientEvaluation): {
  result: PolicyEvaluationResult;
  recipientSplit: boolean;
  recipientDecisions: PerRecipientEvaluation['recipientDecisions'];
  lifecycleDisposition: PerRecipientEvaluation['lifecycleDisposition'];
} {
  return {
    result: e.message,
    recipientSplit: e.split,
    recipientDecisions: e.recipientDecisions,
    lifecycleDisposition: e.lifecycleDisposition,
  };
}

/**
 * `POST /policies/test` and `POST /messages/{messageId}/scans/{scanId}/policy/dry-run` (step 5.2
 * P22, P23): evaluates synthetic facts, or the stored facts of a finished round, against a target
 * snapshot (`active`, `platform`, a version of a policy, or an inline definition) with the same
 * library functions the policy-engine uses (`compileSnapshot`, `buildSyntheticInput` /
 * `buildPolicyInput`, `evaluatePolicyPerRecipient`, step 5.3 Q4). It reads the replica only and **writes nothing**: no
 * evaluation row, no audit row, no outbox row (this service has no writer or audit dependency).
 * Counted `policy_dry_runs_total{kind, result}`. Since step 7.3 the target compiler
 * (`inlineOf`, `compile`) and the round evaluation (`evaluateRound`) are shared with the sample
 * dry-run (`PolicySampleDryRunService`).
 */
@Injectable()
export class PolicyEvaluationService {
  constructor(
    @Inject(API_CONFIG) private readonly settings: Settings,
    private readonly facts: PolicyFactsRepository,
    private readonly metrics: PolicyMetrics,
  ) {}

  test(scope: TenantScope, body: PolicyTest, now: Date = new Date()): Promise<PolicyTestResponse> {
    return this.counted('test', () => this.runTest(scope, body, now));
  }

  dryRun(
    scope: TenantScope,
    messageId: string,
    scanId: bigint,
    body: PolicyDryRun,
  ): Promise<PolicyDryRunResponse> {
    return this.counted('message', () => this.runDryRun(scope, messageId, scanId, body));
  }

  private counted<T>(kind: PolicyDryRunKind, fn: () => Promise<T>): Promise<T> {
    return countDryRun(this.metrics, kind, fn);
  }

  private async runTest(
    scope: TenantScope,
    body: PolicyTest,
    now: Date,
  ): Promise<PolicyTestResponse> {
    const compiled = await this.compile(scope, body.target);
    const facts: SyntheticFacts = {
      ...body.facts,
      evaluationTime: body.facts.evaluationTime ?? now.toISOString(),
    };
    if (body.facts.resolveDirectory === true) {
      facts.directory = await this.syntheticDirectory(scope, compiled, body.facts);
    }
    let input: PolicyInput;
    try {
      input = buildSyntheticInput(facts);
    } catch (error) {
      if (error instanceof PolicyInputError) throw policyTestFactsInvalid();
      throw error;
    }
    return {
      ...perRecipientView(evaluatePolicyPerRecipient(input, compiled)),
      invalidVersions: invalidVersions(compiled),
    };
  }

  private async runDryRun(
    scope: TenantScope,
    messageId: string,
    scanId: bigint,
    body: PolicyDryRun,
  ): Promise<PolicyDryRunResponse> {
    // An inline document is checked before any database access.
    const inline = this.inlineOf(body.target);
    const message = await this.facts.message(scope, messageId);
    if (!message) throw messageNotFound();
    const scan = await this.facts.scan(scope, message, scanId);
    if (!scan) throw policyScanNotFound();
    if (isOpenRound(scan)) throw scanRoundNotComplete(scan.status);
    const compiled = await this.compile(scope, body.target, inline);
    const evaluation = await this.evaluateRound(scope, message, scan, compiled);
    const storedRow = await this.facts.storedEvaluation(scope, message, scanId);
    const stored = storedRow === null ? null : evaluationViewOf(storedRow);
    const view = perRecipientView(evaluation);
    const result = view.result;
    return {
      ...view,
      invalidVersions: invalidVersions(compiled),
      stored,
      reproducible:
        body.target === 'active' &&
        stored !== null &&
        stored.inputSha256 === result.inputSha256 &&
        stored.versions.snapshotSha256 === result.versions.snapshotSha256,
    };
  }

  /**
   * Evaluates one finished round of a message against a compiled snapshot, reading exactly what
   * the policy-engine assembles (P8): the round's rows and, when the snapshot references directory
   * ids, the memberships of the round's addresses, all from the replica. `409
   * policy_input_invalid` when the stored rows do not form an input. Shared by the per-round
   * dry-run and the sample dry-run (step 7.3, one compiled snapshot per request).
   */
  async evaluateRound(
    scope: TenantScope,
    message: FactsMessageRow,
    scan: FactsScanRow,
    compiled: CompiledSnapshot,
    refs: { departmentIds: readonly string[]; userIds: readonly string[] } = referencedDirectoryIds(
      compiled,
    ),
  ): Promise<PerRecipientEvaluation> {
    const rows = await this.facts.roundRows(scope, message, scan.id);
    const directory =
      refs.departmentIds.length === 0 && refs.userIds.length === 0
        ? { departmentsByAddress: {}, usersByAddress: {} }
        : directoryMaps(await this.facts.directory(scope, roundAddresses(message, rows), refs));
    try {
      return evaluatePolicyPerRecipient(
        buildPolicyInput(policyRoundRowsOf(message, scan, rows, directory)),
        compiled,
      );
    } catch (error) {
      if (error instanceof PolicyInputError) throw policyInputInvalid();
      throw error;
    }
  }

  /**
   * `{ definition }` → the inline snapshot policy (400 when the DSL refuses it); null for the
   * other targets. Callers check it before any database access.
   */
  inlineOf(target: PolicyTarget): SnapshotPolicy | null {
    if (typeof target !== 'object' || !('definition' in target)) return null;
    const check = checkDefinition(target.definition);
    if (!check.ok) throw policyDefinitionInvalid(check.violations);
    return inlinePolicy(check.content.definition, check.content.definitionSha256);
  }

  /**
   * The target's compiled snapshot from the replica's active snapshot source (P12): one snapshot
   * read and one compile per call (`404 policy_version_not_found` for an unknown version).
   */
  async compile(
    scope: TenantScope,
    target: PolicyTarget,
    inline: SnapshotPolicy | null = this.inlineOf(target),
  ): Promise<CompiledSnapshot> {
    const rows = await this.facts.snapshot(scope);
    const platformId = this.settings.POLICY_PLATFORM_DEFAULT;
    let source: PolicySnapshotSource;
    if (target === 'active' || target === 'platform') {
      source = snapshotSource(rows, platformId, { kind: target });
    } else if (inline !== null) {
      source = snapshotSource(rows, platformId, { kind: 'replace', policy: inline });
    } else if ('policyId' in target) {
      const version = await this.facts.policyVersion(scope, target.policyId, target.versionNo);
      if (!version) throw policyVersionNotFound();
      source = snapshotSource(rows, platformId, {
        kind: 'replace',
        policy: {
          publicId: version.publicId,
          versionNo: target.versionNo,
          definition: version.definition,
          definitionSha256: version.definitionSha256,
        },
      });
    } else {
      throw new Error('unreachable policy target');
    }
    return compileSnapshot(source);
  }

  /** Memberships of the facts' addresses (`resolveDirectory: true`), keyed by raw address. */
  private async syntheticDirectory(
    scope: TenantScope,
    compiled: CompiledSnapshot,
    facts: SyntheticFacts,
  ): Promise<SyntheticFacts['directory']> {
    const refs = referencedDirectoryIds(compiled);
    if (refs.departmentIds.length === 0 && refs.userIds.length === 0) return {};
    const raw = [
      ...(facts.recipients ?? [{ address: 'recipient@example.net' }]).map((r) => r.address),
      facts.sender?.envelope === undefined ? 'sender@example.com' : facts.sender.envelope,
      facts.sender?.headerFrom ?? null,
    ];
    const addresses = [
      ...new Set(raw.map((a) => addressKey(a)).filter((a): a is string => a !== null)),
    ];
    const maps = directoryMaps(await this.facts.directory(scope, addresses, refs));
    const mutable = (m: Readonly<Record<string, readonly string[]>>) =>
      Object.fromEntries(Object.entries(m).map(([k, v]) => [k, [...v]]));
    return {
      departments: mutable(maps.departmentsByAddress),
      users: mutable(maps.usersByAddress),
    };
  }
}
