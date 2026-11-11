import { Inject, Injectable } from '@nestjs/common';
import {
  buildPolicyInput,
  buildSyntheticInput,
  compileSnapshot,
  type CompiledSnapshot,
  evaluatePolicy,
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
import { PolicyFactsRepository } from '../repositories/policy-facts.repository';
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

const invalidVersions = (compiled: CompiledSnapshot): PolicyTestResponse['invalidVersions'] =>
  compiled.invalid.map((i) => ({
    policyId: i.publicId,
    versionNo: i.versionNo,
    violations: i.violations.map((v) => ({ path: v.path, code: v.code, message: v.message })),
  }));

/**
 * `POST /policies/test` and `POST /messages/{messageId}/scans/{scanId}/policy/dry-run` (step 5.2
 * P22, P23): evaluates synthetic facts, or the stored facts of a finished round, against a target
 * snapshot (`active`, `platform`, a version of a policy, or an inline definition) with the same
 * library functions the policy-engine uses (`compileSnapshot`, `buildSyntheticInput` /
 * `buildPolicyInput`, `evaluatePolicy`). It reads the replica only and **writes nothing**: no
 * evaluation row, no audit row, no outbox row (this service has no writer or audit dependency).
 * Counted `policy_dry_runs_total{kind, result}`.
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

  private async counted<T>(kind: PolicyDryRunKind, fn: () => Promise<T>): Promise<T> {
    try {
      const out = await fn();
      this.metrics.dryRuns.inc({ kind, result: 'ok' });
      return out;
    } catch (error) {
      const result = error instanceof CodedHttpException ? RESULT_OF_CODE[error.code] : undefined;
      if (result !== undefined) this.metrics.dryRuns.inc({ kind, result });
      throw error;
    }
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
    return { result: evaluatePolicy(input, compiled), invalidVersions: invalidVersions(compiled) };
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
    if (OPEN_SCAN_STATUSES.has(scan.status) || scan.completedAt === null) {
      throw scanRoundNotComplete(scan.status);
    }
    const compiled = await this.compile(scope, body.target, inline);
    const rows = await this.facts.roundRows(scope, message, scanId);
    const refs = referencedDirectoryIds(compiled);
    const directory =
      refs.departmentIds.length === 0 && refs.userIds.length === 0
        ? { departmentsByAddress: {}, usersByAddress: {} }
        : directoryMaps(await this.facts.directory(scope, roundAddresses(message, rows), refs));
    let result: PolicyEvaluationResult;
    try {
      result = evaluatePolicy(
        buildPolicyInput(policyRoundRowsOf(message, scan, rows, directory)),
        compiled,
      );
    } catch (error) {
      if (error instanceof PolicyInputError) throw policyInputInvalid();
      throw error;
    }
    const storedRow = await this.facts.storedEvaluation(scope, message, scanId);
    const stored = storedRow === null ? null : evaluationViewOf(storedRow);
    return {
      result,
      invalidVersions: invalidVersions(compiled),
      stored,
      reproducible:
        body.target === 'active' &&
        stored !== null &&
        stored.inputSha256 === result.inputSha256 &&
        stored.versions.snapshotSha256 === result.versions.snapshotSha256,
    };
  }

  /** `{ definition }` → the inline snapshot policy (400 when the DSL refuses it). */
  private inlineOf(target: PolicyTarget): SnapshotPolicy | null {
    if (typeof target !== 'object' || !('definition' in target)) return null;
    const check = checkDefinition(target.definition);
    if (!check.ok) throw policyDefinitionInvalid(check.violations);
    return inlinePolicy(check.content.definition, check.content.definitionSha256);
  }

  /** The target's compiled snapshot from the replica's active snapshot source (P12). */
  private async compile(
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
