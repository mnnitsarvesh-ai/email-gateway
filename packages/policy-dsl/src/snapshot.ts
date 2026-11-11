import { canonicalJson, sha256Hex } from '@email-gateway/risk-scoring';
import { compileNode, leavesOf, type CompiledNode } from './conditions';
import {
  validatePolicyDefinition,
  type DirectoryReferences,
  type PolicyAction,
  type PolicyDefinition,
  type Violation,
} from './definition';
import {
  isPlatformDefaultId,
  POLICY_DEFAULT_PLATFORM_ID,
  POLICY_PLATFORM_DEFAULTS,
  type PlatformDefault,
} from './platform';
import { resolvePolicySettings, type PolicyTenantSettings } from './settings';
import {
  DISPOSITION_OF_ACTION,
  isDispositionAction,
  POLICY_MESSAGE_DIRECTIONS,
  type PolicyDirection,
  type PolicyDisposition,
  type PolicyMessageDirection,
  type PolicyNonTerminalAction,
} from './vocabulary';

/**
 * Snapshots (step 5.2 P12): the organization's active, published policy versions plus its
 * settings, compiled once per `(organization, generation)`. `compileSnapshot` never throws: a
 * stored definition that no longer validates (or whose hash does not match) is excluded and
 * listed in `invalid` (`policy.snapshot.invalid_version`); that can only drop tenant rules,
 * never the platform default or the floor.
 */

export interface PolicySnapshotSource {
  /** `policy_settings.generation` as a decimal string (`'0'` without a settings row). */
  generation: string;
  /** `policy_settings.settings` (null without a row). */
  settings: unknown;
  /** `POLICY_PLATFORM_DEFAULT` (a key of `POLICY_PLATFORM_DEFAULTS`). */
  platformDefaultId: string;
  policies: ReadonlyArray<{
    publicId: string;
    versionNo: number;
    definition: unknown;
    definitionSha256: string;
  }>;
}

export interface CompiledRule {
  /** `<policyPublicId>#<versionNo>/<ruleId>`. */
  ref: string;
  policyPublicId: string;
  versionNo: number;
  ruleId: string;
  /** Index of the rule in the stored definition (paths are `rules[<index>]…`). */
  ruleIndex: number;
  priority: number;
  enabled: boolean;
  /** Effective directions (rule `directions`, else the policy direction). */
  directions: readonly PolicyMessageDirection[];
  when: CompiledNode;
  unless: CompiledNode[];
  disposition: PolicyDisposition | null;
  actions: PolicyAction[];
  nonTerminal: Array<Extract<PolicyAction, { type: PolicyNonTerminalAction }>>;
  stop: boolean;
  override: boolean;
  /** The rule reads an AI-derived field (P9.8). */
  aiDerived: boolean;
}

export interface CompiledPolicy {
  publicId: string;
  versionNo: number;
  definitionSha256: string;
  direction: PolicyDirection;
  priority: number;
  exceptions: CompiledNode[];
  /** Directory ids the definition references (P5). */
  references: DirectoryReferences;
  /** Sorted by `(rule priority, rule id)`. */
  rules: CompiledRule[];
}

export interface InvalidPolicyVersion {
  publicId: string;
  versionNo: number;
  code: 'policy.snapshot.invalid_version';
  /** At most 20 violations (paths and codes). */
  violations: Violation[];
}

export interface CompiledSnapshot {
  generation: string;
  platformDefaultId: string;
  platformDefault: PlatformDefault;
  settings: PolicyTenantSettings;
  /** Non-empty when the stored settings were invalid (defaults used). */
  settingsViolations: Violation[];
  /** Valid policies sorted by `(priority, publicId)`. */
  policies: CompiledPolicy[];
  invalid: InvalidPolicyVersion[];
  /** Snapshot-level codes (`policy.snapshot.*`, `policy.settings.invalid_fallback`). */
  reasonCodes: string[];
  snapshotSha256: string;
  /** Versions of the valid policies (sorted by public id), recorded in every result. */
  versions: Array<{ policyPublicId: string; versionNo: number; definitionSha256: string }>;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

function compilePolicy(
  publicId: string,
  versionNo: number,
  definitionSha256: string,
  def: PolicyDefinition,
  references: DirectoryReferences,
): CompiledPolicy {
  const policyDirections: readonly PolicyMessageDirection[] =
    def.direction === 'any' ? POLICY_MESSAGE_DIRECTIONS : [def.direction];
  const rules = def.rules.map((rule, ruleIndex): CompiledRule => {
    const base = `rules[${ruleIndex}]`;
    const when = compileNode(rule.when, `${base}.when`);
    const unless = (rule.unless ?? []).map((n, k) => compileNode(n, `${base}.unless[${k}]`));
    const dispositionAction = rule.actions.find((a) => isDispositionAction(a.type));
    const disposition = dispositionAction
      ? DISPOSITION_OF_ACTION[dispositionAction.type as keyof typeof DISPOSITION_OF_ACTION]
      : null;
    const aiDerived = [when, ...unless].some((n) => [...leavesOf(n)].some((l) => l.def.aiDerived));
    return {
      ref: `${publicId}#${versionNo}/${rule.id}`,
      policyPublicId: publicId,
      versionNo,
      ruleId: rule.id,
      ruleIndex,
      priority: rule.priority,
      enabled: rule.enabled ?? true,
      directions: rule.directions ?? policyDirections,
      when,
      unless,
      disposition,
      actions: rule.actions,
      nonTerminal: rule.actions.filter(
        (a) => !isDispositionAction(a.type),
      ) as CompiledRule['nonTerminal'],
      stop: rule.stop ?? disposition !== null,
      override: rule.override === true && disposition !== null,
      aiDerived,
    };
  });
  rules.sort((a, b) => a.priority - b.priority || cmp(a.ruleId, b.ruleId));
  return {
    publicId,
    versionNo,
    definitionSha256,
    direction: def.direction,
    priority: def.priority,
    exceptions: (def.exceptions ?? []).map((n, k) => compileNode(n, `exceptions[${k}]`)),
    references,
    rules,
  };
}

/** Compiles a snapshot source (P12). Never throws. */
export function compileSnapshot(source: PolicySnapshotSource): CompiledSnapshot {
  const reasonCodes: string[] = [];
  const generation =
    typeof source.generation === 'string' && /^[0-9]{1,20}$/.test(source.generation)
      ? source.generation
      : '0';
  let platformDefaultId = source.platformDefaultId;
  if (!isPlatformDefaultId(platformDefaultId)) {
    platformDefaultId = POLICY_DEFAULT_PLATFORM_ID;
    reasonCodes.push('policy.snapshot.platform_default_fallback');
  }
  const { settings, violations: settingsViolations } = resolvePolicySettings(source.settings);
  if (settingsViolations.length > 0) reasonCodes.push('policy.settings.invalid_fallback');

  const policies: CompiledPolicy[] = [];
  const invalid: InvalidPolicyVersion[] = [];
  const seen = new Set<string>();
  const sourceRefs: Array<{ publicId: string; versionNo: number; definitionSha256: string }> = [];
  for (const p of source.policies ?? []) {
    const publicId = typeof p?.publicId === 'string' ? p.publicId : '';
    const versionNo = Number.isSafeInteger(p?.versionNo) ? p.versionNo : 0;
    const sha = typeof p?.definitionSha256 === 'string' ? p.definitionSha256 : '';
    sourceRefs.push({ publicId, versionNo, definitionSha256: sha });
    const reject = (violations: Violation[]) =>
      invalid.push({
        publicId,
        versionNo,
        code: 'policy.snapshot.invalid_version',
        violations: violations.slice(0, 20),
      });
    if (!UUID.test(publicId) || versionNo < 1 || !SHA256.test(sha)) {
      reject([{ path: '', code: 'value_invalid', message: 'Malformed policy version reference' }]);
      continue;
    }
    if (seen.has(publicId)) {
      reject([{ path: '', code: 'value_invalid', message: 'Policy listed twice in the snapshot' }]);
      continue;
    }
    seen.add(publicId);
    try {
      const validation = validatePolicyDefinition(p.definition);
      if (!validation.ok) {
        reject(validation.violations);
        continue;
      }
      if (sha256Hex(canonicalJson(p.definition)) !== sha) {
        reject([
          {
            path: '',
            code: 'definition_hash_mismatch',
            message: 'definition_sha256 does not match the stored definition',
          },
        ]);
        continue;
      }
      policies.push(
        compilePolicy(publicId, versionNo, sha, validation.definition, validation.references),
      );
    } catch {
      reject([
        { path: '', code: 'value_invalid', message: 'The definition could not be compiled' },
      ]);
    }
  }
  if (invalid.length > 0) reasonCodes.push('policy.snapshot.invalid_version');
  policies.sort((a, b) => a.priority - b.priority || cmp(a.publicId, b.publicId));
  sourceRefs.sort((a, b) => cmp(a.publicId, b.publicId) || a.versionNo - b.versionNo);
  const snapshotSha256 = sha256Hex(
    canonicalJson({ generation, platformDefaultId, settings, policies: sourceRefs }),
  );
  return {
    generation,
    platformDefaultId,
    platformDefault: POLICY_PLATFORM_DEFAULTS[platformDefaultId]!,
    settings,
    settingsViolations,
    policies,
    invalid,
    reasonCodes,
    snapshotSha256,
    versions: policies
      .map((p) => ({
        policyPublicId: p.publicId,
        versionNo: p.versionNo,
        definitionSha256: p.definitionSha256,
      }))
      .sort((a, b) => cmp(a.policyPublicId, b.policyPublicId)),
  };
}

/** Directory ids the valid policies of a snapshot reference (P5), sorted and unique. */
export function referencedDirectoryIds(compiled: CompiledSnapshot): DirectoryReferences {
  const departmentIds = new Set<string>();
  const userIds = new Set<string>();
  for (const p of compiled.policies) {
    for (const id of p.references.departmentIds) departmentIds.add(id);
    for (const id of p.references.userIds) userIds.add(id);
  }
  return { departmentIds: [...departmentIds].sort(), userIds: [...userIds].sort() };
}
