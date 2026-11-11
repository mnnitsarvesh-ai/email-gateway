import {
  canonicalJson,
  DIRECTORY_FIELDS,
  formatPath,
  POLICY_ACTION_TYPES,
  POLICY_DISPOSITIONS,
  POLICY_DSL_VERSION,
  POLICY_EVALUATOR_VERSION,
  POLICY_FIELD_NAMES,
  POLICY_FIELDS,
  POLICY_INPUT_VERSION,
  POLICY_LIMITS,
  POLICY_NON_TERMINAL_ACTIONS,
  POLICY_OPERATORS,
  POLICY_PLATFORM_DEFAULTS,
  POLICY_SETTINGS_DEFAULTS,
  type PolicyDefinition,
  policyTenantSettingsSchema,
  resolvePolicySettings,
  sha256Hex,
  validatePolicyDefinition,
  type Violation,
} from '@email-gateway/policy-dsl';
import type { Prisma } from '@email-gateway/database';
import type {
  PolicyCatalog,
  PolicyDetail,
  PolicySettingsView,
  PolicySummary,
  PolicyVersionDetail,
  PolicyVersionSummary,
} from '../dto/policies.schemas';
import type {
  PolicyRow,
  SettingsRow,
  VersionContent,
  VersionCounts,
  VersionRow,
} from '../repositories/policies-management.repository';

/**
 * Pure part of policy management (step 5.2 P2–P6, P11, P17, P22): validation of a definition into
 * the stored version columns, the directory reference check with paths, the settings document
 * check, the changed paths of a settings change, the catalog and the views. No I/O.
 */

/** What enforcement in step 5.2 means (every route description carries it). */
export const POLICY_ENFORCEMENT_NOTE =
  'Step 5.2 **enforces** the final disposition (ALLOW delivers; QUARANTINE holds in ' +
  '`quarantined`; REQUIRE_APPROVAL holds in `held_for_review`; REJECT rejects) and the ' +
  'strictness floor (hard blocks, failures, the DLP binding and missing data are never ' +
  'weakened), plus TAG/WARN headers in a delivered copy; it **requests** ARCHIVE (consumed by ' +
  'step 8.1), ALERT and sender non-delivery notices (notification-worker); WARN body banners ' +
  'are recorded only. The quarantine store, end-user quarantine and release re-validation are ' +
  'step 5.3; archiving and journaling are step 8.1.';

/** How a change takes effect (P12). */
export const POLICY_APPLY_NOTE =
  'A change that affects evaluation increments the organization’s policy generation and ' +
  'applies to the **next evaluation** only: messages already evaluated are never re-evaluated.';

/** The synthetic id of an inline definition in a test or dry-run snapshot. */
export const INLINE_POLICY_ID = '00000000-0000-7000-8000-000000000000';

/** SHA-256 of the canonical JSON of `{}` (a lazily created settings row). */
export const EMPTY_SETTINGS_SHA256 = sha256Hex(canonicalJson({}));

export type CheckedDefinition =
  | { ok: true; content: VersionContent; definition: PolicyDefinition }
  | { ok: false; violations: Violation[] };

/** Validates a definition (P2–P6) into the columns a version stores (P17). */
export function checkDefinition(doc: unknown): CheckedDefinition {
  const result = validatePolicyDefinition(doc);
  if (!result.ok) return { ok: false, violations: result.violations };
  const definition = result.definition;
  return {
    ok: true,
    definition,
    content: {
      definition: definition as unknown as Prisma.InputJsonValue,
      definitionSha256: sha256Hex(canonicalJson(definition)),
      dslVersion: POLICY_DSL_VERSION,
      references: {
        departmentIds: [...result.references.departmentIds],
        userIds: [...result.references.userIds],
      },
      hasOverrideRules: result.hasOverrideRules,
      ruleCount: result.ruleCount,
    },
  };
}

/** Rule ids of the rules carrying `override: true` (audit metadata of the override publish). */
export function overrideRuleIds(definition: unknown): string[] {
  const rules = (definition as { rules?: unknown } | null)?.rules;
  if (!Array.isArray(rules)) return [];
  return rules
    .filter((r): r is { id: string; override: true } => {
      const rule = r as { id?: unknown; override?: unknown } | null;
      return typeof rule?.id === 'string' && rule.override === true;
    })
    .map((r) => r.id)
    .sort();
}

/** `{ departmentIds, userIds }` of a stored version (null / malformed → none). */
export function referencesOf(stored: unknown): { departmentIds: string[]; userIds: string[] } {
  const refs = stored as { departmentIds?: unknown; userIds?: unknown } | null;
  const ids = (v: unknown) =>
    Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
  return { departmentIds: ids(refs?.departmentIds), userIds: ids(refs?.userIds) };
}

/**
 * Violations for directory ids the definition references that do not exist in the organization
 * (P5), one per leaf value, with the leaf's path (`rules[0].when.value[1]`).
 */
export function unknownReferenceViolations(
  definition: unknown,
  existing: { departmentIds: ReadonlySet<string>; userIds: ReadonlySet<string> },
): Violation[] {
  const out: Violation[] = [];
  const walk = (node: unknown, path: Array<string | number>): void => {
    if (Array.isArray(node)) {
      node.forEach((child, i) => walk(child, [...path, i]));
      return;
    }
    if (node === null || typeof node !== 'object') return;
    const leaf = node as { field?: unknown; value?: unknown };
    const kind =
      typeof leaf.field === 'string'
        ? (DIRECTORY_FIELDS as Readonly<Record<string, 'department' | 'user'>>)[leaf.field]
        : undefined;
    if (kind !== undefined && Array.isArray(leaf.value)) {
      leaf.value.forEach((id, i) => {
        if (typeof id !== 'string') return;
        const known =
          kind === 'department' ? existing.departmentIds.has(id) : existing.userIds.has(id);
        if (!known) {
          out.push({
            path: formatPath([...path, 'value', i]),
            code: kind === 'department' ? 'department_unknown' : 'user_unknown',
            message:
              kind === 'department'
                ? 'Unknown department of the organization'
                : 'Unknown user of the organization',
          });
        }
      });
      return;
    }
    for (const [key, child] of Object.entries(node)) walk(child, [...path, key]);
  };
  walk(definition, []);
  return out;
}

/** Validates a settings document (strict P11 schema) and returns its canonical form. */
export function checkSettings(
  doc: unknown,
):
  | { ok: true; settings: Prisma.InputJsonValue; sha256: string }
  | { ok: false; violations: Violation[] } {
  const parsed = policyTenantSettingsSchema.safeParse(doc);
  if (!parsed.success) return { ok: false, violations: resolvePolicySettings(doc).violations };
  const settings = JSON.parse(JSON.stringify(parsed.data)) as Prisma.InputJsonValue;
  return { ok: true, settings, sha256: sha256Hex(canonicalJson(settings)) };
}

/** Leaf paths whose effective value differs between two settings documents. */
export function changedSettingsPaths(before: unknown, after: unknown): string[] {
  const a = resolvePolicySettings(before).settings;
  const b = resolvePolicySettings(after).settings;
  const out: string[] = [];
  const walk = (x: unknown, y: unknown, path: string[]) => {
    if (x !== null && typeof x === 'object' && y !== null && typeof y === 'object') {
      const keys = new Set([...Object.keys(x), ...Object.keys(y)]);
      for (const k of [...keys].sort()) {
        walk((x as Record<string, unknown>)[k], (y as Record<string, unknown>)[k], [...path, k]);
      }
      return;
    }
    if (x !== y) out.push(path.join('.'));
  };
  walk(a, b, []);
  return out;
}

// --------------------------------------------------------------------------------------------
// Views
// --------------------------------------------------------------------------------------------

const iso = (d: Date | null): string | null => (d === null ? null : d.toISOString());

export function versionSummary(
  policyPublicId: string,
  row: VersionRow,
  activeVersionId: bigint | null,
): PolicyVersionSummary {
  const refs = row.references === null ? null : referencesOf(row.references);
  return {
    policyId: policyPublicId,
    versionNo: row.version,
    status: row.status,
    active: activeVersionId !== null && row.id === activeVersionId,
    dslVersion: row.dslVersion,
    definitionSha256: row.definitionSha256,
    ruleCount: row.ruleCount,
    hasOverrideRules: row.hasOverrideRules,
    references: refs,
    changeNote: row.changeNote,
    rowVersion: row.rowVersion,
    createdByUserId: row.createdBy?.publicId ?? null,
    updatedByUserId: row.updatedBy?.publicId ?? null,
    publishedByUserId: row.publishedBy?.publicId ?? null,
    publishedAt: iso(row.publishedAt),
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export function versionDetail(
  policyPublicId: string,
  row: VersionRow,
  activeVersionId: bigint | null,
): PolicyVersionDetail {
  const validation = validatePolicyDefinition(row.definition);
  return {
    ...versionSummary(policyPublicId, row, activeVersionId),
    definition: row.definition,
    validation: validation.ok
      ? { valid: true, violations: [] }
      : { valid: false, violations: validation.violations.slice(0, 100) },
  };
}

/** The listed policy status (`archived` rows are never listed or returned). */
const statusOf = (row: PolicyRow): PolicySummary['status'] =>
  row.status === 'archived' ? 'disabled' : row.status;

export function policySummary(
  row: PolicyRow,
  numbers: { active: number | null; latest: number | null },
): PolicySummary {
  return {
    id: row.publicId,
    name: row.name,
    description: row.description,
    status: statusOf(row),
    direction: row.direction,
    priority: row.priority,
    activeVersionNo: numbers.active,
    latestVersionNo: numbers.latest,
    rowVersion: row.rowVersion,
    createdByUserId: row.createdBy?.publicId ?? null,
    updatedByUserId: row.updatedBy?.publicId ?? null,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export function policyDetail(
  row: PolicyRow,
  active: VersionRow | null,
  latest: number | null,
  counts: VersionCounts,
  limit: number,
): PolicyDetail {
  const activeRow = active !== null && active.id === row.activeVersionId ? active : null;
  return {
    ...policySummary(row, { active: activeRow?.version ?? null, latest }),
    activeVersion:
      activeRow === null
        ? null
        : {
            versionNo: activeRow.version,
            definitionSha256: activeRow.definitionSha256,
            ruleCount: activeRow.ruleCount,
            hasOverrideRules: activeRow.hasOverrideRules,
            publishedAt: iso(activeRow.publishedAt),
          },
    counts: { ...counts, limit },
  };
}

export function settingsView(row: SettingsRow | null): PolicySettingsView {
  const stored =
    row !== null && row.settings !== null && typeof row.settings === 'object'
      ? (row.settings as Record<string, unknown>)
      : {};
  const resolved = resolvePolicySettings(row === null ? null : row.settings);
  return {
    settings: stored,
    effective: resolved.settings,
    violations: resolved.violations,
    generation: (row?.generation ?? 0n).toString(),
    rowVersion: row?.rowVersion ?? 0,
    settingsSha256: row?.settingsSha256 ?? null,
    updatedByUserId: row?.updatedBy?.publicId ?? null,
    updatedAt: iso(row?.updatedAt ?? null),
  };
}

/** The organization bounds of this deployment (env, §5) applied to the DSL limits (P4). */
export interface PolicyBounds {
  POLICY_PLATFORM_DEFAULT: string;
  POLICY_MAX_POLICIES: number;
  POLICY_MAX_VERSIONS_PER_POLICY: number;
  POLICY_MAX_ACTIVE_RULES: number;
  POLICY_HISTORY_MAX_RANGE_DAYS: number;
}

export function catalogView(bounds: PolicyBounds): PolicyCatalog {
  const platform = POLICY_PLATFORM_DEFAULTS[bounds.POLICY_PLATFORM_DEFAULT]!;
  const limits: Record<string, number> = {};
  for (const [k, v] of Object.entries(POLICY_LIMITS)) if (typeof v === 'number') limits[k] = v;
  limits.activePoliciesPerOrganization = Math.min(
    POLICY_LIMITS.activePoliciesPerOrganization,
    bounds.POLICY_MAX_POLICIES,
  );
  limits.activeRulesPerOrganization = Math.min(
    POLICY_LIMITS.activeRulesPerOrganization,
    bounds.POLICY_MAX_ACTIVE_RULES,
  );
  limits.policiesPerOrganization = bounds.POLICY_MAX_POLICIES;
  limits.versionsPerPolicy = bounds.POLICY_MAX_VERSIONS_PER_POLICY;
  limits.historyRangeDays = bounds.POLICY_HISTORY_MAX_RANGE_DAYS;
  return {
    versions: {
      dsl: POLICY_DSL_VERSION,
      input: POLICY_INPUT_VERSION,
      evaluator: POLICY_EVALUATOR_VERSION,
    },
    platformDefault: { id: platform.id, description: platform.description },
    fields: POLICY_FIELD_NAMES.map((name) => {
      const f = POLICY_FIELDS[name];
      return {
        name,
        type: f.type,
        scope: f.scope,
        ops: [...f.ops],
        quantified: f.quantified,
        authenticatedIdentity: f.authenticatedIdentity,
        senderIdentity: f.senderIdentity,
        aiDerived: f.aiDerived,
        directions: [...f.directions],
        values: f.values === null ? null : [...f.values],
        ordered: f.ordered,
        min: f.min,
        max: f.max,
        description: f.description,
      };
    }),
    operators: [...POLICY_OPERATORS],
    actions: [...POLICY_ACTION_TYPES],
    nonTerminalActions: [...POLICY_NON_TERMINAL_ACTIONS],
    dispositions: [...POLICY_DISPOSITIONS],
    limits,
    settingsDefaults: {
      allowRecommendationOverrides: POLICY_SETTINGS_DEFAULTS.allowRecommendationOverrides,
      notices: { ...POLICY_SETTINGS_DEFAULTS.notices },
      alerts: { ...POLICY_SETTINGS_DEFAULTS.alerts },
      tagging: { ...POLICY_SETTINGS_DEFAULTS.tagging },
    },
    enforcement: POLICY_ENFORCEMENT_NOTE,
  };
}
