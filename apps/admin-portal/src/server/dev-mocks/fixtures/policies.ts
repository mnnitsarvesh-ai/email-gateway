import 'server-only';
import type { ListItem, RequestBody, SuccessBody } from '@/lib/api/types';
import { fixtureAnchor, paginate, stableUuid } from '../generator';
import {
  apiError,
  noContent,
  ok,
  type FixtureHandler,
  type FixtureHandlers,
  type FixtureRequest,
  type FixtureResponse,
} from '../types';
import { fixtures as attachmentFixtures } from './attachments';
import { fixtures as auditFixtures } from './audit';
import { FIXTURE_MESSAGES, fixtureGuard, guarded } from './messages';
import { riskFixtures } from './policy-risk';
import {
  audit,
  cannedViolations,
  findPolicy,
  findVersion,
  hasOverrideRules,
  idempotent,
  isRecord,
  liveVersionCount,
  nextVersionNo,
  POLICY_LIMIT,
  policyOrg,
  policyRowView,
  policyView,
  ruleCountOf,
  seededPolicyId,
  settingsView,
  sha256,
  VERSION_LIMIT,
  versionRowView,
  versionView,
  type AuditRow,
  type PolicyOrgState,
  type StoredPolicy,
  type StoredVersion,
} from './policy-store';
import { toolFixtures } from './policy-tools';
import { withPrincipal, type Principal } from './reports';
import { fixtures as settingsFixtures } from './settings';
import { fixtures as urlProtectionFixtures } from './url-protection';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of the policy pages (7.1 WP5; step 7.3 WP3, design B15): email policies with
 * their versions in an in-memory per-process store (`policy-store.ts`: create, rename, enable,
 * disable, delete, drafts, publish, activate and roll back with row-version compare-and-set,
 * immutable published versions, Idempotency-Key replays and generation increments), the policy
 * settings, the execution history (derived from the message fixtures' evaluations), the
 * catalogue snapshot and canned validate/test/dry-run answers (`policy-tools.ts`, never an
 * evaluation), the risk profile and its drafts (`policy-risk.ts`), the audit rows of policy and
 * risk changes, and the DLP and BEC lists (replaced by WP5's `dlp-bec.ts`, registered later).
 * Scan settings are owned by the Settings fixtures; a read-only list is provided here only when
 * no other fixture file defines it. Everything is synthetic.
 */

type Execution = ListItem<'PolicyToolsController_history_v1'>;
type Violation = { path: string; code: string; message: string };

const anchor = fixtureAnchor();
const DAY = 86_400_000;
const iso = (offsetDays: number) => new Date(anchor - offsetDays * DAY).toISOString();
const ADMIN = stableUuid('user:organization_admin');

function v0Page<T>(
  items: readonly T[],
  query: URLSearchParams,
): { data: T[]; nextCursor: string | null } {
  const limit = Math.min(100, Math.max(1, Number(query.get('limit') ?? '25') || 25));
  const cursor = query.get('cursor');
  const offset = cursor ? Number(Buffer.from(cursor, 'base64url').toString('utf8')) || 0 : 0;
  return {
    data: items.slice(offset, offset + limit),
    nextCursor:
      offset + limit < items.length
        ? Buffer.from(String(offset + limit)).toString('base64url')
        : null,
  };
}

// ---------------------------------------------------------------------------------------------
// Execution history (the message fixtures' stored evaluations)
// ---------------------------------------------------------------------------------------------

const EXECUTIONS: Execution[] = FIXTURE_MESSAGES.flatMap((m) =>
  m.evaluations.map((e): Execution => ({
    messageId: m.detail.id,
    receivedAt: m.detail.receivedAt,
    lifecycleRound: e.lifecycleRound,
    scanId: e.round.scanId,
    trigger: e.trigger,
    direction: e.direction,
    disposition: e.disposition,
    finalAction: e.finalAction,
    decisive: {
      source: e.decisive.source,
      policyId: e.decisive.policyPublicId ? 'inbound-threats' : null,
      versionNo: e.decisive.versionNo,
      ruleId: e.decisive.ruleId,
    },
    actions: e.actions.map((a, i) => ({ type: a.type, status: e.actionStatuses[i] ?? 'recorded' })),
    matchedRuleCount: e.matchedRules.length,
    overrideApplied: e.override !== null,
    generation: e.versions.generation,
    inputSha256: e.inputSha256,
    durationUs: e.durationUs,
    evaluatedAt: e.evaluatedAt,
  })),
).sort((a, b) => b.evaluatedAt.localeCompare(a.evaluatedAt));

/** The history of the caller's organization: tenant decisions name its seeded main policy. */
function executions(request: FixtureRequest, p: Principal): FixtureResponse {
  const q = request.query;
  const from = Date.parse(q.get('from') ?? '');
  const to = Date.parse(q.get('to') ?? '');
  if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from) {
    return apiError(400, 'validation_failed', ['from: required', 'to: required']);
  }
  if (to - from > 31 * DAY)
    return apiError(400, 'validation_failed', ['to: the range is at most 31 days']);
  const mainPolicy = seededPolicyId(p.organizationId, 'inbound-threats');
  const eq = (name: string, value: string | null) => !q.get(name) || q.get(name) === value;
  const rows = EXECUTIONS.map((row) =>
    row.decisive.policyId ? { ...row, decisive: { ...row.decisive, policyId: mainPolicy } } : row,
  ).filter((row) => {
    const t = Date.parse(row.evaluatedAt);
    return (
      t >= from &&
      t < to &&
      eq('direction', row.direction) &&
      eq('disposition', row.disposition) &&
      eq('source', row.decisive.source) &&
      eq('trigger', row.trigger) &&
      eq('policyId', row.decisive.policyId) &&
      eq('ruleId', row.decisive.ruleId) &&
      eq('overrideApplied', String(row.overrideApplied))
    );
  });
  return ok('PolicyToolsController_history_v1', v0Page(rows, q));
}

// ---------------------------------------------------------------------------------------------
// Policies, versions and settings (the store's rules: CAS, immutability, generation)
// ---------------------------------------------------------------------------------------------

const RESOURCE_POLICY = 'email_policy';
const RESOURCE_VERSION = 'policy_version';
const RESOURCE_SETTINGS = 'policy_settings';

const policyNotFound = () => apiError(404, 'policy_not_found', 'Policy not found');
const versionNotFound = () => apiError(404, 'policy_version_not_found', 'Policy version not found');
const conflict = (current: number) =>
  apiError(409, 'policy_conflict', 'The policy changed since it was read; read it and retry', {
    currentRowVersion: current,
  });
const immutable = () =>
  apiError(
    409,
    'policy_version_immutable',
    'The version is published; a published version is never changed or deleted',
  );
const definitionInvalid = (violations: Violation[]) =>
  apiError(400, 'policy_definition_invalid', 'The definition breaks the policy-dsl/1 schema', {
    violations,
  });

const bodyOf = (request: FixtureRequest): Record<string, unknown> =>
  isRecord(request.body) ? request.body : {};
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const now = () => new Date().toISOString();

function withOrg(
  handler: (state: PolicyOrgState, p: Principal, request: FixtureRequest) => FixtureResponse,
): FixtureHandler {
  return (request) =>
    withPrincipal(request, (p) => handler(policyOrg(p.organizationId), p, request));
}

function withStoredPolicy(
  handler: (
    state: PolicyOrgState,
    policy: StoredPolicy,
    p: Principal,
    request: FixtureRequest,
  ) => FixtureResponse,
): FixtureHandler {
  return withOrg((state, p, request) => {
    const policy = findPolicy(state, request.params.policyId);
    return policy ? handler(state, policy, p, request) : policyNotFound();
  });
}

const nameTaken = (state: PolicyOrgState, name: string, except?: string) =>
  state.policies.some(
    (other) => other.id !== except && other.name.trim().toLowerCase() === name.trim().toLowerCase(),
  );

/** Activation (P17): pointer, status `active`, policy row version and generation incremented. */
function activate(
  state: PolicyOrgState,
  policy: StoredPolicy,
  version: StoredVersion,
  p: Principal,
): void {
  const previousVersionNo = policy.activeVersionNo;
  const previousStatus = policy.status;
  policy.activeVersionNo = version.versionNo;
  policy.status = 'active';
  policy.rowVersion += 1;
  policy.updatedAt = now();
  policy.updatedBy = p.userId;
  state.generation += 1;
  audit(state, p.userId, 'policy.version_activated', RESOURCE_VERSION, policy.id, {
    policyId: policy.id,
    versionNo: version.versionNo,
    definitionSha256: sha256(version.definition),
    previousVersionNo,
    previousStatus,
    rowVersion: policy.rowVersion,
    generation: state.generation,
  });
}

function newVersion(
  policy: StoredPolicy,
  definition: unknown,
  changeNote: string | null,
  p: Principal,
): StoredVersion {
  const at = now();
  const version: StoredVersion = {
    versionNo: nextVersionNo(policy),
    status: 'draft',
    definition,
    changeNote,
    rowVersion: 1,
    createdBy: p.userId,
    updatedBy: p.userId,
    publishedBy: null,
    createdAt: at,
    updatedAt: at,
    publishedAt: null,
    deleted: false,
  };
  policy.versions.push(version);
  return version;
}

const SETTINGS_KEYS: Readonly<Record<string, readonly string[] | null>> = {
  allowRecommendationOverrides: null,
  recipientSplit: null,
  notices: ['senderNonDelivery'],
  alerts: ['enabled'],
  tagging: ['platformTagHeader', 'platformTagOutbound'],
};

/** `400 policy_settings_invalid`: unknown keys or a value that is not a boolean (by path). */
function settingsViolations(settings: unknown): Violation[] {
  if (!isRecord(settings)) {
    return [{ path: 'settings', code: 'value_invalid', message: 'must be an object' }];
  }
  const out: Violation[] = [];
  for (const [key, value] of Object.entries(settings)) {
    const nested = SETTINGS_KEYS[key];
    if (nested === undefined) {
      out.push({ path: key, code: 'unknown_key', message: 'unknown key' });
    } else if (nested === null) {
      if (typeof value !== 'boolean') {
        out.push({ path: key, code: 'value_invalid', message: 'must be a boolean' });
      }
    } else if (!isRecord(value)) {
      out.push({ path: key, code: 'value_invalid', message: 'must be an object' });
    } else {
      for (const [sub, subValue] of Object.entries(value)) {
        if (!nested.includes(sub)) {
          out.push({ path: `${key}.${sub}`, code: 'unknown_key', message: 'unknown key' });
        } else if (typeof subValue !== 'boolean') {
          out.push({ path: `${key}.${sub}`, code: 'value_invalid', message: 'must be a boolean' });
        }
      }
    }
  }
  return out;
}

const managementFixtures: FixtureHandlers = {
  PolicyManagementController_list_v1: withOrg((state, _p, request) => {
    const q = request.query;
    const rows = state.policies
      .filter((policy) => !policy.archived)
      .map(policyRowView)
      .filter(
        (row) =>
          (!q.get('status') || q.get('status') === row.status) &&
          (!q.get('direction') || q.get('direction') === row.direction),
      )
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    return ok('PolicyManagementController_list_v1', {
      ...v0Page(rows, q),
      generation: String(state.generation),
    });
  }),

  PolicyManagementController_get_v1: withStoredPolicy((_state, policy) =>
    ok('PolicyManagementController_get_v1', policyView(policy)),
  ),

  PolicyManagementController_create_v1: withOrg((state, p, request) => {
    const body = bodyOf(request) as Partial<RequestBody<'PolicyManagementController_create_v1'>>;
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    if (name.length < 1 || name.length > 128) {
      return apiError(400, 'validation_failed', ['name: between 1 and 128 characters']);
    }
    if (nameTaken(state, name)) {
      return apiError(
        409,
        'policy_name_taken',
        'A policy with this name exists in the organization',
      );
    }
    if (state.policies.filter((policy) => !policy.archived).length >= POLICY_LIMIT) {
      return apiError(
        409,
        'policy_limit_reached',
        'The organization reached its limit of policies',
        {
          limit: POLICY_LIMIT,
        },
      );
    }
    const violations = cannedViolations(body.definition);
    if (violations.length > 0) return definitionInvalid(violations);
    const at = now();
    const policy: StoredPolicy = {
      id: stableUuid(`${p.organizationId}:policy:${name}:${at}`),
      name,
      description: typeof body.description === 'string' ? body.description : null,
      status: 'draft',
      activeVersionNo: null,
      rowVersion: 1,
      archived: false,
      createdBy: p.userId,
      updatedBy: p.userId,
      createdAt: at,
      updatedAt: at,
      versions: [],
    };
    const version = newVersion(
      policy,
      clone(body.definition),
      typeof body.changeNote === 'string' ? body.changeNote : null,
      p,
    );
    state.policies.push(policy);
    audit(state, p.userId, 'policy.created', RESOURCE_POLICY, policy.id, {
      policyId: policy.id,
      rowVersion: policy.rowVersion,
      versionNo: version.versionNo,
      definitionSha256: sha256(version.definition),
    });
    return ok(
      'PolicyManagementController_create_v1',
      { policy: policyView(policy), version: versionView(policy, version) },
      201,
    );
  }),

  PolicyManagementController_update_v1: withStoredPolicy((state, policy, p, request) => {
    const body = bodyOf(request) as Partial<RequestBody<'PolicyManagementController_update_v1'>>;
    if (body.expectedRowVersion !== policy.rowVersion) return conflict(policy.rowVersion);
    const changed: string[] = [];
    if (typeof body.name === 'string' && body.name.trim() !== policy.name) {
      const name = body.name.trim();
      if (name.length < 1 || name.length > 128) {
        return apiError(400, 'validation_failed', ['name: between 1 and 128 characters']);
      }
      if (nameTaken(state, name, policy.id)) {
        return apiError(
          409,
          'policy_name_taken',
          'A policy with this name exists in the organization',
        );
      }
      policy.name = name;
      changed.push('name');
    }
    if (body.description !== undefined && body.description !== policy.description) {
      policy.description = body.description ?? null;
      changed.push('description');
    }
    if (changed.length > 0) {
      policy.rowVersion += 1;
      policy.updatedAt = now();
      policy.updatedBy = p.userId;
      audit(state, p.userId, 'policy.updated', RESOURCE_POLICY, policy.id, {
        policyId: policy.id,
        rowVersion: policy.rowVersion,
        changedPaths: changed,
      });
    }
    return ok('PolicyManagementController_update_v1', policyView(policy));
  }),

  PolicyManagementController_remove_v1: withStoredPolicy((state, policy, p, request) => {
    const expected = request.query.get('expectedRowVersion');
    if (expected !== null && Number(expected) !== policy.rowVersion) {
      return conflict(policy.rowVersion);
    }
    const wasActive = policy.status === 'active';
    policy.archived = true;
    policy.rowVersion += 1;
    if (wasActive) state.generation += 1;
    audit(state, p.userId, 'policy.deleted', RESOURCE_POLICY, policy.id, {
      policyId: policy.id,
      rowVersion: policy.rowVersion,
      wasActive,
      generation: state.generation,
    });
    return noContent();
  }),

  PolicyManagementController_enable_v1: withStoredPolicy((state, policy, p, request) => {
    const body = bodyOf(request) as Partial<RequestBody<'PolicyManagementController_enable_v1'>>;
    if (body.expectedRowVersion !== undefined && body.expectedRowVersion !== policy.rowVersion) {
      return conflict(policy.rowVersion);
    }
    if (policy.activeVersionNo === null) {
      return apiError(409, 'policy_no_active_version', 'Publish and activate a version first');
    }
    if (policy.status !== 'active') {
      policy.status = 'active';
      policy.rowVersion += 1;
      policy.updatedAt = now();
      policy.updatedBy = p.userId;
      state.generation += 1;
      audit(state, p.userId, 'policy.enabled', RESOURCE_POLICY, policy.id, {
        policyId: policy.id,
        rowVersion: policy.rowVersion,
        versionNo: policy.activeVersionNo,
        generation: state.generation,
      });
    }
    return ok('PolicyManagementController_enable_v1', policyView(policy));
  }),

  PolicyManagementController_disable_v1: withStoredPolicy((state, policy, p, request) => {
    const body = bodyOf(request) as Partial<RequestBody<'PolicyManagementController_disable_v1'>>;
    if (body.expectedRowVersion !== undefined && body.expectedRowVersion !== policy.rowVersion) {
      return conflict(policy.rowVersion);
    }
    if (policy.status === 'active') {
      policy.status = 'disabled';
      policy.rowVersion += 1;
      policy.updatedAt = now();
      policy.updatedBy = p.userId;
      state.generation += 1;
      audit(state, p.userId, 'policy.disabled', RESOURCE_POLICY, policy.id, {
        policyId: policy.id,
        rowVersion: policy.rowVersion,
        generation: state.generation,
      });
    }
    return ok('PolicyManagementController_disable_v1', policyView(policy));
  }),

  PolicyManagementController_listVersions_v1: withStoredPolicy((_state, policy, _p, request) => {
    const status = request.query.get('status');
    const rows = policy.versions
      .filter((v) => !v.deleted && (!status || v.status === status))
      .sort((a, b) => b.versionNo - a.versionNo)
      .map((v) => versionRowView(policy, v));
    return ok('PolicyManagementController_listVersions_v1', v0Page(rows, request.query));
  }),

  PolicyManagementController_getVersion_v1: withStoredPolicy((_state, policy, _p, request) => {
    const version = findVersion(policy, request.params.versionNo);
    return version
      ? ok('PolicyManagementController_getVersion_v1', versionView(policy, version))
      : versionNotFound();
  }),

  PolicyManagementController_createDraft_v1: withStoredPolicy((state, policy, p, request) => {
    const body = bodyOf(request) as Partial<
      RequestBody<'PolicyManagementController_createDraft_v1'>
    >;
    let definition: unknown = body.definition;
    if (definition === undefined) {
      if (body.basedOnVersionNo === undefined) {
        return apiError(400, 'validation_failed', [
          'definition: give a definition or basedOnVersionNo',
        ]);
      }
      const source = findVersion(policy, String(body.basedOnVersionNo));
      if (!source) return versionNotFound();
      definition = clone(source.definition);
    }
    const violations = cannedViolations(definition);
    if (violations.length > 0) return definitionInvalid(violations);
    if (liveVersionCount(policy) >= VERSION_LIMIT) {
      return apiError(
        409,
        'policy_version_limit_reached',
        'The policy reached its limit of versions',
        {
          limit: VERSION_LIMIT,
        },
      );
    }
    const version = newVersion(
      policy,
      clone(definition),
      typeof body.changeNote === 'string' ? body.changeNote : null,
      p,
    );
    audit(state, p.userId, 'policy.version_draft_created', RESOURCE_VERSION, policy.id, {
      policyId: policy.id,
      versionNo: version.versionNo,
      rowVersion: version.rowVersion,
      definitionSha256: sha256(version.definition),
    });
    return ok('PolicyManagementController_createDraft_v1', versionView(policy, version), 201);
  }),

  PolicyManagementController_updateDraft_v1: withStoredPolicy((state, policy, p, request) => {
    const version = findVersion(policy, request.params.versionNo);
    if (!version) return versionNotFound();
    if (version.status !== 'draft') return immutable();
    const body = bodyOf(request) as Partial<
      RequestBody<'PolicyManagementController_updateDraft_v1'>
    >;
    if (body.expectedRowVersion !== version.rowVersion) return conflict(version.rowVersion);
    const violations = cannedViolations(body.definition);
    if (violations.length > 0) return definitionInvalid(violations);
    const before = sha256(version.definition);
    version.definition = clone(body.definition);
    if (body.changeNote !== undefined) version.changeNote = body.changeNote ?? null;
    version.rowVersion += 1;
    version.updatedAt = now();
    version.updatedBy = p.userId;
    audit(state, p.userId, 'policy.version_draft_updated', RESOURCE_VERSION, policy.id, {
      policyId: policy.id,
      versionNo: version.versionNo,
      rowVersion: version.rowVersion,
      definitionSha256Before: before,
      definitionSha256: sha256(version.definition),
    });
    return ok('PolicyManagementController_updateDraft_v1', versionView(policy, version));
  }),

  PolicyManagementController_deleteDraft_v1: withStoredPolicy((state, policy, p, request) => {
    const version = findVersion(policy, request.params.versionNo);
    if (!version) return versionNotFound();
    if (version.status !== 'draft') return immutable();
    const expected = request.query.get('expectedRowVersion');
    if (expected !== null && Number(expected) !== version.rowVersion) {
      return conflict(version.rowVersion);
    }
    version.deleted = true;
    audit(state, p.userId, 'policy.version_draft_deleted', RESOURCE_VERSION, policy.id, {
      policyId: policy.id,
      versionNo: version.versionNo,
      rowVersion: version.rowVersion,
    });
    return noContent();
  }),

  PolicyManagementController_publish_v1: withStoredPolicy((state, policy, p, request) =>
    idempotent(state, request, () => {
      const version = findVersion(policy, request.params.versionNo);
      if (!version) return versionNotFound();
      if (version.status !== 'draft') return immutable();
      const body = bodyOf(request) as Partial<RequestBody<'PolicyManagementController_publish_v1'>>;
      if (body.expectedRowVersion !== version.rowVersion) return conflict(version.rowVersion);
      const violations = cannedViolations(version.definition);
      if (violations.length > 0) return definitionInvalid(violations);
      version.status = 'published';
      version.rowVersion += 1;
      version.publishedAt = now();
      version.publishedBy = p.userId;
      version.updatedAt = version.publishedAt;
      audit(state, p.userId, 'policy.version_published', RESOURCE_VERSION, policy.id, {
        policyId: policy.id,
        versionNo: version.versionNo,
        rowVersion: version.rowVersion,
        definitionSha256: sha256(version.definition),
        ruleCount: ruleCountOf(version.definition),
      });
      if (hasOverrideRules(version.definition)) {
        audit(state, p.userId, 'policy.override_rules_published', RESOURCE_VERSION, policy.id, {
          policyId: policy.id,
          versionNo: version.versionNo,
        });
      }
      if (body.activate !== false) activate(state, policy, version, p);
      return ok('PolicyManagementController_publish_v1', {
        version: versionView(policy, version),
        policy: policyView(policy),
        generation: String(state.generation),
      });
    }),
  ),

  PolicyManagementController_activate_v1: withStoredPolicy((state, policy, p, request) =>
    idempotent(state, request, () => {
      const version = findVersion(policy, request.params.versionNo);
      if (!version) return versionNotFound();
      const body = bodyOf(request) as Partial<
        RequestBody<'PolicyManagementController_activate_v1'>
      >;
      if (body.expectedRowVersion !== undefined && body.expectedRowVersion !== policy.rowVersion) {
        return conflict(policy.rowVersion);
      }
      if (version.status !== 'published') {
        return apiError(
          409,
          'policy_version_not_published',
          'Only a published version can be activated',
        );
      }
      if (!(policy.activeVersionNo === version.versionNo && policy.status === 'active')) {
        activate(state, policy, version, p);
      }
      return ok('PolicyManagementController_activate_v1', {
        version: versionView(policy, version),
        policy: policyView(policy),
        generation: String(state.generation),
      });
    }),
  ),

  PolicySettingsController_get_v1: withOrg((state) =>
    ok('PolicySettingsController_get_v1', settingsView(state)),
  ),

  PolicySettingsController_put_v1: withOrg((state, p, request) => {
    const body = bodyOf(request) as Partial<RequestBody<'PolicySettingsController_put_v1'>>;
    if (body.expectedRowVersion !== state.settings.rowVersion) {
      return conflict(state.settings.rowVersion);
    }
    const violations = settingsViolations(body.settings);
    if (violations.length > 0) {
      return apiError(400, 'policy_settings_invalid', 'The policy settings are invalid', {
        violations,
      });
    }
    const next = clone(body.settings ?? {}) as Record<string, unknown>;
    if (sha256(next) === sha256(state.settings.stored)) {
      return ok('PolicySettingsController_put_v1', settingsView(state));
    }
    const before = settingsView(state).effective.allowRecommendationOverrides;
    const beforeSha =
      Object.keys(state.settings.stored).length > 0 ? sha256(state.settings.stored) : null;
    state.settings = {
      stored: next,
      rowVersion: state.settings.rowVersion + 1,
      updatedAt: now(),
      updatedBy: p.userId,
    };
    state.generation += 1;
    const resourceId = stableUuid(`${p.organizationId}:policy-settings`);
    audit(state, p.userId, 'policy.settings_updated', RESOURCE_SETTINGS, resourceId, {
      rowVersion: state.settings.rowVersion,
      generation: state.generation,
      settingsSha256Before: beforeSha,
      settingsSha256: sha256(next),
    });
    if (!before && settingsView(state).effective.allowRecommendationOverrides) {
      audit(state, p.userId, 'policy.settings_overrides_enabled', RESOURCE_SETTINGS, resourceId, {
        rowVersion: state.settings.rowVersion,
        generation: state.generation,
      });
    }
    return ok('PolicySettingsController_put_v1', settingsView(state));
  }),

  PolicyToolsController_history_v1: (request) =>
    withPrincipal(request, (p) => executions(request, p)),
};

// ---------------------------------------------------------------------------------------------
// Audit rows of policy and risk changes (the policy detail's Audit tab, the Audit logs page)
// ---------------------------------------------------------------------------------------------

const STORE_RESOURCES = new Set([
  'email_policy',
  'policy_version',
  'policy_settings',
  'risk_scoring_profile',
  'risk_scoring_profile_version',
]);
const STORE_PREFIXES = ['policy.', 'risk_profile.'];

/** Rows of the store when the request asks for policy or risk resources; else the audit fixture. */
function auditSearch(request: FixtureRequest): FixtureResponse | Promise<FixtureResponse> {
  const q = request.query;
  const resourceType = q.get('resourceType');
  const prefix = q.get('actionPrefix');
  const action = q.get('action');
  const fromStore =
    (resourceType !== null && STORE_RESOURCES.has(resourceType)) ||
    (prefix !== null && STORE_PREFIXES.includes(prefix)) ||
    (action !== null && STORE_PREFIXES.some((p) => action.startsWith(p)));
  const fallback = auditFixtures.AuditLogsController_search_v1;
  if (!fromStore && fallback) return fallback(request);
  return withPrincipal(request, (p) => {
    const state = policyOrg(p.organizationId);
    const to = q.get('to') ? Date.parse(q.get('to') ?? '') : Date.now() + 3_600_000;
    const from = q.get('from') ? Date.parse(q.get('from') ?? '') : to - 7 * DAY;
    if (!Number.isFinite(from) || !Number.isFinite(to)) {
      return apiError(400, 'validation_failed', ['from: must be an ISO 8601 date-time']);
    }
    if (to - from > 90 * DAY) {
      return apiError(400, 'validation_failed', ['from: the range is longer than 90 days']);
    }
    const rows = state.audit.filter((row: AuditRow) => {
      const t = Date.parse(row.createdAt);
      return (
        t >= from &&
        t < to &&
        (!action || row.action === action) &&
        (!prefix || row.action.startsWith(prefix)) &&
        (!resourceType || row.resourceType === resourceType) &&
        (!q.get('resourceId') || row.resourceId === q.get('resourceId')) &&
        (!q.get('actorType') || row.actor.type === q.get('actorType')) &&
        (!q.get('actorId') || row.actor.id === q.get('actorId'))
      );
    });
    const ordered = q.get('sort') === 'createdAt' ? [...rows].reverse() : rows;
    return { status: 200, body: paginate(ordered, q) };
  });
}

// ---------------------------------------------------------------------------------------------
// DLP and BEC lists (7.1, unchanged; WP5's dlp-bec.ts replaces these handlers)
// ---------------------------------------------------------------------------------------------

const dlpBase = (key: string, i: number) => ({
  id: stableUuid(`dlp:${key}:${i}`),
  version: 1,
  createdByUserId: ADMIN,
  updatedByUserId: ADMIN,
  createdAt: iso(60 - i),
  updatedAt: iso(20 - i),
});

const DLP_POLICIES: ListItem<'DlpPoliciesController_list_v1'>[] = [
  {
    ...dlpBase('policy', 1),
    name: 'Payment cards outbound',
    description: 'Block card numbers leaving the company',
    enabled: true,
    mode: 'enforce',
    priority: 10,
    directions: ['outbound'],
    ruleCount: 2,
  },
  {
    ...dlpBase('policy', 2),
    name: 'Source code monitoring',
    description: null,
    enabled: true,
    mode: 'monitor',
    priority: 20,
    directions: ['outbound', 'internal'],
    ruleCount: 1,
  },
  {
    ...dlpBase('policy', 3),
    name: 'Legacy PII rule',
    description: 'Kept for reference',
    enabled: false,
    mode: 'monitor',
    priority: 30,
    directions: ['outbound'],
    ruleCount: 3,
  },
];
const DLP_PATTERNS: ListItem<'DlpPatternsController_list_v1'>[] = [
  {
    ...dlpBase('pattern', 1),
    name: 'Employee ID',
    pattern: 'EMP-[0-9]{6}',
    caseInsensitive: true,
    validator: 'none',
    contextKeywords: ['employee'],
    requireContext: false,
    severity: 'medium',
    baseConfidence: 0.7,
    maskStyle: 'last4',
    enabled: true,
  },
  {
    ...dlpBase('pattern', 2),
    name: 'Project codename <b>',
    pattern: '(?i)project\\s+(falcon|heron)',
    caseInsensitive: true,
    validator: 'none',
    contextKeywords: [],
    requireContext: true,
    severity: 'high',
    baseConfidence: 0.6,
    maskStyle: 'full',
    enabled: true,
  },
];
const DLP_DICTIONARIES: ListItem<'DlpDictionariesController_list_v1'>[] = [
  {
    ...dlpBase('dictionary', 1),
    name: 'Confidential project names',
    category: 'confidential',
    termCount: 24,
    severity: 'high',
    baseConfidence: 0.8,
    minMatches: 1,
    enabled: true,
  },
];
const DLP_EXCEPTIONS: ListItem<'DlpExceptionsController_list_v1'>[] = [
  {
    ...dlpBase('exception', 1),
    scope: 'recipient_domain',
    value: 'auditor.example.test',
    policyId: DLP_POLICIES[0]?.id ?? null,
    ruleId: null,
    filters: { categories: ['payment_card'] },
    reason: 'External auditors receive statements',
    expiresAt: new Date(anchor + 60 * DAY).toISOString(),
    expired: false,
    enabled: true,
  },
  {
    ...dlpBase('exception', 2),
    scope: 'sender_address',
    value: 'payroll@alpha.example.test',
    policyId: null,
    ruleId: null,
    filters: null,
    reason: 'Payroll run',
    expiresAt: iso(3),
    expired: true,
    enabled: true,
  },
];
const DLP_INCIDENTS: ListItem<'DlpIncidentsController_list_v1'>[] = FIXTURE_MESSAGES.filter(
  (m) => m.detail.direction === 'outbound',
)
  .slice(0, 12)
  .map((m, i) => ({
    messageId: m.detail.id,
    scanId: m.rounds[0]?.scanId ?? '0',
    lifecycleRound: 0,
    receivedAt: m.detail.receivedAt,
    direction: 'outbound',
    verdict: 'suspicious',
    action: i % 3 === 0 ? 'block' : 'alert',
    actionSource: 'tenant_policy',
    coverage: 'complete',
    findingCount: 1 + (i % 4),
    categories: [
      {
        category: i % 2 === 0 ? 'payment_card' : 'personal_info',
        count: 1 + (i % 4),
        maxSeverity: 'high',
        maxConfidence: 0.92,
      },
    ],
    findings: [
      {
        detector: i % 2 === 0 ? 'PC1' : 'PI1',
        code: i % 2 === 0 ? 'dlp.payment_card' : 'dlp.personal_info',
        category: i % 2 === 0 ? 'payment_card' : 'personal_info',
        severity: 'high',
        count: 1 + (i % 4),
        capped: false,
      },
    ],
    policy: {
      winner: {
        policyId: DLP_POLICIES[0]?.id ?? stableUuid('dlp:policy:1'),
        ruleId: stableUuid('dlp:rule:1'),
      },
      matched: [],
      exceptionsApplied: [],
    },
    detectedAt: new Date(Date.parse(m.detail.receivedAt) + 3_000).toISOString(),
  }));
const DLP_COMPLIANCE: SuccessBody<'DlpComplianceController_get_v1'> = {
  aadhaar: {
    enabled: false,
    active: false,
    basis: null,
    reference: null,
    attested: false,
    recordedByUserId: null,
    recordedAt: null,
    reviewDueAt: null,
  },
  version: 0,
  updatedAt: null,
};

const becBase = (key: string, i: number) => ({
  id: stableUuid(`bec:${key}:${i}`),
  createdByUserId: ADMIN,
  createdAt: iso(50 - i),
});
const EXECUTIVES: ListItem<'BecExecutivesController_list_v1'>[] = [
  {
    ...becBase('exec', 1),
    displayName: 'Dana Whitfield',
    normalizedName: 'dana whitfield',
    aliases: ['D. Whitfield'],
    knownAddresses: ['ceo@alpha.example.test'],
    title: 'Chief Executive Officer',
    enabled: true,
    updatedByUserId: ADMIN,
    version: 2,
    updatedAt: iso(5),
  },
  {
    ...becBase('exec', 2),
    displayName: 'Ravi Kumar',
    normalizedName: 'ravi kumar',
    aliases: [],
    knownAddresses: ['cfo@alpha.example.test'],
    title: 'CFO',
    enabled: true,
    updatedByUserId: ADMIN,
    version: 1,
    updatedAt: iso(40),
  },
];
const VENDORS: ListItem<'BecVendorsController_list_v1'>[] = [
  {
    ...becBase('vendor', 1),
    name: 'Bravo Logistics',
    normalizedName: 'bravo logistics',
    aliases: [],
    domains: ['bravo.example.test'],
    knownSenders: ['billing@bravo.example.test'],
    paymentChangeSensitive: true,
    enabled: true,
    updatedByUserId: ADMIN,
    version: 1,
    updatedAt: iso(30),
  },
];
const TRUSTED: ListItem<'BecTrustedSendersController_list_v1'>[] = [
  {
    ...becBase('trusted', 1),
    kind: 'domain',
    value: 'partner.example.test',
    reason: 'Long-standing partner',
    expiresAt: null,
    expired: false,
    version: 1,
    updatedAt: iso(20),
  },
  {
    ...becBase('trusted', 2),
    kind: 'address',
    value: 'board<b>@example.test',
    reason: 'Board secretary',
    expiresAt: iso(1),
    expired: true,
    version: 1,
    updatedAt: iso(25),
  },
];
const FEEDBACK: ListItem<'BecFeedbackController_list_v1'>[] = FIXTURE_MESSAGES.filter(
  (m) => m.detail.finalVerdict === 'bec',
)
  .slice(0, 6)
  .map((m, i) => ({
    ...becBase('feedback', i),
    kind: i % 2 === 0 ? 'false_positive' : 'false_negative',
    messageId: m.detail.id,
    scanId: m.rounds[0]?.scanId ?? '0',
    reasonCodes: ['bec.exec_impersonation'],
    note: i === 0 ? 'Known vendor <script>' : null,
  }));
const SUPPRESSIONS: ListItem<'BecFeedbackController_listSuppressions_v1'>[] = [
  {
    ...becBase('suppression', 1),
    reasonCode: 'bec.exec_impersonation',
    senderScope: 'domain',
    senderValue: 'partner.example.test',
    expiresAt: new Date(anchor + 30 * DAY).toISOString(),
    expired: false,
    feedbackId: FEEDBACK[0]?.id ?? null,
  },
];

function filtered<T>(
  items: readonly T[],
  request: FixtureRequest,
  predicate: (item: T, q: URLSearchParams) => boolean,
) {
  return v0Page(
    items.filter((item) => predicate(item, request.query)),
    request.query,
  );
}
const flag = (q: URLSearchParams, name: string, value: boolean) =>
  !q.get(name) || q.get(name) === String(value);

/** Read-only scan settings, used only when no other fixture file (Settings, WP3) defines them. */
const SCAN_SETTINGS: SuccessBody<'ScanSettingsController_list_v1'> = {
  note: 'Tenant overrides apply to the next scan round; platform bounds always win.',
  data: [
    {
      engine: 'rspamd',
      platform: {
        spamScore: 6,
        suspiciousScore: 4,
        scoreMin: 1,
        scoreMax: 20,
        phishingVerdict: 'malicious',
        dmarcRejectVerdict: 'suspicious',
        authFailureVerdict: 'reason_only',
      },
      bounds: {
        spamScore: { min: 3, max: 15 },
        suspiciousScore: { min: 2, max: 12 },
        phishingVerdict: ['suspicious', 'malicious'],
        dmarcRejectVerdict: ['suspicious', 'malicious'],
        authFailureVerdict: ['reason_only', 'suspicious'],
      },
      override: { spamScore: 7 },
      effective: {
        spamScore: 7,
        suspiciousScore: 4,
        phishingVerdict: 'malicious',
        dmarcRejectVerdict: 'suspicious',
        authFailureVerdict: 'reason_only',
      },
      required: true,
      tenantMayDisable: false,
      overrideApplied: true,
      violations: [],
      version: 2,
      updatedAt: iso(15),
    },
  ],
};

const scanSettingsOwned =
  'ScanSettingsController_list_v1' in settingsFixtures ||
  'ScanSettingsController_list_v1' in urlProtectionFixtures ||
  'ScanSettingsController_list_v1' in attachmentFixtures;

export const fixtures: FixtureHandlers = {
  ...managementFixtures,
  ...toolFixtures,
  ...riskFixtures,
  AuditLogsController_search_v1: auditSearch,
  DlpPoliciesController_list_v1: guarded((request) =>
    ok(
      'DlpPoliciesController_list_v1',
      filtered(DLP_POLICIES, request, (p, q) => flag(q, 'enabled', p.enabled)),
    ),
  ),
  DlpPatternsController_list_v1: guarded((request) =>
    ok(
      'DlpPatternsController_list_v1',
      filtered(DLP_PATTERNS, request, (p, q) => flag(q, 'enabled', p.enabled)),
    ),
  ),
  DlpDictionariesController_list_v1: guarded((request) =>
    ok(
      'DlpDictionariesController_list_v1',
      filtered(DLP_DICTIONARIES, request, (p, q) => flag(q, 'enabled', p.enabled)),
    ),
  ),
  DlpExceptionsController_list_v1: guarded((request) =>
    ok(
      'DlpExceptionsController_list_v1',
      filtered(
        DLP_EXCEPTIONS,
        request,
        (e, q) => (!q.get('scope') || q.get('scope') === e.scope) && flag(q, 'active', !e.expired),
      ),
    ),
  ),
  DlpIncidentsController_list_v1: guarded((request) =>
    ok(
      'DlpIncidentsController_list_v1',
      filtered(
        DLP_INCIDENTS,
        request,
        (i, q) =>
          (!q.get('action') || q.get('action') === i.action) &&
          (!q.get('direction') || q.get('direction') === i.direction),
      ),
    ),
  ),
  DlpComplianceController_get_v1: guarded(() =>
    ok('DlpComplianceController_get_v1', DLP_COMPLIANCE),
  ),
  BecExecutivesController_list_v1: guarded((request) =>
    ok(
      'BecExecutivesController_list_v1',
      filtered(EXECUTIVES, request, (e, q) => flag(q, 'enabled', e.enabled)),
    ),
  ),
  BecVendorsController_list_v1: guarded((request) =>
    ok(
      'BecVendorsController_list_v1',
      filtered(VENDORS, request, (v, q) => flag(q, 'enabled', v.enabled)),
    ),
  ),
  BecTrustedSendersController_list_v1: guarded((request) =>
    ok(
      'BecTrustedSendersController_list_v1',
      filtered(TRUSTED, request, (t, q) => !q.get('kind') || q.get('kind') === t.kind),
    ),
  ),
  BecFeedbackController_list_v1: guarded((request) =>
    ok(
      'BecFeedbackController_list_v1',
      filtered(FEEDBACK, request, (f, q) => !q.get('kind') || q.get('kind') === f.kind),
    ),
  ),
  BecFeedbackController_listSuppressions_v1: guarded((request) =>
    ok(
      'BecFeedbackController_listSuppressions_v1',
      filtered(SUPPRESSIONS, request, (s, q) => flag(q, 'active', !s.expired)),
    ),
  ),
  ...(scanSettingsOwned
    ? {}
    : {
        ScanSettingsController_list_v1: (request: FixtureRequest) =>
          fixtureGuard(request) ?? ok('ScanSettingsController_list_v1', SCAN_SETTINGS),
      }),
};
