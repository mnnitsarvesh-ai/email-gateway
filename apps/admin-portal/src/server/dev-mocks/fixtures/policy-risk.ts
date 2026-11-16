import 'server-only';
import type { ListItem, RequestBody, SuccessBody } from '@/lib/api/types';
import { fixtureAnchor, stableUuid } from '../generator';
import { apiError, noContent, ok, type FixtureHandlers, type FixtureRequest } from '../types';
import {
  audit,
  FIXTURE_ADMIN_ID,
  idempotent,
  isRecord,
  policyOrg,
  sha256,
  type PolicyOrgState,
} from './policy-store';
import { withPrincipal } from './reports';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Risk-profile fixtures of dev fixture mode (step 7.3 design B13, B15): the platform profile
 * with its override bounds and hard-block catalogue (the values of `@email-gateway/risk-scoring`
 * `rsk-default/1`, transcribed; a few signals of the map), and per organization an in-memory
 * version store (published, active, draft) with row-version and profile-version compare-and-set,
 * immutable published versions, Idempotency-Key replays on publish/activate/reset and audit
 * rows. The bound checks below only exercise the editor's error mapping; nothing is scored.
 */

type PlatformView = SuccessBody<'RiskProfilesController_platformProfile_v1'>;
type EffectiveProfile = PlatformView['profile'];
type RiskVersion = SuccessBody<'RiskProfilesController_getVersion_v1'>;
type RiskVersionRow = ListItem<'RiskProfilesController_listVersions_v1'>;
type RiskProfile = SuccessBody<'RiskProfilesController_profile_v1'>;
type RiskViolation = { path: string; message: string };

const DAY = 86_400_000;
const anchor = fixtureAnchor();
const iso = (daysAgo: number) => new Date(anchor - daysAgo * DAY).toISOString();
const PLATFORM_ID = 'rsk-default/1';
const RISK_VERSION_LIMIT = 200;
const RESOURCE_VERSION = 'risk_scoring_profile_version';
const RESOURCE_PROFILE = 'risk_scoring_profile';

type RiskAction = 'deliver' | 'tag' | 'require_approval' | 'quarantine' | 'block';
const block = (enabled: boolean, action: RiskAction) => ({ enabled, action });

/** The shipped platform profile (`rsk-default/1`). */
export const PLATFORM_PROFILE: EffectiveProfile = {
  base: 'rsk-default/1',
  thresholds: { low: 100, medium: 300, high: 550, critical: 800 },
  actions: {
    none: 'deliver',
    low: 'deliver',
    medium: 'tag',
    high: 'quarantine',
    critical: 'quarantine',
  },
  groupMultipliersPermille: {
    auth_dmarc: 1000,
    auth_other: 1000,
    spam: 1000,
    reputation_ip: 1000,
    reputation_domain: 1000,
    url_threat: 1000,
    lookalike: 1000,
    credential: 1000,
    url_structure: 1000,
    phishing_content: 1000,
    attachment_malware: 1000,
    attachment_risky: 1000,
    bec_impersonation: 1000,
    bec_identity: 1000,
    bec_intent: 1000,
    bec_history: 1000,
    dlp: 1000,
    coverage: 1000,
    engine_failure: 1000,
    engine_unknown: 1000,
    sandbox: 1000,
  },
  hardBlocks: {
    'hb.malware_attachment': block(true, 'block'),
    'hb.malware_url': block(true, 'block'),
    'hb.malware_sandbox': block(true, 'quarantine'),
    'hb.dlp_block': block(true, 'block'),
    'hb.known_phishing': block(true, 'quarantine'),
    'hb.tenant_domain_spoof': block(true, 'quarantine'),
    'hb.url_tenant_blocked': block(true, 'quarantine'),
    'hb.bec_malicious': block(true, 'quarantine'),
    'hb.dmarc_reject': block(false, 'quarantine'),
  },
  failures: {
    engineFailureWeight: 300,
    groupCap: 600,
    unknownWeight: 60,
    minLevel: 'medium',
    unknownMinLevel: 'low',
    action: 'quarantine',
    unknownAction: 'tag',
  },
  floors: { engineMalicious: 'high', becSuspicious: 'low' },
  trust: { mode: 'reduce_content', contentFactorPermille: 500 },
  ai: { tagOnAiOnlyRaise: true },
};

const TUNABLE = [
  'auth_dmarc',
  'auth_other',
  'spam',
  'reputation_ip',
  'reputation_domain',
  'url_threat',
  'lookalike',
  'credential',
  'url_structure',
  'phishing_content',
  'attachment_risky',
  'bec_impersonation',
  'bec_identity',
  'bec_intent',
  'bec_history',
  'dlp',
  'coverage',
] as const;
const LOCKED = ['attachment_malware', 'engine_failure', 'engine_unknown', 'sandbox'] as const;

const range = (min: number, max: number) => ({ min, max });
const hb = (
  id: keyof EffectiveProfile['hardBlocks'],
  verdict: string,
  control: 'locked' | 'may_disable' | 'may_enable',
  allowedActions: RiskAction[],
  firesWhen: string,
): PlatformView['hardBlocks'][number] => ({
  id,
  verdict,
  defaultEnabled: PLATFORM_PROFILE.hardBlocks[id].enabled,
  defaultAction: PLATFORM_PROFILE.hardBlocks[id].action,
  control,
  allowedActions,
  firesWhen,
});

export const PLATFORM_VIEW: PlatformView = {
  id: PLATFORM_ID,
  sha256: sha256(PLATFORM_PROFILE),
  profile: PLATFORM_PROFILE,
  versions: { scorer: 'risk-score/1', signalMap: 'risk-signals/1', input: 'risk-input/1' },
  bounds: {
    thresholds: {
      low: range(50, 250),
      medium: range(200, 450),
      high: range(400, 700),
      critical: range(650, 950),
    },
    thresholdMinGap: 50,
    actions: {
      none: ['deliver'],
      low: ['deliver', 'tag'],
      medium: ['tag', 'require_approval', 'quarantine'],
      high: ['require_approval', 'quarantine', 'block'],
      critical: ['quarantine', 'block'],
    },
    groupMultiplierPermille: range(500, 2000),
    tunableGroups: [...TUNABLE],
    lockedGroups: [...LOCKED],
    failures: {
      engineFailureWeight: range(200, 600),
      groupCap: range(300, 1000),
      unknownWeight: range(30, 200),
      minLevel: ['medium', 'high', 'critical'],
      unknownMinLevel: ['low', 'medium', 'high'],
      action: ['require_approval', 'quarantine'],
      unknownAction: ['tag', 'require_approval', 'quarantine'],
    },
    floors: { engineMalicious: ['high', 'critical'], becSuspicious: ['low', 'medium', 'high'] },
    trustContentFactorPermille: range(250, 1000),
    raiseOnly: [
      'failures.minLevel',
      'failures.unknownMinLevel',
      'failures.action',
      'failures.unknownAction',
      'floors.engineMalicious',
      'floors.becSuspicious',
    ],
  },
  groups: [...TUNABLE, ...LOCKED].map((group) => ({
    group,
    rule: 'max' as const,
    cap: null,
    capFromProfile: false,
    verdict: group.startsWith('bec') ? 'bec' : group.startsWith('url') ? 'phishing' : 'suspicious',
    locked: (LOCKED as readonly string[]).includes(group),
  })),
  signals: [
    {
      id: 'auth_dmarc_reject',
      group: 'auth_dmarc',
      codes: ['rspamd:auth.dmarc_reject'],
      weight: 300,
      weightFrom: 'map',
      trustReducible: false,
      directions: ['inbound', 'internal'],
      source: 'code',
    },
    {
      id: 'url_known_phishing',
      group: 'url_threat',
      codes: ['url:url.feed_malicious', 'url:url.dnsbl_phishing'],
      weight: 800,
      weightFrom: 'map',
      trustReducible: false,
      directions: ['inbound', 'outbound', 'internal'],
      source: 'code',
    },
    {
      id: 'engine_failed_rspamd',
      group: 'engine_failure',
      codes: ['rspamd:status.failed', 'rspamd:status.missing'],
      weight: 300,
      weightFrom: 'failures.engineFailureWeight',
      trustReducible: false,
      directions: ['inbound', 'outbound', 'internal'],
      source: 'input',
    },
  ],
  hardBlocks: [
    hb(
      'hb.malware_attachment',
      'malware',
      'locked',
      ['block', 'quarantine'],
      'signal attachment_malware',
    ),
    hb('hb.malware_url', 'malware', 'locked', ['block', 'quarantine'], 'signal url_known_malware'),
    hb(
      'hb.malware_sandbox',
      'malware',
      'locked',
      ['block', 'quarantine'],
      'revision 1, sandbox outcome malicious',
    ),
    hb(
      'hb.dlp_block',
      'dlp_violation',
      'locked',
      ['block'],
      'dlp action block (changed only through the tenant DLP policy)',
    ),
    hb(
      'hb.known_phishing',
      'phishing',
      'may_disable',
      ['block', 'quarantine'],
      'signal url_known_phishing',
    ),
    hb(
      'hb.tenant_domain_spoof',
      'phishing',
      'may_disable',
      ['block', 'quarantine'],
      'inbound, signals auth_tenant_domain_spoof and auth_dmarc_reject',
    ),
    hb(
      'hb.url_tenant_blocked',
      'phishing',
      'may_disable',
      ['block', 'quarantine'],
      'signal url_tenant_blocked',
    ),
    hb(
      'hb.bec_malicious',
      'bec',
      'may_disable',
      ['block', 'quarantine'],
      'bec deterministicVerdict malicious',
    ),
    hb(
      'hb.dmarc_reject',
      'phishing',
      'may_enable',
      ['block', 'quarantine'],
      'inbound, signal auth_dmarc_reject (any sender domain)',
    ),
  ],
  notice:
    'Step 5.1 recommends and never enforces: policy (5.2) decides and quarantine (5.3) acts. The default weights and thresholds are engineering defaults calibrated on a synthetic dataset; they are not validated detection accuracy. A profile change applies to the next scan round only; open rounds and stored scores never change.',
};

// ---------------------------------------------------------------------------------------------
// Overrides: merge, canned bound checks
// ---------------------------------------------------------------------------------------------

const SECTIONS = [
  'thresholds',
  'actions',
  'groupMultipliersPermille',
  'hardBlocks',
  'failures',
  'floors',
  'trust',
  'ai',
] as const;

function mergeOverrides(overrides: Record<string, unknown>): EffectiveProfile {
  const out = JSON.parse(JSON.stringify(PLATFORM_PROFILE)) as Record<string, unknown>;
  const merge = (target: Record<string, unknown>, patch: Record<string, unknown>) => {
    for (const [key, value] of Object.entries(patch)) {
      const current = target[key];
      if (isRecord(current) && isRecord(value)) merge(current, value);
      else if (key in target) target[key] = value;
    }
  };
  merge(out, overrides);
  return out as unknown as EffectiveProfile;
}

/** Unknown keys and the threshold/multiplier/action bounds (the editor's 400 mapping). */
function checkOverrides(overrides: unknown): RiskViolation[] {
  if (!isRecord(overrides)) return [{ path: '$', message: 'must be an object' }];
  const v: RiskViolation[] = [];
  for (const key of Object.keys(overrides)) {
    if (!(SECTIONS as readonly string[]).includes(key))
      v.push({ path: key, message: 'unknown key' });
  }
  const merged = mergeOverrides(overrides);
  const b = PLATFORM_VIEW.bounds;
  const levels = Object.keys(b.thresholds) as Array<keyof typeof b.thresholds>;
  levels.forEach((level, i) => {
    const value = merged.thresholds[level];
    const { min, max } = b.thresholds[level];
    if (value < min || value > max) {
      v.push({ path: `thresholds.${level}`, message: `must be between ${min} and ${max}` });
    }
    const lower = levels[i - 1];
    if (lower && value - merged.thresholds[lower] < b.thresholdMinGap) {
      v.push({
        path: `thresholds.${level}`,
        message: `must exceed thresholds.${lower} by at least ${b.thresholdMinGap}`,
      });
    }
  });
  for (const level of Object.keys(b.actions) as Array<keyof typeof b.actions>) {
    if (!b.actions[level].includes(merged.actions[level])) {
      v.push({
        path: `actions.${level}`,
        message: `must be one of ${b.actions[level].join(', ')}`,
      });
    }
  }
  for (const group of b.tunableGroups) {
    const value = merged.groupMultipliersPermille[group];
    if (value < b.groupMultiplierPermille.min || value > b.groupMultiplierPermille.max) {
      v.push({
        path: `groupMultipliersPermille.${group}`,
        message: `must be between ${b.groupMultiplierPermille.min} and ${b.groupMultiplierPermille.max}`,
      });
    }
  }
  return v;
}

// ---------------------------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------------------------

interface StoredRiskVersion {
  id: string;
  versionNo: number;
  status: 'draft' | 'published';
  overrides: Record<string, unknown>;
  changeNote: string | null;
  rowVersion: number;
  createdBy: string | null;
  updatedBy: string | null;
  publishedBy: string | null;
  createdAt: string;
  updatedAt: string;
  publishedAt: string | null;
  deleted: boolean;
}

interface RiskState {
  id: string;
  profileVersion: number;
  activeVersionId: string | null;
  versions: StoredRiskVersion[];
  updatedAt: string | null;
  updatedBy: string | null;
}

const globalState = globalThis as typeof globalThis & {
  __egDevFixtureRisk?: Map<string, RiskState>;
};
const riskOrgs: Map<string, RiskState> = (globalState.__egDevFixtureRisk ??= new Map<
  string,
  RiskState
>());

function seedRisk(organizationId: string): RiskState {
  const version = (
    n: number,
    status: 'draft' | 'published',
    overrides: Record<string, unknown>,
    changeNote: string,
    daysAgo: number,
  ): StoredRiskVersion => ({
    id: stableUuid(`${organizationId}:risk-version:${n}`),
    versionNo: n,
    status,
    overrides,
    changeNote,
    rowVersion: status === 'published' ? 2 : 1,
    createdBy: FIXTURE_ADMIN_ID,
    updatedBy: FIXTURE_ADMIN_ID,
    publishedBy: status === 'published' ? FIXTURE_ADMIN_ID : null,
    createdAt: iso(daysAgo + 1),
    updatedAt: iso(daysAgo),
    publishedAt: status === 'published' ? iso(daysAgo) : null,
    deleted: false,
  });
  const versions = [
    version(
      1,
      'published',
      { groupMultipliersPermille: { url_threat: 1100 } },
      'Initial tenant profile',
      60,
    ),
    version(
      2,
      'published',
      {
        thresholds: { high: 500 },
        groupMultipliersPermille: { url_threat: 1200, bec_impersonation: 1100 },
      },
      'Stricter on links and impersonation',
      30,
    ),
    version(
      3,
      'draft',
      {
        thresholds: { high: 500 },
        actions: { critical: 'block' },
        groupMultipliersPermille: { url_threat: 1300, bec_impersonation: 1100 },
      },
      'Block critical risk',
      3,
    ),
  ];
  return {
    id: stableUuid(`${organizationId}:risk-profile`),
    profileVersion: 3,
    activeVersionId: versions[1]?.id ?? null,
    versions,
    updatedAt: iso(30),
    updatedBy: FIXTURE_ADMIN_ID,
  };
}

function riskOrg(organizationId: string): RiskState {
  let state = riskOrgs.get(organizationId);
  if (!state) {
    state = seedRisk(organizationId);
    riskOrgs.set(organizationId, state);
  }
  return state;
}

/** Test support: forget every organization's risk state. */
export function resetRiskStore(): void {
  riskOrgs.clear();
}

const live = (state: RiskState) =>
  state.versions.filter((v) => !v.deleted).sort((a, b) => b.versionNo - a.versionNo);

function versionView(state: RiskState, v: StoredRiskVersion): RiskVersion {
  const violations = checkOverrides(v.overrides);
  const effective = violations.length === 0 ? mergeOverrides(v.overrides) : PLATFORM_PROFILE;
  return {
    ...rowView(state, v),
    overrides: v.overrides,
    resolved: {
      valid: violations.length === 0,
      profileId: `${PLATFORM_ID}+t:${v.id}#${v.versionNo}`,
      sha256: sha256(effective),
      effectiveProfile: effective,
      violations,
    },
  };
}

function rowView(state: RiskState, v: StoredRiskVersion): RiskVersionRow {
  return {
    id: v.id,
    versionNo: v.versionNo,
    status: v.status,
    baseProfile: PLATFORM_ID,
    overridesSha256: sha256(v.overrides),
    profileSha256: v.status === 'published' ? sha256(mergeOverrides(v.overrides)) : null,
    changeNote: v.changeNote,
    rowVersion: v.rowVersion,
    active: state.activeVersionId === v.id,
    createdByUserId: v.createdBy,
    updatedByUserId: v.updatedBy,
    publishedByUserId: v.publishedBy,
    publishedAt: v.publishedAt,
    createdAt: v.createdAt,
    updatedAt: v.updatedAt,
  };
}

function profileView(state: RiskState): RiskProfile {
  const active = state.versions.find((v) => v.id === state.activeVersionId && !v.deleted) ?? null;
  const effective = active ? mergeOverrides(active.overrides) : PLATFORM_PROFILE;
  const versions = live(state);
  return {
    id: state.id,
    profileVersion: state.profileVersion,
    platformProfile: PLATFORM_ID,
    active: {
      source: active ? 'tenant' : 'platform',
      versionId: active?.id ?? null,
      versionNo: active?.versionNo ?? null,
      profileId: active ? `${PLATFORM_ID}+t:${active.id}#${active.versionNo}` : PLATFORM_ID,
      sha256: sha256(effective),
      fallback: null,
      violations: [],
    },
    effectiveProfile: effective,
    counts: {
      drafts: versions.filter((v) => v.status === 'draft').length,
      published: versions.filter((v) => v.status === 'published').length,
      limit: RISK_VERSION_LIMIT,
    },
    updatedByUserId: state.updatedBy,
    updatedAt: state.updatedAt,
  };
}

const notFound = () =>
  apiError(404, 'risk_profile_version_not_found', 'Risk profile version not found');
const invalid = (violations: RiskViolation[]) =>
  apiError(400, 'risk_profile_invalid', 'The risk profile overrides are invalid', { violations });
const rowConflict = (current: number) =>
  apiError(
    409,
    'risk_profile_version_conflict',
    'The risk profile changed since it was read; read it and retry',
    {
      currentRowVersion: current,
    },
  );
const profileConflict = (current: number) =>
  apiError(
    409,
    'risk_profile_version_conflict',
    'The risk profile changed since it was read; read it and retry',
    {
      currentProfileVersion: current,
    },
  );
const immutable = () =>
  apiError(
    409,
    'risk_profile_version_immutable',
    'The risk profile version is published and immutable; create a new draft',
  );

function bodyOf(request: FixtureRequest): Record<string, unknown> {
  return isRecord(request.body) ? request.body : {};
}

function find(state: RiskState, id: string | undefined) {
  return state.versions.find((v) => v.id === id && !v.deleted) ?? null;
}

function paginate<T>(items: readonly T[], query: URLSearchParams) {
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

const recordAudit = (
  org: PolicyOrgState,
  actor: string,
  action: string,
  resourceType: string,
  resourceId: string,
  metadata: Record<string, unknown>,
) => audit(org, actor, action, resourceType, resourceId, metadata);

export const riskFixtures: FixtureHandlers = {
  RiskProfilesController_platformProfile_v1: (request) =>
    withPrincipal(request, () => ok('RiskProfilesController_platformProfile_v1', PLATFORM_VIEW)),

  RiskProfilesController_profile_v1: (request) =>
    withPrincipal(request, (p) =>
      ok('RiskProfilesController_profile_v1', profileView(riskOrg(p.organizationId))),
    ),

  RiskProfilesController_listVersions_v1: (request) =>
    withPrincipal(request, (p) => {
      const state = riskOrg(p.organizationId);
      const status = request.query.get('status');
      const rows = live(state)
        .filter((v) => !status || v.status === status)
        .map((v) => rowView(state, v));
      return ok('RiskProfilesController_listVersions_v1', paginate(rows, request.query));
    }),

  RiskProfilesController_getVersion_v1: (request) =>
    withPrincipal(request, (p) => {
      const state = riskOrg(p.organizationId);
      const version = find(state, request.params.versionId);
      return version
        ? ok('RiskProfilesController_getVersion_v1', versionView(state, version))
        : notFound();
    }),

  RiskProfilesController_createDraft_v1: (request) =>
    withPrincipal(request, (p) => {
      const state = riskOrg(p.organizationId);
      const body = bodyOf(request) as Partial<RequestBody<'RiskProfilesController_createDraft_v1'>>;
      let overrides: Record<string, unknown> = isRecord(body.overrides) ? body.overrides : {};
      if (body.basedOnVersionId) {
        const source = find(state, body.basedOnVersionId);
        if (!source) return notFound();
        overrides = JSON.parse(JSON.stringify(source.overrides)) as Record<string, unknown>;
      }
      const violations = checkOverrides(overrides);
      if (violations.length > 0) return invalid(violations);
      if (live(state).length >= RISK_VERSION_LIMIT) {
        return apiError(
          409,
          'risk_profile_limit_reached',
          'The organization reached its limit of risk profile versions',
          {
            limit: RISK_VERSION_LIMIT,
          },
        );
      }
      const now = new Date().toISOString();
      const versionNo = Math.max(0, ...state.versions.map((v) => v.versionNo)) + 1;
      const version: StoredRiskVersion = {
        id: stableUuid(`${p.organizationId}:risk-version:${versionNo}:${now}`),
        versionNo,
        status: 'draft',
        overrides,
        changeNote: typeof body.changeNote === 'string' ? body.changeNote : null,
        rowVersion: 1,
        createdBy: p.userId,
        updatedBy: p.userId,
        publishedBy: null,
        createdAt: now,
        updatedAt: now,
        publishedAt: null,
        deleted: false,
      };
      state.versions.push(version);
      recordAudit(
        policyOrg(p.organizationId),
        p.userId,
        'risk_profile.draft_created',
        RESOURCE_VERSION,
        version.id,
        {
          versionNo,
          rowVersion: 1,
        },
      );
      return ok('RiskProfilesController_createDraft_v1', versionView(state, version), 201);
    }),

  RiskProfilesController_updateDraft_v1: (request) =>
    withPrincipal(request, (p) => {
      const state = riskOrg(p.organizationId);
      const version = find(state, request.params.versionId);
      if (!version) return notFound();
      const body = bodyOf(request) as Partial<RequestBody<'RiskProfilesController_updateDraft_v1'>>;
      if (version.status !== 'draft') return immutable();
      if (body.expectedRowVersion !== version.rowVersion) return rowConflict(version.rowVersion);
      const overrides = isRecord(body.overrides) ? body.overrides : {};
      const violations = checkOverrides(overrides);
      if (violations.length > 0) return invalid(violations);
      version.overrides = overrides;
      if (body.changeNote !== undefined) version.changeNote = body.changeNote ?? null;
      version.rowVersion += 1;
      version.updatedAt = new Date().toISOString();
      version.updatedBy = p.userId;
      recordAudit(
        policyOrg(p.organizationId),
        p.userId,
        'risk_profile.draft_updated',
        RESOURCE_VERSION,
        version.id,
        {
          versionNo: version.versionNo,
          rowVersion: version.rowVersion,
        },
      );
      return ok('RiskProfilesController_updateDraft_v1', versionView(state, version));
    }),

  RiskProfilesController_deleteDraft_v1: (request) =>
    withPrincipal(request, (p) => {
      const state = riskOrg(p.organizationId);
      const version = find(state, request.params.versionId);
      if (!version) return notFound();
      if (version.status !== 'draft') return immutable();
      const expected = request.query.get('expectedRowVersion');
      if (expected !== null && Number(expected) !== version.rowVersion) {
        return rowConflict(version.rowVersion);
      }
      version.deleted = true;
      recordAudit(
        policyOrg(p.organizationId),
        p.userId,
        'risk_profile.draft_deleted',
        RESOURCE_VERSION,
        version.id,
        {
          versionNo: version.versionNo,
        },
      );
      return noContent();
    }),

  RiskProfilesController_publish_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = policyOrg(p.organizationId);
      return idempotent(org, request, () => {
        const state = riskOrg(p.organizationId);
        const version = find(state, request.params.versionId);
        if (!version) return notFound();
        const body = bodyOf(request) as Partial<RequestBody<'RiskProfilesController_publish_v1'>>;
        if (version.status !== 'draft') return immutable();
        if (body.expectedRowVersion !== version.rowVersion) return rowConflict(version.rowVersion);
        const violations = checkOverrides(version.overrides);
        if (violations.length > 0) return invalid(violations);
        const now = new Date().toISOString();
        version.status = 'published';
        version.rowVersion += 1;
        version.publishedAt = now;
        version.publishedBy = p.userId;
        version.updatedAt = now;
        if (body.activate !== false) {
          state.activeVersionId = version.id;
          state.profileVersion += 1;
          state.updatedAt = now;
          state.updatedBy = p.userId;
        }
        recordAudit(org, p.userId, 'risk_profile.published', RESOURCE_VERSION, version.id, {
          versionNo: version.versionNo,
          activated: body.activate !== false,
        });
        return ok('RiskProfilesController_publish_v1', {
          version: versionView(state, version),
          profile: profileView(state),
        });
      });
    }),

  RiskProfilesController_activate_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = policyOrg(p.organizationId);
      return idempotent(org, request, () => {
        const state = riskOrg(p.organizationId);
        const version = find(state, request.params.versionId);
        if (!version) return notFound();
        const body = bodyOf(request) as Partial<RequestBody<'RiskProfilesController_activate_v1'>>;
        if (
          body.expectedProfileVersion !== undefined &&
          body.expectedProfileVersion !== state.profileVersion
        ) {
          return profileConflict(state.profileVersion);
        }
        if (version.status !== 'published') {
          return apiError(
            409,
            'risk_profile_version_not_published',
            'Only a published version can be activated',
          );
        }
        if (state.activeVersionId !== version.id) {
          const previous = state.versions.find((v) => v.id === state.activeVersionId) ?? null;
          state.activeVersionId = version.id;
          state.profileVersion += 1;
          state.updatedAt = new Date().toISOString();
          state.updatedBy = p.userId;
          recordAudit(org, p.userId, 'risk_profile.activated', RESOURCE_VERSION, version.id, {
            versionNo: version.versionNo,
            previousVersionNo: previous?.versionNo ?? null,
          });
        }
        return ok('RiskProfilesController_activate_v1', profileView(state));
      });
    }),

  RiskProfilesController_reset_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = policyOrg(p.organizationId);
      return idempotent(org, request, () => {
        const state = riskOrg(p.organizationId);
        const body = bodyOf(request) as Partial<RequestBody<'RiskProfilesController_reset_v1'>>;
        if (
          body.expectedProfileVersion !== undefined &&
          body.expectedProfileVersion !== state.profileVersion
        ) {
          return profileConflict(state.profileVersion);
        }
        if (state.activeVersionId !== null) {
          state.activeVersionId = null;
          state.profileVersion += 1;
          state.updatedAt = new Date().toISOString();
          state.updatedBy = p.userId;
          recordAudit(org, p.userId, 'risk_profile.reset', RESOURCE_PROFILE, state.id, {
            profileVersion: state.profileVersion,
          });
        }
        return ok('RiskProfilesController_reset_v1', profileView(state));
      });
    }),
};
