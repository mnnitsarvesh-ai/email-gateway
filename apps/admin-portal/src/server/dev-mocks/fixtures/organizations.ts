import 'server-only';
import type { SuccessBody } from '@/lib/api/types';
import { SeededRandom, fixtureAnchor, hashString, paginate, stableUuid } from '../generator';
import { apiError, noContent, ok, type FixtureHandlers, type FixtureRequest } from '../types';
import { bodyOf, withPrincipal, type Principal, str } from './reports';
import { CUSTOMER_ORGS, PLATFORM_ORG } from './session';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Organization catalogue, configuration, usage and deletion fixtures (WP3). Replaces the
 * tenant-switcher fixtures of `session.ts` with a mutable catalogue on globalThis (every
 * `next dev` route bundle shares it). Deletion follows the four-eyes rule by role: the role that
 * requested a deletion cannot confirm it (sign in as `platform_admin` to confirm a
 * `super_admin` request).
 */

type Organization = SuccessBody<'OrganizationsController_get_v1'>;
type Settings = SuccessBody<'OrganizationConfigurationController_getSettings_v1'>;
type Feature = SuccessBody<'OrganizationConfigurationController_listFeatures_v1'>['data'][number];
type Limit = SuccessBody<'OrganizationConfigurationController_listLimits_v1'>['data'][number];
type Deletion = SuccessBody<'OrganizationDeletionController_get_v1'>;

export const PLANS: Record<
  string,
  {
    name: string;
    description: string;
    limits: Record<string, number>;
    features: Record<string, boolean>;
  }
> = {
  starter: {
    name: 'Starter',
    description: 'Gateway filtering for small teams.',
    limits: {
      max_users: 25,
      max_domains: 2,
      messages_per_day: 5_000,
      quarantine_retention_days: 30,
      api_requests_per_minute: 60,
    },
    features: {
      inbound_filtering: true,
      outbound_filtering: false,
      url_rewriting: true,
      attachment_sandbox: false,
      dlp: false,
      webhooks: false,
      api_access: true,
      sso: false,
    },
  },
  business: {
    name: 'Business',
    description: 'Inbound and outbound protection with DLP and webhooks.',
    limits: {
      max_users: 250,
      max_domains: 10,
      messages_per_day: 50_000,
      quarantine_retention_days: 90,
      api_requests_per_minute: 300,
    },
    features: {
      inbound_filtering: true,
      outbound_filtering: true,
      url_rewriting: true,
      attachment_sandbox: false,
      dlp: true,
      webhooks: true,
      api_access: true,
      sso: false,
    },
  },
  enterprise: {
    name: 'Enterprise',
    description: 'Every engine, the sandbox and archiving.',
    limits: {
      max_users: 5_000,
      max_domains: 100,
      messages_per_day: 1_000_000,
      quarantine_retention_days: 365,
      api_requests_per_minute: 1_200,
    },
    features: {
      inbound_filtering: true,
      outbound_filtering: true,
      url_rewriting: true,
      attachment_sandbox: true,
      dlp: true,
      webhooks: true,
      api_access: true,
      sso: false,
      archiving: true,
    },
  },
};

interface OrgState {
  orgs: Map<string, Organization>;
  settings: Map<string, Settings>;
  features: Map<string, Map<string, Feature>>;
  limits: Map<string, Map<string, Limit>>;
  deletions: Map<string, Deletion & { requestedRole?: string }>;
}

const anchor = fixtureAnchor();
const store = globalThis as typeof globalThis & { __egDevFixtureOrgState?: OrgState };

function seedEntitlements(state: OrgState, org: Organization): void {
  const plan = PLANS[org.plan.code] ?? PLANS.business!;
  const at = org.createdAt;
  state.features.set(
    org.id,
    new Map(
      Object.entries(plan.features).map(([key, enabled]) => [
        key,
        { key, enabled, config: null, source: 'plan' as const, updatedAt: at },
      ]),
    ),
  );
  state.limits.set(
    org.id,
    new Map(
      Object.entries(plan.limits).map(([key, value]) => [
        key,
        { key, value, source: 'plan' as const, updatedAt: at },
      ]),
    ),
  );
}

function defaultSettings(org: Organization): Settings {
  return {
    organizationId: org.id,
    timezone: 'UTC',
    locale: 'en-GB',
    quarantineRetentionDays: 30,
    quarantineRetentionMaxDays:
      (PLANS[org.plan.code] ?? PLANS.business!).limits.quarantine_retention_days ?? 90,
    digestEnabled: true,
    digestSchedule: '0 8 * * 1-5',
    notificationEmail: org.kind === 'platform' ? null : `security@${org.slug}.example.test`,
    mfaRequired: org.kind === 'platform',
    preferences: {},
    updatedAt: org.updatedAt,
  };
}

export function orgState(): OrgState {
  if (store.__egDevFixtureOrgState) return store.__egDevFixtureOrgState;
  const state: OrgState = {
    orgs: new Map(),
    settings: new Map(),
    features: new Map(),
    limits: new Map(),
    deletions: new Map(),
  };
  const all = [PLATFORM_ORG, ...CUSTOMER_ORGS].map((o) => structuredClone(o));
  // Variety for the catalogue filters: a suspended tenant, a dedicated one, one pending deletion.
  const t5 = all.find((o) => o.slug === 'tenant-05');
  if (t5)
    Object.assign(t5, {
      status: 'suspended',
      statusReason: 'Unpaid invoices (synthetic)',
      statusChangedAt: new Date(anchor - 3 * 86_400_000).toISOString(),
    });
  const charlie = all.find((o) => o.slug === 'charlie');
  if (charlie) {
    charlie.deploymentMode = 'dedicated';
    charlie.dataRegion = 'ap-south-1';
    charlie.deployments = [
      {
        deploymentMode: 'dedicated',
        region: 'ap-south-1',
        environment: 'prod',
        status: 'provisioning',
        endpointHostname: null,
        mxHostname: null,
        releaseVersion: null,
        provisionedAt: null,
        createdAt: charlie.createdAt,
      },
    ];
  }
  for (const org of all) {
    if (org.deployments.length === 0)
      org.deployments = [
        {
          deploymentMode: 'saas',
          region: org.dataRegion,
          environment: 'prod',
          status: 'active',
          endpointHostname: null,
          mxHostname: 'mx.gateway.example.test',
          releaseVersion: '1.7.0',
          provisionedAt: org.createdAt,
          createdAt: org.createdAt,
        },
      ];
    state.orgs.set(org.id, org);
    state.settings.set(org.id, defaultSettings(org));
    seedEntitlements(state, org);
  }
  const t9 = all.find((o) => o.slug === 'tenant-09');
  if (t9) {
    const requestedAt = new Date(anchor - 2 * 3_600_000).toISOString();
    t9.status = 'pending_deletion';
    t9.deletion = {
      state: 'pending_deletion',
      requestedAt,
      reason: 'Contract ended (synthetic)',
      confirmedAt: null,
      purgeAfter: null,
    };
    state.deletions.set(t9.id, {
      organizationId: t9.id,
      status: 'pending_deletion',
      state: 'pending_deletion',
      requestedAt,
      requestedBy: stableUuid('user:super_admin@example.com'),
      reason: 'Contract ended (synthetic)',
      confirmationDeadline: new Date(anchor + 22 * 3_600_000).toISOString(),
      confirmedAt: null,
      confirmedBy: null,
      purgeAfter: null,
      cancellable: true,
      requestedRole: 'super_admin',
    });
  }
  store.__egDevFixtureOrgState = state;
  return state;
}

const isPlatform = (p: Principal) => p.permissions.includes('platform:organizations');

/** The organization when the caller may see it (platform: any; others: their own), else 404. */
function visibleOrg(request: FixtureRequest, p: Principal): Organization | null {
  const org = orgState().orgs.get(request.params.id ?? '');
  if (!org) return null;
  return isPlatform(p) || org.id === p.organizationId ? org : null;
}

const notFound = () => apiError(404, 'organization_not_found', 'Organization not found');
const now = () => new Date().toISOString();

function deletionView(org: Organization): Deletion {
  const d = orgState().deletions.get(org.id);
  if (d) {
    const { requestedRole: _ignored, ...view } = d;
    return { ...view, status: org.status };
  }
  return {
    organizationId: org.id,
    status: org.status,
    state: 'none',
    requestedAt: null,
    requestedBy: null,
    reason: null,
    confirmationDeadline: null,
    confirmedAt: null,
    confirmedBy: null,
    purgeAfter: null,
    cancellable: false,
  };
}

/** Usage of an organization (shared with `GET /usage` in billing.ts). */
export function usageOf(org: Organization, request: FixtureRequest) {
  const to = request.query.get('to')
    ? Date.parse(request.query.get('to') ?? '')
    : anchor + 3_600_000;
  const from = request.query.get('from')
    ? Date.parse(request.query.get('from') ?? '')
    : to - 30 * 86_400_000;
  if (!Number.isFinite(from) || !Number.isFinite(to) || from >= to)
    return apiError(400, 'validation_failed', ['from: must be before to']);
  if (to - from > 31 * 86_400_000)
    return apiError(400, 'validation_failed', ['from: at most 31 days']);
  const r = new SeededRandom(hashString(`usage:${org.id}`));
  const days = Math.round((to - from) / 86_400_000);
  const empty = org.slug === 'bravo';
  const inbound = empty ? 0 : r.int(700, 1100) * days;
  const outbound = empty ? 0 : r.int(150, 300) * days;
  const internal = empty ? 0 : r.int(20, 60) * days;
  const users = {
    total: r.int(20, 60),
    active: 0,
    invited: r.int(0, 4),
    disabled: r.int(0, 2),
    locked: r.int(0, 1),
  };
  users.active = users.total - users.invited - users.disabled - users.locked;
  const today = empty ? 0 : r.int(300, 1500);
  const limits = [...(orgState().limits.get(org.id)?.values() ?? [])].map((l) => ({
    key: l.key,
    value: l.value,
    source: l.source,
    used:
      l.key === 'max_users'
        ? users.total
        : l.key === 'max_domains'
          ? 3
          : l.key === 'messages_per_day'
            ? today
            : null,
  }));
  return ok('OrganizationsController_getUsage_v1', {
    organizationId: org.id,
    period: { from: new Date(from).toISOString(), to: new Date(to).toISOString() },
    users,
    domains: { total: 3, verified: 3, pendingVerification: 0, active: 3, suspended: 0 },
    messages: { total: inbound + outbound + internal, inbound, outbound, internal, today },
    quarantine: { active: empty ? 0 : r.int(5, 40) },
    apiKeys: { active: r.int(0, 3) },
    sessions: { active: r.int(1, 12) },
    limits,
  });
}

const SLUG = /^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$/;

export const fixtures: FixtureHandlers = {
  OrganizationsController_list_v1: (request) =>
    withPrincipal(request, (p) => {
      const q = request.query.get('q')?.toLowerCase();
      const status = request.query.get('status');
      const kind = request.query.get('kind');
      const planCode = request.query.get('planCode');
      const mode = request.query.get('deploymentMode');
      const all = [...orgState().orgs.values()].filter(
        (o) => isPlatform(p) || o.id === p.organizationId,
      );
      const rows = all.filter(
        (o) =>
          (!q || o.name.toLowerCase().startsWith(q) || o.slug.startsWith(q)) &&
          (status ? o.status === status : o.status !== 'deleted') &&
          (!kind || o.kind === kind) &&
          (!planCode || o.plan.code === planCode) &&
          (!mode || o.deploymentMode === mode),
      );
      return { status: 200, body: paginate(rows, request.query) };
    }),

  OrganizationsController_get_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = visibleOrg(request, p);
      return org ? ok('OrganizationsController_get_v1', org) : notFound();
    }),

  OrganizationsController_create_v1: (request) =>
    withPrincipal(request, () => {
      const b = bodyOf(request);
      const slug = str(b, 'slug', '');
      const planCode = str(b, 'planCode', '');
      if (!SLUG.test(slug) || ['platform', 'admin', 'api', 'www', 'system'].includes(slug))
        return apiError(400, 'validation_failed', ['slug: invalid or reserved']);
      if (!PLANS[planCode])
        return apiError(400, 'plan_not_found', `Unknown or inactive plan ${planCode}`);
      const state = orgState();
      if ([...state.orgs.values()].some((o) => o.slug === slug))
        return apiError(
          409,
          'organization_slug_exists',
          'An organization with this slug already exists',
        );
      const dedicated = b.deploymentMode === 'dedicated';
      const deployment =
        b.deployment && typeof b.deployment === 'object'
          ? (b.deployment as { region?: string; environment?: string })
          : null;
      if (dedicated && !deployment)
        return apiError(400, 'validation_failed', [
          'deployment: required for dedicated organizations',
        ]);
      const createdAt = now();
      const org: Organization = {
        id: crypto.randomUUID(),
        slug,
        name: str(b, 'name', slug),
        kind: 'customer',
        status: 'active',
        statusReason: null,
        statusChangedAt: null,
        plan: { code: planCode, name: PLANS[planCode].name },
        deploymentMode: dedicated ? 'dedicated' : 'saas',
        dataRegion: str(b, 'dataRegion', 'eu-west-1'),
        deployments: [
          {
            deploymentMode: dedicated ? 'dedicated' : 'saas',
            region: deployment?.region ?? str(b, 'dataRegion', 'eu-west-1'),
            environment: deployment?.environment ?? 'prod',
            status: dedicated ? 'provisioning' : 'active',
            endpointHostname: null,
            mxHostname: dedicated ? null : 'mx.gateway.example.test',
            releaseVersion: null,
            provisionedAt: dedicated ? null : createdAt,
            createdAt,
          },
        ],
        deletion: null,
        createdAt,
        updatedAt: createdAt,
      };
      state.orgs.set(org.id, org);
      state.settings.set(org.id, defaultSettings(org));
      seedEntitlements(state, org);
      const admin = b.initialAdmin as { email?: string } | undefined;
      return ok(
        'OrganizationsController_create_v1',
        {
          ...org,
          initialAdmin: admin?.email
            ? {
                id: crypto.randomUUID(),
                email: admin.email,
                status: 'invited',
                invitationExpiresAt: new Date(Date.now() + 7 * 86_400_000).toISOString(),
                invitationSent: true,
              }
            : null,
        },
        201,
      );
    }),

  OrganizationsController_update_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = visibleOrg(request, p);
      if (!org) return notFound();
      if (!isPlatform(p) && !p.permissions.includes('organization:manage'))
        return apiError(403, 'forbidden', 'Forbidden');
      if (org.status === 'pending_deletion' || org.status === 'deleted')
        return apiError(
          409,
          'organization_pending_deletion',
          'The organization is pending deletion',
        );
      const b = bodyOf(request);
      if (b.planCode !== undefined) {
        if (!isPlatform(p))
          return apiError(403, 'forbidden', 'Changing the plan needs platform:organizations');
        const plan = PLANS[str(b, 'planCode')];
        if (!plan) return apiError(400, 'plan_not_found', 'Unknown plan');
        org.plan = { code: str(b, 'planCode'), name: plan.name };
        seedEntitlements(orgState(), org);
      }
      org.name = str(b, 'name', org.name);
      org.updatedAt = now();
      return ok('OrganizationsController_update_v1', org);
    }),

  OrganizationsController_changeStatus_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = visibleOrg(request, p);
      if (!org) return notFound();
      const b = bodyOf(request);
      if (org.kind === 'platform')
        return apiError(
          409,
          'organization_status_conflict',
          'The platform organization cannot be suspended',
        );
      if (b.status === 'suspended' && !b.reason)
        return apiError(400, 'validation_failed', ['reason: required to suspend']);
      if (org.status !== 'active' && org.status !== 'suspended')
        return apiError(
          409,
          'organization_status_conflict',
          'Only active and suspended organizations change status',
        );
      org.status = b.status === 'suspended' ? 'suspended' : 'active';
      org.statusReason = typeof b.reason === 'string' ? b.reason : null;
      org.statusChangedAt = now();
      org.updatedAt = org.statusChangedAt;
      return ok('OrganizationsController_changeStatus_v1', org);
    }),

  OrganizationsController_getUsage_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = visibleOrg(request, p);
      return org ? usageOf(org, request) : notFound();
    }),

  OrganizationConfigurationController_getSettings_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = visibleOrg(request, p);
      return org
        ? ok('OrganizationConfigurationController_getSettings_v1', orgState().settings.get(org.id)!)
        : notFound();
    }),

  OrganizationConfigurationController_updateSettings_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = visibleOrg(request, p);
      if (!org) return notFound();
      const current = orgState().settings.get(org.id)!;
      const b = bodyOf(request);
      if (Object.keys(b).length === 0)
        return apiError(400, 'validation_failed', ['(root): give at least one field']);
      if (
        typeof b.quarantineRetentionDays === 'number' &&
        current.quarantineRetentionMaxDays !== null &&
        b.quarantineRetentionDays > current.quarantineRetentionMaxDays
      )
        return apiError(400, 'validation_failed', [
          `quarantineRetentionDays: at most ${current.quarantineRetentionMaxDays}`,
        ]);
      if (typeof b.timezone === 'string') {
        try {
          new Intl.DateTimeFormat('en', { timeZone: b.timezone });
        } catch {
          return apiError(400, 'validation_failed', ['timezone: unknown IANA time zone']);
        }
      }
      const next = {
        ...current,
        ...(b as Partial<Settings>),
        organizationId: org.id,
        updatedAt: now(),
      };
      orgState().settings.set(org.id, next);
      return ok('OrganizationConfigurationController_updateSettings_v1', next);
    }),

  OrganizationConfigurationController_listFeatures_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = visibleOrg(request, p);
      return org
        ? ok('OrganizationConfigurationController_listFeatures_v1', {
            organizationId: org.id,
            data: [...orgState().features.get(org.id)!.values()],
          })
        : notFound();
    }),

  OrganizationConfigurationController_overrideFeature_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = visibleOrg(request, p);
      if (!org) return notFound();
      const key = request.params.featureKey ?? '';
      const feature: Feature = {
        key,
        enabled: bodyOf(request).enabled === true,
        config: null,
        source: 'override',
        updatedAt: now(),
      };
      orgState().features.get(org.id)!.set(key, feature);
      return ok('OrganizationConfigurationController_overrideFeature_v1', feature);
    }),

  OrganizationConfigurationController_resetFeature_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = visibleOrg(request, p);
      if (!org) return notFound();
      const key = request.params.featureKey ?? '';
      const planValue = (PLANS[org.plan.code] ?? PLANS.business!).features[key];
      const map = orgState().features.get(org.id)!;
      if (planValue === undefined) map.delete(key);
      else
        map.set(key, { key, enabled: planValue, config: null, source: 'plan', updatedAt: now() });
      return noContent();
    }),

  OrganizationConfigurationController_listLimits_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = visibleOrg(request, p);
      return org
        ? ok('OrganizationConfigurationController_listLimits_v1', {
            organizationId: org.id,
            data: [...orgState().limits.get(org.id)!.values()],
          })
        : notFound();
    }),

  OrganizationConfigurationController_overrideLimit_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = visibleOrg(request, p);
      if (!org) return notFound();
      const value = bodyOf(request).value;
      if (typeof value !== 'number' || !Number.isInteger(value) || value < 0)
        return apiError(400, 'validation_failed', ['value: a non-negative integer']);
      const key = request.params.limitKey ?? '';
      const limit: Limit = { key, value, source: 'override', updatedAt: now() };
      orgState().limits.get(org.id)!.set(key, limit);
      return ok('OrganizationConfigurationController_overrideLimit_v1', limit);
    }),

  OrganizationConfigurationController_resetLimit_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = visibleOrg(request, p);
      if (!org) return notFound();
      const key = request.params.limitKey ?? '';
      const planValue = (PLANS[org.plan.code] ?? PLANS.business!).limits[key];
      const map = orgState().limits.get(org.id)!;
      if (planValue === undefined) map.delete(key);
      else map.set(key, { key, value: planValue, source: 'plan', updatedAt: now() });
      return noContent();
    }),

  OrganizationDeletionController_get_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = visibleOrg(request, p);
      return org ? ok('OrganizationDeletionController_get_v1', deletionView(org)) : notFound();
    }),

  OrganizationDeletionController_request_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = visibleOrg(request, p);
      if (!org) return notFound();
      const b = bodyOf(request);
      if (b.confirmSlug !== org.slug)
        return apiError(400, 'validation_failed', [
          'confirmSlug: does not match the organization slug',
        ]);
      if (org.kind === 'platform' || orgState().deletions.has(org.id))
        return apiError(
          409,
          'organization_deletion_conflict',
          'A deletion is already requested or not allowed',
        );
      const requestedAt = now();
      org.status = 'pending_deletion';
      org.deletion = {
        state: 'pending_deletion',
        requestedAt,
        reason: str(b, 'reason', ''),
        confirmedAt: null,
        purgeAfter: null,
      };
      orgState().deletions.set(org.id, {
        organizationId: org.id,
        status: 'pending_deletion',
        state: 'pending_deletion',
        requestedAt,
        requestedBy: stableUuid(`user:${p.role}@example.com`),
        reason: str(b, 'reason', ''),
        confirmationDeadline: new Date(Date.now() + 24 * 3_600_000).toISOString(),
        confirmedAt: null,
        confirmedBy: null,
        purgeAfter: null,
        cancellable: true,
        requestedRole: p.role,
      });
      return ok('OrganizationDeletionController_request_v1', deletionView(org));
    }),

  OrganizationDeletionController_confirm_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = visibleOrg(request, p);
      if (!org) return notFound();
      const d = orgState().deletions.get(org.id);
      if (!d || d.state !== 'pending_deletion')
        return apiError(409, 'organization_deletion_conflict', 'No deletion is pending');
      if (bodyOf(request).confirmSlug !== org.slug)
        return apiError(400, 'validation_failed', [
          'confirmSlug: does not match the organization slug',
        ]);
      if (d.requestedRole === p.role)
        return apiError(
          403,
          'forbidden',
          'The deletion must be confirmed by a different platform user',
        );
      const confirmedAt = now();
      const purgeAfter = new Date(Date.now() + 30 * 86_400_000).toISOString();
      Object.assign(d, {
        state: 'deleted',
        status: 'deleted',
        confirmedAt,
        confirmedBy: stableUuid(`user:${p.role}@example.com`),
        purgeAfter,
        cancellable: true,
      });
      org.status = 'deleted';
      org.deletion = {
        state: 'deleted',
        requestedAt: d.requestedAt ?? confirmedAt,
        reason: d.reason,
        confirmedAt,
        purgeAfter,
      };
      return ok('OrganizationDeletionController_confirm_v1', deletionView(org));
    }),

  OrganizationDeletionController_cancel_v1: (request) =>
    withPrincipal(request, (p) => {
      const org = visibleOrg(request, p);
      if (!org) return notFound();
      if (!orgState().deletions.has(org.id))
        return apiError(409, 'organization_deletion_conflict', 'No deletion to cancel');
      orgState().deletions.delete(org.id);
      org.status = 'suspended';
      org.statusReason = str(bodyOf(request), 'reason', 'Deletion cancelled');
      org.statusChangedAt = now();
      org.deletion = null;
      return ok('OrganizationDeletionController_cancel_v1', deletionView(org));
    }),
};
