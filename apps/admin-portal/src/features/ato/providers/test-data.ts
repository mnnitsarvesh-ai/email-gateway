import {
  PROVIDER_ACTIONS,
  defaultBindingSettings,
  type MailboxItem,
  type MailboxState,
  type ProviderCandidate,
  type ProviderConnections,
  type ProviderDetail,
  type ProviderKind,
  type ProviderList,
  type ProviderProfileView,
  type ProviderSummary,
} from './model';
import { REQUIREMENTS } from './requirements.data';

/**
 * Builders of the identity-provider pages (typed against schema.gen.ts), shared by the component
 * tests and the dev fixtures. Names carry "EXAMPLE", domains are reserved example names, ids are
 * well-formed placeholders; nothing is real.
 */

export const INTEGRATION_ID = '0193c1a0-aaaa-7a00-8000-000000000001';
export const GOOGLE_INTEGRATION_ID = '0193c1a0-aaaa-7a00-8000-000000000002';
export const CONNECTION_ID = '0193c1a0-bbbb-7a00-8000-000000000001';
export const GOOGLE_CONNECTION_ID = '0193c1a0-bbbb-7a00-8000-000000000002';
export const SPARE_CONNECTION_ID = '0193c1a0-bbbb-7a00-8000-000000000003';
export const GRANT_ID = '0193c1a0-cccc-7a00-8000-000000000001';
export const RULE_ITEM_ID = '0193c1a0-dddd-7a00-8000-000000000001';
export const FORWARDING_ITEM_ID = '0193c1a0-dddd-7a00-8000-000000000002';

const T = '2026-11-20T09:00:00.000Z';
const T_MINUS = (minutes: number) => new Date(Date.parse(T) - minutes * 60_000).toISOString();

export function requirementOf(kind: ProviderKind) {
  const found = REQUIREMENTS.providers.find((p) => p.provider === kind);
  if (!found) throw new Error(`no requirements for ${kind}`);
  return found;
}

/** Profile views of a provider: every permission granted unless listed in `missing`. */
export function profilesOf(
  kind: ProviderKind,
  missing: readonly string[] = [],
  ungranted: readonly string[] = [],
): ProviderProfileView[] {
  return requirementOf(kind).profiles.map((p, i) => {
    const required = p.permissions.map((x) => x.name);
    const notObservable = p.permissions
      .filter((x) => x.api === 'o365_management')
      .map((x) => x.name);
    return {
      profile: p.key,
      purpose: p.purpose,
      title: p.title,
      readOnly: p.readOnly,
      required,
      notObservable,
      grant: ungranted.includes(p.key)
        ? null
        : {
            id: `0193c1a0-cccc-7a00-8000-00000000000${i + 1}`,
            status: 'active',
            observed: required.filter((r) => !missing.includes(r) && !notObservable.includes(r)),
            missing: required.filter((r) => missing.includes(r)),
            excess: [],
          },
    };
  });
}

export function summary(over: Partial<ProviderSummary> = {}): ProviderSummary {
  const provider = over.provider ?? 'microsoft_entra';
  return {
    id: INTEGRATION_ID,
    provider,
    displayName: 'EXAMPLE Contoso Microsoft 365',
    status: 'active',
    pausedReason: null,
    disabledReason: null,
    disabledAt: null,
    connection: {
      id: CONNECTION_ID,
      provider: provider === 'microsoft_entra' ? 'microsoft_365' : 'google_workspace',
      displayName: 'EXAMPLE Contoso Microsoft 365',
      status: 'active',
    },
    health: { status: 'healthy', checkedAt: T_MINUS(5), stale: false },
    streams: { enabled: 4, available: 4, failing: 0, backfilling: 0, maxLagSeconds: 420 },
    capabilities: {
      streams: ['sign_ins', 'risk_events', 'oauth_consents', 'mailbox_audit'],
      actions: ['revoke_sessions', 'suspend_account', 'remove_forwarding_rule'],
    },
    createdAt: T_MINUS(60 * 24),
    updatedAt: T_MINUS(5),
    ...over,
  };
}

export function list(rows: ProviderSummary[] = [summary()], over: Partial<ProviderList> = {}) {
  return {
    featureEnabled: true,
    limit: { max: 5, used: rows.filter((r) => r.status !== 'disabled').length },
    data: rows,
    ...over,
  } satisfies ProviderList;
}

export function detail(over: Partial<ProviderDetail> = {}): ProviderDetail {
  const base = summary(over);
  const kind = base.provider;
  const requirement = requirementOf(kind);
  const settings = defaultBindingSettings();
  settings.actions.revoke_oauth_grant.enabled = false;
  if (kind === 'microsoft_entra') settings.mfaEnforcement.groupId = null;
  return {
    ...base,
    rowVersion: 3,
    settingsVersion: 2,
    settingsSchema: 'ato-idp-binding/1',
    settings,
    settingsInvalid: false,
    healthDetail: {
      status: base.health.status,
      checkedAt: base.health.checkedAt,
      nextCheckAt: T_MINUS(-10),
      stale: base.health.stale,
      ok: base.health.status === 'healthy',
      code: base.health.status === 'healthy' ? null : 'missing_permission',
      grants: requirement.profiles.map((p) => ({
        profile: p.key,
        status: 'active' as const,
        missingPermissions: [],
      })),
    },
    streamDetails: requirement.streams.map((s) => ({
      stream: s.stream,
      role: s.role,
      primary: s.primary,
      enabled: s.role !== 'unsupported',
      status: s.role === 'unsupported' ? ('unsupported' as const) : ('active' as const),
      availability: s.role === 'unsupported' ? ('not_offered' as const) : ('available' as const),
      availabilityCode: null,
      capability: s.role === 'unsupported' ? ('not_offered' as const) : ('available' as const),
      watermarkAt: s.role === 'primary' ? T_MINUS(7) : null,
      lagSeconds: s.role === 'primary' ? 420 : null,
      nextPollAt: s.role === 'primary' ? T_MINUS(-3) : null,
      lastAttemptAt: s.role === 'primary' ? T_MINUS(2) : null,
      lastSuccessAt: s.role === 'primary' ? T_MINUS(2) : null,
      lastEventAt: s.role === 'primary' ? T_MINUS(9) : null,
      lastErrorCode: null,
      consecutiveFailures: 0,
      throttledUntil: null,
      backfill: { active: false, from: null, requestedAt: null, completedAt: T_MINUS(60 * 20) },
      eventsTotal: s.role === 'primary' ? 1200 : 0,
      pagesTotal: s.role === 'primary' ? 40 : 0,
    })),
    actions: PROVIDER_ACTIONS.map((action) => {
      const a = requirement.actions.find((x) => x.action === action);
      return {
        action,
        enabled: settings.actions[action].enabled,
        capability: !settings.actions[action].enabled
          ? ('disabled' as const)
          : action === 'require_mfa'
            ? ('not_configured' as const)
            : ('available' as const),
        code: action === 'require_mfa' ? 'not_configured' : null,
        rollback: a?.rollback ?? false,
        confirmation: a?.confirmation ?? 'synchronous',
        requiresConfiguration: a?.requiresConfiguration ?? null,
      };
    }),
    permissions: {
      granted: profilesOf(kind).flatMap((p) => p.grant?.observed ?? []),
      profiles: profilesOf(kind),
    },
    directory: { domainCount: 2 },
    ...over,
  };
}

export function candidate(over: Partial<ProviderCandidate> = {}): ProviderCandidate {
  const kind = over.kind ?? 'microsoft_entra';
  return {
    id: SPARE_CONNECTION_ID,
    provider: kind === 'google_workspace' ? 'google_workspace' : 'microsoft_365',
    kind,
    displayName: 'EXAMPLE Fabrikam Microsoft 365',
    status: 'active',
    eligibility: 'eligible',
    reasons: [],
    integrationId: null,
    providerVerifiedDomainCount: 1,
    profiles: profilesOf(kind ?? 'microsoft_entra', ['User.RevokeSessions.All']),
    ...over,
  };
}

export function connections(
  rows: ProviderCandidate[] = [candidate()],
  over: Partial<ProviderConnections> = {},
): ProviderConnections {
  return { featureEnabled: true, limit: { max: 5, used: 1 }, data: rows, ...over };
}

export function mailboxItem(over: Partial<MailboxItem> = {}): MailboxItem {
  return {
    id: RULE_ITEM_ID,
    kind: 'inbox_rule',
    state: 'present',
    targetDomain: 'mail.example.net',
    traits: ['forwards', 'forwards_external', 'matches_finance_keywords'],
    enabled: true,
    source: 'snapshot',
    lastChange: 'added',
    provider: 'microsoft_entra',
    integrationId: INTEGRATION_ID,
    firstSeenAt: T_MINUS(90),
    lastSeenAt: T_MINUS(10),
    removedAt: null,
    ...over,
  };
}

export function mailboxState(
  accountId: string,
  items: MailboxItem[] = [
    mailboxItem(),
    mailboxItem({
      id: FORWARDING_ITEM_ID,
      kind: 'forwarding',
      traits: ['forwards', 'forwards_external'],
      enabled: true,
    }),
    mailboxItem({
      id: '0193c1a0-dddd-7a00-8000-000000000003',
      kind: 'delegate',
      targetDomain: 'alpha.example.test',
      traits: [],
      enabled: null,
    }),
  ],
  over: Partial<MailboxState> = {},
): MailboxState {
  return {
    accountId,
    items,
    truncated: false,
    identities: [
      {
        provider: 'microsoft_entra',
        integrationId: INTEGRATION_ID,
        userPrincipalName: 'finance@alpha.example.test',
        directoryStatus: 'active',
        directoryStatusAt: T_MINUS(30),
        refreshRequestedAt: null,
        refreshSupported: true,
      },
    ],
    integrations: [
      {
        id: INTEGRATION_ID,
        provider: 'microsoft_entra',
        displayName: 'EXAMPLE Contoso Microsoft 365',
        status: 'active',
        lastSweepAt: T_MINUS(15),
      },
    ],
    refreshRequestedAt: null,
    ...over,
  };
}
