/**
 * Read-only capability probe of the Microsoft adapter (design note D6, ADR-0084):
 *
 * 1. the 8.2 connection view (active, same directory as at bind time, grants and observed
 *    permissions);
 * 2. token acquisition per active ATO grant and resource (Graph; Office 365 Management for the
 *    telemetry grant);
 * 3. one cheap read per primary stream (`$top=1` over the last hour; the Office 365 content
 *    listing without starting the subscription) and the inbox-rule read of one user;
 * 4. action prerequisites without writing: the response grant active with its permissions, and
 *    for `require_mfa` the configured group readable.
 *
 * Never writes (invariant 7); a missing permission or licence is reported, never assumed (inv. 8).
 */
import type {
  GrantProbe,
  ProbeReport,
  StreamProbe,
  ActionProbe,
  Availability,
} from '../core/capabilities';
import { ProviderCallError, toProviderCallError } from '../core/errors';
import { directoryRefHash } from '../core/hash';
import type { ProviderSession } from '../core/session';
import {
  PROVIDER_ACTION_TYPES,
  PROVIDER_STREAMS,
  type ProviderActionType,
  type ProviderStream,
} from '../port/ato-port';
import type { TokenResource } from '../port/connection-port';
import { MICROSOFT_PROFILES, PERMISSION_REQUIREMENTS, STREAM_ROLES } from '../requirements';
import { MICROSOFT_DECLARED_CAPABILITIES, MICROSOFT_PROVIDER } from './constants';
import type { MicrosoftCalls, MicrosoftContext } from './context';
import { GRAPH_USER_SELECT } from './graph-client';
import { graphUserSchema } from './schemas';

const REQUIREMENTS = PERMISSION_REQUIREMENTS.microsoft_entra;
const PROBE_WINDOW_MS = 60 * 60 * 1000;

type ProbeResult = { availability: Availability; code?: string };

/** Maps a probe failure onto an availability (D6). */
export function availabilityOf(error: unknown): ProbeResult {
  const failure = toProviderCallError(error);
  switch (failure.code) {
    case 'missing_permission':
    case 'missing_privileged_role':
      return { availability: 'missing_permission', code: failure.providerCode ?? failure.code };
    case 'missing_license':
      return { availability: 'missing_license', code: failure.providerCode ?? failure.code };
    case 'not_found':
      return { availability: 'not_configured', code: 'not_found' };
    case 'grant_missing':
    case 'consent_missing':
      return { availability: 'missing_permission', code: failure.code };
    default:
      return { availability: 'error', code: failure.code };
  }
}

function grantFailure(status: GrantProbe['status']): ProbeResult {
  if (status === 'absent') return { availability: 'missing_permission', code: 'grant_missing' };
  if (status === 'pending') return { availability: 'missing_permission', code: 'consent_missing' };
  return { availability: 'missing_permission', code: 'grant_inactive' };
}

function emptyReport(
  checkedAt: string,
  result: ProbeResult,
  directory: string | null,
): ProbeReport {
  const streams = {} as Record<ProviderStream, StreamProbe>;
  for (const stream of PROVIDER_STREAMS) streams[stream] = { ...result };
  const actions = {} as Record<ProviderActionType, ActionProbe>;
  for (const action of PROVIDER_ACTION_TYPES) {
    const declared = MICROSOFT_DECLARED_CAPABILITIES.actions[action];
    actions[action] = {
      ...result,
      rollback: declared?.rollback ?? false,
      confirmation: declared?.confirmation ?? 'synchronous',
    };
  }
  return {
    ok: false,
    ...(result.code ? { code: result.code } : {}),
    checkedAt,
    directoryRefHash: directory,
    streams,
    actions,
    grants: REQUIREMENTS.profiles.map((profile) => ({
      profile: profile.key,
      status: 'absent' as const,
      missingPermissions: [],
    })),
  };
}

interface GrantState {
  probe: GrantProbe;
  /** Token failure per resource (absent = acquired). */
  tokenFailures: Partial<Record<TokenResource, ProbeResult>>;
}

async function probeGrant(
  session: ProviderSession,
  profile: (typeof REQUIREMENTS.profiles)[number],
  resources: readonly TokenResource[],
): Promise<GrantState> {
  const grant = session.grant(profile.key);
  const status: GrantProbe['status'] = grant?.status ?? 'absent';
  const required = profile.permissions.map((permission) => permission.name);
  const observed = grant?.observedPermissions ?? null;
  const missing = observed === null ? [] : required.filter((name) => !observed.includes(name));
  const state: GrantState = {
    probe: { profile: profile.key, status, missingPermissions: missing },
    tokenFailures: {},
  };
  if (status !== 'active') return state;
  for (const resource of resources) {
    try {
      await session.checkToken(profile.key, resource);
    } catch (error) {
      state.tokenFailures[resource] = availabilityOf(error);
    }
  }
  return state;
}

function addMissing(grant: GrantState, names: readonly string[]): void {
  for (const name of names) {
    if (!grant.probe.missingPermissions.includes(name)) grant.probe.missingPermissions.push(name);
  }
}

/** One cheap Graph read of a primary stream over the last hour. */
async function probeGraphStream(
  calls: MicrosoftCalls,
  path: string,
  dateField: string,
  since: Date,
): Promise<ProbeResult> {
  const params = new URLSearchParams({
    $filter: `${dateField} ge ${since.toISOString()}`,
    $top: '1',
  });
  try {
    await calls.graph.page(`${path}?${params.toString()}`, path);
    return { availability: 'available' };
  } catch (error) {
    return availabilityOf(error);
  }
}

/** Inbox rules of the first user are readable (MailboxSettings.Read, D8.3); `null` = unknown. */
async function rulesReadable(calls: MicrosoftCalls): Promise<boolean | null> {
  try {
    const params = new URLSearchParams({ $select: GRAPH_USER_SELECT, $top: '1' });
    const page = await calls.graph.page(`/v1.0/users?${params.toString()}`, '/v1.0/users');
    const first = page.value.map((raw) => graphUserSchema.safeParse(raw)).find((r) => r.success);
    if (!first?.success) return null;
    await calls.graph.listRules(first.data.id);
    return true;
  } catch (error) {
    if (error instanceof ProviderCallError && error.code === 'missing_permission') return false;
    return null;
  }
}

export async function probeMicrosoft(
  ctx: MicrosoftContext,
  signal: AbortSignal,
): Promise<ProbeReport> {
  const report = await runProbe(ctx, signal);
  ctx.deps.metrics?.probe?.({ provider: MICROSOFT_PROVIDER, result: report.ok ? 'ok' : 'failed' });
  return report;
}

async function runProbe(ctx: MicrosoftContext, signal: AbortSignal): Promise<ProbeReport> {
  const deps = ctx.deps;
  const now = deps.clock();
  const checkedAt = now.toISOString();
  const since = new Date(now.getTime() - PROBE_WINDOW_MS);

  // 1. Connection view.
  let calls: MicrosoftCalls;
  try {
    calls = await ctx.open(signal);
  } catch (error) {
    const failure = toProviderCallError(error);
    return emptyReport(checkedAt, { availability: 'error', code: failure.code }, null);
  }
  const view = calls.session.view;
  const directory = view.externalTenantId
    ? directoryRefHash(MICROSOFT_PROVIDER, view.externalTenantId)
    : null;
  const expected = deps.integration.directoryRefHash ?? null;
  if (directory === null || (expected !== null && expected !== directory)) {
    const code = directory === null ? 'directory_unverified' : 'directory_changed';
    return emptyReport(checkedAt, { availability: 'error', code }, directory);
  }

  // 2. Grants and tokens.
  const profiles = REQUIREMENTS.profiles;
  const byKey = (key: string) =>
    profiles.find((profile) => profile.key === key) as (typeof profiles)[number];
  const telemetry = await probeGrant(calls.session, byKey(MICROSOFT_PROFILES.telemetry), [
    'graph',
    'o365_management',
  ]);
  const response = await probeGrant(calls.session, byKey(MICROSOFT_PROFILES.response), ['graph']);
  const extended = await probeGrant(calls.session, byKey(MICROSOFT_PROFILES.responseExtended), [
    'graph',
  ]);
  const grantsByProfile = new Map<string, GrantState>([
    [MICROSOFT_PROFILES.telemetry, telemetry],
    [MICROSOFT_PROFILES.response, response],
    [MICROSOFT_PROFILES.responseExtended, extended],
  ]);

  // 3. Primary streams.
  const primaries: Partial<Record<ProviderStream, ProbeResult>> = {};
  const telemetryActive = telemetry.probe.status === 'active';
  const graphFailure = telemetry.tokenFailures.graph;
  const o365Failure = telemetry.tokenFailures.o365_management;
  const graphStreams: [ProviderStream, string, string][] = [
    ['sign_ins', '/v1.0/auditLogs/signIns', 'createdDateTime'],
    ['risk_events', '/v1.0/identityProtection/riskDetections', 'lastUpdatedDateTime'],
    ['oauth_consents', '/v1.0/auditLogs/directoryAudits', 'activityDateTime'],
  ];
  for (const [stream, path, field] of graphStreams) {
    if (!telemetryActive) primaries[stream] = grantFailure(telemetry.probe.status);
    else if (graphFailure) primaries[stream] = graphFailure;
    else primaries[stream] = await probeGraphStream(calls, path, field, since);
  }
  if (!telemetryActive) primaries.mailbox_audit = grantFailure(telemetry.probe.status);
  else if (o365Failure) primaries.mailbox_audit = o365Failure;
  else if (graphFailure) primaries.mailbox_audit = graphFailure;
  else {
    try {
      const listing = await calls.o365().probe({ start: since, end: now });
      primaries.mailbox_audit =
        listing === 'ok'
          ? { availability: 'available' }
          : { availability: 'available', code: 'subscription_pending' };
    } catch (error) {
      primaries.mailbox_audit = availabilityOf(error);
    }
    if (primaries.mailbox_audit.availability === 'available') {
      const readable = await rulesReadable(calls);
      if (readable === false) addMissing(telemetry, ['MailboxSettings.Read']);
    }
  }
  for (const [stream, result] of Object.entries(primaries) as [ProviderStream, ProbeResult][]) {
    if (result.availability === 'missing_permission' && telemetryActive) {
      const observed = calls.session.grant(MICROSOFT_PROFILES.telemetry)?.observedPermissions;
      if (observed === null || observed === undefined) {
        addMissing(telemetry, REQUIREMENTS.streams[stream].permissions);
      }
    }
  }
  const streams = {} as Record<ProviderStream, StreamProbe>;
  for (const stream of PROVIDER_STREAMS) {
    const role = STREAM_ROLES.microsoft_entra[stream];
    const primary = role.role === 'primary' ? stream : role.primary;
    const result = primary ? primaries[primary] : undefined;
    streams[stream] = result ? { ...result } : { availability: 'not_offered' };
  }

  // 4. Action prerequisites (no write).
  const actions = {} as Record<ProviderActionType, ActionProbe>;
  for (const action of PROVIDER_ACTION_TYPES) {
    const requirement = REQUIREMENTS.actions[action];
    const declared = MICROSOFT_DECLARED_CAPABILITIES.actions[action];
    const base = {
      rollback: declared?.rollback ?? false,
      confirmation: declared?.confirmation ?? ('synchronous' as const),
    };
    const grant = requirement.profile ? grantsByProfile.get(requirement.profile) : undefined;
    let result: ProbeResult;
    if (!declared?.supported || !grant) result = { availability: 'not_offered' };
    else if (grant.probe.status !== 'active') result = grantFailure(grant.probe.status);
    else if (grant.tokenFailures.graph) result = grant.tokenFailures.graph;
    else if (requirement.permissions.some((p) => grant.probe.missingPermissions.includes(p))) {
      result = { availability: 'missing_permission', code: 'permission_missing' };
    } else if (action === 'require_mfa') {
      result = await probeMfaGroup(ctx, calls);
    } else {
      result = { availability: 'available' };
    }
    actions[action] = { ...result, ...base };
  }

  const enabledPrimaries = PROVIDER_STREAMS.filter(
    (stream) =>
      STREAM_ROLES.microsoft_entra[stream].role === 'primary' &&
      deps.integration.settings.streams[stream].enabled,
  );
  let code: string | undefined;
  if (!telemetryActive) code = 'telemetry_grant_inactive';
  else if (graphFailure || o365Failure)
    code = (graphFailure ?? o365Failure)?.code ?? 'token_failed';
  else if (enabledPrimaries.some((stream) => streams[stream].availability !== 'available')) {
    code = 'stream_unavailable';
  }
  return {
    ok: code === undefined,
    ...(code ? { code } : {}),
    checkedAt,
    directoryRefHash: directory,
    streams,
    actions,
    grants: [telemetry.probe, response.probe, extended.probe],
  };
}

async function probeMfaGroup(ctx: MicrosoftContext, calls: MicrosoftCalls): Promise<ProbeResult> {
  const groupId = ctx.deps.integration.settings.mfaEnforcement.groupId;
  if (!groupId) return { availability: 'not_configured', code: 'mfa_group_not_configured' };
  try {
    const exists = await calls.graph.groupExists(groupId, MICROSOFT_PROFILES.responseExtended);
    return exists
      ? { availability: 'available' }
      : { availability: 'not_configured', code: 'mfa_group_not_found' };
  } catch (error) {
    return availabilityOf(error);
  }
}
