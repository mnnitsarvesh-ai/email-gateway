/**
 * Read-only capability probe of the Google adapter (design note D6, ADR-0084):
 *
 * 1. the 8.2 connection view (active, same Google customer as at bind time, grants and observed
 *    scopes);
 * 2. token acquisition per active ATO grant as its delegated administrator (`subjectEmail`; a
 *    grant without one cannot call the Admin SDK: `delegated_admin_missing`);
 * 3. one cheap read per primary stream over the last hour (`maxResults=1`): Reports `login` and
 *    `token`; for the settings sweep a Directory `users.list` page and the **impersonation of one
 *    active user of a provider-verified linked domain** with a Gmail settings read;
 * 4. action prerequisites without writing: the response grant active with its scopes, and for
 *    `require_mfa` the configured organizational unit readable (`orgunits.get`).
 *
 * Never writes (invariant 7); a missing scope is reported, never assumed (invariant 8).
 * `session_events` is `not_offered` (Google exposes no session or token anomaly events).
 */
import type {
  ActionProbe,
  Availability,
  GrantProbe,
  ProbeReport,
  StreamProbe,
} from '../core/capabilities';
import { toProviderCallError } from '../core/errors';
import { directoryRefHash, domainOf } from '../core/hash';
import { verifiedLinkedDomains, type ProviderSession } from '../core/session';
import { availabilityOf } from '../microsoft/probe';
import {
  PROVIDER_ACTION_TYPES,
  PROVIDER_STREAMS,
  type ProviderActionType,
  type ProviderStream,
} from '../port/ato-port';
import {
  GOOGLE_PROFILES,
  GOOGLE_SCOPES,
  PERMISSION_REQUIREMENTS,
  STREAM_ROLES,
} from '../requirements';
import { GOOGLE_DECLARED_CAPABILITIES, GOOGLE_PROVIDER, TOKEN_AUTHORIZE_EVENT } from './constants';
import type { GoogleCalls, GoogleContext } from './context';
import { directoryUserSchema } from './schemas';

const REQUIREMENTS = PERMISSION_REQUIREMENTS.google_workspace;
const PROBE_WINDOW_MS = 60 * 60 * 1000;
/** Users listed to find one active user of a linked domain to impersonate. */
const PROBE_USERS = 10;

type ProbeResult = { availability: Availability; code?: string };

function grantFailure(status: GrantProbe['status']): ProbeResult {
  if (status === 'absent') return { availability: 'missing_permission', code: 'grant_missing' };
  if (status === 'pending') return { availability: 'missing_permission', code: 'consent_missing' };
  return { availability: 'missing_permission', code: 'grant_inactive' };
}

function actionBase(action: ProviderActionType) {
  const declared = GOOGLE_DECLARED_CAPABILITIES.actions[action];
  return {
    rollback: declared?.rollback ?? false,
    confirmation: declared?.confirmation ?? ('synchronous' as const),
  };
}

function emptyReport(
  checkedAt: string,
  result: ProbeResult,
  directory: string | null,
): ProbeReport {
  const streams = {} as Record<ProviderStream, StreamProbe>;
  for (const stream of PROVIDER_STREAMS) {
    streams[stream] =
      STREAM_ROLES.google_workspace[stream].role === 'unsupported'
        ? { availability: 'not_offered' }
        : { ...result };
  }
  const actions = {} as Record<ProviderActionType, ActionProbe>;
  for (const action of PROVIDER_ACTION_TYPES) {
    actions[action] = { ...result, ...actionBase(action) };
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
  /** Token failure as the delegated administrator (absent = acquired). */
  tokenFailure?: ProbeResult;
}

async function probeGrant(
  session: ProviderSession,
  profile: (typeof REQUIREMENTS.profiles)[number],
): Promise<GrantState> {
  const grant = session.grant(profile.key);
  const status: GrantProbe['status'] = grant?.status ?? 'absent';
  const required = profile.permissions.map((permission) => permission.name);
  const observed = grant?.observedPermissions ?? null;
  const missing = observed === null ? [] : required.filter((name) => !observed.includes(name));
  const state: GrantState = {
    probe: { profile: profile.key, status, missingPermissions: missing },
  };
  if (status !== 'active') return state;
  const subject = grant?.subjectEmail ?? null;
  if (!subject) {
    state.tokenFailure = { availability: 'not_configured', code: 'delegated_admin_missing' };
    return state;
  }
  try {
    await session.checkToken(profile.key, 'google', subject);
  } catch (error) {
    state.tokenFailure = availabilityOf(error);
  }
  return state;
}

function addMissing(grant: GrantState, names: readonly string[]): void {
  for (const name of names) {
    if (!grant.probe.missingPermissions.includes(name)) grant.probe.missingPermissions.push(name);
  }
}

/** A failed read whose scope 8.2 never verified names that scope in the grant's list. */
function noteMissing(
  calls: GoogleCalls,
  grant: GrantState,
  result: ProbeResult,
  scopes: readonly string[],
): ProbeResult {
  if (result.availability === 'missing_permission') {
    const observed = calls.session.grant(GOOGLE_PROFILES.telemetry)?.observedPermissions;
    if (observed === null || observed === undefined) addMissing(grant, scopes);
  }
  return result;
}

async function probeReports(
  calls: GoogleCalls,
  application: 'login' | 'token',
  since: Date,
  now: Date,
): Promise<ProbeResult> {
  try {
    await calls.reports.page({
      application,
      start: since,
      end: now,
      maxResults: 1,
      ...(application === 'token' ? { eventName: TOKEN_AUTHORIZE_EVENT } : {}),
    });
    return { availability: 'available' };
  } catch (error) {
    return availabilityOf(error);
  }
}

/**
 * The settings sweep: the directory is listable and one active user of a provider-verified linked
 * domain can be impersonated for a Gmail settings read (D6 step 5).
 */
async function probeSettings(calls: GoogleCalls, telemetry: GrantState): Promise<ProbeResult> {
  let users: unknown[];
  try {
    users = (await calls.directory().listUsers(PROBE_USERS)).users ?? [];
  } catch (error) {
    return noteMissing(calls, telemetry, availabilityOf(error), [
      GOOGLE_SCOPES.directoryUserReadonly,
    ]);
  }
  const linked = verifiedLinkedDomains(calls.session.view);
  const candidate = users
    .map((raw) => directoryUserSchema.safeParse(raw))
    .find(
      (result) =>
        result.success &&
        result.data.suspended !== true &&
        result.data.archived !== true &&
        linked.has(domainOf(result.data.primaryEmail) ?? ''),
    );
  if (!candidate?.success) return { availability: 'not_configured', code: 'no_linked_user' };
  try {
    await calls.gmail().getAutoForwarding(candidate.data.primaryEmail.toLowerCase());
    return { availability: 'available' };
  } catch (error) {
    const result = availabilityOf(error);
    return noteMissing(calls, telemetry, result, [GOOGLE_SCOPES.gmailSettingsBasic]);
  }
}

async function probeMfaOrgUnit(ctx: GoogleContext, calls: GoogleCalls): Promise<ProbeResult> {
  const orgUnitPath = ctx.deps.integration.settings.mfaEnforcement.orgUnitPath;
  if (!orgUnitPath) return { availability: 'not_configured', code: 'mfa_ou_not_configured' };
  try {
    const exists = await calls
      .directory(GOOGLE_PROFILES.responseExtended)
      .orgUnitExists(orgUnitPath);
    return exists
      ? { availability: 'available' }
      : { availability: 'not_configured', code: 'mfa_ou_not_found' };
  } catch (error) {
    return availabilityOf(error);
  }
}

export async function probeGoogle(ctx: GoogleContext, signal: AbortSignal): Promise<ProbeReport> {
  const report = await runProbe(ctx, signal);
  ctx.deps.metrics?.probe?.({ provider: GOOGLE_PROVIDER, result: report.ok ? 'ok' : 'failed' });
  return report;
}

async function runProbe(ctx: GoogleContext, signal: AbortSignal): Promise<ProbeReport> {
  const deps = ctx.deps;
  const now = deps.clock();
  const checkedAt = now.toISOString();
  const since = new Date(now.getTime() - PROBE_WINDOW_MS);

  // 1. Connection view.
  let calls: GoogleCalls;
  try {
    calls = await ctx.open(signal);
  } catch (error) {
    const failure = toProviderCallError(error);
    return emptyReport(checkedAt, { availability: 'error', code: failure.code }, null);
  }
  const view = calls.session.view;
  const directory = view.externalTenantId
    ? directoryRefHash(GOOGLE_PROVIDER, view.externalTenantId)
    : null;
  const expected = deps.integration.directoryRefHash ?? null;
  if (directory === null || (expected !== null && expected !== directory)) {
    const code = directory === null ? 'directory_unverified' : 'directory_changed';
    return emptyReport(checkedAt, { availability: 'error', code }, directory);
  }

  // 2. Grants and tokens (as each grant's delegated administrator).
  const byKey = (key: string) =>
    REQUIREMENTS.profiles.find(
      (profile) => profile.key === key,
    ) as (typeof REQUIREMENTS.profiles)[number];
  const telemetry = await probeGrant(calls.session, byKey(GOOGLE_PROFILES.telemetry));
  const response = await probeGrant(calls.session, byKey(GOOGLE_PROFILES.response));
  const extended = await probeGrant(calls.session, byKey(GOOGLE_PROFILES.responseExtended));
  const grantsByProfile = new Map<string, GrantState>([
    [GOOGLE_PROFILES.telemetry, telemetry],
    [GOOGLE_PROFILES.response, response],
    [GOOGLE_PROFILES.responseExtended, extended],
  ]);

  // 3. Primary streams.
  const primaries: Partial<Record<ProviderStream, ProbeResult>> = {};
  const telemetryActive = telemetry.probe.status === 'active';
  const tokenFailure = telemetry.tokenFailure;
  for (const stream of ['sign_ins', 'oauth_consents', 'forwarding_changes'] as const) {
    if (!telemetryActive) primaries[stream] = grantFailure(telemetry.probe.status);
    else if (tokenFailure) primaries[stream] = tokenFailure;
  }
  if (telemetryActive && !tokenFailure) {
    primaries.sign_ins = noteMissing(
      calls,
      telemetry,
      await probeReports(calls, 'login', since, now),
      [GOOGLE_SCOPES.reportsAudit],
    );
    primaries.oauth_consents = noteMissing(
      calls,
      telemetry,
      await probeReports(calls, 'token', since, now),
      [GOOGLE_SCOPES.reportsAudit],
    );
    primaries.forwarding_changes = await probeSettings(calls, telemetry);
  }
  const streams = {} as Record<ProviderStream, StreamProbe>;
  for (const stream of PROVIDER_STREAMS) {
    const role = STREAM_ROLES.google_workspace[stream];
    const primary = role.role === 'primary' ? stream : role.primary;
    const result = primary ? primaries[primary] : undefined;
    streams[stream] = result ? { ...result } : { availability: 'not_offered' };
  }

  // 4. Action prerequisites (no write).
  const actions = {} as Record<ProviderActionType, ActionProbe>;
  for (const action of PROVIDER_ACTION_TYPES) {
    const requirement = REQUIREMENTS.actions[action];
    const declared = GOOGLE_DECLARED_CAPABILITIES.actions[action];
    const grant = requirement.profile ? grantsByProfile.get(requirement.profile) : undefined;
    let result: ProbeResult;
    if (!declared?.supported || !grant) result = { availability: 'not_offered' };
    else if (grant.probe.status !== 'active') result = grantFailure(grant.probe.status);
    else if (grant.tokenFailure) result = grant.tokenFailure;
    else if (requirement.permissions.some((p) => grant.probe.missingPermissions.includes(p))) {
      result = { availability: 'missing_permission', code: 'permission_missing' };
    } else if (action === 'require_mfa') {
      result = await probeMfaOrgUnit(ctx, calls);
    } else {
      result = { availability: 'available' };
    }
    actions[action] = { ...result, ...actionBase(action) };
  }

  const enabledPrimaries = PROVIDER_STREAMS.filter(
    (stream) =>
      STREAM_ROLES.google_workspace[stream].role === 'primary' &&
      deps.integration.settings.streams[stream].enabled,
  );
  let code: string | undefined;
  if (!telemetryActive) code = 'telemetry_grant_inactive';
  else if (tokenFailure) code = tokenFailure.code ?? 'token_failed';
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
