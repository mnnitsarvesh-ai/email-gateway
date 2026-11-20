/**
 * Probes, effective capabilities and integration health (design note D6, ADR-0084).
 *
 * Effective capabilities = declared by the adapter ∩ `available` in the last probe report ∩
 * enabled in the binding settings. A report older than 3 × the health interval is stale: every
 * capability is `unknown` for the api (actions still run; the adapter re-probes first).
 */
import {
  PROVIDER_ACTION_TYPES,
  PROVIDER_STREAMS,
  type ProviderActionType,
  type ProviderCapabilities,
  type ProviderStream,
} from '../port/ato-port';
import type { AtoProviderKind } from '../kinds';
import { STREAM_ROLES } from '../requirements';
import type { IdpBindingSettings } from './settings';

export const AVAILABILITIES = [
  'available',
  'missing_permission',
  'missing_license',
  'not_configured',
  'not_offered',
  'error',
] as const;
export type Availability = (typeof AVAILABILITIES)[number];

export interface StreamProbe {
  availability: Availability;
  code?: string;
}
export interface ActionProbe {
  availability: Availability;
  code?: string;
  rollback: boolean;
  confirmation: 'synchronous' | 'polling';
}
export interface GrantProbe {
  profile: string;
  status: 'active' | 'pending' | 'error' | 'revoked' | 'absent';
  missingPermissions: string[];
}

export interface ProbeReport {
  ok: boolean;
  code?: string;
  checkedAt: string;
  /** SHA-256(provider|external tenant id) seen by this probe (deviation WP1-5). */
  directoryRefHash: string | null;
  streams: Record<ProviderStream, StreamProbe>;
  actions: Record<ProviderActionType, ActionProbe>;
  grants: GrantProbe[];
}

/** What 8.4's `ato_provider_integrations.health_detail` stores: the last probe report. */
export type IdpHealthDetail = ProbeReport;

export type CapabilityView = Availability | 'unknown' | 'disabled';

export interface EffectiveCapabilities {
  capabilities: ProviderCapabilities;
  /** The last report is missing or older than 3 × the health interval. */
  stale: boolean;
  /** Per stream and action, for the api and portal (`unknown` when stale). */
  view: {
    streams: Record<ProviderStream, CapabilityView>;
    actions: Record<ProviderActionType, CapabilityView>;
  };
}

export function isReportStale(
  report: ProbeReport | null,
  now: Date,
  healthIntervalSeconds: number,
): boolean {
  if (report === null) return true;
  const checked = Date.parse(report.checkedAt);
  if (Number.isNaN(checked)) return true;
  return now.getTime() - checked > 3 * healthIntervalSeconds * 1000;
}

export function computeEffectiveCapabilities(input: {
  provider: AtoProviderKind;
  declared: ProviderCapabilities;
  report: ProbeReport | null;
  settings: IdpBindingSettings;
  now: Date;
  healthIntervalSeconds: number;
}): EffectiveCapabilities {
  const { declared, report, settings } = input;
  const stale = isReportStale(report, input.now, input.healthIntervalSeconds);
  const streams: ProviderCapabilities['streams'] = {};
  const actions: ProviderCapabilities['actions'] = {};
  const streamView = {} as Record<ProviderStream, CapabilityView>;
  const actionView = {} as Record<ProviderActionType, CapabilityView>;

  for (const stream of PROVIDER_STREAMS) {
    const declaredStream = declared.streams[stream];
    const role = STREAM_ROLES[input.provider][stream];
    const enabled = settings.streams[stream].enabled;
    const probed = report?.streams[stream]?.availability ?? null;
    const supported =
      declaredStream?.supported === true &&
      role.role !== 'unsupported' &&
      enabled &&
      probed === 'available';
    streams[stream] = {
      supported,
      ...(declaredStream?.latencySeconds !== undefined
        ? { latencySeconds: declaredStream.latencySeconds }
        : {}),
    };
    if (declaredStream?.supported !== true || role.role === 'unsupported')
      streamView[stream] = 'not_offered';
    else if (!enabled) streamView[stream] = 'disabled';
    else if (stale || probed === null) streamView[stream] = 'unknown';
    else streamView[stream] = probed;
  }

  for (const action of PROVIDER_ACTION_TYPES) {
    const declaredAction = declared.actions[action];
    const enabled = settings.actions[action].enabled;
    const probed = report?.actions[action]?.availability ?? null;
    const supported = declaredAction?.supported === true && enabled && probed === 'available';
    actions[action] = {
      supported,
      rollback: supported && declaredAction.rollback,
      confirmation: declaredAction?.confirmation ?? 'synchronous',
    };
    if (declaredAction?.supported !== true) actionView[action] = 'not_offered';
    else if (!enabled) actionView[action] = 'disabled';
    else if (stale || probed === null) actionView[action] = 'unknown';
    else actionView[action] = probed;
  }

  return {
    capabilities: { streams, actions },
    stale,
    view: { streams: streamView, actions: actionView },
  };
}

export type IntegrationHealth = 'unknown' | 'healthy' | 'degraded' | 'unhealthy';

export interface StreamRuntimeState {
  stream: ProviderStream;
  enabled: boolean;
  role: 'primary' | 'companion' | 'unsupported';
  /** Consecutive failures of the stream's polls. */
  consecutiveFailures: number;
  /** Throttled until (epoch ms) and since when (epoch ms) the stream is throttled. */
  throttledSinceMs?: number | null;
  lagSeconds?: number | null;
}

/** Integration health (D6). */
export function computeHealthStatus(input: {
  report: ProbeReport | null;
  connectionActive: boolean;
  tokenFailing: boolean;
  streams: readonly StreamRuntimeState[];
  now: Date;
  lagWarnSeconds: number;
  /** Failures before a stream counts as failing (8.4 ATO_PROVIDER_MAX_CONSECUTIVE_FAILURES or 3). */
  failingAfter?: number;
}): IntegrationHealth {
  if (input.report === null) return 'unknown';
  if (!input.connectionActive || input.tokenFailing) return 'unhealthy';
  const failingAfter = input.failingAfter ?? 3;
  const primaries = input.streams.filter((s) => s.enabled && s.role === 'primary');
  if (primaries.length === 0) return 'degraded';
  const failing = primaries.filter(
    (s) =>
      s.consecutiveFailures >= failingAfter ||
      input.report?.streams[s.stream]?.availability !== 'available',
  );
  if (failing.length === primaries.length) return 'unhealthy';
  if (failing.length > 0) return 'degraded';
  const throttledLong = primaries.some(
    (s) => s.throttledSinceMs != null && input.now.getTime() - s.throttledSinceMs > 15 * 60_000,
  );
  const lagging = primaries.some(
    (s) => s.lagSeconds != null && s.lagSeconds > input.lagWarnSeconds,
  );
  const anyFailure = primaries.some((s) => s.consecutiveFailures > 0);
  if (throttledLong || lagging || anyFailure) return 'degraded';
  return 'healthy';
}
