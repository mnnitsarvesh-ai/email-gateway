/**
 * Google Workspace adapter `gws-ato/1` (design note D1–D9, §3): Admin SDK Reports `login` (sign-ins
 * and their risk companion) and `token` (OAuth consents), the Gmail settings snapshot sweep
 * (forwarding, filters, delegates), provider-confirmed response actions over Directory and Gmail
 * settings, and read-only probes. Implements the 8.4 port plus `IdpAdapterExtras`.
 *
 * Streams (D3): `sign_ins` primary (Reports `login`), `risk_events` companion of `sign_ins`,
 * `session_events` unsupported (not offered by Google), `oauth_consents` primary (Reports `token`,
 * `authorize`), `forwarding_changes` primary (settings sweep), `mailbox_audit` and
 * `delegation_changes` companions of `forwarding_changes`.
 */
import type { AdapterDeps, IdpAdapter } from '../adapter-types';
import {
  computeEffectiveCapabilities,
  isReportStale,
  type ProbeReport,
} from '../core/capabilities';
import { companionCursor, encodeCursor, resolveCursor, type CursorV1 } from '../core/cursor';
import { THROTTLE_CODES, toProviderCallError } from '../core/errors';
import { normalizedAddress } from '../core/normalize';
import { PageCollector } from '../core/page';
import { hasMoreWindows, nextWindow } from '../core/windows';
import { throttledPage } from '../microsoft/adapter';
import type {
  ProviderActionResult,
  ProviderActionType,
  ProviderCapabilities,
  ProviderIdentityRef,
  ProviderIngestPage,
  ProviderStream,
} from '../port/ato-port';
import { PROVIDER_RETENTION_DAYS, STREAM_ROLES } from '../requirements';
import { confirmAction, executeAction, rollbackAction } from './actions';
import {
  GOOGLE_ADAPTER_VERSION,
  GOOGLE_DECLARED_CAPABILITIES,
  GOOGLE_PROVIDER,
  TOKEN_AUTHORIZE_EVENT,
  type ReportsApplication,
} from './constants';
import { GoogleContext } from './context';
import { ingestSettingsSnapshot } from './mailbox';
import type { ActivityEventResult } from './mappers/activity';
import { mapLoginActivity } from './mappers/login';
import { mapTokenActivity } from './mappers/token';
import { probeGoogle } from './probe';

/** Cursor of an unsupported stream (never polled; `ingest` answers it instead of throwing). */
export const UNSUPPORTED_CURSOR_PREFIX = 'unsupported:v1:';

interface ReportsSpec {
  stream: ProviderStream;
  application: ReportsApplication;
  eventName?: string;
  map(raw: unknown): ActivityEventResult[];
}

const LOGIN: ReportsSpec = { stream: 'sign_ins', application: 'login', map: mapLoginActivity };
const TOKEN: ReportsSpec = {
  stream: 'oauth_consents',
  application: 'token',
  eventName: TOKEN_AUTHORIZE_EVENT,
  map: mapTokenActivity,
};

export class GoogleAdapter implements IdpAdapter {
  readonly kind = GOOGLE_PROVIDER;
  readonly version = GOOGLE_ADAPTER_VERSION;
  readonly context: GoogleContext;
  private lastReport: ProbeReport | null = null;

  constructor(readonly deps: AdapterDeps) {
    if (deps.integration.provider !== GOOGLE_PROVIDER) throw new Error('adapter_provider_mismatch');
    this.context = new GoogleContext(deps);
  }

  /** The newest probe report: the stored one (`health_detail`) or one this instance ran. */
  currentReport(): ProbeReport | null {
    const stored = this.deps.integration.health;
    const own = this.lastReport;
    if (!stored) return own;
    if (!own) return stored;
    return Date.parse(own.checkedAt) >= Date.parse(stored.checkedAt) ? own : stored;
  }

  /** Effective capabilities (declared ∩ probed ∩ enabled, D6). */
  capabilities(): ProviderCapabilities {
    return computeEffectiveCapabilities({
      provider: GOOGLE_PROVIDER,
      declared: GOOGLE_DECLARED_CAPABILITIES,
      report: this.currentReport(),
      settings: this.deps.integration.settings,
      now: this.deps.clock(),
      healthIntervalSeconds: this.deps.config.healthIntervalSeconds,
    }).capabilities;
  }

  declaredCapabilities(): ProviderCapabilities {
    return GOOGLE_DECLARED_CAPABILITIES;
  }

  async health(signal: AbortSignal): Promise<{ ok: boolean; code?: string }> {
    const report = await this.probe(signal);
    return report.ok ? { ok: true } : { ok: false, ...(report.code ? { code: report.code } : {}) };
  }

  async probe(signal: AbortSignal): Promise<ProbeReport> {
    const report = await probeGoogle(this.context, signal);
    this.lastReport = report;
    return report;
  }

  /** A priority mailbox refresh needs the settings sweep proven by the last probe (D6 step 5). */
  mailboxRefreshSupported(): boolean {
    const report = this.currentReport();
    return report?.streams.forwarding_changes?.availability === 'available';
  }

  async ingest(
    stream: ProviderStream,
    cursor: string | null,
    signal: AbortSignal,
  ): Promise<ProviderIngestPage> {
    const role = STREAM_ROLES.google_workspace[stream];
    if (role.role === 'companion') {
      return { events: [], cursor: companionCursor(role.primary ?? stream), hasMore: false };
    }
    switch (stream) {
      case 'sign_ins':
        return this.reports(LOGIN, cursor, signal);
      case 'oauth_consents':
        return this.reports(TOKEN, cursor, signal);
      case 'forwarding_changes':
        return ingestSettingsSnapshot(this.context, cursor, signal);
      default:
        // `session_events`: not offered by Google (D3); the runner never polls it.
        return { events: [], cursor: `${UNSUPPORTED_CURSOR_PREFIX}${stream}`, hasMore: false };
    }
  }

  /**
   * A Reports stream: one `activities.list` page per call over `[watermark − 60 min, now − 5 min]`
   * (D7.2); cursor `{ wm, ws, we, page: pageToken }`. Duplicates in the overlap are dropped
   * downstream by event id.
   */
  private async reports(
    spec: ReportsSpec,
    raw: string | null,
    signal: AbortSignal,
  ): Promise<ProviderIngestPage> {
    const now = this.deps.clock();
    const { cursor, reset } = resolveCursor(raw, this.version, now);
    if (reset) this.deps.metrics?.cursorReset?.({ provider: this.kind, stream: spec.stream });
    const unchanged = raw !== null && !reset ? raw : encodeCursor(cursor);
    let window: { start: Date; end: Date } | null;
    if (cursor.ws && cursor.we) {
      window = { start: new Date(cursor.ws), end: new Date(cursor.we) };
    } else {
      window = nextWindow({
        family: 'google_reports',
        watermark: cursor.wm ? new Date(cursor.wm) : null,
        now,
        retentionDays: PROVIDER_RETENTION_DAYS.google_workspace[spec.stream],
      });
      if (window === null) return { events: [], cursor: unchanged, hasMore: false };
    }
    const page = new PageCollector(this.kind, this.deps.integration.settings, this.deps.metrics);
    try {
      const calls = await this.context.open(signal);
      const result = await calls.reports.page({
        application: spec.application,
        start: window.start,
        end: window.end,
        maxResults: this.deps.config.pageMaxEvents,
        ...(typeof cursor.page === 'string' ? { pageToken: cursor.page } : {}),
        ...(spec.eventName ? { eventName: spec.eventName } : {}),
      });
      for (const item of result.items ?? []) {
        for (const mapped of spec.map(item)) {
          if (mapped.kind === 'event') page.add(mapped.event);
          else
            page.drop(mapped.stream, mapped.kind === 'dropped' ? 'dropped_operation' : 'invalid');
        }
      }
      const next: CursorV1 = { v: 1, a: this.version, seq: cursor.seq + 1 };
      let hasMore: boolean;
      if (result.nextPageToken) {
        if (cursor.wm) next.wm = cursor.wm;
        next.ws = window.start.toISOString();
        next.we = window.end.toISOString();
        next.page = result.nextPageToken;
        hasMore = true;
      } else {
        next.wm = window.end.toISOString();
        hasMore = hasMoreWindows({ family: 'google_reports', watermark: window.end, now });
      }
      return { events: page.events, cursor: encodeCursor(next), hasMore };
    } catch (error) {
      const failure = toProviderCallError(error);
      if (THROTTLE_CODES.has(failure.code)) return throttledPage(failure, unchanged);
      throw failure;
    } finally {
      page.flush();
    }
  }

  /**
   * Directory `users.get(userKey = address)` as the telemetry grant's delegated administrator;
   * Google resolves aliases to the user (D9.2). `null` when unknown or not an address.
   */
  async resolveIdentity(address: string, signal: AbortSignal): Promise<ProviderIdentityRef | null> {
    const normalized = normalizedAddress(address);
    if (!normalized) return null;
    const calls = await this.context.open(signal);
    const user = await calls.directory().getUser(normalized);
    return user ? this.context.identityFromUser(user) : null;
  }

  execute(
    request: {
      actionPublicId: string;
      idempotencyKey: string;
      type: ProviderActionType;
      identity: ProviderIdentityRef;
      params: Record<string, string | number | boolean>;
    },
    signal: AbortSignal,
  ): Promise<ProviderActionResult> {
    return executeAction(this.context, request, signal, (type, gateSignal) =>
      this.actionGate(type, gateSignal),
    );
  }

  /**
   * Checked before an action's first step (D6, D9.1, deviation WP1-10): disabled in the binding
   * settings ⇒ `action_disabled`; a stale report is refreshed by a probe first; an action whose
   * probed availability is not `available` ⇒ `not_configured` or `capability_unavailable`.
   */
  private async actionGate(type: ProviderActionType, signal: AbortSignal): Promise<string | null> {
    if (!this.deps.integration.settings.actions[type].enabled) return 'action_disabled';
    let report = this.currentReport();
    if (isReportStale(report, this.deps.clock(), this.deps.config.healthIntervalSeconds)) {
      report = await this.probe(signal);
    }
    const availability = report?.actions[type]?.availability;
    if (availability === 'available') return null;
    return availability === 'not_configured' ? 'not_configured' : 'capability_unavailable';
  }

  confirm(
    ref: { type: ProviderActionType; providerReference: string },
    signal: AbortSignal,
  ): Promise<ProviderActionResult> {
    return confirmAction(this.context, ref, signal);
  }

  rollback(
    request: {
      actionPublicId: string;
      idempotencyKey: string;
      type: ProviderActionType;
      identity: ProviderIdentityRef;
      providerReference: string;
    },
    signal: AbortSignal,
  ): Promise<ProviderActionResult> {
    return rollbackAction(this.context, request, signal);
  }
}

/** Factory used by `createIdpAdapter` for kind `google_workspace`. */
export function createGoogleAdapter(deps: AdapterDeps): GoogleAdapter {
  return new GoogleAdapter(deps);
}
