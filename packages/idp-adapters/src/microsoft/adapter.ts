/**
 * Microsoft Entra ID / Microsoft 365 adapter `msgraph-ato/1` (design note D1–D9, §3): Graph v1.0
 * sign-ins, risk detections and consent audits, Office 365 Management `Audit.Exchange` with Graph
 * inbox rules, provider-confirmed response actions and read-only probes. Implements the 8.4 port
 * plus `IdpAdapterExtras`.
 */
import type { AdapterDeps, IdpAdapter } from '../adapter-types';
import {
  computeEffectiveCapabilities,
  isReportStale,
  type ProbeReport,
} from '../core/capabilities';
import { companionCursor, encodeCursor, resolveCursor, type CursorV1 } from '../core/cursor';
import { THROTTLE_CODES, type ProviderCallError, toProviderCallError } from '../core/errors';
import { PageCollector } from '../core/page';
import { hasMoreWindows, nextWindow, type WindowFamily } from '../core/windows';
import type {
  ProviderActionResult,
  ProviderActionType,
  ProviderCapabilities,
  ProviderIdentityRef,
  ProviderIngestPage,
  ProviderStream,
} from '../port/ato-port';
import { PROVIDER_RETENTION_DAYS, STREAM_ROLES } from '../requirements';
import { executeAction, confirmAction, rollbackAction } from './actions';
import {
  CONSENT_ACTIVITIES,
  MICROSOFT_ADAPTER_VERSION,
  MICROSOFT_DECLARED_CAPABILITIES,
  MICROSOFT_PROVIDER,
} from './constants';
import { MicrosoftContext, type MicrosoftCalls } from './context';
import { odataString } from './graph-client';
import { ingestMailboxAudit } from './mailbox';
import { mapDirectoryAudit } from './mappers/audits';
import { mapRiskDetection } from './mappers/risk';
import { mapSignIn } from './mappers/sign-ins';
import { probeMicrosoft } from './probe';
import { normalizedAddress } from '../core/normalize';

interface WindowedSpec {
  stream: ProviderStream;
  path: string;
  pathTemplate: string;
  dateField: string;
  family: WindowFamily;
  extraFilter?: string;
  collect(calls: MicrosoftCalls, records: readonly unknown[], page: PageCollector): Promise<void>;
}

/** Ingest outcome when a throttle-like error ends a page early (D7.5). */
export function throttledPage(
  error: ProviderCallError,
  cursor: string,
  events: ProviderIngestPage['events'] = [],
): ProviderIngestPage {
  return { events, cursor, hasMore: true, retryAfterMs: Math.max(1, error.retryAfterMs ?? 1_000) };
}

export class MicrosoftAdapter implements IdpAdapter {
  readonly kind = MICROSOFT_PROVIDER;
  readonly version = MICROSOFT_ADAPTER_VERSION;
  readonly context: MicrosoftContext;
  private lastReport: ProbeReport | null = null;

  constructor(readonly deps: AdapterDeps) {
    if (deps.integration.provider !== MICROSOFT_PROVIDER)
      throw new Error('adapter_provider_mismatch');
    this.context = new MicrosoftContext(deps);
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
      provider: MICROSOFT_PROVIDER,
      declared: MICROSOFT_DECLARED_CAPABILITIES,
      report: this.currentReport(),
      settings: this.deps.integration.settings,
      now: this.deps.clock(),
      healthIntervalSeconds: this.deps.config.healthIntervalSeconds,
    }).capabilities;
  }

  declaredCapabilities(): ProviderCapabilities {
    return MICROSOFT_DECLARED_CAPABILITIES;
  }

  async health(signal: AbortSignal): Promise<{ ok: boolean; code?: string }> {
    const report = await this.probe(signal);
    return report.ok ? { ok: true } : { ok: false, ...(report.code ? { code: report.code } : {}) };
  }

  async probe(signal: AbortSignal): Promise<ProbeReport> {
    const report = await probeMicrosoft(this.context, signal);
    this.lastReport = report;
    return report;
  }

  /** Priority mailbox refresh needs inbox rule reads (MailboxSettings.Read) proven by the last probe. */
  mailboxRefreshSupported(): boolean {
    const report = this.currentReport();
    if (!report || report.streams.mailbox_audit?.availability !== 'available') return false;
    const telemetry = report.grants.find((g) => g.profile === 'm365.ato_telemetry');
    return (
      telemetry?.status === 'active' &&
      !telemetry.missingPermissions.includes('MailboxSettings.Read')
    );
  }

  async ingest(
    stream: ProviderStream,
    cursor: string | null,
    signal: AbortSignal,
  ): Promise<ProviderIngestPage> {
    const role = STREAM_ROLES.microsoft_entra[stream];
    if (role.role === 'companion') {
      return { events: [], cursor: companionCursor(role.primary ?? stream), hasMore: false };
    }
    switch (stream) {
      case 'sign_ins':
        return this.windowed(this.signInSpec(), cursor, signal);
      case 'risk_events':
        return this.windowed(this.riskSpec(), cursor, signal);
      case 'oauth_consents':
        return this.windowed(this.consentSpec(), cursor, signal);
      case 'mailbox_audit':
        return ingestMailboxAudit(this.context, cursor, signal);
      default:
        return { events: [], cursor: companionCursor(stream), hasMore: false };
    }
  }

  private signInSpec(): WindowedSpec {
    return {
      stream: 'sign_ins',
      path: '/v1.0/auditLogs/signIns',
      pathTemplate: '/v1.0/auditLogs/signIns',
      dateField: 'createdDateTime',
      family: 'graph_sign_ins',
      collect: (_calls, records, page) => {
        for (const raw of records) {
          const event = mapSignIn(raw);
          if (event) page.add(event);
          else page.drop('sign_ins', 'invalid');
        }
        return Promise.resolve();
      },
    };
  }

  private riskSpec(): WindowedSpec {
    return {
      stream: 'risk_events',
      path: '/v1.0/identityProtection/riskDetections',
      pathTemplate: '/v1.0/identityProtection/riskDetections',
      dateField: 'lastUpdatedDateTime',
      family: 'graph_risk',
      collect: (_calls, records, page) => {
        for (const raw of records) {
          const result = mapRiskDetection(raw);
          if (result.kind === 'event') page.add(result.event);
          else
            page.drop('risk_events', result.kind === 'dropped' ? 'dropped_operation' : 'invalid');
        }
        return Promise.resolve();
      },
    };
  }

  private consentSpec(): WindowedSpec {
    return {
      stream: 'oauth_consents',
      path: '/v1.0/auditLogs/directoryAudits',
      pathTemplate: '/v1.0/auditLogs/directoryAudits',
      dateField: 'activityDateTime',
      family: 'graph_audits',
      extraFilter: `activityDisplayName in (${CONSENT_ACTIVITIES.map(odataString).join(',')})`,
      collect: async (calls, records, page) => {
        const lookups =
          calls.session.hasObservedPermission('m365.ato_telemetry', 'Directory.Read.All') ||
          calls.session.hasObservedPermission('m365.ato_telemetry', 'Application.Read.All');
        for (const raw of records) {
          const result = mapDirectoryAudit(raw);
          if (result.kind !== 'event') {
            page.drop(
              'oauth_consents',
              result.kind === 'dropped' ? 'dropped_operation' : 'invalid',
            );
            continue;
          }
          if (lookups && result.event.oauth) {
            const verified = await this.context.publisherVerified(calls, result.servicePrincipalId);
            if (verified !== undefined) result.event.oauth.publisherVerified = verified;
          }
          page.add(result.event);
        }
      },
    };
  }

  /** A windowed Graph stream: one page per call; cursor `{ wm, ws, we, page: $skiptoken }` (D7). */
  private async windowed(
    spec: WindowedSpec,
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
        family: spec.family,
        watermark: cursor.wm ? new Date(cursor.wm) : null,
        now,
        retentionDays: PROVIDER_RETENTION_DAYS.microsoft_entra[spec.stream],
      });
      if (window === null) return { events: [], cursor: unchanged, hasMore: false };
    }
    const page = new PageCollector(this.kind, this.deps.integration.settings, this.deps.metrics);
    try {
      const calls = await this.context.open(signal);
      const clauses = [
        `${spec.dateField} ge ${window.start.toISOString()}`,
        `${spec.dateField} le ${window.end.toISOString()}`,
      ];
      if (spec.extraFilter) clauses.push(spec.extraFilter);
      const params = new URLSearchParams({
        $filter: clauses.join(' and '),
        $top: String(this.deps.config.pageMaxEvents),
      });
      if (typeof cursor.page === 'string') params.set('$skiptoken', cursor.page);
      const result = await calls.graph.page(`${spec.path}?${params.toString()}`, spec.pathTemplate);
      await spec.collect(calls, result.value, page);
      const nextLink = result['@odata.nextLink'];
      const next: CursorV1 = { v: 1, a: this.version, seq: cursor.seq + 1 };
      let hasMore: boolean;
      if (nextLink) {
        next.wm = cursor.wm;
        next.ws = window.start.toISOString();
        next.we = window.end.toISOString();
        next.page = calls.graph.skipToken(nextLink);
        if (next.wm === undefined) delete next.wm;
        hasMore = true;
      } else {
        next.wm = window.end.toISOString();
        hasMore = hasMoreWindows({ family: spec.family, watermark: window.end, now });
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

  async resolveIdentity(address: string, signal: AbortSignal): Promise<ProviderIdentityRef | null> {
    const normalized = normalizedAddress(address);
    if (!normalized) return null;
    const calls = await this.context.open(signal);
    const direct = await calls.graph.getUser(normalized);
    if (direct) return this.context.identityFromUser(direct);
    const byMail = await calls.graph.findUsers(`mail eq ${odataString(normalized)}`, false);
    if (byMail.length === 1 && byMail[0]) return this.context.identityFromUser(byMail[0]);
    const byProxy = await calls.graph.findUsers(
      `proxyAddresses/any(x:x eq ${odataString(`smtp:${normalized}`)})`,
      true,
    );
    if (byProxy.length === 1 && byProxy[0]) return this.context.identityFromUser(byProxy[0]);
    return null;
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
   * Checked before an action's first step (D6, D9.1): disabled in the binding settings ⇒
   * `action_disabled`; a stale report is refreshed by a probe first; an action whose probed
   * availability is not `available` ⇒ `not_configured` or `capability_unavailable` (unsupported,
   * never executed). The 8.4 worker checks the effective capability as well.
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

/** Factory used by WP2's `createIdpAdapter` for kind `microsoft_entra`. */
export function createMicrosoftAdapter(deps: AdapterDeps): MicrosoftAdapter {
  return new MicrosoftAdapter(deps);
}
