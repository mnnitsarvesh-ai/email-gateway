import {
  PROVIDER_ACTION_TYPES,
  PROVIDER_STREAMS,
  type ProviderActionType,
  type ProviderStream,
} from '@email-gateway/ato-detection';
import {
  type AtoProviderKind,
  computeEffectiveCapabilities,
  connectionProviderFromKind,
  defaultBindingSettings,
  type DirectoryConnection,
  type DirectoryProfileView,
  GOOGLE_DECLARED_CAPABILITIES,
  type IdpBindingSettings,
  isReportStale,
  MICROSOFT_DECLARED_CAPABILITIES,
  PERMISSION_REQUIREMENTS,
  PROVIDER_RETENTION_DAYS,
  type ProbeReport,
  STREAM_ROLES,
  streamLagSeconds,
  validateBindingSettings,
} from '@email-gateway/idp-adapters';
import type {
  MailboxStateView,
  ProviderConnectionsView,
  ProviderDetailView,
  ProviderRequirementsView,
  ProviderSummaryView,
} from '../dto/ato-providers.schemas';
import type { IntegrationRow, StreamRow } from '../repositories/ato-providers.repository';

/**
 * Pure view builders of the step 8.5 identity-provider routes (design note §6, D3, D6, D10):
 * integrations with their health, streams, effective capabilities and permissions, the 8.2
 * connections with their D4 eligibility, the requirements catalogue and the mailbox state items.
 * No database access; every input is a row already scoped to the caller's organization.
 */

/** Failures after which a stream counts as failing (8.4 ATO_PROVIDER_MAX_CONSECUTIVE_FAILURES). */
const FAILING_AFTER = 3;

export const ATO_PROVIDER_KIND_VALUES: readonly AtoProviderKind[] = [
  'microsoft_entra',
  'google_workspace',
];

/** The provider kind of a row, or null for a kind the providers routes do not manage (`fake`). */
export function kindOf(row: Pick<IntegrationRow, 'provider'>): AtoProviderKind | null {
  return (ATO_PROVIDER_KIND_VALUES as readonly string[]).includes(row.provider)
    ? (row.provider as AtoProviderKind)
    : null;
}

export function declaredCapabilities(kind: AtoProviderKind) {
  return kind === 'microsoft_entra'
    ? MICROSOFT_DECLARED_CAPABILITIES
    : GOOGLE_DECLARED_CAPABILITIES;
}

const iso = (d: Date | null | undefined): string | null => (d ? d.toISOString() : null);

/** The stored settings of an integration (defaults, flagged invalid, when they no longer validate). */
export function resolveSettings(
  kind: AtoProviderKind,
  stored: unknown,
): { settings: IdpBindingSettings; invalid: boolean } {
  const result = validateBindingSettings(kind, stored);
  return result.ok
    ? { settings: result.settings, invalid: false }
    : { settings: defaultBindingSettings(), invalid: true };
}

/** The last probe report of `health_detail` (null when absent or not a report). */
export function parseReport(raw: unknown): ProbeReport | null {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const r = raw as Partial<ProbeReport>;
  if (
    typeof r.checkedAt !== 'string' ||
    typeof r.ok !== 'boolean' ||
    r.streams === null ||
    typeof r.streams !== 'object' ||
    r.actions === null ||
    typeof r.actions !== 'object'
  ) {
    return null;
  }
  // `health_detail` may omit the grants (the stored report drops domains and permission names).
  return { ...(r as ProbeReport), grants: Array.isArray(r.grants) ? r.grants : [] };
}

function stringList(raw: unknown, max: number): string[] {
  return Array.isArray(raw)
    ? raw.filter((v): v is string => typeof v === 'string').slice(0, max)
    : [];
}

interface Context {
  now: Date;
  healthIntervalSeconds: number;
}

function effective(
  row: IntegrationRow,
  kind: AtoProviderKind,
  settings: IdpBindingSettings,
  ctx: Context,
) {
  return computeEffectiveCapabilities({
    provider: kind,
    declared: declaredCapabilities(kind),
    report: parseReport(row.healthDetail),
    settings,
    now: ctx.now,
    healthIntervalSeconds: ctx.healthIntervalSeconds,
  });
}

function connectionRef(
  row: IntegrationRow,
  kind: AtoProviderKind,
  entry: DirectoryConnection | null | undefined,
): ProviderSummaryView['connection'] {
  if (row.connectorRef === null) return null;
  if (!entry) {
    return {
      id: row.connectorRef,
      provider: connectionProviderFromKind(kind),
      displayName: row.displayName ?? '',
      status: 'missing',
    };
  }
  return {
    id: entry.connection.publicId,
    provider: entry.connection.provider,
    displayName: entry.connection.displayName,
    status: entry.connection.status,
  };
}

function isPrimary(kind: AtoProviderKind, stream: ProviderStream): boolean {
  return STREAM_ROLES[kind][stream].role === 'primary';
}

/** The list item of an integration (§6 #1). */
export function summaryView(
  row: IntegrationRow,
  kind: AtoProviderKind,
  streams: readonly StreamRow[],
  entry: DirectoryConnection | null | undefined,
  ctx: Context,
): ProviderSummaryView {
  const { settings } = resolveSettings(kind, row.settings);
  const caps = effective(row, kind, settings, ctx);
  const report = parseReport(row.healthDetail);
  const primaries = streams.filter((s) => s.enabled && isPrimary(kind, s.stream));
  const lags = primaries
    .map((s) => streamLagSeconds(s.watermarkAt, ctx.now))
    .filter((l): l is number => l !== null);
  return {
    id: row.publicId,
    provider: kind,
    displayName: row.displayName,
    status: row.status,
    pausedReason: row.pausedReason,
    disabledReason: row.disabledReason,
    disabledAt: iso(row.disabledAt),
    connection: connectionRef(row, kind, entry),
    health: {
      status: row.healthStatus,
      checkedAt: iso(row.healthCheckedAt),
      stale: isReportStale(report, ctx.now, ctx.healthIntervalSeconds),
    },
    streams: {
      enabled: primaries.length,
      available: primaries.filter((s) => s.availability === 'available').length,
      failing: primaries.filter(
        (s) => s.status === 'error' || s.consecutiveFailures >= FAILING_AFTER,
      ).length,
      backfilling: primaries.filter((s) => s.status === 'backfilling').length,
      maxLagSeconds: lags.length === 0 ? null : Math.max(0, ...lags.map((l) => Math.round(l))),
    },
    capabilities: {
      streams: PROVIDER_STREAMS.filter((s) => caps.view.streams[s] === 'available'),
      actions: PROVIDER_ACTION_TYPES.filter((a) => caps.view.actions[a] === 'available'),
    },
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export function profileView(
  p: DirectoryProfileView,
): ProviderDetailView['permissions']['profiles'][number] {
  return {
    profile: p.profile,
    purpose: p.purpose,
    title: p.title,
    readOnly: p.readOnly,
    required: [...p.required],
    notObservable: [...p.notObservable],
    grant: p.grant
      ? {
          id: p.grant.publicId,
          status: p.grant.status,
          observed: p.grant.observed === null ? null : [...p.grant.observed],
          missing: [...p.grant.missing],
          excess: [...p.grant.excess],
        }
      : null,
  };
}

/** The full view of an integration (§6 #5). */
export function detailView(
  row: IntegrationRow,
  kind: AtoProviderKind,
  streams: readonly StreamRow[],
  entry: DirectoryConnection | null | undefined,
  ctx: Context,
): ProviderDetailView {
  const summary = summaryView(row, kind, streams, entry, ctx);
  const { settings, invalid } = resolveSettings(kind, row.settings);
  const caps = effective(row, kind, settings, ctx);
  const report = parseReport(row.healthDetail);
  const byStream = new Map(streams.map((s) => [s.stream, s]));
  const requirements = PERMISSION_REQUIREMENTS[kind];
  return {
    ...summary,
    rowVersion: row.rowVersion,
    settingsVersion: row.settingsVersion,
    settingsSchema: 'ato-idp-binding/1',
    settings,
    settingsInvalid: invalid,
    healthDetail: {
      status: row.healthStatus,
      checkedAt: iso(row.healthCheckedAt),
      nextCheckAt: iso(row.nextHealthAt),
      stale: summary.health.stale,
      ok: report?.ok ?? null,
      code: report?.code ?? null,
      grants: (report?.grants ?? []).slice(0, 10).map((g) => ({
        profile: g.profile,
        status: g.status,
        missingPermissions: stringList(g.missingPermissions, 64),
      })),
    },
    streamDetails: PROVIDER_STREAMS.map((stream) => {
      const s = byStream.get(stream);
      const role = STREAM_ROLES[kind][stream];
      const lag = s ? streamLagSeconds(s.watermarkAt, ctx.now) : null;
      return {
        stream,
        role: role.role,
        primary: role.primary ?? null,
        enabled: s?.enabled ?? false,
        status: s?.status ?? (role.role === 'unsupported' ? 'unsupported' : 'paused'),
        availability: s?.availability ?? (role.role === 'unsupported' ? 'not_offered' : 'unknown'),
        availabilityCode: s?.availabilityCode ?? null,
        capability: caps.view.streams[stream],
        watermarkAt: iso(s?.watermarkAt),
        lagSeconds: lag === null ? null : Math.max(0, Math.round(lag)),
        nextPollAt: iso(s?.nextPollAt),
        lastAttemptAt: iso(s?.lastAttemptAt),
        lastSuccessAt: iso(s?.lastSuccessAt),
        lastEventAt: iso(s?.lastEventAt),
        lastErrorCode: s?.lastErrorCode ?? null,
        consecutiveFailures: s?.consecutiveFailures ?? 0,
        throttledUntil: iso(s?.throttledUntil),
        backfill: {
          active: s?.status === 'backfilling',
          from: iso(s?.backfillFrom),
          requestedAt: iso(s?.backfillRequestedAt),
          completedAt: iso(s?.backfillCompletedAt),
        },
        eventsTotal: Number(s?.eventsTotal ?? 0n),
        pagesTotal: Number(s?.pagesTotal ?? 0n),
      };
    }),
    actions: PROVIDER_ACTION_TYPES.map((action: ProviderActionType) => {
      const req = requirements.actions[action];
      const probed = report?.actions[action];
      return {
        action,
        enabled: settings.actions[action].enabled,
        capability: caps.view.actions[action],
        code: probed?.code ?? null,
        rollback: req.rollback,
        confirmation: req.confirmation,
        requiresConfiguration: req.requiresConfiguration ?? null,
      };
    }),
    permissions: {
      granted: stringList(row.grantedPermissions, 64),
      profiles: entry ? entry.profiles.map(profileView) : [],
    },
    directory: { domainCount: stringList(row.directoryDomains, 500).length },
  };
}

/** One 8.2 connection with its D4 eligibility (§6 #3). */
export function connectionCandidateView(
  entry: DirectoryConnection,
  eligibility: {
    eligibility: ProviderConnectionsView['data'][number]['eligibility'];
    reasons: ProviderConnectionsView['data'][number]['reasons'];
  },
  integrationId: string | null,
): ProviderConnectionsView['data'][number] {
  return {
    id: entry.connection.publicId,
    provider: entry.connection.provider,
    kind: entry.kind,
    displayName: entry.connection.displayName,
    status: entry.connection.status,
    eligibility: eligibility.eligibility,
    reasons: [...eligibility.reasons],
    integrationId,
    providerVerifiedDomainCount: entry.providerVerifiedDomains.length,
    profiles: entry.profiles.map(profileView),
  };
}

/** `PERMISSION_REQUIREMENTS` of both providers (§6 #2). */
export function requirementsView(): ProviderRequirementsView {
  return {
    providers: ATO_PROVIDER_KIND_VALUES.map((kind) => {
      const r = PERMISSION_REQUIREMENTS[kind];
      return {
        provider: kind,
        connectionProvider: connectionProviderFromKind(kind),
        profiles: r.profiles.map((p) => ({
          key: p.key,
          version: p.version,
          purpose: p.purpose,
          readOnly: p.readOnly,
          title: p.title,
          description: p.description,
          permissions: p.permissions.map((perm) => ({ name: perm.name, api: perm.api })),
        })),
        streams: PROVIDER_STREAMS.map((stream) => {
          const s = r.streams[stream];
          return {
            stream,
            role: s.role,
            primary: s.primary ?? null,
            profile: s.profile,
            permissions: [...s.permissions],
            optionalPermissions: [...(s.optionalPermissions ?? [])],
            licences: [...s.licences],
            retentionDays: PROVIDER_RETENTION_DAYS[kind][stream],
            notes: s.notes,
          };
        }),
        actions: PROVIDER_ACTION_TYPES.map((action) => {
          const a = r.actions[action];
          return {
            action,
            supported: a.supported,
            profile: a.profile,
            permissions: [...a.permissions],
            rollback: a.rollback,
            confirmation: a.confirmation,
            impact: a.impact,
            requiresConfiguration: a.requiresConfiguration ?? null,
            notes: a.notes,
          };
        }),
        licences: r.licences.map((l) => ({ code: l.code, title: l.title, enables: l.enables })),
        notes: [...r.notes],
      };
    }),
  };
}

/** The stream whose polls build the mailbox state of a provider (D8.3). */
export function mailboxStateStream(kind: AtoProviderKind): ProviderStream {
  return kind === 'google_workspace' ? 'forwarding_changes' : 'mailbox_audit';
}

/**
 * Whether a priority mailbox refresh reaches an integration (§6 #13): the integration is active,
 * its mailbox-state stream is enabled and, as the adapters' `mailboxRefreshSupported()` decides
 * from the last probe (D6), available — for Microsoft also the inbox rule reads
 * (`MailboxSettings.Read`) on an active telemetry grant.
 */
export function refreshSupported(row: IntegrationRow, kind: AtoProviderKind): boolean {
  if (row.status !== 'active') return false;
  const { settings } = resolveSettings(kind, row.settings);
  const stream = mailboxStateStream(kind);
  if (!settings.streams[stream].enabled) return false;
  const report = parseReport(row.healthDetail);
  if (report?.streams[stream]?.availability !== 'available') return false;
  if (kind === 'google_workspace') return true;
  const telemetry = report.grants.find((g) => g.profile === 'm365.ato_telemetry');
  return (
    telemetry?.status === 'active' &&
    !stringList(telemetry.missingPermissions, 64).includes('MailboxSettings.Read')
  );
}

/** One mailbox state item (§6 #12): hashes, kinds, domains and trait codes only. */
export function mailboxItemView(
  item: {
    publicId: string;
    itemKind: MailboxStateView['items'][number]['kind'];
    state: 'present' | 'removed';
    targetDomain: string | null;
    traits: unknown;
    enabled: boolean | null;
    source: 'snapshot' | 'audit';
    lastChange: 'added' | 'changed' | 'removed';
    firstSeenAt: Date;
    lastSeenAt: Date;
    removedAt: Date | null;
  },
  integration: { publicId: string; kind: AtoProviderKind },
): MailboxStateView['items'][number] {
  return {
    id: item.publicId,
    kind: item.itemKind,
    state: item.state,
    targetDomain: item.targetDomain,
    traits: stringList(item.traits, 16),
    enabled: item.enabled,
    source: item.source,
    lastChange: item.lastChange,
    provider: integration.kind,
    integrationId: integration.publicId,
    firstSeenAt: item.firstSeenAt.toISOString(),
    lastSeenAt: item.lastSeenAt.toISOString(),
    removedAt: iso(item.removedAt),
  };
}

/** Dotted paths of the leaves that differ between two settings documents (audit, D10). */
export function changedPaths(before: unknown, after: unknown, prefix = ''): string[] {
  const isObject = (v: unknown): v is Record<string, unknown> =>
    v !== null && typeof v === 'object' && !Array.isArray(v);
  if (isObject(before) && isObject(after)) {
    const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
    return keys.flatMap((k) => changedPaths(before[k], after[k], prefix ? `${prefix}.${k}` : k));
  }
  return JSON.stringify(before) === JSON.stringify(after) ? [] : [prefix || '(root)'];
}
