import 'server-only';
import { fixtureAnchor, paginate, stableUuid } from '../generator';
import {
  apiError,
  ok,
  type FixtureHandler,
  type FixtureHandlers,
  type FixtureRequest,
  type FixtureResponse,
} from '../types';
import {
  RESOLUTIONS,
  TRANSITIONS,
  atoOrgOf,
  bodyOf,
  idempotent,
  principalOf,
  type IncidentDetail,
  type IncidentRecord,
  type OrgAto,
  type TimelineEntry,
} from './ato';
import { fixtureGuard } from './messages';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of the generic security incident routes (step 8.4 §5.2, D24): the 8 `incidents`
 * operations over the ATO fixture state (category `account_takeover`, the only one in 8.4). Every
 * read is limited to the categories whose permission the caller holds (another category's id
 * answers `404 incident_not_found`, like another tenant's); transitions follow the shared state
 * machine with its resolution and note requirements; updates use `expectedRowVersion` (CAS).
 */

export const INCIDENT_OPERATIONS = [
  'IncidentsController_list_v1',
  'IncidentsController_create_v1',
  'IncidentsController_get_v1',
  'IncidentsController_update_v1',
  'IncidentsController_addNote_v1',
  'IncidentsController_timeline_v1',
  'IncidentsController_messages_v1',
  'IncidentsController_report_v1',
] as const;

const CATEGORY_PERMISSIONS: Record<string, { read: string; manage: string }> = {
  account_takeover: { read: 'ato:read', manage: 'ato:manage' },
};

function route(handler: (request: FixtureRequest, org: OrgAto) => FixtureResponse): FixtureHandler {
  return (request) => fixtureGuard(request) ?? handler(request, atoOrgOf(request));
}

function canRead(request: FixtureRequest, category: string): boolean {
  const p = CATEGORY_PERMISSIONS[category];
  return Boolean(p && principalOf(request).permissions.includes(p.read));
}

function canManage(request: FixtureRequest, category: string): boolean {
  const p = CATEGORY_PERMISSIONS[category];
  return Boolean(p && principalOf(request).permissions.includes(p.manage));
}

/** The incident as the caller sees it (`canManage`, `allowedTransitions`). */
function view(request: FixtureRequest, record: IncidentRecord): IncidentDetail {
  const manage = canManage(request, record.incident.category);
  return {
    ...record.incident,
    canManage: manage,
    allowedTransitions: manage
      ? (TRANSITIONS[record.incident.status] ?? []).map((to) => ({
          to: to as IncidentDetail['status'],
          resolutionCodes: RESOLUTIONS[to] ?? [],
          noteRequired: to === 'confirmed' || Boolean(RESOLUTIONS[to]),
        }))
      : [],
  };
}

function find(request: FixtureRequest, org: OrgAto): IncidentRecord | FixtureResponse {
  const record = org.incidents.get(request.params.incidentId ?? '');
  if (!record || !canRead(request, record.incident.category)) {
    return apiError(404, 'incident_not_found', 'Incident not found');
  }
  return record;
}

const isResponse = (v: unknown): v is FixtureResponse =>
  typeof v === 'object' &&
  v !== null &&
  'status' in v &&
  typeof v.status === 'number' &&
  !('incident' in v);

function event(
  request: FixtureRequest,
  record: IncidentRecord,
  entry: Partial<TimelineEntry> & { type: string },
): void {
  const now = new Date().toISOString();
  record.timeline.push({
    id: stableUuid(`tl:${record.incident.id}:${record.timeline.length}:${now}`)
      .replace(/-/g, '')
      .slice(0, 20),
    at: now,
    actor: { type: 'user', id: principalOf(request).userId },
    fromStatus: null,
    toStatus: null,
    fromSeverity: null,
    toSeverity: null,
    note: null,
    details: null,
    ...entry,
  });
}

const list = (query: URLSearchParams, key: string) =>
  (query.get(key) ?? '')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean);

const SEVERITY_RANK: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };

export const fixtures: FixtureHandlers = {
  IncidentsController_list_v1: route((request, org) => {
    const q = request.query;
    const categories = list(q, 'category');
    const statuses = list(q, 'status');
    const severities = list(q, 'severity');
    const assignee = q.get('assignee');
    const me = principalOf(request).userId;
    const rows = [...org.incidents.values()]
      .map((r) => r.incident)
      .filter(
        (i) =>
          canRead(request, i.category) &&
          (categories.length === 0 || categories.includes(i.category)) &&
          (statuses.length === 0 || statuses.includes(i.status)) &&
          (severities.length === 0 || severities.includes(i.severity)) &&
          (!assignee ||
            (assignee === 'me'
              ? i.assigneeId === me
              : assignee === 'unassigned'
                ? !i.assigneeId
                : i.assigneeId === assignee)),
      )
      .sort((a, b) =>
        q.get('sort') === '-severity'
          ? (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0) ||
            b.detectedAt.localeCompare(a.detectedAt)
          : b.detectedAt.localeCompare(a.detectedAt),
      )
      .map(
        ({
          rowVersion: _rv,
          detectorVersion: _dv,
          firstEvidenceAt: _f,
          assignedAt: _a,
          confirmedAt: _c,
          mitigatedAt: _m,
          resolution: _r,
          createdBy: _cb,
          canManage: _cm,
          allowedTransitions: _t,
          evidence: _e,
          detail: _d,
          ...summary
        }) => summary,
      );
    return { status: 200, body: paginate(rows, q) };
  }),

  IncidentsController_create_v1: route((request, org) =>
    idempotent(request, org, () => {
      const body = bodyOf(request);
      const category = typeof body.category === 'string' ? body.category : '';
      if (!CATEGORY_PERMISSIONS[category])
        return apiError(422, 'incident_category_unsupported', 'Unsupported category');
      if (!canManage(request, category))
        return apiError(404, 'incident_not_found', 'Incident not found');
      const reason = typeof body.reason === 'string' ? body.reason.trim() : '';
      if (reason.length < 10 || reason.length > 4000) {
        return apiError(400, 'validation_failed', ['reason: must be 10-4000 characters']);
      }
      const subject = (body.subject ?? {}) as { type?: string; id?: string };
      const account = org.accounts.get(subject.id ?? '');
      if (!account || subject.type !== 'ato_account') {
        return apiError(404, 'incident_subject_not_found', 'Subject not found');
      }
      if (account.activeIncident) {
        return apiError(409, 'incident_active', 'The subject has an active incident', {
          incidentId: account.activeIncident.id,
        });
      }
      const now = new Date().toISOString();
      const id = crypto.randomUUID();
      const severity = (body.severity as IncidentDetail['severity'] | undefined) ?? 'medium';
      const incident: IncidentDetail = {
        id,
        category,
        subject: {
          type: 'ato_account',
          id: account.id,
          display: account.address ?? account.displayName,
        },
        origin: 'manual',
        status: 'open',
        severity,
        titleCode: null,
        reasonCodes: [],
        detectedAt: now,
        lastEvidenceAt: null,
        evidenceCount: 0,
        assigneeId: null,
        escalatedAt: null,
        resolvedAt: null,
        resolutionCode: null,
        createdAt: now,
        updatedAt: now,
        rowVersion: 1,
        detectorVersion: null,
        firstEvidenceAt: null,
        assignedAt: null,
        confirmedAt: null,
        mitigatedAt: null,
        resolution: null,
        createdBy: { type: 'user', id: principalOf(request).userId },
        canManage: true,
        allowedTransitions: [],
        evidence: {},
        detail: {
          account: {
            id: account.id,
            kind: account.kind,
            address: account.address,
            userId: null,
            connectorId: null,
            riskScore: account.riskScore,
            riskLevel: account.riskLevel,
            protected: account.protected,
          },
          riskScoreAtOpen: account.riskScore,
          peakRiskScore: account.riskScore,
          detectionReason: { codes: [], contributions: [], versions: {} },
          detectionReasonText: [],
          recommendedActions: [],
          relatedIps: [],
          geoSummary: null,
          deviceSummary: null,
          counts: { signals: 0, authEvents: 0, messages: 0, findings: 0 },
          responses: { total: 0, pendingApproval: 0, byStatus: {} },
        },
      };
      const record: IncidentRecord = {
        incident,
        timeline: [],
        messages: [],
        signalIds: [],
        authEventIds: [],
      };
      event(request, record, {
        type: 'created',
        toStatus: 'open',
        toSeverity: severity,
        note: reason,
      });
      org.incidents.set(id, record);
      account.activeIncident = { id, severity, status: 'open' };
      return ok('IncidentsController_create_v1', view(request, record), 201);
    }),
  ),

  IncidentsController_get_v1: route((request, org) => {
    const record = find(request, org);
    return isResponse(record) ? record : ok('IncidentsController_get_v1', view(request, record));
  }),

  IncidentsController_update_v1: route((request, org) => {
    const record = find(request, org);
    if (isResponse(record)) return record;
    if (!canManage(request, record.incident.category))
      return apiError(404, 'incident_not_found', 'Incident not found');
    return idempotent(request, org, () => {
      const body = bodyOf(request);
      const incident = record.incident;
      if (body.expectedRowVersion !== incident.rowVersion) {
        return apiError(409, 'incident_conflict', 'The incident changed', {
          currentRowVersion: incident.rowVersion,
        });
      }
      if (incident.status === 'false_positive' || incident.status === 'resolved') {
        return apiError(409, 'incident_closed', 'The incident is closed');
      }
      const now = new Date().toISOString();
      const note = typeof body.note === 'string' && body.note.trim() ? body.note.trim() : null;
      if (typeof body.status === 'string' && body.status !== incident.status) {
        const to = body.status as IncidentDetail['status'];
        if (!(TRANSITIONS[incident.status] ?? []).includes(to)) {
          return apiError(422, 'incident_transition_invalid', 'Transition not allowed', {
            reason: 'not_allowed',
            from: incident.status,
            to,
          });
        }
        const resolution = body.resolution as { code?: string; note?: string } | undefined;
        if (RESOLUTIONS[to]) {
          if (
            !resolution?.code ||
            !RESOLUTIONS[to].includes(resolution.code as never) ||
            (resolution.note ?? '').trim().length < 10
          ) {
            return apiError(
              422,
              'incident_transition_invalid',
              'A resolution with a note is required',
              { reason: 'resolution_required', from: incident.status, to },
            );
          }
          incident.resolution = {
            code: resolution.code as never,
            note: resolution.note ?? '',
            resolvedAt: now,
          };
          incident.resolutionCode = resolution.code as never;
          incident.resolvedAt = now;
        } else if (to === 'confirmed' && !note) {
          return apiError(422, 'incident_transition_invalid', 'A note is required', {
            reason: 'note_required',
            from: incident.status,
            to,
          });
        }
        if (to === 'confirmed') incident.confirmedAt = now;
        if (to === 'mitigated') incident.mitigatedAt = now;
        event(request, record, {
          type: 'status_changed',
          fromStatus: incident.status,
          toStatus: to,
          note: (resolution?.note ?? note) || null,
        });
        if (to === 'false_positive') {
          const feedback = (body.categoryFeedback ?? {}) as {
            dismissSignals?: boolean;
            trustedContexts?: unknown[];
          };
          const accountId = (incident.detail as { account?: { id?: string } }).account?.id ?? '';
          if (feedback.dismissSignals !== false) {
            for (const s of org.signals.get(accountId) ?? []) {
              if (record.signalIds.includes(s.id) && s.status === 'active') {
                s.status = 'dismissed';
                s.dismissedAt = now;
                s.dismissReason = `false positive: ${incident.id}`;
              }
            }
          }
          const account = org.accounts.get(accountId);
          if (account) {
            for (const c of Array.isArray(feedback.trustedContexts)
              ? feedback.trustedContexts
              : []) {
              const x = c as { kind: never; value: string; reason: string; expiresInDays: number };
              account.trustedContexts.push({
                id: crypto.randomUUID(),
                kind: x.kind,
                value: x.value,
                reason: x.reason,
                source: 'false_positive_feedback',
                incidentId: incident.id,
                createdAt: now,
                expiresAt: new Date(Date.now() + x.expiresInDays * 86_400_000).toISOString(),
              });
            }
            const active = (org.signals.get(accountId) ?? []).filter((s) => s.status === 'active');
            account.riskScore = Math.min(
              100,
              active.reduce((sum, s) => sum + s.weight, 0),
            );
            account.riskLevel =
              account.riskScore >= 75
                ? 'critical'
                : account.riskScore >= 50
                  ? 'high'
                  : account.riskScore >= 30
                    ? 'medium'
                    : 'low';
          }
          event(request, record, { type: 'ato.feedback_applied' });
        }
        incident.status = to;
      } else if (note && body.assigneeId === undefined && body.severity === undefined) {
        event(request, record, { type: 'note_added', note });
      }
      if (body.assigneeId !== undefined) {
        const assignee = body.assigneeId as string | null;
        incident.assigneeId = assignee;
        incident.assignedAt = assignee ? now : null;
        event(request, record, { type: assignee ? 'assigned' : 'unassigned', note });
      }
      if (typeof body.severity === 'string' && body.severity !== incident.severity) {
        event(request, record, {
          type: 'severity_changed',
          fromSeverity: incident.severity,
          toSeverity: body.severity as never,
          note,
        });
        incident.severity = body.severity as IncidentDetail['severity'];
      }
      incident.rowVersion += 1;
      incident.updatedAt = now;
      const accountId = (incident.detail as { account?: { id?: string } }).account?.id ?? '';
      const account = org.accounts.get(accountId);
      if (account) {
        account.activeIncident =
          incident.status === 'false_positive' || incident.status === 'resolved'
            ? null
            : { id: incident.id, severity: incident.severity, status: incident.status };
      }
      return ok('IncidentsController_update_v1', view(request, record));
    });
  }),

  IncidentsController_addNote_v1: route((request, org) => {
    const record = find(request, org);
    if (isResponse(record)) return record;
    if (!canManage(request, record.incident.category))
      return apiError(404, 'incident_not_found', 'Incident not found');
    return idempotent(request, org, () => {
      const note =
        typeof bodyOf(request).note === 'string' ? (bodyOf(request).note as string).trim() : '';
      if (!note || note.length > 4000)
        return apiError(400, 'validation_failed', ['note: must be 1-4000 characters']);
      event(request, record, { type: 'note_added', note });
      return ok('IncidentsController_addNote_v1', record.timeline.at(-1)!, 201);
    });
  }),

  IncidentsController_timeline_v1: route((request, org) => {
    const record = find(request, org);
    return isResponse(record)
      ? record
      : { status: 200, body: paginate(record.timeline, request.query) };
  }),

  IncidentsController_messages_v1: route((request, org) => {
    const record = find(request, org);
    return isResponse(record)
      ? record
      : { status: 200, body: paginate(record.messages, request.query) };
  }),

  IncidentsController_report_v1: route((request, org) => {
    const record = find(request, org);
    if (isResponse(record)) return record;
    const i = record.incident;
    return ok('IncidentsController_report_v1', {
      version: 'security-incident-report/1',
      generatedAt: new Date(fixtureAnchor()).toISOString(),
      incident: {
        id: i.id,
        category: i.category,
        status: i.status,
        severity: i.severity,
        origin: i.origin,
        detectedAt: i.detectedAt,
        subject: i.subject.display,
        reasonCodes: i.reasonCodes,
      },
      resolution: i.resolution ? { code: i.resolution.code, note: i.resolution.note } : null,
      timeline: record.timeline.map((t) => ({
        at: t.at,
        type: t.type,
        toStatus: t.toStatus,
        toSeverity: t.toSeverity,
      })),
      notes: record.timeline
        .filter((t) => t.note)
        .map((t) => ({
          at: t.at,
          actorType: t.actor.type,
          actorId: t.actor.id,
          note: t.note ?? '',
        })),
      evidence: i.evidence,
      messages: record.messages.map((m) => ({
        messageId: m.id ?? '',
        receivedAt: m.receivedAt,
        direction: m.direction,
        senderMasked: 'f***@alpha.example.test',
      })),
      truncated: false,
      sections: [
        {
          id: 'ato.detection',
          title: 'Detection reason',
          data: { riskScoreAtOpen: (i.detail as Record<string, unknown>).riskScoreAtOpen ?? null },
        },
        {
          id: 'ato.signals',
          title: 'Signals',
          data: [...org.signals.values()]
            .flat()
            .filter((s) => record.signalIds.includes(s.id))
            .map((s) => ({
              code: s.ruleCode,
              title: s.title,
              category: s.category,
              strength: s.strength,
              status: s.status,
              lastOccurredAt: s.lastOccurredAt,
              explanation: s.explanation,
            })),
        },
        {
          id: 'ato.responses',
          title: 'Responses',
          data: [...org.responses.values()]
            .filter((r) => r.incidentId === i.id)
            .map((r) => ({
              id: r.id,
              type: r.actionType,
              status: r.status,
              providerStatus: r.providerStatus,
              requestedAt: r.createdAt,
            })),
        },
      ],
    });
  }),
};
