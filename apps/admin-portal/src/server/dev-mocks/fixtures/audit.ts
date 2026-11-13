import 'server-only';
import type { ListItem } from '@/lib/api/types';
import { SeededRandom, fixtureAnchor, paginate, stableUuid, syntheticPerson } from '../generator';
import {
  apiError,
  type FixtureHandlers,
  type FixtureRequest,
  type FixtureResponse,
} from '../types';
import { withPrincipal } from './reports';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Audit trail and sign-in events (WP3): 150 synthetic entries per organization over 30 days,
 * filtered and paged like the api (range, action / actionPrefix, resource, actor, sort).
 * Metadata is synthetic and contains markup on purpose (the portal renders it as text).
 */

type AuditRow = ListItem<'AuditLogsController_search_v1'>;
type LoginRow = ListItem<'LoginEventsController_list_v1'>;

const ACTIONS: [string, string][] = [
  ['domain.created', 'domain'],
  ['domain.verified', 'domain'],
  ['user.invited', 'user'],
  ['user.roles_replaced', 'user'],
  ['quarantine.released', 'quarantine_entry'],
  ['quarantine.release_requested', 'quarantine_entry'],
  ['policy.published', 'policy'],
  ['api_key.created', 'api_key'],
  ['webhook.updated', 'webhook'],
  ['scan_settings.updated', 'scan_settings'],
  ['audit.searched', 'audit_log'],
  ['attachment.searched', 'attachment'],
];

function auditRows(scope: string): AuditRow[] {
  const r = new SeededRandom(`audit:${scope}`);
  const anchor = fixtureAnchor();
  return Array.from({ length: 150 }, (_, i) => {
    const [action, resourceType] = r.pick(ACTIONS);
    const actorType = r.bool(0.8) ? 'user' : r.bool(0.5) ? 'api_key' : 'system';
    return {
      id: String(9_000_000 + i),
      createdAt: new Date(anchor - i * 4.7 * 3_600_000 - r.int(0, 3_000_000)).toISOString(),
      actor: {
        type: actorType,
        id: actorType === 'system' ? null : stableUuid(`actor:${scope}:${r.int(1, 6)}`),
      },
      action,
      resourceType,
      resourceId: stableUuid(`${resourceType}:${scope}:${r.int(1, 30)}`),
      correlationId: r.uuid(),
      sourceIp: actorType === 'system' ? null : `198.51.100.${r.int(2, 250)}`,
      metadata: r.bool(0.7)
        ? {
            reason: r.pick(['ticket 4711', 'routine change', 'user request <b>urgent</b>']),
            changed: r.int(1, 4),
          }
        : null,
    } satisfies AuditRow;
  });
}

function filterAudit(rows: AuditRow[], q: URLSearchParams): AuditRow[] | FixtureResponse {
  const to = q.get('to') ? Date.parse(q.get('to') ?? '') : Date.now() + 3_600_000;
  const from = q.get('from') ? Date.parse(q.get('from') ?? '') : to - 7 * 86_400_000;
  if (!Number.isFinite(from) || !Number.isFinite(to))
    return apiError(400, 'validation_failed', ['from: must be an ISO 8601 date-time']);
  if (to - from > 90 * 86_400_000)
    return apiError(400, 'validation_failed', ['from: the range is longer than 90 days']);
  const prefix = q.get('actionPrefix');
  if (prefix && !/^[a-z_]+\.$/.test(prefix))
    return apiError(400, 'validation_failed', ['actionPrefix: must match ^[a-z_]+\\.$']);
  const out = rows.filter((row) => {
    const t = Date.parse(row.createdAt);
    return (
      t >= from &&
      t < to &&
      (!q.get('action') || row.action === q.get('action')) &&
      (!prefix || row.action.startsWith(prefix)) &&
      (!q.get('resourceType') || row.resourceType === q.get('resourceType')) &&
      (!q.get('resourceId') || row.resourceId === q.get('resourceId')) &&
      (!q.get('actorType') || row.actor.type === q.get('actorType')) &&
      (!q.get('actorId') || row.actor.id === q.get('actorId'))
    );
  });
  return q.get('sort') === 'createdAt' ? out.reverse() : out;
}

function loginRows(scope: string): LoginRow[] {
  const r = new SeededRandom(`logins:${scope}`);
  const anchor = fixtureAnchor();
  const outcomes: LoginRow['outcome'][] = [
    'success',
    'success',
    'success',
    'success',
    'failure',
    'mfa_required',
    'mfa_failure',
    'locked',
    'rate_limited',
  ];
  return Array.from({ length: 80 }, (_, i) => {
    const person = syntheticPerson(r);
    const outcome = r.pick(outcomes);
    const known = outcome !== 'failure' || r.bool(0.5);
    return {
      id: String(500_000 + i),
      occurredAt: new Date(anchor - i * 2.3 * 3_600_000).toISOString(),
      email: person.email,
      outcome,
      failureReason:
        outcome === 'failure'
          ? known
            ? 'invalid_credentials'
            : 'unknown_user'
          : outcome === 'locked'
            ? 'account_locked'
            : null,
      ipAddress: `203.0.113.${r.int(2, 250)}`,
      userAgent: r.pick([
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0',
        'curl/8.7.1',
      ]),
      userId: known ? stableUuid(`user:${person.email}`) : null,
    } satisfies LoginRow;
  });
}

function searchResponse(
  rows: AuditRow[] | FixtureResponse,
  request: FixtureRequest,
): FixtureResponse {
  if (!Array.isArray(rows)) return rows;
  return { status: 200, body: paginate(rows, request.query) };
}

export const fixtures: FixtureHandlers = {
  AuditLogsController_search_v1: (request) =>
    withPrincipal(request, (p) =>
      searchResponse(filterAudit(auditRows(p.organizationId), request.query), request),
    ),

  LoginEventsController_list_v1: (request) =>
    withPrincipal(request, (p) => {
      const q = request.query;
      const to = q.get('to') ? Date.parse(q.get('to') ?? '') : Date.now() + 3_600_000;
      const from = q.get('from') ? Date.parse(q.get('from') ?? '') : 0;
      const rows = loginRows(p.organizationId).filter((row) => {
        const t = Date.parse(row.occurredAt);
        return (
          t >= from &&
          t < to &&
          (!q.get('userId') || row.userId === q.get('userId')) &&
          (!q.get('outcome') || row.outcome === q.get('outcome'))
        );
      });
      return { status: 200, body: paginate(rows, q) };
    }),

  PlatformAuditLogsController_search_v1: (request) =>
    withPrincipal(request, () => {
      const organizationId = request.query.get('organizationId');
      const scope = request.query.get('scope');
      if ((organizationId ? 1 : 0) + (scope ? 1 : 0) !== 1) {
        return apiError(400, 'validation_failed', [
          'organizationId: give exactly one of organizationId or scope=platform',
        ]);
      }
      return searchResponse(
        filterAudit(auditRows(organizationId ?? 'platform-scope'), request.query),
        request,
      );
    }),
};
