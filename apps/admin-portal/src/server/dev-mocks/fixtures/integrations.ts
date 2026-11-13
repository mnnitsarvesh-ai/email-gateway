import 'server-only';
import type { RequestBody, SuccessBody } from '@/lib/api/types';
import { paginate, stableUuid } from '../generator';
import { apiError, noContent, ok, type FixtureHandlers, type FixtureResponse } from '../types';
import { DAY, HOUR, MINUTE, bodyOf, domainsOf, guarded, idempotent, isoAgo } from './domains';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of the `integrations` feature (WP4, design P9): webhooks (v1 list, secret once,
 * redacted replay of create and rotate, version conflicts, test pings), the event catalogue,
 * the delivery history with attempts and untrusted response snippets, single and range replays,
 * and API keys (key once, scopes limited to the caller's permissions). Secrets are obviously
 * fake: `whsec_dev_fixture_…`, `egk_dev_fixture_…`.
 */

type Webhook = SuccessBody<'WebhooksController_get_v1'>;
type EventType = Webhook['eventTypes'][number];
type Delivery = SuccessBody<'WebhookDeliveriesController_get_v1'>;
type Replay = SuccessBody<'WebhookDeliveriesController_getReplay_v1'>;
type ApiKey = SuccessBody<'ApiKeysController_list_v1'>['data'][number];

const EVENT_TYPES: {
  type: EventType;
  description: string;
  severity: string;
  appliesFilters: ('directions' | 'domainIds' | 'minSeverity' | 'verdicts')[];
}[] = [
  {
    type: 'email.received',
    description: 'A message was accepted by the gateway',
    severity: 'info',
    appliesFilters: ['directions', 'domainIds'],
  },
  {
    type: 'email.scanned',
    description: 'The initial scan round of a message completed',
    severity: 'info or the verdict severity',
    appliesFilters: ['directions', 'domainIds', 'minSeverity', 'verdicts'],
  },
  {
    type: 'email.threat.detected',
    description: 'A scan found a threat',
    severity: 'by verdict',
    appliesFilters: ['directions', 'domainIds', 'minSeverity', 'verdicts'],
  },
  {
    type: 'email.policy.triggered',
    description: 'A policy rule matched',
    severity: 'by action',
    appliesFilters: ['directions', 'domainIds', 'minSeverity'],
  },
  {
    type: 'email.quarantined',
    description: 'Recipients of a message were quarantined',
    severity: 'medium',
    appliesFilters: ['directions', 'domainIds', 'minSeverity', 'verdicts'],
  },
  {
    type: 'email.released',
    description: 'Quarantined mail was released',
    severity: 'low',
    appliesFilters: ['directions', 'domainIds'],
  },
  {
    type: 'email.delivered',
    description: 'A recipient delivery succeeded',
    severity: 'info',
    appliesFilters: ['directions', 'domainIds'],
  },
  {
    type: 'email.rejected',
    description: 'A message was rejected',
    severity: 'medium',
    appliesFilters: ['directions', 'domainIds', 'minSeverity'],
  },
  {
    type: 'domain.verified',
    description: 'Domain ownership was verified',
    severity: 'info',
    appliesFilters: ['domainIds'],
  },
  {
    type: 'domain.dns.failed',
    description: 'A required DNS record of a domain is missing or invalid',
    severity: 'high',
    appliesFilters: ['domainIds', 'minSeverity'],
  },
];

interface OrgState {
  webhooks: Webhook[];
  deliveries: Map<string, Delivery[]>;
  replays: Map<string, Replay & { polls: number; webhookId: string }>;
  apiKeys: ApiKey[];
}
interface IntegrationState {
  orgs: Map<string, OrgState>;
  idempotency: Map<string, FixtureResponse>;
}
const globalState = globalThis as typeof globalThis & {
  __egDevFixtureIntegrations?: IntegrationState;
};
const state: IntegrationState = (globalState.__egDevFixtureIntegrations ??= {
  orgs: new Map(),
  idempotency: new Map(),
});

const fakeSecret = () => `whsec_dev_fixture_${crypto.randomUUID().replace(/-/g, '')}`;
const fakeKey = () => `egk_dev_fixture_${crypto.randomUUID().replace(/-/g, '')}`;

function webhook(organizationId: string, i: number, overrides: Partial<Webhook>): Webhook {
  const created = isoAgo((i + 1) * 11 * DAY);
  return {
    id: stableUuid(`${organizationId}:webhook:${i}`),
    name: `Webhook ${i + 1}`,
    description: null,
    url: `https://hooks.partner${i + 1}.example.com/email-gateway`,
    eventTypes: ['email.threat.detected', 'email.quarantined'],
    filters: null,
    status: 'active',
    disabledReason: null,
    disabledAt: null,
    maxConcurrency: null,
    secretVersion: 1,
    secretRotatedAt: null,
    previousSecretExpiresAt: null,
    consecutiveFailures: 0,
    failingSince: null,
    lastSuccessAt: isoAgo(12 * MINUTE),
    lastFailureAt: null,
    createdBy: { type: 'user', id: stableUuid('user:organization_admin@example.com') },
    createdAt: created,
    updatedAt: created,
    rowVersion: 1,
    ...overrides,
  };
}

const OUTCOMES = [
  'succeeded',
  'succeeded',
  'succeeded',
  'failed',
  'dead',
  'pending',
  'succeeded',
  'cancelled',
] as const;

function deliveriesFor(hook: Webhook): Delivery[] {
  return Array.from({ length: 40 }, (_, i) => {
    const status = OUTCOMES[i % OUTCOMES.length] ?? 'succeeded';
    const eventType = hook.eventTypes[i % hook.eventTypes.length] ?? 'email.received';
    const occurredAt = isoAgo(i * 37 * MINUTE + 5 * MINUTE);
    const attempts =
      status === 'succeeded' ? 1 : status === 'pending' ? 0 : status === 'dead' ? 8 : 3;
    return {
      id: stableUuid(`${hook.id}:delivery:${i}`),
      eventId: stableUuid(`${hook.id}:event:${i}`),
      eventType,
      occurredAt,
      status,
      trigger: i % 13 === 0 ? 'replay' : 'event',
      deliverySeq: 0,
      attemptCount: attempts,
      nextAttemptAt: status === 'pending' ? new Date(Date.now() + 30_000).toISOString() : null,
      firstAttemptAt: attempts > 0 ? occurredAt : null,
      lastAttemptAt: attempts > 0 ? occurredAt : null,
      lastResponseCode:
        status === 'succeeded' ? 200 : status === 'failed' ? 503 : status === 'dead' ? 500 : null,
      lastLatencyMs: attempts > 0 ? 80 + (i % 7) * 35 : null,
      lastError:
        status === 'failed'
          ? 'http_503'
          : status === 'dead'
            ? 'http_500'
            : status === 'cancelled'
              ? 'webhook_paused'
              : null,
      completedAt: status === 'pending' ? null : occurredAt,
      createdAt: occurredAt,
      attempts: Array.from({ length: attempts }, (_, n) => ({
        attemptNo: n + 1,
        attemptedAt: occurredAt,
        outcome:
          status === 'succeeded' && n === attempts - 1
            ? ('succeeded' as const)
            : ('http_error' as const),
        httpStatus:
          status === 'succeeded' && n === attempts - 1 ? 200 : status === 'dead' ? 500 : 503,
        latencyMs: 80 + n * 40,
        responseSnippet:
          status === 'succeeded'
            ? '{"ok":true}'
            : n === 0
              ? '<html><body><script>alert(1)</script>Service Unavailable</body></html>'
              : 'upstream timeout [token redacted]',
        retryAfterSeconds: n === 0 && status !== 'succeeded' ? 30 : null,
        errorCode:
          status === 'succeeded' && n === attempts - 1
            ? null
            : `http_${status === 'dead' ? 500 : 503}`,
        signatureCount: 1,
      })),
      event: {
        id: stableUuid(`${hook.id}:event:${i}`),
        type: eventType,
        version: 1,
        occurredAt,
        organizationId: 'redacted-in-fixture',
        data: { domain: 'alpha-1.example.test', direction: 'inbound', verdict: 'phishing' },
      },
    };
  });
}

function seed(organizationId: string): OrgState {
  const firstDomain = domainsOf(organizationId)[0]?.domain.id;
  const webhooks = [
    webhook(organizationId, 0, {
      name: 'SIEM threat feed',
      description: 'Threat and quarantine events for the SOC',
      filters: { minSeverity: 'medium', directions: ['inbound'] },
      maxConcurrency: 4,
    }),
    webhook(organizationId, 1, {
      name: 'Ticketing (DNS alerts)',
      eventTypes: ['domain.dns.failed', 'domain.verified'],
      ...(firstDomain ? { filters: { domainIds: [firstDomain] } } : {}),
    }),
    webhook(organizationId, 2, {
      name: 'Legacy receiver',
      status: 'disabled',
      disabledReason: 'sustained_failure',
      disabledAt: isoAgo(DAY),
      consecutiveFailures: 57,
      failingSince: isoAgo(2 * DAY),
      lastFailureAt: isoAgo(DAY),
      lastSuccessAt: isoAgo(3 * DAY),
    }),
    webhook(organizationId, 3, {
      name: 'Staging receiver',
      status: 'paused',
      url: 'https://staging.hooks.example.com/eg?token=receiver-token-123',
    }),
  ];
  const deliveries = new Map(webhooks.map((hook) => [hook.id, deliveriesFor(hook)]));
  const apiKeys: ApiKey[] = [
    {
      name: 'SIEM export',
      scopes: ['message:read', 'report:read', 'audit:read'],
      revokedAt: null,
      expiresAt: new Date(Date.now() + 90 * DAY).toISOString(),
    },
    {
      name: 'Provisioning script',
      scopes: ['domain:read', 'domain:manage', 'user:read'],
      revokedAt: null,
      expiresAt: null,
    },
    {
      name: 'Old monitoring',
      scopes: ['report:read'],
      revokedAt: isoAgo(20 * DAY),
      expiresAt: null,
    },
  ].map((key, i) => ({
    id: stableUuid(`${organizationId}:apikey:${i}`),
    name: key.name,
    prefix: `egk_${stableUuid(`${organizationId}:apikey:${i}`).slice(0, 8)}`,
    scopes: key.scopes,
    createdBy: {
      id: stableUuid('user:organization_admin@example.com'),
      displayName: 'Organization Admin',
    },
    lastUsedAt: key.revokedAt ? isoAgo(25 * DAY) : isoAgo((i + 1) * 3 * HOUR),
    expiresAt: key.expiresAt,
    revokedAt: key.revokedAt,
    createdAt: isoAgo((i + 1) * 30 * DAY),
  }));
  return { webhooks, deliveries, replays: new Map(), apiKeys };
}

function org(organizationId: string): OrgState {
  let value = state.orgs.get(organizationId);
  if (!value) {
    value = seed(organizationId);
    state.orgs.set(organizationId, value);
  }
  return value;
}

const notFound = () => apiError(404, 'webhook_not_found', 'Webhook not found');
const redactSecret = (response: FixtureResponse): FixtureResponse => ({
  ...response,
  body: { ...(response.body as object), secret: null },
});

function checkUrl(url: unknown): FixtureResponse | null {
  try {
    const parsed = new URL(String(url));
    if (parsed.protocol !== 'https:')
      return apiError(422, 'webhook_url_not_allowed', 'The URL must use https', {
        reason: 'scheme',
      });
    if (/^(localhost|127\.|10\.|192\.168\.)|\.(local|internal)$/.test(parsed.hostname))
      return apiError(422, 'webhook_url_not_allowed', 'The host is not allowed', {
        reason: 'name',
      });
    return null;
  } catch {
    return apiError(422, 'webhook_url_not_allowed', 'The URL is not valid', { reason: 'format' });
  }
}

function checkFilters(organizationId: string, filters: unknown): FixtureResponse | null {
  const ids = (filters as { domainIds?: string[] } | null | undefined)?.domainIds ?? [];
  const own = new Set(domainsOf(organizationId).map((e) => e.domain.id));
  const bad = ids.findIndex((id) => !own.has(id));
  return bad >= 0
    ? apiError(422, 'webhook_filter_invalid', 'Unknown domain in the filter', {
        path: `filters.domainIds.${bad}`,
      })
    : null;
}

export const fixtures: FixtureHandlers = {
  WebhooksController_eventTypes_v1: guarded('WebhooksController_eventTypes_v1', () =>
    ok('WebhooksController_eventTypes_v1', {
      data: EVENT_TYPES.map((t) => ({
        ...t,
        version: 1,
        subscribable: true,
        example: { type: t.type, version: 1 },
      })),
      severities: ['info', 'low', 'medium', 'high'],
    }),
  ),
  WebhooksController_list_v1: guarded('WebhooksController_list_v1', (request, p) => {
    const statuses = request.query.get('status')?.split(',').filter(Boolean) ?? [];
    const rows = org(p.organizationId).webhooks.filter((w) =>
      statuses.length > 0 ? statuses.includes(w.status) : w.status !== 'deleted',
    );
    return { status: 200, body: paginate(rows, request.query) };
  }),
  WebhooksController_get_v1: guarded('WebhooksController_get_v1', (request, p) => {
    const hook = org(p.organizationId).webhooks.find((w) => w.id === request.params.webhookId);
    return hook ? ok('WebhooksController_get_v1', hook) : notFound();
  }),
  WebhooksController_create_v1: guarded('WebhooksController_create_v1', (request, p) =>
    idempotent(
      state.idempotency,
      request,
      () => {
        const state = org(p.organizationId);
        const body = bodyOf<RequestBody<'WebhooksController_create_v1'>>(request);
        const urlError = checkUrl(body.url) ?? checkFilters(p.organizationId, body.filters);
        if (urlError) return urlError;
        if (state.webhooks.filter((w) => w.status !== 'deleted').length >= 10)
          return apiError(409, 'webhook_limit_reached', 'Webhook limit reached');
        const now = new Date().toISOString();
        const hook = webhook(p.organizationId, state.webhooks.length, {
          id: stableUuid(`${p.organizationId}:webhook:${now}`),
          name: String(body.name),
          description: body.description ?? null,
          url: String(body.url),
          eventTypes: body.eventTypes ?? [],
          filters: body.filters ?? null,
          status: body.status ?? 'active',
          maxConcurrency: body.maxConcurrency ?? null,
          lastSuccessAt: null,
          createdAt: now,
          updatedAt: now,
        });
        state.webhooks.unshift(hook);
        state.deliveries.set(hook.id, []);
        return ok('WebhooksController_create_v1', { ...hook, secret: fakeSecret() }, 201);
      },
      redactSecret,
    ),
  ),
  WebhooksController_update_v1: guarded('WebhooksController_update_v1', (request, p) => {
    const list = org(p.organizationId).webhooks;
    const index = list.findIndex(
      (w) => w.id === request.params.webhookId && w.status !== 'deleted',
    );
    const current = list[index];
    if (!current) return notFound();
    const body = bodyOf<RequestBody<'WebhooksController_update_v1'>>(request);
    if (body.expectedRowVersion !== current.rowVersion)
      return apiError(409, 'webhook_version_conflict', 'The webhook was changed meanwhile', {
        currentRowVersion: current.rowVersion,
      });
    const refused =
      (body.url !== undefined ? checkUrl(body.url) : null) ??
      (body.filters ? checkFilters(p.organizationId, body.filters) : null);
    if (refused) return refused;
    const next: Webhook = {
      ...current,
      ...(body.name !== undefined ? { name: body.name } : {}),
      ...(body.description !== undefined ? { description: body.description } : {}),
      ...(body.url !== undefined ? { url: body.url } : {}),
      ...(body.eventTypes !== undefined ? { eventTypes: body.eventTypes } : {}),
      ...(body.filters !== undefined ? { filters: body.filters } : {}),
      ...(body.maxConcurrency !== undefined ? { maxConcurrency: body.maxConcurrency } : {}),
      ...(body.status !== undefined
        ? {
            status: body.status,
            ...(body.status === 'active'
              ? {
                  disabledReason: null,
                  disabledAt: null,
                  consecutiveFailures: 0,
                  failingSince: null,
                }
              : {}),
            ...(body.status === 'disabled'
              ? { disabledReason: 'manual', disabledAt: new Date().toISOString() }
              : {}),
          }
        : {}),
      rowVersion: current.rowVersion + 1,
      updatedAt: new Date().toISOString(),
    };
    list[index] = next;
    return ok('WebhooksController_update_v1', next);
  }),
  WebhooksController_delete_v1: guarded('WebhooksController_delete_v1', (request, p) =>
    idempotent(state.idempotency, request, () => {
      const hook = org(p.organizationId).webhooks.find(
        (w) => w.id === request.params.webhookId && w.status !== 'deleted',
      );
      if (!hook) return notFound();
      hook.status = 'deleted';
      return noContent();
    }),
  ),
  WebhooksController_rotate_v1: guarded('WebhooksController_rotate_v1', (request, p) =>
    idempotent(
      state.idempotency,
      request,
      () => {
        const hook = org(p.organizationId).webhooks.find(
          (w) => w.id === request.params.webhookId && w.status !== 'deleted',
        );
        if (!hook) return notFound();
        const overlap = bodyOf<{ overlapHours?: number }>(request).overlapHours ?? 24;
        const now = new Date();
        hook.secretVersion += 1;
        hook.secretRotatedAt = now.toISOString();
        hook.previousSecretExpiresAt =
          overlap > 0 ? new Date(now.getTime() + overlap * HOUR).toISOString() : null;
        return ok('WebhooksController_rotate_v1', {
          id: hook.id,
          secret: fakeSecret(),
          secretVersion: hook.secretVersion,
          secretRotatedAt: hook.secretRotatedAt,
          previousSecretExpiresAt: hook.previousSecretExpiresAt,
        });
      },
      redactSecret,
    ),
  ),
  WebhooksController_test_v1: guarded('WebhooksController_test_v1', (request, p) => {
    const state = org(p.organizationId);
    const hook = state.webhooks.find(
      (w) => w.id === request.params.webhookId && w.status !== 'deleted',
    );
    if (!hook) return notFound();
    if (hook.status !== 'active')
      return apiError(409, 'webhook_not_active', 'The webhook is not active');
    const now = new Date().toISOString();
    const delivery: Delivery = {
      id: stableUuid(`${hook.id}:test:${now}`),
      eventId: stableUuid(`${hook.id}:ping:${now}`),
      eventType: 'webhook.ping',
      occurredAt: now,
      status: 'succeeded',
      trigger: 'test',
      deliverySeq: 0,
      attemptCount: 1,
      nextAttemptAt: null,
      firstAttemptAt: now,
      lastAttemptAt: now,
      lastResponseCode: 204,
      lastLatencyMs: 64,
      lastError: null,
      completedAt: now,
      createdAt: now,
      attempts: [
        {
          attemptNo: 1,
          attemptedAt: now,
          outcome: 'succeeded',
          httpStatus: 204,
          latencyMs: 64,
          responseSnippet: null,
          retryAfterSeconds: null,
          errorCode: null,
          signatureCount: hook.previousSecretExpiresAt ? 2 : 1,
        },
      ],
      event: { type: 'webhook.ping', version: 1, occurredAt: now },
    };
    state.deliveries.set(hook.id, [delivery, ...(state.deliveries.get(hook.id) ?? [])]);
    return ok(
      'WebhooksController_test_v1',
      { deliveryId: delivery.id, eventId: delivery.eventId },
      202,
    );
  }),
  WebhookDeliveriesController_list_v1: guarded(
    'WebhookDeliveriesController_list_v1',
    (request, p) => {
      const state = org(p.organizationId);
      const hook = state.webhooks.find((w) => w.id === request.params.webhookId);
      if (!hook) return notFound();
      const to = Date.parse(request.query.get('to') ?? new Date().toISOString());
      const from = Date.parse(request.query.get('from') ?? new Date(to - DAY).toISOString());
      if (!(from < to) || to - from > 31 * DAY)
        return apiError(400, 'validation_failed', ['from: at most 31 days']);
      const statuses = request.query.get('status')?.split(',').filter(Boolean) ?? [];
      const types = request.query.get('eventType')?.split(',').filter(Boolean) ?? [];
      const triggers = request.query.get('trigger')?.split(',').filter(Boolean) ?? [];
      const rows = (state.deliveries.get(hook.id) ?? [])
        .filter((d) => {
          const at = Date.parse(d.occurredAt);
          return (
            at >= from &&
            at < to &&
            (statuses.length === 0 || statuses.includes(d.status)) &&
            (types.length === 0 || types.includes(d.eventType)) &&
            (triggers.length === 0 || triggers.includes(d.trigger))
          );
        })
        .map(({ attempts: _attempts, event: _event, ...summary }) => summary);
      return { status: 200, body: paginate(rows, request.query) };
    },
  ),
  WebhookDeliveriesController_get_v1: guarded(
    'WebhookDeliveriesController_get_v1',
    (request, p) => {
      const delivery = org(p.organizationId)
        .deliveries.get(request.params.webhookId ?? '')
        ?.find((d) => d.id === request.params.deliveryId);
      return delivery
        ? ok('WebhookDeliveriesController_get_v1', delivery)
        : apiError(404, 'webhook_delivery_not_found', 'Delivery not found');
    },
  ),
  WebhookDeliveriesController_replay_v1: guarded(
    'WebhookDeliveriesController_replay_v1',
    (request, p) =>
      idempotent(state.idempotency, request, () => {
        const state = org(p.organizationId);
        const hook = state.webhooks.find((w) => w.id === request.params.webhookId);
        if (!hook) return notFound();
        if (hook.status !== 'active')
          return apiError(409, 'webhook_not_active', 'The webhook is not active');
        const list = state.deliveries.get(hook.id) ?? [];
        const original = list.find((d) => d.id === request.params.deliveryId);
        if (!original) return apiError(404, 'webhook_delivery_not_found', 'Delivery not found');
        const now = new Date().toISOString();
        const copy: Delivery = {
          ...original,
          id: stableUuid(`${original.id}:replay:${now}`),
          trigger: 'replay',
          status: 'pending',
          attemptCount: 0,
          attempts: [],
          nextAttemptAt: now,
          completedAt: null,
          createdAt: now,
          deliverySeq: original.deliverySeq + 1,
        };
        state.deliveries.set(hook.id, [copy, ...list]);
        return ok('WebhookDeliveriesController_replay_v1', { deliveryId: copy.id }, 202);
      }),
  ),
  WebhookDeliveriesController_createReplay_v1: guarded(
    'WebhookDeliveriesController_createReplay_v1',
    (request, p) =>
      idempotent(state.idempotency, request, () => {
        const state = org(p.organizationId);
        const hook = state.webhooks.find((w) => w.id === request.params.webhookId);
        if (!hook) return notFound();
        if (hook.status !== 'active')
          return apiError(409, 'webhook_not_active', 'The webhook is not active');
        const running = [...state.replays.values()].find(
          (r) => r.webhookId === hook.id && (r.status === 'queued' || r.status === 'running'),
        );
        if (running)
          return apiError(409, 'webhook_replay_in_progress', 'A replay is in progress', {
            replayId: running.id,
          });
        const body = bodyOf<RequestBody<'WebhookDeliveriesController_createReplay_v1'>>(request);
        const from = Date.parse(String(body.from));
        const to = Date.parse(String(body.to));
        if (!(from < to) || to - from > 72 * HOUR)
          return apiError(400, 'validation_failed', ['to: the range must be at most 72 hours']);
        const statuses = body.statuses ?? ['failed', 'dead'];
        const matched = (state.deliveries.get(hook.id) ?? []).filter((d) => {
          const at = Date.parse(d.occurredAt);
          return (
            at >= from &&
            at < to &&
            (statuses as string[]).includes(d.status) &&
            (!body.eventTypes || (body.eventTypes as string[]).includes(d.eventType))
          );
        }).length;
        const now = new Date().toISOString();
        const replay = {
          id: stableUuid(`${hook.id}:replay:${now}`),
          status: 'queued' as const,
          from: new Date(from).toISOString(),
          to: new Date(to).toISOString(),
          statuses,
          eventTypes: body.eventTypes ?? null,
          matchedCount: matched,
          createdCount: 0,
          truncated: false,
          errorCode: null,
          createdAt: now,
          startedAt: null,
          completedAt: null,
          polls: 0,
          webhookId: hook.id,
        };
        state.replays.set(replay.id, replay);
        return ok(
          'WebhookDeliveriesController_createReplay_v1',
          { replayId: replay.id, status: 'queued' },
          202,
        );
      }),
  ),
  WebhookDeliveriesController_getReplay_v1: guarded(
    'WebhookDeliveriesController_getReplay_v1',
    (request, p) => {
      const replay = org(p.organizationId).replays.get(request.params.replayId ?? '');
      if (!replay || replay.webhookId !== request.params.webhookId)
        return apiError(404, 'webhook_replay_not_found', 'Replay not found');
      // Simulated worker progress: queued → running → completed over three polls.
      replay.polls += 1;
      const now = new Date().toISOString();
      if (replay.polls === 1) Object.assign(replay, { status: 'running', startedAt: now });
      else if (replay.polls >= 2)
        Object.assign(replay, {
          status: 'completed',
          createdCount: replay.matchedCount,
          completedAt: now,
        });
      const { polls: _polls, webhookId: _webhookId, ...body } = replay;
      return ok('WebhookDeliveriesController_getReplay_v1', body);
    },
  ),
  ApiKeysController_list_v1: guarded('ApiKeysController_list_v1', (request, p) => ({
    status: 200,
    body: paginate(org(p.organizationId).apiKeys, request.query),
  })),
  ApiKeysController_create_v1: guarded('ApiKeysController_create_v1', (request, p) => {
    const body = bodyOf<RequestBody<'ApiKeysController_create_v1'>>(request);
    const scopes = Array.isArray(body.scopes) ? body.scopes.map(String) : [];
    const lacking = scopes.filter((s) => !p.permissions.includes(s) || s.startsWith('platform:'));
    if (lacking.length > 0)
      return apiError(
        403,
        'forbidden',
        `API keys cannot carry permissions you do not hold: ${lacking.join(', ')}`,
      );
    const now = new Date().toISOString();
    const key = fakeKey();
    const apiKey: ApiKey = {
      id: stableUuid(`${p.organizationId}:apikey:${now}`),
      name: String(body.name ?? 'API key'),
      prefix: key.slice(0, 12),
      scopes,
      createdBy: { id: stableUuid(`user:${p.role}`), displayName: p.role },
      lastUsedAt: null,
      expiresAt: body.expiresAt ?? null,
      revokedAt: null,
      createdAt: now,
    };
    org(p.organizationId).apiKeys.unshift(apiKey);
    return ok('ApiKeysController_create_v1', { apiKey, key }, 201);
  }),
  ApiKeysController_revoke_v1: guarded('ApiKeysController_revoke_v1', (request, p) => {
    const key = org(p.organizationId).apiKeys.find((k) => k.id === request.params.id);
    if (!key) return apiError(404, 'not_found', 'API key not found');
    key.revokedAt ??= new Date().toISOString();
    return noContent();
  }),
};
