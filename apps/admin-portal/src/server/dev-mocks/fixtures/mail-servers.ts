import 'server-only';
import type { RequestBody, SuccessBody } from '@/lib/api/types';
import { SeededRandom, paginate, stableUuid } from '../generator';
import { apiError, noContent, ok, type FixtureHandlers, type FixtureResponse } from '../types';
import { DAY, HOUR, MINUTE, bodyOf, domainsOf, guarded, idempotent, isoAgo } from './domains';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of the `mail-servers` feature (WP4, design P9): SMTP connectors (SASL credentials
 * shown once, rotation), recipient suppressions (v1 cursor, filters, Idempotency-Key replay,
 * `suppression_exists`, `suppression_limit_reached`) and per-recipient deliveries. Synthetic,
 * deterministic, per organization. Secrets are obviously fake (`dev-fixture-…`).
 */

type Connector = SuccessBody<'SmtpConnectorsController_get_v1'>;
type Suppression = SuccessBody<'RecipientSuppressionsController_get_v1'>;
type Delivery = SuccessBody<'DeliveriesController_list_v1'>['data'][number];

interface OrgState {
  connectors: Connector[];
  suppressions: Suppression[];
  deliveries: Delivery[];
  nextSuppressionId: number;
}
interface MailServerState {
  orgs: Map<string, OrgState>;
  idempotency: Map<string, FixtureResponse>;
}
const globalState = globalThis as typeof globalThis & {
  __egDevFixtureMailServers?: MailServerState;
};
const state: MailServerState = (globalState.__egDevFixtureMailServers ??= {
  orgs: new Map(),
  idempotency: new Map(),
});

/** Manual + unsubscribe entries allowed per organization (RECIPIENT_SUPPRESSIONS_MAX_MANUAL). */
const MAX_MANUAL = 60;

function fakePassword(): string {
  return `dev-fixture-sasl-${crypto.randomUUID().replace(/-/g, '')}`;
}

function seed(organizationId: string): OrgState {
  const random = new SeededRandom(`${organizationId}:mail-servers`);
  const connectors: Connector[] = [
    { name: 'On-prem Exchange', authType: 'sasl' as const },
    { name: 'Datacenter relay', authType: 'source_ip' as const },
    { name: 'Scanner appliance', authType: 'client_certificate' as const },
    { name: 'Legacy CRM relay', authType: 'sasl' as const },
  ].map((c, i) => {
    const created = isoAgo((i + 2) * 9 * DAY);
    return {
      id: stableUuid(`${organizationId}:connector:${i}`),
      name: c.name,
      authType: c.authType,
      status: i === 3 ? 'disabled' : 'active',
      saslUsername: c.authType === 'sasl' ? `egc-devfixture${String(i).padStart(6, '0')}` : null,
      certificateFingerprintSha256: c.authType === 'client_certificate' ? 'ab'.repeat(32) : null,
      networks:
        c.authType === 'source_ip'
          ? [
              { cidr: '192.0.2.0/27', ipVersion: 4 as const },
              { cidr: '2001:db8:10::/48', ipVersion: 6 as const },
            ]
          : [],
      requireTls: true,
      secretSetAt: c.authType === 'sasl' ? created : null,
      createdAt: created,
      updatedAt: created,
    };
  });
  const reasons: Suppression['reason'][] = ['hard_bounce', 'complaint', 'manual', 'unsubscribe'];
  const suppressions: Suppression[] = Array.from({ length: 34 }, (_, i) => {
    const reason = reasons[i % 4] ?? 'manual';
    const expired = i % 9 === 8;
    return {
      id: String(4000 + i),
      address: `recipient${i + 1}@partner${(i % 5) + 1}.example.com`,
      reason,
      source: reason === 'hard_bounce' || reason === 'complaint' ? 'postfix_log' : 'portal',
      expiresAt: expired
        ? isoAgo(DAY)
        : i % 7 === 0
          ? new Date(Date.now() + 30 * DAY).toISOString()
          : null,
      active: !expired,
      createdAt: isoAgo(i * 7 * HOUR),
      createdBy: reason === 'manual' ? stableUuid('user:organization_admin@example.com') : null,
    };
  }).sort((a, b) => Number(b.id) - Number(a.id));
  const domains = domainsOf(organizationId).map((e) => e.domain.name);
  const statuses: Delivery['status'][] = [
    'delivered',
    'delivered',
    'delivered',
    'deferred',
    'bounced',
    'queued',
    'delivered',
    'failed',
    'suppressed',
    'unknown',
  ];
  const deliveries: Delivery[] = Array.from({ length: 60 }, (_, i) => {
    const status = statuses[i % statuses.length] ?? 'delivered';
    const direction = i % 3 === 0 ? 'outbound' : i % 3 === 1 ? 'inbound' : 'internal';
    return {
      messageId: stableUuid(`${organizationId}:message:${Math.floor(i / 2)}`),
      rcptSeq: i % 2,
      recipient:
        direction === 'outbound'
          ? `contact${i}@customer${(i % 4) + 1}.example.com`
          : `user${i}@${domains[i % Math.max(1, domains.length)] ?? 'alpha-1.example.test'}`,
      direction,
      status,
      attemptCount: status === 'deferred' ? random.int(2, 6) : 1,
      lastErrorClass:
        status === 'deferred'
          ? 'remote_4xx'
          : status === 'bounced'
            ? 'remote_5xx'
            : status === 'failed'
              ? 'no_destination'
              : null,
      statusChangedAt: isoAgo(i * 47 * MINUTE),
    };
  });
  return { connectors, suppressions, deliveries, nextSuppressionId: 5000 };
}

function orgState(organizationId: string): OrgState {
  let org = state.orgs.get(organizationId);
  if (!org) {
    org = seed(organizationId);
    state.orgs.set(organizationId, org);
  }
  return org;
}

const connectorNotFound = () => apiError(404, 'not_found', 'SMTP connector not found');
const PRIVATE = /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;

function parseNetworks(networks: unknown): { cidr: string; ipVersion: 4 | 6 }[] | FixtureResponse {
  const list = Array.isArray(networks) ? networks.map(String) : [];
  const out: { cidr: string; ipVersion: 4 | 6 }[] = [];
  for (const [i, value] of list.entries()) {
    if (PRIVATE.test(value))
      return apiError(400, 'validation_failed', [
        `networks.${i}: must be a publicly routable network`,
      ]);
    out.push({
      cidr: value.includes('/') ? value : `${value}/${value.includes(':') ? 128 : 32}`,
      ipVersion: value.includes(':') ? 6 : 4,
    });
  }
  return out;
}

export const fixtures: FixtureHandlers = {
  SmtpConnectorsController_list_v1: guarded('SmtpConnectorsController_list_v1', (request, p) => {
    const status = request.query.get('status');
    const authType = request.query.get('authType');
    const rows = orgState(p.organizationId).connectors.filter(
      (c) => (!status || c.status === status) && (!authType || c.authType === authType),
    );
    return { status: 200, body: paginate(rows, request.query) };
  }),
  SmtpConnectorsController_get_v1: guarded('SmtpConnectorsController_get_v1', (request, p) => {
    const connector = orgState(p.organizationId).connectors.find((c) => c.id === request.params.id);
    return connector ? ok('SmtpConnectorsController_get_v1', connector) : connectorNotFound();
  }),
  SmtpConnectorsController_create_v1: guarded(
    'SmtpConnectorsController_create_v1',
    (request, p) => {
      const org = orgState(p.organizationId);
      const body = bodyOf<RequestBody<'SmtpConnectorsController_create_v1'>>(request);
      const name = String(body.name ?? '').trim();
      if (!name) return apiError(400, 'validation_failed', ['name: Required']);
      if (org.connectors.some((c) => c.name === name))
        return apiError(409, 'conflict', 'SMTP connector name already exists');
      const networks = parseNetworks(body.networks);
      if ('status' in networks) return networks;
      const now = new Date().toISOString();
      const authType = body.authType ?? 'sasl';
      const connector: Connector = {
        id: stableUuid(`${p.organizationId}:connector:${name}:${now}`),
        name,
        authType,
        status: 'active',
        saslUsername: authType === 'sasl' ? `egc-dev${Date.now().toString(36)}` : null,
        certificateFingerprintSha256:
          authType === 'client_certificate'
            ? String(body.certificateFingerprintSha256 ?? '')
                .replace(/:/g, '')
                .toLowerCase()
            : null,
        networks,
        requireTls: body.requireTls ?? true,
        secretSetAt: authType === 'sasl' ? now : null,
        createdAt: now,
        updatedAt: now,
      };
      org.connectors.unshift(connector);
      return ok(
        'SmtpConnectorsController_create_v1',
        authType === 'sasl'
          ? {
              ...connector,
              credentials: { username: connector.saslUsername ?? '', password: fakePassword() },
            }
          : connector,
        201,
      );
    },
  ),
  SmtpConnectorsController_update_v1: guarded(
    'SmtpConnectorsController_update_v1',
    (request, p) => {
      const org = orgState(p.organizationId);
      const index = org.connectors.findIndex((c) => c.id === request.params.id);
      const current = org.connectors[index];
      if (!current) return connectorNotFound();
      const body = bodyOf<RequestBody<'SmtpConnectorsController_update_v1'>>(request);
      if (body.networks !== undefined && current.authType === 'sasl')
        return apiError(400, 'validation_failed', ['networks: not allowed for sasl connectors']);
      const networks =
        body.networks === undefined ? current.networks : parseNetworks(body.networks);
      if ('status' in networks) return networks;
      const next: Connector = {
        ...current,
        ...(body.name ? { name: body.name } : {}),
        ...(body.status ? { status: body.status } : {}),
        ...(body.requireTls !== undefined ? { requireTls: body.requireTls } : {}),
        networks,
        updatedAt: new Date().toISOString(),
      };
      org.connectors[index] = next;
      return ok('SmtpConnectorsController_update_v1', next);
    },
  ),
  SmtpConnectorsController_remove_v1: guarded(
    'SmtpConnectorsController_remove_v1',
    (request, p) => {
      const org = orgState(p.organizationId);
      const before = org.connectors.length;
      org.connectors = org.connectors.filter((c) => c.id !== request.params.id);
      return org.connectors.length < before ? noContent() : connectorNotFound();
    },
  ),
  SmtpConnectorsController_rotateSecret_v1: guarded(
    'SmtpConnectorsController_rotateSecret_v1',
    (request, p) => {
      const connector = orgState(p.organizationId).connectors.find(
        (c) => c.id === request.params.id,
      );
      if (!connector) return connectorNotFound();
      if (connector.authType !== 'sasl')
        return apiError(409, 'conflict', 'Only sasl connectors have a secret');
      connector.secretSetAt = new Date().toISOString();
      return ok('SmtpConnectorsController_rotateSecret_v1', {
        id: connector.id,
        credentials: { username: connector.saslUsername ?? '', password: fakePassword() },
        secretSetAt: connector.secretSetAt,
      });
    },
  ),
  RecipientSuppressionsController_list_v1: guarded(
    'RecipientSuppressionsController_list_v1',
    (request, p) => {
      const reasons = request.query.get('reason')?.split(',').filter(Boolean) ?? [];
      const address = request.query.get('address')?.toLowerCase();
      const active = request.query.get('active');
      const rows = orgState(p.organizationId).suppressions.filter(
        (s) =>
          (reasons.length === 0 || reasons.includes(s.reason)) &&
          (!address || s.address === address) &&
          (active === null || String(s.active) === active),
      );
      return { status: 200, body: paginate(rows, request.query) };
    },
  ),
  RecipientSuppressionsController_get_v1: guarded(
    'RecipientSuppressionsController_get_v1',
    (request, p) => {
      const row = orgState(p.organizationId).suppressions.find(
        (s) => s.id === request.params.suppressionId,
      );
      return row
        ? ok('RecipientSuppressionsController_get_v1', row)
        : apiError(404, 'suppression_not_found', 'Suppression not found');
    },
  ),
  RecipientSuppressionsController_create_v1: guarded(
    'RecipientSuppressionsController_create_v1',
    (request, p) =>
      idempotent(state.idempotency, request, () => {
        const org = orgState(p.organizationId);
        const body = bodyOf<RequestBody<'RecipientSuppressionsController_create_v1'>>(request);
        const address = String(body.address ?? '')
          .trim()
          .toLowerCase();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address))
          return apiError(400, 'validation_failed', ['address: must be an email address']);
        const existing = org.suppressions.find((s) => s.address === address);
        if (existing)
          return apiError(409, 'suppression_exists', 'The address is already suppressed', {
            id: existing.id,
          });
        if (
          org.suppressions.filter((s) => s.reason === 'manual' || s.reason === 'unsubscribe')
            .length >= MAX_MANUAL
        )
          return apiError(409, 'suppression_limit_reached', 'Manual suppression limit reached');
        const row: Suppression = {
          id: String(org.nextSuppressionId++),
          address,
          reason: body.reason ?? 'manual',
          source: 'api',
          expiresAt: body.expiresAt ?? null,
          active: true,
          createdAt: new Date().toISOString(),
          createdBy: stableUuid(`user:${p.role}`),
        };
        org.suppressions.unshift(row);
        return ok('RecipientSuppressionsController_create_v1', row, 201);
      }),
  ),
  RecipientSuppressionsController_delete_v1: guarded(
    'RecipientSuppressionsController_delete_v1',
    (request, p) =>
      idempotent(state.idempotency, request, () => {
        const org = orgState(p.organizationId);
        const before = org.suppressions.length;
        org.suppressions = org.suppressions.filter((s) => s.id !== request.params.suppressionId);
        return org.suppressions.length < before
          ? noContent()
          : apiError(404, 'suppression_not_found', 'Suppression not found');
      }),
  ),
  DeliveriesController_list_v1: guarded('DeliveriesController_list_v1', (request, p) => {
    const to = Date.parse(request.query.get('to') ?? new Date().toISOString());
    const from = Date.parse(request.query.get('from') ?? new Date(to - DAY).toISOString());
    if (!(from < to) || to - from > 31 * DAY)
      return apiError(400, 'validation_failed', [
        'from: the range must be at most 31 days and from before to',
      ]);
    const status = request.query.get('status');
    const direction = request.query.get('direction');
    const rows = orgState(p.organizationId).deliveries.filter((d) => {
      const at = Date.parse(d.statusChangedAt ?? '');
      return (
        at >= from &&
        at < to &&
        (!status || d.status === status) &&
        (!direction || d.direction === direction)
      );
    });
    return { status: 200, body: paginate(rows, request.query) };
  }),
};
