import 'server-only';
import type { OperationId, RequestBody, SuccessBody } from '@/lib/api/types';
import { canPerform } from '@/lib/auth/permissions';
import { SeededRandom, fixtureAnchor, paginate, stableUuid } from '../generator';
import {
  apiError,
  noContent,
  ok,
  type FixtureHandlers,
  type FixtureRequest,
  type FixtureResponse,
} from '../types';
import { resolveFixturePrincipal } from './session';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of the `domains` feature (WP4, design P9): domains with every lifecycle state,
 * DNS records and checks, DKIM keys and rotation, recipient validation and registry, destination
 * servers and providers. Synthetic only (`*.example.test`), per organization (another tenant's
 * id is a 404 exactly like the api), deterministic, with cursor pagination. Mutable state lives on
 * globalThis (each `next dev` route handler is its own bundle).
 *
 * The helpers at the top (`authorize`, `bodyOf`, `isoAgo`) are shared by the other WP4 fixture
 * files (mail-servers, users, roles, integrations).
 */

export interface FixturePrincipal {
  readonly role: string;
  readonly permissions: readonly string[];
  readonly organizationId: string;
}

/** 401 without a session, 403 when the caller's permissions do not satisfy the operation. */
export function authorize(
  request: FixtureRequest,
  operationId: OperationId,
): FixturePrincipal | FixtureResponse {
  const principal = resolveFixturePrincipal(request.token);
  if (!principal) return apiError(401, 'unauthorized', 'Unauthorized');
  if (!canPerform(operationId, principal.permissions))
    return apiError(403, 'forbidden', 'Forbidden');
  return principal;
}

export function isResponse(value: FixturePrincipal | FixtureResponse): value is FixtureResponse {
  return 'status' in value;
}

/** Runs a handler with the authorized principal (401/403 otherwise). */
export function guarded(
  operationId: OperationId,
  fn: (request: FixtureRequest, principal: FixturePrincipal) => FixtureResponse,
): (request: FixtureRequest) => FixtureResponse {
  return (request) => {
    const principal = authorize(request, operationId);
    return isResponse(principal) ? principal : fn(request, principal);
  };
}

export function bodyOf<T>(request: FixtureRequest): Partial<T> {
  return request.body && typeof request.body === 'object' ? request.body : {};
}

export const anchor = fixtureAnchor();
export function isoAgo(ms: number): string {
  return new Date(anchor - ms).toISOString();
}
export const MINUTE = 60_000;
export const HOUR = 60 * MINUTE;
export const DAY = 24 * HOUR;

/** Replay of an operation that takes an Idempotency-Key: same key → stored response, replayed. */
export function idempotent(
  store: Map<string, FixtureResponse>,
  request: FixtureRequest,
  run: () => FixtureResponse,
  redact?: (response: FixtureResponse) => FixtureResponse,
): FixtureResponse {
  const key = request.headers.get('idempotency-key');
  if (!key)
    return apiError(400, 'idempotency_key_required', 'An Idempotency-Key header is required');
  const scoped = `${request.operationId}:${request.params.webhookId ?? ''}:${key}`;
  const stored = store.get(scoped);
  if (stored) {
    return { ...stored, headers: { ...(stored.headers ?? {}), 'idempotency-replayed': 'true' } };
  }
  const response = run();
  if (response.status < 300) store.set(scoped, redact ? redact(response) : response);
  return response;
}

// ---------------------------------------------------------------------------------------------

type Domain = SuccessBody<'DomainsController_get_v1'>;
type DnsRecord = SuccessBody<'DomainDnsController_dnsRecords_v1'>['records'][number];
type StatusView = SuccessBody<'DomainDnsController_status_v1'>;
type Destinations = SuccessBody<'DomainDestinationsController_get_v1'>;
type Validation = SuccessBody<'DomainRecipientsController_get_v1'>;
type Recipient = SuccessBody<'DomainRecipientsController_list_v1'>['data'][number];
type Provider = SuccessBody<'DestinationProvidersController_list_v1'>['data'][number];

interface DomainEntry {
  domain: Domain;
  checks: Record<'ownership' | 'mx' | 'spf' | 'dkim' | 'dmarc', DnsRecord['status']>;
  destinations: Destinations;
  validation: Omit<Validation, 'addressCount'>;
  recipients: Recipient[];
  deleted: boolean;
  checkFailures: number;
}

interface DomainState {
  orgs: Map<string, DomainEntry[]>;
}
const globalState = globalThis as typeof globalThis & { __egDevFixtureDomains?: DomainState };
const state: DomainState = (globalState.__egDevFixtureDomains ??= { orgs: new Map() });

const GATEWAY_MX = 'mx1.gateway.example.test';
const WORDS = ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf', 'hotel'];
const STATUS_CYCLE: Domain['status'][] = [
  'active',
  'active',
  'verified',
  'pending_verification',
  'active',
  'suspended',
  'failed',
  'active',
];

function dkimKey(
  name: string,
  selector: string,
  status: 'pending' | 'active' | 'rotating',
  createdAt: string,
) {
  return {
    selector,
    algorithm: 'rsa_2048' as const,
    status,
    host: `${selector}._domainkey.${name}`,
    createdAt,
    activatedAt: status === 'pending' ? null : createdAt,
    retireAfter: null,
    retiredAt: null,
  };
}

function makeEntry(organizationId: string, index: number): DomainEntry {
  const random = new SeededRandom(`${organizationId}:domain:${index}`);
  const name = `${WORDS[index % WORDS.length]}-${index + 1}.example.test`;
  const status = STATUS_CYCLE[index % STATUS_CYCLE.length] ?? 'active';
  const created = isoAgo((index + 1) * 3 * DAY + random.int(0, 20) * HOUR);
  const owned = status === 'verified' || status === 'active' || status === 'suspended';
  const neverChecked = status === 'pending_verification' && index % 2 === 1;
  const lastChecked = neverChecked ? null : isoAgo(random.int(5, 50) * MINUTE);
  const domain: Domain = {
    id: stableUuid(`${organizationId}:domain:${index}`),
    name,
    unicodeName: name,
    status,
    statusReason:
      status === 'failed'
        ? 'verification_expired'
        : status === 'suspended'
          ? 'Paused during mail migration'
          : null,
    inboundEnabled: index % 5 !== 4,
    outboundEnabled: status === 'active',
    verifiedAt: owned ? isoAgo((index + 1) * 3 * DAY - 2 * HOUR) : null,
    activatedAt:
      status === 'active' || status === 'suspended'
        ? isoAgo((index + 1) * 3 * DAY - 3 * HOUR)
        : null,
    lastCheckedAt: lastChecked,
    nextCheckAt:
      status === 'failed' ? null : new Date(anchor + random.int(2, 30) * MINUTE).toISOString(),
    createdAt: created,
    updatedAt: created,
    statusChangedAt: status === 'pending_verification' ? null : isoAgo(index * DAY + HOUR),
    verification: {
      method: 'dns_txt',
      host: `_emailgateway-verify.${name}`,
      value: `eg-verify=${random.uuid().replace(/-/g, '')}`,
      status: owned ? 'verified' : status === 'failed' ? 'expired' : 'pending',
      attempts: neverChecked ? 0 : random.int(1, 9),
      lastCheckedAt: lastChecked,
      lastOutcome: neverChecked ? null : owned ? 'valid' : 'missing',
      lastError: null,
      expiresAt: new Date(Date.parse(created) + 7 * DAY).toISOString(),
      verifiedAt: owned ? isoAgo((index + 1) * 3 * DAY - 2 * HOUR) : null,
    },
    dkimKeys: [
      dkimKey(
        name,
        `eg${2026}${String(index % 12).padStart(2, '0')}a`,
        owned ? 'active' : 'pending',
        created,
      ),
    ],
  };
  const hasDestinations = status === 'active' || status === 'suspended';
  const destinations: Destinations = hasDestinations
    ? index % 3 === 0
      ? {
          provider: 'microsoft_365',
          servers: [
            {
              id: stableUuid(`${domain.id}:server:0`),
              host: `${WORDS[index % WORDS.length]}-${index + 1}-example-test.mail.protection.outlook.com`,
              port: 25,
              priority: 10,
              tlsMode: 'verify',
              tlsVerifyNames: 'mail.protection.outlook.com',
              enabled: true,
              createdAt: created,
              updatedAt: created,
            },
          ],
        }
      : {
          provider: 'custom',
          servers: [0, 1].map((n) => ({
            id: stableUuid(`${domain.id}:server:${n}`),
            host: `mx${n + 1}.${name}`,
            port: 25,
            priority: 10 + n * 10,
            tlsMode: n === 0 ? ('required' as const) : ('opportunistic' as const),
            tlsVerifyNames: null,
            enabled: true,
            createdAt: created,
            updatedAt: created,
          })),
        }
    : { provider: null, servers: [] };
  const recipients: Recipient[] =
    index === 0
      ? Array.from({ length: 32 }, (_, n) => ({
          localPart:
            ['sales', 'support', 'billing', 'jane.doe', 'it', 'hr', 'press', 'legal'][n % 8] +
            (n >= 8 ? String(n) : ''),
          createdAt: isoAgo(n * HOUR),
        }))
      : [];
  return {
    domain,
    checks: {
      ownership: owned ? 'valid' : neverChecked ? 'pending' : 'missing',
      mx: status === 'active' ? 'valid' : owned ? 'missing' : 'pending',
      spf: status === 'active' ? 'valid' : 'pending',
      dkim: status === 'active' ? 'valid' : 'pending',
      dmarc: status === 'active' ? (index % 2 ? 'valid' : 'invalid') : 'pending',
    },
    destinations,
    validation: {
      domainId: domain.id,
      mode: index === 0 ? 'allow_list' : 'accept_all',
      enforcement: index === 0 ? 'monitor' : 'reject',
      implemented: true,
    },
    recipients,
    deleted: false,
    checkFailures: status === 'pending_verification' && !neverChecked ? 2 : 0,
  };
}

/** The organization's domains (created on first use; the first customer has 30, others 3). */
export function domainsOf(organizationId: string): DomainEntry[] {
  let list = state.orgs.get(organizationId);
  if (!list) {
    const count = organizationId === stableUuid('org:alpha') ? 30 : 3;
    list = Array.from({ length: count }, (_, i) => makeEntry(organizationId, i));
    state.orgs.set(organizationId, list);
  }
  return list;
}

/** A live (non-deleted) domain of the organization, or null (foreign and unknown ids alike). */
export function findDomain(organizationId: string, id: string | undefined): DomainEntry | null {
  return (
    domainsOf(organizationId).find((entry) => entry.domain.id === id && !entry.deleted) ?? null
  );
}

const notFound = () => apiError(404, 'domain_not_found', 'Domain not found');

function summary(domain: Domain) {
  return {
    id: domain.id,
    name: domain.name,
    unicodeName: domain.unicodeName,
    status: domain.status,
    statusReason: domain.statusReason,
    inboundEnabled: domain.inboundEnabled,
    outboundEnabled: domain.outboundEnabled,
    verifiedAt: domain.verifiedAt,
    activatedAt: domain.activatedAt,
    lastCheckedAt: domain.lastCheckedAt,
    nextCheckAt: domain.nextCheckAt,
    createdAt: domain.createdAt,
    updatedAt: domain.updatedAt,
  };
}

function records(entry: DomainEntry): DnsRecord[] {
  const { domain, checks } = entry;
  const base = (status: DnsRecord['status']) => ({
    status,
    lastOutcome:
      status === 'pending' ? null : status === 'valid' ? ('valid' as const) : ('missing' as const),
    observedValue: null,
    lastCheckedAt: domain.lastCheckedAt,
    lastError: null,
    warnings: [] as string[],
  });
  const key = domain.dkimKeys.find((k) => k.status !== 'retired') ?? domain.dkimKeys[0];
  const list: DnsRecord[] = [
    {
      key: 'verification',
      purpose: 'verification',
      requirement: 'activation',
      type: 'TXT',
      host: domain.verification?.host ?? `_emailgateway-verify.${domain.name}`,
      name: '_emailgateway-verify',
      value: domain.verification?.value ?? 'eg-verify=unknown',
      priority: null,
      ...base(checks.ownership),
      instructions: 'Publish this TXT record to prove that you control the domain.',
    },
    {
      key: `mx:${GATEWAY_MX}`,
      purpose: 'mx',
      requirement: 'inbound',
      type: 'MX',
      host: domain.name,
      name: '@',
      value: GATEWAY_MX,
      priority: 10,
      ...base(checks.mx),
      instructions: 'Point the MX record to the gateway after activating the domain.',
    },
    {
      key: 'spf',
      purpose: 'spf',
      requirement: 'outbound',
      type: 'TXT',
      host: domain.name,
      name: '@',
      value: 'v=spf1 include:_spf.gateway.example.test ~all',
      priority: null,
      ...base(checks.spf),
      instructions: 'Merge the include into your existing SPF record (one SPF record per domain).',
    },
    {
      key: `dkim:${key?.selector ?? 'eg'}`,
      purpose: 'dkim',
      requirement: 'outbound',
      type: 'TXT',
      host: key?.host ?? `eg._domainkey.${domain.name}`,
      name: `${key?.selector ?? 'eg'}._domainkey`,
      value:
        'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAdevfixture0000000000000000',
      priority: null,
      ...base(checks.dkim),
      instructions: 'Publish the DKIM public key so receivers can verify signatures.',
    },
    {
      key: 'dmarc',
      purpose: 'dmarc',
      requirement: 'recommended',
      type: 'TXT',
      host: `_dmarc.${domain.name}`,
      name: '_dmarc',
      value: `v=DMARC1; p=none; rua=mailto:dmarc@${domain.name}`,
      priority: null,
      ...base(checks.dmarc),
      ...(checks.dmarc === 'invalid'
        ? {
            observedValue: 'v=DMARC1; p=nonee',
            warnings: ['The published DMARC record has an invalid policy tag'],
          }
        : {}),
      instructions: 'Start with p=none, then move to quarantine and reject.',
    },
  ];
  return list;
}

function statusView(entry: DomainEntry): StatusView {
  const { domain, checks } = entry;
  const check = (status: DnsRecord['status']) => ({
    status,
    lastOutcome:
      status === 'pending' ? null : status === 'valid' ? ('valid' as const) : ('missing' as const),
    lastCheckedAt: domain.lastCheckedAt,
    warnings: [] as string[],
  });
  return {
    domainId: domain.id,
    name: domain.name,
    status: domain.status,
    statusReason: domain.statusReason,
    readyForActivation: domain.status === 'verified',
    mailFlowReady: domain.status === 'active' && checks.mx === 'valid',
    lastCheckedAt: domain.lastCheckedAt,
    nextCheckAt: domain.nextCheckAt,
    checkFailures: entry.checkFailures,
    checks: {
      ownership: check(checks.ownership),
      mx: {
        ...check(checks.mx),
        observed:
          checks.mx === 'valid' ? [{ priority: 10, host: GATEWAY_MX, pointsToGateway: true }] : [],
        propagation: [],
      },
      spf: {
        ...check(checks.spf),
        lookupCount: checks.spf === 'valid' ? 3 : null,
        recommendedValue: 'v=spf1 include:_spf.gateway.example.test ~all',
      },
      dkim: {
        ...check(checks.dkim),
        selectors: domain.dkimKeys.map((k) => ({
          selector: k.selector,
          algorithm: k.algorithm,
          keyStatus: k.status,
          recordStatus: k.status === 'active' ? checks.dkim : 'pending',
        })),
      },
      dmarc: {
        ...check(checks.dmarc),
        ...(checks.dmarc === 'invalid'
          ? { warnings: ['The published DMARC record has an invalid policy tag'] }
          : {}),
        stage: checks.dmarc === 'valid' ? 'none' : 'missing',
        recommendedValue: `v=DMARC1; p=none; rua=mailto:dmarc@${domain.name}`,
        nextStep:
          checks.dmarc === 'valid'
            ? 'Move to p=quarantine once reports look clean.'
            : 'Publish a DMARC record with p=none.',
      },
    },
  };
}

const verifyCounters = new Map<string, number>();

const PROVIDERS: Provider[] = [
  {
    provider: 'custom',
    displayName: 'Your own servers',
    hostHint: null,
    hostPatterns: [],
    port: 25,
    tlsMode: 'opportunistic',
    tlsVerifyNames: 'nexthop',
    maxServers: 10,
    defaultServers: null,
    documentationUrl: null,
  },
  {
    provider: 'microsoft_365',
    displayName: 'Microsoft 365',
    hostHint: 'contoso-com.mail.protection.outlook.com',
    hostPatterns: ['*.mail.protection.outlook.com', '*.mx.microsoft'],
    port: 25,
    tlsMode: 'verify',
    tlsVerifyNames: 'mail.protection.outlook.com',
    maxServers: 1,
    defaultServers: null,
    documentationUrl: 'https://learn.microsoft.com/exchange/mail-flow-best-practices',
  },
  {
    provider: 'google_workspace',
    displayName: 'Google Workspace',
    hostHint: null,
    hostPatterns: ['*.google.com'],
    port: 25,
    tlsMode: 'verify',
    tlsVerifyNames: 'nexthop',
    maxServers: 5,
    defaultServers: [
      { host: 'aspmx.l.google.com', priority: 1 },
      { host: 'alt1.aspmx.l.google.com', priority: 5 },
      { host: 'alt2.aspmx.l.google.com', priority: 5 },
      { host: 'alt3.aspmx.l.google.com', priority: 10 },
      { host: 'alt4.aspmx.l.google.com', priority: 10 },
    ],
    documentationUrl: 'https://support.google.com/a/answer/174125',
  },
];

function servers(
  domainId: string,
  list: {
    host: string;
    port: number;
    priority: number;
    tlsMode: 'none' | 'opportunistic' | 'required' | 'verify';
    tlsVerifyNames: string | null;
  }[],
) {
  const now = new Date().toISOString();
  return list.map((server, n) => ({
    id: stableUuid(`${domainId}:server:${server.host}:${n}`),
    ...server,
    enabled: true,
    createdAt: now,
    updatedAt: now,
  }));
}

export const fixtures: FixtureHandlers = {
  DomainsController_list_v1: guarded('DomainsController_list_v1', (request, p) => {
    const q = request.query.get('q')?.toLowerCase() ?? '';
    const status = request.query.get('status');
    const rows = domainsOf(p.organizationId)
      .filter((entry) => !entry.deleted)
      .map((entry) => entry.domain)
      .filter((d) => (!q || d.name.startsWith(q)) && (!status || d.status === status))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map(summary);
    return { status: 200, body: paginate(rows, request.query) };
  }),
  DomainsController_create_v1: guarded('DomainsController_create_v1', (request, p) => {
    const body = bodyOf<RequestBody<'DomainsController_create_v1'>>(request);
    const name = String(body.name ?? '')
      .trim()
      .replace(/\.$/, '')
      .toLowerCase();
    if (!/^([a-z0-9-]+\.)+[a-z0-9-]+$/.test(name))
      return apiError(400, 'validation_failed', ['name: invalid domain name (invalid)']);
    const list = domainsOf(p.organizationId);
    if (list.some((e) => !e.deleted && e.domain.name === name))
      return apiError(409, 'domain_exists', 'Domain already exists');
    const entry = makeEntry(p.organizationId, list.length);
    const now = new Date().toISOString();
    entry.domain = {
      ...entry.domain,
      id: stableUuid(`${p.organizationId}:domain:${name}:${list.length}`),
      name,
      unicodeName: name,
      status: 'pending_verification',
      statusReason: null,
      inboundEnabled: body.inboundEnabled ?? true,
      outboundEnabled: false,
      verifiedAt: null,
      activatedAt: null,
      lastCheckedAt: null,
      nextCheckAt: new Date(Date.now() + MINUTE).toISOString(),
      createdAt: now,
      updatedAt: now,
      statusChangedAt: null,
      verification: {
        method: 'dns_txt',
        host: `_emailgateway-verify.${name}`,
        value: `eg-verify=${stableUuid(name).replace(/-/g, '')}`,
        status: 'pending',
        attempts: 0,
        lastCheckedAt: null,
        lastOutcome: null,
        lastError: null,
        expiresAt: new Date(Date.now() + 7 * DAY).toISOString(),
        verifiedAt: null,
      },
      dkimKeys: [dkimKey(name, 'eg2026a', 'pending', now)],
    };
    entry.checks = {
      ownership: 'pending',
      mx: 'pending',
      spf: 'pending',
      dkim: 'pending',
      dmarc: 'pending',
    };
    entry.destinations = { provider: null, servers: [] };
    entry.validation = {
      domainId: entry.domain.id,
      mode: 'accept_all',
      enforcement: 'reject',
      implemented: true,
    };
    entry.recipients = [];
    entry.checkFailures = 0;
    list.push(entry);
    return ok('DomainsController_create_v1', { ...entry.domain, dnsRecords: records(entry) }, 201);
  }),
  DomainsController_get_v1: guarded('DomainsController_get_v1', (request, p) => {
    const entry = findDomain(p.organizationId, request.params.id);
    return entry ? ok('DomainsController_get_v1', entry.domain) : notFound();
  }),
  DomainsController_remove_v1: guarded('DomainsController_remove_v1', (request, p) => {
    const entry = findDomain(p.organizationId, request.params.id);
    if (!entry) return notFound();
    if (entry.domain.status === 'active')
      return apiError(409, 'conflict', 'Suspend the domain before deleting it');
    entry.deleted = true;
    return noContent();
  }),
  DomainsController_changeStatus_v1: guarded('DomainsController_changeStatus_v1', (request, p) => {
    const entry = findDomain(p.organizationId, request.params.id);
    if (!entry) return notFound();
    const body = bodyOf<RequestBody<'DomainsController_changeStatus_v1'>>(request);
    const from = entry.domain.status;
    if (body.status === 'active' && (from === 'verified' || from === 'suspended')) {
      entry.domain = {
        ...entry.domain,
        status: 'active',
        statusReason: null,
        outboundEnabled: true,
        activatedAt: entry.domain.activatedAt ?? new Date().toISOString(),
        statusChangedAt: new Date().toISOString(),
      };
    } else if (body.status === 'suspended' && from === 'active') {
      if (!body.reason) return apiError(400, 'validation_failed', ['reason: Required to suspend']);
      entry.domain = {
        ...entry.domain,
        status: 'suspended',
        statusReason: body.reason,
        statusChangedAt: new Date().toISOString(),
      };
    } else {
      return apiError(409, 'conflict', `Domain is ${from}`);
    }
    return ok('DomainsController_changeStatus_v1', entry.domain);
  }),
  DomainDnsController_status_v1: guarded('DomainDnsController_status_v1', (request, p) => {
    const entry = findDomain(p.organizationId, request.params.id);
    return entry ? ok('DomainDnsController_status_v1', statusView(entry)) : notFound();
  }),
  DomainDnsController_verify_v1: guarded('DomainDnsController_verify_v1', (request, p) => {
    const entry = findDomain(p.organizationId, request.params.id);
    if (!entry) return notFound();
    const now = new Date().toISOString();
    const count = (verifyCounters.get(entry.domain.id) ?? 0) + 1;
    verifyCounters.set(entry.domain.id, count);
    entry.domain = { ...entry.domain, lastCheckedAt: now };
    // The second "Verify now" of a pending domain finds the record (simulated propagation).
    if (
      (entry.domain.status === 'pending_verification' || entry.domain.status === 'failed') &&
      count >= 2
    ) {
      entry.domain = {
        ...entry.domain,
        status: 'verified',
        statusReason: null,
        verifiedAt: now,
        statusChangedAt: now,
      };
      entry.checks.ownership = 'valid';
      entry.domain.dkimKeys = entry.domain.dkimKeys.map((k) => ({
        ...k,
        status: 'active' as const,
        activatedAt: now,
      }));
    } else if (entry.domain.status === 'pending_verification' || entry.domain.status === 'failed') {
      entry.domain = { ...entry.domain, status: 'pending_verification', statusReason: null };
      entry.checks.ownership = 'missing';
    }
    return ok('DomainDnsController_verify_v1', statusView(entry));
  }),
  DomainDnsController_dnsRecords_v1: guarded('DomainDnsController_dnsRecords_v1', (request, p) => {
    const entry = findDomain(p.organizationId, request.params.id);
    return entry
      ? ok('DomainDnsController_dnsRecords_v1', {
          domainId: entry.domain.id,
          records: records(entry),
          cleanup: [],
        })
      : notFound();
  }),
  DomainDnsController_rotate_v1: guarded('DomainDnsController_rotate_v1', (request, p) => {
    const entry = findDomain(p.organizationId, request.params.id);
    if (!entry) return notFound();
    if (
      entry.domain.dkimKeys.some((k) => k.status === 'pending') &&
      entry.domain.dkimKeys.some((k) => k.status === 'active')
    )
      return apiError(409, 'conflict', 'A DKIM rotation is already in progress');
    const body = bodyOf<RequestBody<'DomainDnsController_rotate_v1'>>(request);
    const now = new Date().toISOString();
    const selector = `eg${Date.now().toString(36)}`;
    const key = {
      ...dkimKey(entry.domain.name, selector, 'pending', now),
      algorithm: body.algorithm ?? 'rsa_2048',
    };
    const previous = entry.domain.dkimKeys.find((k) => k.status === 'active') ?? null;
    entry.domain = { ...entry.domain, dkimKeys: [...entry.domain.dkimKeys, key] };
    const record = records(entry).find((r) => r.purpose === 'dkim');
    return ok(
      'DomainDnsController_rotate_v1',
      {
        domainId: entry.domain.id,
        key,
        previous,
        dnsRecord: {
          ...(record as DnsRecord),
          key: `dkim:${selector}`,
          host: key.host,
          name: `${selector}._domainkey`,
          status: 'pending',
        },
        overlapDays: 7,
      },
      201,
    );
  }),
  DomainRecipientsController_get_v1: guarded('DomainRecipientsController_get_v1', (request, p) => {
    const entry = findDomain(p.organizationId, request.params.id);
    return entry
      ? ok('DomainRecipientsController_get_v1', {
          ...entry.validation,
          addressCount: entry.recipients.length,
        })
      : notFound();
  }),
  DomainRecipientsController_set_v1: guarded('DomainRecipientsController_set_v1', (request, p) => {
    const entry = findDomain(p.organizationId, request.params.id);
    if (!entry) return notFound();
    const body = bodyOf<{ mode: Validation['mode']; enforcement?: Validation['enforcement'] }>(
      request,
    );
    if (body.mode === 'smtp_callout' || body.mode === 'ldap')
      return apiError(422, 'unprocessable', 'Not implemented');
    if (
      body.mode === 'allow_list' &&
      body.enforcement === 'reject' &&
      entry.recipients.length === 0
    )
      return apiError(409, 'conflict', 'Add recipients before enforcing the allow-list');
    entry.validation = {
      ...entry.validation,
      mode: body.mode === 'allow_list' ? 'allow_list' : 'accept_all',
      enforcement: body.mode === 'allow_list' ? (body.enforcement ?? 'monitor') : 'reject',
    };
    return ok('DomainRecipientsController_set_v1', {
      ...entry.validation,
      addressCount: entry.recipients.length,
    });
  }),
  DomainRecipientsController_list_v1: guarded(
    'DomainRecipientsController_list_v1',
    (request, p) => {
      const entry = findDomain(p.organizationId, request.params.id);
      if (!entry) return notFound();
      const q = request.query.get('q')?.toLowerCase() ?? '';
      const rows = entry.recipients.filter((r) => !q || r.localPart.startsWith(q));
      return { status: 200, body: paginate(rows, request.query) };
    },
  ),
  DomainRecipientsController_add_v1: guarded('DomainRecipientsController_add_v1', (request, p) => {
    const entry = findDomain(p.organizationId, request.params.id);
    if (!entry) return notFound();
    const parts = [
      ...new Set(
        (bodyOf<{ localParts: string[] }>(request).localParts ?? []).map((s) => s.toLowerCase()),
      ),
    ];
    const existing = parts.filter((lp) => entry.recipients.some((r) => r.localPart === lp));
    const now = new Date().toISOString();
    entry.recipients = [
      ...parts
        .filter((lp) => !existing.includes(lp))
        .map((localPart) => ({ localPart, createdAt: now })),
      ...entry.recipients,
    ];
    return ok('DomainRecipientsController_add_v1', {
      added: parts.length - existing.length,
      existing: existing.length,
    });
  }),
  DomainRecipientsController_remove_v1: guarded(
    'DomainRecipientsController_remove_v1',
    (request, p) => {
      const entry = findDomain(p.organizationId, request.params.id);
      if (!entry) return notFound();
      const parts = new Set(
        (bodyOf<{ localParts: string[] }>(request).localParts ?? []).map((s) => s.toLowerCase()),
      );
      const before = entry.recipients.length;
      entry.recipients = entry.recipients.filter((r) => !parts.has(r.localPart));
      return ok('DomainRecipientsController_remove_v1', {
        removed: before - entry.recipients.length,
      });
    },
  ),
  DestinationProvidersController_list_v1: guarded('DestinationProvidersController_list_v1', () =>
    ok('DestinationProvidersController_list_v1', { data: PROVIDERS }),
  ),
  DomainDestinationsController_get_v1: guarded(
    'DomainDestinationsController_get_v1',
    (request, p) => {
      const entry = findDomain(p.organizationId, request.params.id);
      return entry ? ok('DomainDestinationsController_get_v1', entry.destinations) : notFound();
    },
  ),
  DomainDestinationsController_replace_v1: guarded(
    'DomainDestinationsController_replace_v1',
    (request, p) => {
      const entry = findDomain(p.organizationId, request.params.id);
      if (!entry) return notFound();
      const body = bodyOf<RequestBody<'DomainDestinationsController_replace_v1'>>(
        request,
      ) as Record<string, unknown>;
      const id = entry.domain.id;
      if (body.provider === 'microsoft_365') {
        const host = (typeof body.host === 'string' ? body.host : '').toLowerCase();
        if (!/\.mail\.protection\.outlook\.com$|\.mx\.microsoft$/.test(host))
          return apiError(422, 'unprocessable', 'The host does not match the provider', {
            reason: 'host_not_allowed_for_provider',
            field: 'host',
          });
        entry.destinations = {
          provider: 'microsoft_365',
          servers: servers(id, [
            {
              host,
              port: 25,
              priority: 10,
              tlsMode: 'verify',
              tlsVerifyNames: 'mail.protection.outlook.com',
            },
          ]),
        };
      } else if (body.provider === 'google_workspace') {
        entry.destinations = {
          provider: 'google_workspace',
          servers: servers(
            id,
            (PROVIDERS[2]?.defaultServers ?? []).map((s) => ({
              ...s,
              port: 25,
              tlsMode: 'verify' as const,
              tlsVerifyNames: 'nexthop',
            })),
          ),
        };
      } else {
        const list = Array.isArray(body.servers) ? (body.servers as Record<string, unknown>[]) : [];
        for (const [i, server] of list.entries()) {
          const host = typeof server.host === 'string' ? server.host : '';
          if (!host.includes('.'))
            return apiError(
              422,
              'unprocessable',
              'Destination host must be a fully qualified name',
              { reason: 'single_label', field: `servers.${i}.host` },
            );
          if (/\.(local|internal|localhost)$/.test(host))
            return apiError(422, 'unprocessable', 'Destination host is an internal name', {
              reason: 'internal_suffix',
              field: `servers.${i}.host`,
            });
        }
        entry.destinations = {
          provider: 'custom',
          servers: servers(
            id,
            list.map((s) => ({
              host: String(s.host).toLowerCase(),
              port: typeof s.port === 'number' ? s.port : 25,
              priority: typeof s.priority === 'number' ? s.priority : 10,
              tlsMode:
                (s.tlsMode as 'none' | 'opportunistic' | 'required' | 'verify' | undefined) ??
                'opportunistic',
              tlsVerifyNames: typeof s.tlsVerifyNames === 'string' ? s.tlsVerifyNames : null,
            })),
          ),
        };
      }
      return ok('DomainDestinationsController_replace_v1', entry.destinations);
    },
  ),
  DomainDestinationsController_remove_v1: guarded(
    'DomainDestinationsController_remove_v1',
    (request, p) => {
      const entry = findDomain(p.organizationId, request.params.id);
      if (!entry) return notFound();
      entry.destinations = { provider: null, servers: [] };
      return noContent();
    },
  ),
};
