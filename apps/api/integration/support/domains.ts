/**
 * Domain onboarding helpers for the API integration suites (step 2.1, WP4). Every domain suite
 * runs against an in-process `TestDnsServer` (and `TestDohServer` for DoH mode): the app is built
 * with `DNS_SERVERS` pointing at it, the DNS cache off and short DNS timeouts, so no test ever
 * resolves a public name and timeout tests stay fast. Names are unique `.test` names.
 *
 * Publishing helpers read the expected records from the API (`GET /dns-records`) and put them on
 * the test server, exactly as a customer would copy them into their DNS zone.
 */
import type { AuditLog, MessageOutbox, Prisma } from '@email-gateway/database';
import type { Test } from 'supertest';
import { domainKvKeys } from '../../src/modules/domains/domains.constants';
import type { TestDnsServer } from '../../test/support/dns/test-dns-server';
import { TEST_DOMAIN_ENV } from '../../test/support/test-env';
import { createIntegrationApp, type IntegrationApp } from './app';
import { uniqueSuffix } from './fixtures';
import { idem, uniqueIp } from './http';

/** Gateway DNS settings of every domain suite (pinned, independent of the local `.env`). */
export const GATEWAY_MX = [
  { priority: 10, exchange: 'mx1.mail-gateway.test' },
  { priority: 20, exchange: 'mx2.mail-gateway.test' },
] as const;
export const GATEWAY_SPF_INCLUDE = '_spf.mail-gateway.test';
export const GATEWAY_DMARC_RUA = 'mailto:dmarc-reports@mail-gateway.test';
export const VERIFICATION_LABEL = '_emailgateway-verify';
/** Customers may not add names under this suffix (`DOMAIN_RESERVED_SUFFIXES`). */
export const RESERVED_SUFFIX = 'reserved-it.test';

/** Schedule settings pinned by `domainTestEnv` (seconds). */
export const SCHEDULE = {
  retryBase: 60,
  retryMax: 3600,
  recheckIncomplete: 1800,
  recheckInterval: 86_400,
  verificationTtlDays: 7,
  overlapDays: 7,
} as const;

/** DNS timing pinned by `domainTestEnv`: an injected timeout costs ~300 ms, never 15 s. */
export const DNS_TIMEOUT_MS = 300;

/**
 * Environment overrides for `createIntegrationApp` (D16): system resolver against the test
 * server, no propagation upstreams, cache off, short timeouts, background jobs off (suites call
 * `DomainCheckScheduler.runOnce` themselves).
 */
export function domainTestEnv(
  dns: Pick<TestDnsServer, 'address'>,
  extra: Record<string, string> = {},
): Record<string, string> {
  return {
    ...TEST_DOMAIN_ENV,
    GATEWAY_MX_HOSTS: GATEWAY_MX.map((mx) => `${mx.priority}:${mx.exchange}`).join(','),
    GATEWAY_SPF_INCLUDE,
    GATEWAY_DMARC_RUA,
    GATEWAY_DMARC_RUF: '',
    DOMAIN_VERIFICATION_LABEL: VERIFICATION_LABEL,
    DOMAIN_RESERVED_SUFFIXES: RESERVED_SUFFIX,
    DNS_RESOLVER_MODE: 'system',
    DNS_SERVERS: dns.address,
    DNS_PROPAGATION_UPSTREAMS: '',
    DNS_CACHE_MAX_TTL_SECONDS: '0',
    DNS_CACHE_NEGATIVE_TTL_SECONDS: '0',
    DNS_TIMEOUT_MS: String(DNS_TIMEOUT_MS),
    DNS_TRIES: '1',
    DOMAIN_CHECK_DEADLINE_MS: '2000',
    DOMAIN_BACKGROUND_JOBS_ENABLED: 'false',
    DOMAIN_JOBS_INTERVAL_SECONDS: '30',
    DOMAIN_CHECK_BATCH_SIZE: '50',
    DOMAIN_CHECK_CONCURRENCY: '4',
    DOMAIN_RETRY_BASE_SECONDS: String(SCHEDULE.retryBase),
    DOMAIN_RETRY_MAX_SECONDS: String(SCHEDULE.retryMax),
    DOMAIN_RECHECK_INCOMPLETE_SECONDS: String(SCHEDULE.recheckIncomplete),
    DOMAIN_RECHECK_INTERVAL_SECONDS: String(SCHEDULE.recheckInterval),
    DOMAIN_VERIFICATION_TTL_DAYS: String(SCHEDULE.verificationTtlDays),
    DKIM_ROTATION_OVERLAP_DAYS: String(SCHEDULE.overlapDays),
    ...extra,
  };
}

/** An integration app whose DNS is the given test server. */
export function createDomainApp(
  dns: Pick<TestDnsServer, 'address'>,
  extra: Record<string, string> = {},
): Promise<IntegrationApp> {
  return createIntegrationApp(domainTestEnv(dns, extra));
}

/** A unique, valid, test-only domain name, e.g. `acme-mh3x8k1a2b3c.domains-it.test`. */
export function uniqueDomainName(label = 'd'): string {
  return `${label}-${uniqueSuffix()}.domains-it.test`;
}

/** The gateway's own SPF include, published so SPF lookup counting follows a real record. */
export function publishGatewaySpf(dns: TestDnsServer): void {
  dns.setTxt(GATEWAY_SPF_INCLUDE, ['v=spf1 ip4:192.0.2.0/24 -all']);
}

// ---- API shapes used by the suites (subset of §4) ----------------------------------------

export interface DnsRecordBody {
  key: string;
  purpose: 'verification' | 'mx' | 'spf' | 'dkim' | 'dmarc';
  requirement: 'activation' | 'inbound' | 'outbound' | 'recommended';
  type: 'MX' | 'TXT';
  host: string;
  name: string;
  value: string;
  priority: number | null;
  status: 'pending' | 'valid' | 'invalid' | 'missing';
  lastOutcome: 'valid' | 'invalid' | 'missing' | 'indeterminate' | null;
  observedValue: string | null;
  lastCheckedAt: string | null;
  lastError: string | null;
  warnings: string[];
  instructions: string;
}

export interface DnsRecordsBody {
  domainId: string;
  records: DnsRecordBody[];
  cleanup: Array<{ type: string; host: string; reason: string; retiredAt: string }>;
}

export interface DkimKeyBody {
  selector: string;
  algorithm: 'rsa_2048' | 'ed25519';
  status: 'pending' | 'active' | 'rotating' | 'retired' | 'revoked';
  host: string;
  createdAt: string;
  activatedAt: string | null;
  retireAfter: string | null;
  retiredAt: string | null;
}

export interface DomainBody {
  id: string;
  name: string;
  unicodeName: string;
  status: string;
  statusReason: string | null;
  verifiedAt: string | null;
  activatedAt: string | null;
  nextCheckAt: string | null;
  lastCheckedAt: string | null;
  statusChangedAt: string | null;
  verification: {
    method: 'dns_txt';
    host: string;
    value: string;
    status: string;
    attempts: number;
    lastOutcome: string | null;
    lastError: string | null;
    expiresAt: string;
    verifiedAt: string | null;
  } | null;
  dkimKeys: DkimKeyBody[];
  dnsRecords?: DnsRecordBody[];
}

interface CheckBody {
  status: string;
  lastOutcome: string | null;
  lastCheckedAt: string | null;
  warnings: string[];
}

export interface StatusViewBody {
  domainId: string;
  name: string;
  status: string;
  statusReason: string | null;
  readyForActivation: boolean;
  mailFlowReady: boolean;
  lastCheckedAt: string | null;
  nextCheckAt: string | null;
  checkFailures: number;
  checks: {
    ownership: CheckBody;
    mx: CheckBody & {
      observed: Array<{ priority: number; host: string; pointsToGateway: boolean }>;
      propagation: Array<{ upstream: string; outcome: string }>;
    };
    spf: CheckBody & { lookupCount: number | null; recommendedValue: string };
    dkim: CheckBody & {
      selectors: Array<{
        selector: string;
        algorithm: string;
        keyStatus: string;
        recordStatus: string;
      }>;
    };
    dmarc: CheckBody & { stage: string; recommendedValue: string; nextStep: string };
  };
}

/**
 * The domain routes as one caller (bearer token or API key headers). Methods return the
 * supertest request so tests can assert any status; `ok*` helpers assert success and return the
 * typed body. `verify` gives each call its own client IP (the per-IP limit) and, unless asked
 * not to, clears the per-domain manual-verification counter so suites can verify many times.
 */
export class DomainApi {
  constructor(
    private readonly ctx: IntegrationApp,
    readonly headers: Record<string, string>,
  ) {}

  private url(id?: string, suffix = ''): string {
    return id === undefined ? '/api/v1/domains' : `/api/v1/domains/${id}${suffix}`;
  }

  create(body: Record<string, unknown>): Test {
    return this.ctx.http.post(this.url()).set(this.headers).send(body);
  }

  list(query = ''): Test {
    return this.ctx.http.get(`${this.url()}${query}`).set(this.headers);
  }

  get(id: string): Test {
    return this.ctx.http.get(this.url(id)).set(this.headers);
  }

  dnsRecords(id: string): Test {
    return this.ctx.http.get(this.url(id, '/dns-records')).set(this.headers);
  }

  status(id: string): Test {
    return this.ctx.http.get(this.url(id, '/status')).set(this.headers);
  }

  verify(id: string, ip: string = uniqueIp()): Test {
    return this.ctx.http.post(this.url(id, '/verify')).set(this.headers).set('X-Forwarded-For', ip);
  }

  /** `key`: the Idempotency-Key (step 6.1 §3.5; a fresh one by default). */
  rotate(id: string, body?: Record<string, unknown>, key?: string): Test {
    const req = this.ctx.http.post(this.url(id, '/dkim/rotate')).set(this.headers).set(idem(key));
    return body === undefined ? req : req.send(body);
  }

  setStatus(id: string, body: Record<string, unknown>): Test {
    return this.ctx.http.patch(this.url(id, '/status')).set(this.headers).send(body);
  }

  remove(id: string): Test {
    return this.ctx.http.delete(this.url(id)).set(this.headers);
  }

  async okCreate(name: string, extra: Record<string, unknown> = {}): Promise<DomainBody> {
    const res = await this.create({ name, ...extra });
    if (res.status !== 201) {
      throw new Error(`create ${name} failed: ${res.status} ${JSON.stringify(res.body)}`);
    }
    return res.body as DomainBody;
  }

  async okGet(id: string): Promise<DomainBody> {
    const res = await this.get(id).expect(200);
    return res.body as DomainBody;
  }

  async okRecords(id: string): Promise<DnsRecordsBody> {
    const res = await this.dnsRecords(id).expect(200);
    return res.body as DnsRecordsBody;
  }

  async okStatus(id: string): Promise<StatusViewBody> {
    const res = await this.status(id).expect(200);
    return res.body as StatusViewBody;
  }

  /** `POST /verify` expecting `200`, after clearing the per-domain verification counter. */
  async okVerify(id: string): Promise<StatusViewBody> {
    await resetVerifyLimit(this.ctx, id);
    const res = await this.verify(id);
    if (res.status !== 200) {
      throw new Error(`verify failed: ${res.status} ${JSON.stringify(res.body)}`);
    }
    return res.body as StatusViewBody;
  }
}

/** Clears `domains:verify:<id>` so the next manual verification is not rate-limited. */
export async function resetVerifyLimit(ctx: IntegrationApp, publicId: string): Promise<void> {
  const row = await ctx.prisma.domain.findUnique({ where: { publicId }, select: { id: true } });
  if (row) await ctx.kv.del(domainKvKeys.verifyCounter(row.id));
}

export type Purpose = DnsRecordBody['purpose'];

/**
 * Publishes the given records on the test server as a customer would (all purposes by default).
 * MX rows of one host become one MX set; each TXT host gets exactly the listed values (an
 * existing TXT set at that host is replaced, as `setTxt` does).
 */
export function publishRecords(
  dns: TestDnsServer,
  records: readonly DnsRecordBody[],
  purposes: readonly Purpose[] = ['verification', 'mx', 'spf', 'dkim', 'dmarc'],
): void {
  const selected = records.filter((r) => purposes.includes(r.purpose));
  const mx = new Map<string, Array<{ priority: number; exchange: string }>>();
  const txt = new Map<string, string[]>();
  for (const record of selected) {
    if (record.type === 'MX') {
      const list = mx.get(record.host) ?? [];
      list.push({ priority: record.priority ?? 10, exchange: record.value });
      mx.set(record.host, list);
    } else {
      const list = txt.get(record.host) ?? [];
      list.push(record.value);
      txt.set(record.host, list);
    }
  }
  for (const [host, list] of mx) dns.setMx(host, list);
  for (const [host, list] of txt) dns.setTxt(host, list);
}

/** Reads the records to publish from the API and publishes them (see `publishRecords`). */
export async function publishFromApi(
  api: DomainApi,
  dns: TestDnsServer,
  domainId: string,
  purposes?: readonly Purpose[],
): Promise<DnsRecordBody[]> {
  const { records } = await api.okRecords(domainId);
  publishRecords(dns, records, purposes);
  return records;
}

const DOMAIN_CHILDREN = {
  verifications: { orderBy: { id: 'asc' } },
  dnsRecords: { orderBy: { id: 'asc' } },
  dkimKeys: { orderBy: { id: 'asc' } },
  mxRecords: { orderBy: [{ priority: 'asc' }, { host: 'asc' }] },
} satisfies Prisma.DomainInclude;

export type DomainWithChildren = Prisma.DomainGetPayload<{ include: typeof DOMAIN_CHILDREN }>;

/** A domain row with its children, from the writer. */
export function domainRow(ctx: IntegrationApp, publicId: string): Promise<DomainWithChildren> {
  return ctx.prisma.domain.findUniqueOrThrow({ where: { publicId }, include: DOMAIN_CHILDREN });
}

/** Audit rows of one domain (oldest first), optionally of one action. */
export function domainAudit(
  ctx: IntegrationApp,
  publicId: string,
  action?: string,
): Promise<AuditLog[]> {
  return ctx.prisma.auditLog.findMany({
    where: { resourceType: 'domain', resourceId: publicId, ...(action && { action }) },
    orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
  });
}

/** `domain.status.changed.v1` outbox rows of one domain (oldest first). */
export async function domainEvents(
  ctx: IntegrationApp,
  publicId: string,
): Promise<MessageOutbox[]> {
  const { id } = await ctx.prisma.domain.findUniqueOrThrow({
    where: { publicId },
    select: { id: true },
  });
  return ctx.prisma.messageOutbox.findMany({
    where: {
      aggregateType: 'domain',
      aggregateId: id.toString(10),
      eventType: 'domain.status.changed.v1',
    },
    orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
  });
}

/** `domain.dns.records_changed.v1` outbox rows of one domain (step 6.2 §4.1), oldest first. */
export async function domainRecordEvents(
  ctx: IntegrationApp,
  publicId: string,
): Promise<MessageOutbox[]> {
  const { id } = await ctx.prisma.domain.findUniqueOrThrow({
    where: { publicId },
    select: { id: true },
  });
  return ctx.prisma.messageOutbox.findMany({
    where: {
      aggregateType: 'domain',
      aggregateId: id.toString(10),
      eventType: 'domain.dns.records_changed.v1',
    },
    orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
  });
}

/** Direct writer update of a domain row (time travel and fault set-up in tests only). */
export function updateDomain(
  ctx: IntegrationApp,
  publicId: string,
  data: Prisma.DomainUpdateInput,
): Promise<unknown> {
  return ctx.prisma.domain.update({ where: { publicId }, data });
}

/** Whole-second delta between an ISO timestamp (or Date) and a reference time. */
export function secondsAfter(at: string | Date | null, reference: Date): number {
  if (at === null) throw new Error('timestamp is null');
  return (new Date(at).getTime() - reference.getTime()) / 1000;
}

/** Bounds of a delay after the ±10 % schedule jitter (D11), with one second of slack. */
export function jittered(seconds: number): [number, number] {
  return [seconds * 0.9 - 1, seconds * 1.1 + 1];
}
