/**
 * Shared doubles of the step 6.1 WP3 e2e suites (audit logs, reports, usage, billing, threat
 * intelligence): the stubbed api of `support/api-test-app.ts` with in-memory doubles of the WP3
 * repositories, the organization repositories they reuse and AuditService. Test-only; nothing
 * here is used by production code.
 */
import type { TestingModuleBuilder } from '@nestjs/testing';
import { AuditService, type AuditEntry } from '../src/audit/audit.service';
import type { Principal } from '../src/auth-contracts/principal';
import {
  type AuditFilter,
  type AuditKey,
  type AuditLogRecord,
  AuditLogsRepository,
  type AuditSearch,
} from '../src/modules/audit-logs/audit-logs.repository';
import { BillingRepository } from '../src/modules/billing/billing.repository';
import type { OrganizationAccess } from '../src/modules/organizations/domain/organization-access';
import {
  OrganizationUsageRepository,
  type UsageCounts,
} from '../src/modules/organizations/organization-usage.repository';
import {
  type FeatureRecord,
  type LimitRecord,
  OrganizationsRepository,
  type VisibleOrganization,
} from '../src/modules/organizations/organizations.repository';
import { ReportsRepository } from '../src/modules/reports/reports.repository';
import { ThreatIntelligenceRepository } from '../src/modules/threat-intelligence/threat-intelligence.repository';
import { createStubbedApiApp, type StubbedApiApp } from './support/api-test-app';

/** Every WP3 permission (tests remove the one under test). */
export const INSIGHT_PERMISSIONS = [
  'audit:read',
  'report:read',
  'organization:read',
  'billing:read',
  'threat_intel:read',
] as const;

export const OTHER_ORG_PUBLIC_ID = '01930c2e-7d1a-7000-8000-00000000b0b0';

/** Audit rows in memory with the semantics of `auditSql` (owner, range, keyset, filters). */
export class InMemoryAuditLogs {
  rows: AuditLogRecord[] = [];
  calls = { page: 0, boundary: 0, filtered: 0 };

  private visible(search: AuditSearch): AuditLogRecord[] {
    const sign = search.direction === 'desc' ? -1 : 1;
    const cmp = (a: AuditKey, b: AuditKey) =>
      a.createdAt.getTime() !== b.createdAt.getTime()
        ? (a.createdAt.getTime() - b.createdAt.getTime()) * sign
        : Number(a.id - b.id) * sign;
    return this.rows
      .filter((r) =>
        search.owner.kind === 'organization'
          ? r.organizationId === search.owner.organizationId
          : r.organizationId === null,
      )
      .filter((r) => r.createdAt >= search.from && r.createdAt < search.to)
      .filter((r) => !search.after || cmp(r, search.after) > 0)
      .sort(cmp);
  }

  readonly repository = {
    page: (search: AuditSearch, take: number) => {
      this.calls.page += 1;
      return Promise.resolve(this.visible(search).slice(0, take));
    },
    boundary: (search: AuditSearch, budget: number) => {
      this.calls.boundary += 1;
      const row = this.visible(search)[budget - 1];
      return Promise.resolve(row ? { createdAt: row.createdAt, id: row.id } : null);
    },
    filtered: (
      search: AuditSearch,
      filter: AuditFilter,
      boundary: AuditKey | null,
      take: number,
    ) => {
      this.calls.filtered += 1;
      const all = this.visible(search);
      const end = boundary ? all.findIndex((r) => r.id === boundary.id) + 1 : all.length;
      const match = (r: AuditLogRecord) =>
        (filter.action === undefined || r.action === filter.action) &&
        (filter.actionPrefix === undefined || r.action.startsWith(filter.actionPrefix)) &&
        (filter.resourceType === undefined || r.resourceType === filter.resourceType) &&
        (filter.resourceId === undefined || r.resourceId === filter.resourceId) &&
        (filter.actorType === undefined || r.actorType === filter.actorType) &&
        (filter.actorId === undefined || r.actorId === filter.actorId);
      return Promise.resolve(all.slice(0, end).filter(match).slice(0, take));
    },
  };
}

export class RecordingAudit {
  readonly entries: AuditEntry[] = [];
  readonly double = {
    record: (entry: AuditEntry) => {
      this.entries.push(entry);
      return Promise.resolve();
    },
    actorFrom: (principal: Principal) =>
      principal.kind === 'api_key'
        ? { type: 'api_key' as const, id: principal.apiKeyPublicId }
        : { type: 'user' as const, id: principal.userPublicId },
  };
  actions(): string[] {
    return this.entries.map((e) => e.action);
  }
}

/** The caller's organization (id 1, the TestPrincipals' organization) and one other. */
export class InMemoryOrganizations {
  limits: LimitRecord[] = [
    { limitKey: 'max_domains', limitValue: 10n, source: 'plan', updatedAt: new Date() },
    { limitKey: 'max_users', limitValue: 500n, source: 'override', updatedAt: new Date() },
    { limitKey: 'messages_per_day', limitValue: 100_000n, source: 'plan', updatedAt: new Date() },
  ];
  features: FeatureRecord[] = [
    { featureKey: 'dlp', enabled: false, config: null, source: 'plan', updatedAt: new Date() },
    {
      featureKey: 'inbound_filtering',
      enabled: true,
      config: null,
      source: 'plan',
      updatedAt: new Date(),
    },
  ];
  readonly orgs: VisibleOrganization[];

  constructor(ownPublicId: string) {
    const org = (id: bigint, publicId: string) =>
      ({
        id,
        publicId,
        plan: { code: 'standard', name: 'Standard' },
      }) as unknown as VisibleOrganization;
    this.orgs = [org(1n, ownPublicId), org(2n, OTHER_ORG_PUBLIC_ID)];
  }

  readonly repository = {
    findVisibleOnReader: (access: OrganizationAccess, publicId: string) =>
      Promise.resolve(
        this.orgs.find(
          (o) =>
            o.publicId === publicId &&
            (access.kind === 'platform' || o.id === access.scope.organizationId),
        ) ?? null,
      ),
    listLimitsFromReader: () => Promise.resolve(this.limits),
    listFeatures: () => Promise.resolve(this.features),
  };
}

export const USAGE_COUNTS: UsageCounts = {
  usersByStatus: new Map([
    ['active', 7],
    ['invited', 2],
  ]),
  domainsByStatus: new Map([
    ['active', 2],
    ['deleted', 1],
  ]),
  messagesByDirection: new Map([
    ['inbound', 30],
    ['outbound', 12],
  ]),
  messagesToday: 4,
  quarantineActive: 3,
  apiKeysActive: 1,
  sessionsActive: 2,
};

export interface InsightDoubles {
  audit: RecordingAudit;
  auditLogs: InMemoryAuditLogs;
  organizations: InMemoryOrganizations;
  reports: Record<keyof ReportsRepository, (...args: never[]) => Promise<unknown>>;
  billing: Record<keyof BillingRepository, (...args: never[]) => Promise<unknown>>;
  threatIntel: Record<keyof ThreatIntelligenceRepository, (...args: never[]) => Promise<unknown>>;
  usageCounts: (...args: unknown[]) => Promise<UsageCounts>;
}

export interface InsightApp extends StubbedApiApp {
  doubles: InsightDoubles;
}

/** An object whose methods call the (replaceable) functions of `target` at call time. */
function delegate<T extends Record<string, (...args: never[]) => Promise<unknown>>>(target: T): T {
  const out = {} as Record<string, unknown>;
  for (const name of Object.keys(target)) {
    out[name] = (...args: never[]) => target[name]!(...args);
  }
  return out as T;
}

/** The stubbed api with the WP3 doubles; `env` overrides config (e.g. a low expensive limit). */
export async function createInsightApp(
  env: Record<string, string> = {},
  options: { discovery?: boolean } = {},
): Promise<InsightApp> {
  const audit = new RecordingAudit();
  const auditLogs = new InMemoryAuditLogs();
  const holder: { organizations?: InMemoryOrganizations } = {};
  const lazyOrgs = {
    findVisibleOnReader: (
      ...args: Parameters<InMemoryOrganizations['repository']['findVisibleOnReader']>
    ) => holder.organizations!.repository.findVisibleOnReader(...args),
    listLimitsFromReader: () => holder.organizations!.repository.listLimitsFromReader(),
    listFeatures: () => holder.organizations!.repository.listFeatures(),
  };
  const reports = {
    traffic: () => Promise.resolve([]),
    directions: () => Promise.resolve([]),
    outcomes: () => Promise.resolve([]),
    quarantine: () => Promise.resolve([]),
    clicks: () => Promise.resolve([]),
    deliveries: () => Promise.resolve([]),
    scanRounds: () => Promise.resolve([]),
    domainVerdicts: () => Promise.resolve([]),
    domains: () => Promise.resolve(new Map()),
  } as InsightDoubles['reports'];
  const billing = {
    plan: () =>
      Promise.resolve({
        code: 'standard',
        name: 'Standard',
        description: 'Inbound and outbound filtering for small and medium organizations',
      }),
    entities: () => Promise.resolve({ users: 9, domains: 2, apiKeys: 1 }),
    features: () => holder.organizations!.repository.listFeatures(),
  } as InsightDoubles['billing'];
  const threatIntel = {
    indicators: () => Promise.resolve([]),
    signature: () => Promise.resolve(null),
  } as InsightDoubles['threatIntel'];
  const doubles: InsightDoubles = {
    audit,
    auditLogs,
    get organizations() {
      return holder.organizations!;
    },
    reports,
    billing,
    threatIntel,
    usageCounts: () => Promise.resolve(USAGE_COUNTS),
  };
  const app = await createStubbedApiApp(env, {
    ...(options.discovery && { discovery: true }),
    override: (builder: TestingModuleBuilder) =>
      builder
        .overrideProvider(AuditService)
        .useValue(audit.double)
        .overrideProvider(AuditLogsRepository)
        .useValue(auditLogs.repository)
        .overrideProvider(OrganizationsRepository)
        .useValue(lazyOrgs)
        .overrideProvider(OrganizationUsageRepository)
        .useValue({ counts: (...args: unknown[]) => doubles.usageCounts(...args) })
        .overrideProvider(ReportsRepository)
        .useValue(delegate(doubles.reports))
        .overrideProvider(BillingRepository)
        .useValue(delegate(doubles.billing))
        .overrideProvider(ThreatIntelligenceRepository)
        .useValue(delegate(doubles.threatIntel)),
  });
  holder.organizations = new InMemoryOrganizations(app.principals.ids.org);
  return Object.assign(app, { doubles });
}

/** A 400 body: `validation_failed` (or the given code) with a request id. */
export function expectCoded(body: { code?: unknown; requestId?: unknown }, code: string): void {
  if (body.code !== code || typeof body.requestId !== 'string') {
    throw new Error(`expected code ${code}, got ${JSON.stringify(body)}`);
  }
}
