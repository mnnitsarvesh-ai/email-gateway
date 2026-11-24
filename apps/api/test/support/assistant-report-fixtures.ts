/**
 * In-memory doubles of the step AI-R report storage (docs/plan/steps/31-ai-chat-reports.md §3,
 * D5–D7): `ai_chat_reports`, `ai_chat_report_deliveries` with their outbox rows, the recipient
 * directory (users and domains of an organization) and the report object store (the mail
 * bucket). Owned by `AssistantWorld` (`world.reportWorld`), so the conversation content purge of
 * its conversations double also purges the reports. Synthetic data only; nothing here reaches
 * MySQL, S3 or the network, and nothing is used by production code.
 */
/* eslint-disable @typescript-eslint/no-this-alias -- the doubles close over the world's state */
import type { TenantScope } from '../../src/auth-contracts/tenant-scope';
import type { Owner } from '../../src/modules/assistant/repositories/conversations.repository';
import type { RecipientDirectoryRepository } from '../../src/modules/assistant/repositories/recipient-directory.repository';
import type {
  DeliveryCreate,
  DeliveryRow,
  ReportDeliveriesRepository,
} from '../../src/modules/assistant/repositories/report-deliveries.repository';
import type {
  ReportCreate,
  ReportObjectRow,
  ReportRow,
  ReportsRepository,
  ReportWithRefs,
} from '../../src/modules/assistant/repositories/reports.repository';
import {
  isReportKeyOf,
  ReportObjectError,
  type ReportObjectStore,
  sha256Hex,
} from '../../src/modules/assistant/services/reports/report-object-store';

export type StoredReport = ReportRow & { conversationPublicId: string };
export type StoredDelivery = DeliveryRow & {
  conversationId: bigint;
  confirmationId: bigint;
  recipientSha256: string;
  sizeBytes: number;
  correlationId: string;
};

export interface DirectoryUser {
  id: bigint;
  organizationId: bigint;
  email: string;
  status: 'invited' | 'active' | 'disabled' | 'locked';
  verified: boolean;
  deleted: boolean;
}

export interface DirectoryDomain {
  organizationId: bigint;
  name: string;
  status:
    | 'pending_verification'
    | 'verified'
    | 'failed'
    | 'disabled'
    | 'active'
    | 'suspended'
    | 'deleted';
  deleted: boolean;
}

export interface OutboxRow {
  eventId: string;
  organizationId: bigint;
  eventType: string;
  aggregateType: string;
  aggregateId: string;
  correlationId: string;
  payload: unknown;
}

export class ReportWorld {
  reports: StoredReport[] = [];
  deliveries: StoredDelivery[] = [];
  outbox: OutboxRow[] = [];
  users: DirectoryUser[] = [];
  domains: DirectoryDomain[] = [];
  /** Object key → bytes (the mail bucket). */
  objects = new Map<string, Buffer>();
  /** Organizations whose `ai_chat_settings` row exists (the lock). */
  settingsRows = new Set<bigint>();
  /** Calls of the object store and the lock, in order (`put:<key>`, `delete:<key>`, `lock`). */
  readonly log: string[] = [];
  /** Makes the next object store call of this kind fail (S3 outage). */
  failNext: { put?: boolean; get?: boolean; delete?: boolean } = {};
  /** Public ids of conversations and executions by row id (set by `AssistantWorld`). */
  conversationPublicIdOf: (id: bigint) => string = (id) => `conv-${id}`;
  executionPublicIdOf: (id: bigint) => string | null = () => null;
  private nextId = 9000n;

  id(): bigint {
    this.nextId += 1n;
    return this.nextId;
  }

  reset(): void {
    this.reports = [];
    this.deliveries = [];
    this.outbox = [];
    this.users = [];
    this.domains = [];
    this.objects.clear();
    this.settingsRows.clear();
    this.log.length = 0;
    this.failNext = {};
  }

  private owns(owner: Owner, overrideId: string | null, row: StoredReport): boolean {
    return (
      row.organizationId === owner.scope.organizationId &&
      row.userId === owner.userId &&
      row.platformOverrideId === overrideId
    );
  }

  /** D7: the content purge of conversations (the conversations double calls it). */
  purgeConversations(organizationId: bigint, conversationIds: readonly bigint[], now: Date): void {
    const reportIds = new Set<bigint>();
    for (const r of this.reports) {
      if (r.organizationId !== organizationId || !conversationIds.includes(r.conversationId))
        continue;
      reportIds.add(r.id);
      if (r.status !== 'purged') {
        r.status = 'purged';
        r.purgedAt = now;
      }
    }
    for (const d of this.deliveries) {
      if (d.organizationId !== organizationId || !reportIds.has(d.reportId)) continue;
      if (d.status === 'queued') {
        d.status = 'failed';
        d.errorCode = 'assistant_report_purged';
      }
      d.recipientAddress = null;
    }
  }

  reportsDouble(): ReportsRepository {
    const world = this;
    return {
      insertPending: (owner: Owner, data: ReportCreate) => {
        const id = world.id();
        world.reports.push({
          id,
          publicId: data.publicId,
          organizationId: owner.scope.organizationId,
          userId: owner.userId,
          platformOverrideId: data.platformOverrideId,
          conversationId: data.conversationId,
          conversationPublicId: world.conversationPublicIdOf(data.conversationId),
          executionId: null,
          status: 'pending',
          title: data.title,
          periodFrom: data.periodFrom,
          periodTo: data.periodTo,
          granularity: data.granularity,
          sections: structuredClone(data.sections) as ReportRow['sections'],
          figures: structuredClone(data.figures) as ReportRow['figures'],
          templateVersion: data.templateVersion,
          objectKey: data.objectKey,
          sizeBytes: data.sizeBytes,
          sha256: data.sha256,
          errorCode: null,
          purgedAt: null,
          objectDeletedAt: null,
          createdAt: data.createdAt,
          updatedAt: data.createdAt,
        });
        world.log.push('insertPending');
        return Promise.resolve(id);
      },
      markAvailable: (owner: Owner, id: bigint, executionRowId: bigint) => {
        const row = world.reports.find(
          (r) =>
            r.id === id &&
            r.organizationId === owner.scope.organizationId &&
            r.userId === owner.userId &&
            r.status === 'pending',
        );
        world.log.push('markAvailable');
        if (!row) return Promise.resolve(false);
        row.status = 'available';
        row.executionId = executionRowId;
        return Promise.resolve(true);
      },
      markFailed: (owner: Owner, id: bigint, errorCode: string) => {
        const row = world.reports.find(
          (r) =>
            r.id === id &&
            r.organizationId === owner.scope.organizationId &&
            r.status === 'pending',
        );
        if (!row) return Promise.resolve(false);
        row.status = 'failed';
        row.errorCode = errorCode;
        return Promise.resolve(true);
      },
      countSince: (owner: Owner, since: Date) =>
        Promise.resolve(
          world.reports.filter(
            (r) =>
              r.organizationId === owner.scope.organizationId &&
              r.userId === owner.userId &&
              r.createdAt >= since,
          ).length,
        ),
      findOwned: (owner: Owner, overrideId: string | null, publicId: string) => {
        const row = world.reports.find(
          (r) => r.publicId === publicId && world.owns(owner, overrideId, r),
        );
        if (!row) return Promise.resolve(null);
        const view: ReportWithRefs = {
          ...structuredClone(row),
          executionPublicId:
            row.executionId === null ? null : world.executionPublicIdOf(row.executionId),
        };
        return Promise.resolve(view);
      },
      findForConversation: (
        owner: Owner,
        overrideId: string | null,
        conversationId: bigint,
        publicId: string | null,
      ) => {
        const rows = world.reports
          .filter(
            (r) =>
              world.owns(owner, overrideId, r) &&
              r.conversationId === conversationId &&
              (publicId === null ? r.status === 'available' : r.publicId === publicId),
          )
          .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime() || (a.id < b.id ? 1 : -1));
        return Promise.resolve(rows[0] ? structuredClone(rows[0]) : null);
      },
      objectsOfConversation: (organizationId: bigint, conversationId: bigint) =>
        Promise.resolve(
          world.reports
            .filter(
              (r) =>
                r.organizationId === organizationId &&
                r.conversationId === conversationId &&
                r.status === 'purged' &&
                r.objectDeletedAt === null,
            )
            .map((r): ReportObjectRow => ({
              id: r.id,
              organizationId: r.organizationId,
              objectKey: r.objectKey,
            })),
        ),
      objectPurgeBatch: (take: number) =>
        Promise.resolve(
          world.reports
            .filter((r) => r.status === 'purged' && r.objectDeletedAt === null)
            .slice(0, take)
            .map((r): ReportObjectRow => ({
              id: r.id,
              organizationId: r.organizationId,
              objectKey: r.objectKey,
            })),
        ),
      markObjectDeleted: (organizationId: bigint, id: bigint, now: Date) => {
        const row = world.reports.find(
          (r) => r.id === id && r.organizationId === organizationId && r.objectDeletedAt === null,
        );
        if (!row) return Promise.resolve(false);
        row.objectDeletedAt = now;
        row.objectKey = null;
        return Promise.resolve(true);
      },
      pendingBefore: (before: Date, take: number) =>
        Promise.resolve(
          world.reports
            .filter((r) => r.status === 'pending' && r.createdAt < before)
            .slice(0, take)
            .map((r): ReportObjectRow => ({
              id: r.id,
              organizationId: r.organizationId,
              objectKey: r.objectKey,
            })),
        ),
      abandon: (organizationId: bigint, id: bigint, now: Date) => {
        const row = world.reports.find(
          (r) => r.id === id && r.organizationId === organizationId && r.status === 'pending',
        );
        if (!row) return Promise.resolve(false);
        Object.assign(row, {
          status: 'failed',
          errorCode: 'assistant_report_abandoned',
          objectDeletedAt: now,
          objectKey: null,
        });
        return Promise.resolve(true);
      },
    } as unknown as ReportsRepository;
  }

  deliveriesDouble(): ReportDeliveriesRepository {
    const world = this;
    return {
      lockTenant: (organizationId: bigint) => {
        world.log.push('lock');
        return Promise.resolve(world.settingsRows.has(organizationId));
      },
      insertEmailRequested: (
        _tx: unknown,
        event: { organizationId: bigint; correlationId: string; payload: { deliveryId: string } },
      ) => {
        world.log.push('outbox');
        world.outbox.push({
          eventId: event.payload.deliveryId,
          organizationId: event.organizationId,
          eventType: 'assistant.report.email_requested.v1',
          aggregateType: 'assistant_report_delivery',
          aggregateId: event.payload.deliveryId,
          correlationId: event.correlationId,
          payload: structuredClone(event.payload),
        });
        return Promise.resolve();
      },
      insert: (data: DeliveryCreate) => {
        if (world.deliveries.some((d) => d.confirmationId === data.confirmationId)) {
          return Promise.reject(new Error('unique confirmation_id'));
        }
        const id = world.id();
        world.deliveries.push({
          id,
          publicId: data.publicId,
          organizationId: data.organizationId,
          userId: data.userId,
          conversationId: data.conversationId,
          reportId: data.reportId,
          confirmationId: data.confirmationId,
          recipientAddress: data.recipientAddress,
          recipientSha256: data.recipientSha256,
          recipientKind: data.recipientKind,
          status: 'queued',
          errorCode: null,
          sizeBytes: data.sizeBytes,
          correlationId: data.correlationId,
          requestedAt: data.requestedAt,
          sentAt: null,
        });
        world.log.push('delivery');
        return Promise.resolve({ id, publicId: data.publicId });
      },
      countTenantSince: (organizationId: bigint, since: Date) =>
        Promise.resolve(
          world.deliveries.filter(
            (d) => d.organizationId === organizationId && d.requestedAt >= since,
          ).length,
        ),
      countUserSince: (organizationId: bigint, userId: bigint, since: Date) =>
        Promise.resolve(
          world.deliveries.filter(
            (d) =>
              d.organizationId === organizationId && d.userId === userId && d.requestedAt >= since,
          ).length,
        ),
      listForReport: (organizationId: bigint, reportId: bigint, take: number) =>
        Promise.resolve(
          world.deliveries
            .filter((d) => d.organizationId === organizationId && d.reportId === reportId)
            .sort((a, b) => b.requestedAt.getTime() - a.requestedAt.getTime())
            .slice(0, take)
            .map((d) => structuredClone(d)),
        ),
      failQueuedBefore: (before: Date, code: string, batch: number) => {
        let n = 0;
        for (const d of world.deliveries) {
          if (n >= batch) break;
          if (d.status === 'queued' && d.requestedAt < before) {
            d.status = 'failed';
            d.errorCode = code;
            n += 1;
          }
        }
        return Promise.resolve(n);
      },
    } as unknown as ReportDeliveriesRepository;
  }

  directoryDouble(): RecipientDirectoryRepository {
    const world = this;
    return {
      selfEmail: (userId: bigint) => {
        const user = world.users.find((u) => u.id === userId && u.verified && !u.deleted);
        return Promise.resolve(user?.email ?? null);
      },
      isActiveMember: (scope: TenantScope, address: string) =>
        Promise.resolve(
          world.users.some(
            (u) =>
              u.organizationId === scope.organizationId &&
              u.email.toLowerCase() === address.toLowerCase() &&
              u.status === 'active' &&
              u.verified &&
              !u.deleted,
          ),
        ),
      verifiedDomains: (scope: TenantScope, names: readonly string[]) =>
        Promise.resolve(
          new Set(
            world.domains
              .filter(
                (d) =>
                  d.organizationId === scope.organizationId &&
                  names.map((n) => n.toLowerCase()).includes(d.name.toLowerCase()) &&
                  (d.status === 'verified' || d.status === 'active') &&
                  !d.deleted,
              )
              .map((d) => d.name.toLowerCase()),
          ),
        ),
    } as unknown as RecipientDirectoryRepository;
  }

  storeDouble(): ReportObjectStore {
    const world = this;
    return {
      put: (organizationId: bigint, key: string, bytes: Buffer, sha256: string) => {
        if (!isReportKeyOf(key, organizationId))
          return Promise.reject(new ReportObjectError('foreign_key'));
        world.log.push(`put:${key}`);
        if (world.failNext.put) {
          world.failNext.put = false;
          return Promise.reject(
            Object.assign(new Error('S3 down'), { name: 'ServiceUnavailable' }),
          );
        }
        if (sha256Hex(bytes) !== sha256) return Promise.reject(new Error('BadDigest'));
        world.objects.set(key, Buffer.from(bytes));
        return Promise.resolve();
      },
      get: (organizationId: bigint, key: string, maxBytes: number, sha256: string) => {
        if (!isReportKeyOf(key, organizationId))
          return Promise.reject(new ReportObjectError('foreign_key'));
        if (world.failNext.get) {
          world.failNext.get = false;
          return Promise.reject(new ReportObjectError('not_found'));
        }
        const bytes = world.objects.get(key);
        if (!bytes) return Promise.reject(new ReportObjectError('not_found'));
        if (bytes.length > maxBytes) return Promise.reject(new ReportObjectError('too_large'));
        if (sha256Hex(bytes) !== sha256) return Promise.reject(new ReportObjectError('integrity'));
        return Promise.resolve(Buffer.from(bytes));
      },
      delete: (organizationId: bigint, key: string) => {
        if (!isReportKeyOf(key, organizationId))
          return Promise.reject(new ReportObjectError('foreign_key'));
        world.log.push(`delete:${key}`);
        if (world.failNext.delete) {
          world.failNext.delete = false;
          return Promise.reject(
            Object.assign(new Error('S3 down'), { name: 'ServiceUnavailable' }),
          );
        }
        world.objects.delete(key);
        return Promise.resolve();
      },
    } as unknown as ReportObjectStore;
  }
}

// ---- report source bodies (synthetic 200 answers of the nine source operations) -------------

const counts = (keys: readonly string[], value = (i: number) => i + 1): Record<string, number> =>
  Object.fromEntries(keys.map((k, i) => [k, value(i)]));

const VERDICT_KEYS = [
  'clean',
  'spam',
  'bulk',
  'phishing',
  'malware',
  'bec',
  'dlp_violation',
  'suspicious',
  'unknown',
  'none',
];
const ACTIONS = [
  'deliver',
  'tag',
  'quarantine',
  'discard',
  'reject',
  'require_approval',
  'partial',
  'none',
];
const REASONS = [
  'spam',
  'bulk',
  'phishing',
  'malware',
  'bec',
  'dlp',
  'policy',
  'suspicious',
  'engine_unavailable',
  'manual',
];
const ENGINES = ['rspamd', 'attachment', 'url', 'bec', 'dlp', 'sandbox', 'policy', 'none'];
const DELIVERY = [
  'pending',
  'in_progress',
  'queued',
  'deferred',
  'delivered',
  'bounced',
  'expired',
  'failed',
  'suppressed',
  'unknown',
];
const CLICKS = ['allowed', 'warned', 'blocked', 'continued', 'expired', 'not_found'];

/** Source key → 200 body, shaped like the response schemas (`.test` names only). */
export function reportSourceBodies(
  window: { from: string; to: string },
  options: { atoFeature?: boolean; accountDisplayName?: string } = {},
): Record<string, unknown> {
  const meta = { from: window.from, to: window.to, generatedAt: window.to };
  const start = window.from;
  return {
    traffic: {
      ...meta,
      buckets: [
        {
          start,
          total: 120,
          inbound: 100,
          outbound: 15,
          internal: 5,
          verdicts: counts(VERDICT_KEYS),
        },
      ],
      totals: {
        total: 120,
        inbound: 100,
        outbound: 15,
        internal: 5,
        verdicts: counts(VERDICT_KEYS),
      },
    },
    threats: {
      ...meta,
      messages: { total: 120, verdicts: counts(VERDICT_KEYS), actions: counts(ACTIONS) },
      outcomes: [{ verdict: 'spam', action: 'quarantine', count: 7 }],
      quarantine: { total: 9, reasons: counts(REASONS), primaryEngines: counts(ENGINES) },
    },
    top_domains: {
      ...meta,
      domains: [
        {
          name: 'alpha.example.test',
          status: 'active',
          deleted: false,
          inbound: 80,
          threats: 6,
          verdicts: { spam: 3, phishing: 1, malware: 1, bec: 0, suspicious: 1 },
        },
      ],
      unattributed: { inbound: 2, threats: 0 },
    },
    delivery: {
      ...meta,
      buckets: [{ start, total: 50, statuses: counts(DELIVERY), successRate: 0.98 }],
      totals: { total: 50, statuses: counts(DELIVERY), successRate: 0.98 },
      latency: {
        delivered: 49,
        averageMs: 900,
        p50UpperBoundMs: 1000,
        p95UpperBoundMs: 5000,
        histogram: [
          { leMs: 1000, count: 40 },
          { leMs: null, count: 9 },
        ],
      },
    },
    processing: {
      ...meta,
      buckets: [{ start, rounds: 120, averageMs: 300, p95UpperBoundMs: 1000 }],
      totals: {
        rounds: 120,
        averageMs: 300,
        p50UpperBoundMs: 500,
        p95UpperBoundMs: 1000,
        histogram: [{ leMs: 1000, count: 120 }],
      },
    },
    url_clicks: {
      ...meta,
      buckets: [{ start, total: 6, decisions: counts(CLICKS) }],
      totals: { total: 6, decisions: counts(CLICKS) },
    },
    quarantine_summary: {
      from: window.from,
      to: window.to,
      counts: { held: 4, released: 2 },
      pendingApprovals: 1,
    },
    ato_overview: {
      generatedAt: window.to,
      range: '7d',
      from: window.from,
      to: window.to,
      monitoring: {
        featureEnabled: options.atoFeature ?? true,
        mode: options.atoFeature === false ? 'off' : 'monitor',
      },
      accounts: { monitored: 10, highRisk: 1, criticalRisk: 0 },
      incidents: {
        active: 1,
        trend: [{ bucketStart: start, low: 0, medium: 1, high: 0, critical: 0 }],
      },
      logins: { suspiciousInRange: 2 },
      outbound: { restrictedAccounts: 0 },
      geography: { available: false, topCountries: [] },
    },
    ato_accounts: {
      data: [
        {
          kind: 'mailbox',
          address: 'it-risky@example.test',
          displayName: options.accountDisplayName ?? 'Risky Account',
          riskScore: 81,
          riskLevel: 'high',
          activeIncident: null,
        },
      ],
    },
  };
}
