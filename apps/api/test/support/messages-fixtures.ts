/**
 * In-memory doubles of the step 6.1 WP2 repositories for the stubbed e2e suites
 * (messages-list, messages-data, recipients, route-security-messages): a tiny tenant-scoped
 * "database" of messages, recipients, deliveries, attachments, URLs, clicks and suppressions,
 * with the same echo of the organization the real repositories enforce, plus a recording
 * AuditService and a no-op organization row lock. Test-only: never used by production code.
 */
import { randomUUID } from 'node:crypto';
import type { TestingModuleBuilder } from '@nestjs/testing';
import { AuditService, type AuditEntry } from '../../src/audit/audit.service';
import type { TenantScope } from '../../src/auth-contracts/tenant-scope';
import type { CursorDirection } from '../../src/http/cursor/cursor-codec';
import {
  type AttachmentPart,
  AttachmentsRepository,
  type AttachmentSearchRow,
  type LatestResultRow,
} from '../../src/modules/attachments/attachments.repository';
import type { TimeIdKey } from '../../src/modules/messages/domain/v1-list';
import {
  type DeliveryRow,
  MessageDataRepository,
  type MessageDetailRow,
  type MessageListRow,
  type MessageRef,
  type RecipientKeyRow,
  type RecipientRow,
  type ResolvedMessageFilters,
} from '../../src/modules/messages/repositories/message-data.repository';
import {
  RecipientSuppressionsRepository,
  type SuppressionFilters,
  type SuppressionRow,
} from '../../src/modules/recipients/recipient-suppressions.repository';
import { DomainsRepository } from '../../src/modules/tenant-data/domains.repository';
import { MessagesRepository } from '../../src/modules/tenant-data/messages.repository';
import {
  type ClickFilters,
  type ClickRow,
  type MessageUrlFullRow,
  UrlProtectionRepository,
  type UrlLatestRow,
} from '../../src/modules/url-protection/url-protection.repository';
import { OrganizationLimitsService } from '../../src/tenancy/organization-limits.service';

export interface WorldMessage extends MessageDetailRow {
  recipients: string[];
}

const cmp = (a: TimeIdKey, b: TimeIdKey): number =>
  a.at.getTime() !== b.at.getTime()
    ? a.at.getTime() - b.at.getTime()
    : a.id === b.id
      ? 0
      : a.id < b.id
        ? -1
        : 1;

function keyset<R>(
  rows: readonly R[],
  keyOf: (r: R) => TimeIdKey,
  input: { after?: TimeIdKey | undefined; direction: CursorDirection; take: number },
  boundary?: TimeIdKey | null,
): R[] {
  const sign = input.direction === 'desc' ? -1 : 1;
  return rows
    .filter((r) => !input.after || sign * cmp(keyOf(r), input.after) > 0)
    .filter((r) => !boundary || sign * cmp(keyOf(r), boundary) <= 0)
    .sort((a, b) => sign * cmp(keyOf(a), keyOf(b)))
    .slice(0, input.take);
}

const inRange = (at: Date, range: { from: Date; to: Date }) =>
  at.getTime() >= range.from.getTime() && at.getTime() < range.to.getTime();

/** Async repository methods of `T` written synchronously (the doubles have nothing to await). */
type SyncDouble<T> = {
  [K in keyof T]?: T[K] extends (...args: infer A) => Promise<infer R> ? (...args: A) => R : never;
};

function asyncDouble<T>(sync: SyncDouble<T>): Partial<T> {
  return Object.fromEntries(
    Object.entries(sync).map(([name, fn]) => [
      name,
      (...args: unknown[]) => Promise.resolve((fn as (...a: unknown[]) => unknown)(...args)),
    ]),
  ) as Partial<T>;
}

/** The in-memory rows every double reads (by organization). */
export class MessagesWorld {
  messages: WorldMessage[] = [];
  recipients: RecipientRow[] = [];
  deliveries: DeliveryRow[] = [];
  domains: Array<{ id: bigint; publicId: string; organizationId: bigint }> = [];
  users: Array<{ id: bigint; publicId: string; organizationId: bigint }> = [];
  attachments: AttachmentPart[] = [];
  attachmentResults: LatestResultRow[] = [];
  urls: MessageUrlFullRow[] = [];
  urlResults: Array<UrlLatestRow & { organizationId: bigint; messageId: bigint }> = [];
  clicks: ClickRow[] = [];
  scans: Array<{ id: bigint; messageId: bigint; organizationId: bigint; lifecycleRound: number }> =
    [];
  suppressions: SuppressionRow[] = [];
  private nextId = 1000n;

  id(): bigint {
    this.nextId += 1n;
    return this.nextId;
  }

  addMessage(org: bigint, over: Partial<WorldMessage> = {}): WorldMessage {
    const id = over.id ?? this.id();
    const receivedAt = over.receivedAt ?? new Date(Date.now() - 60_000);
    const message: WorldMessage = {
      id,
      publicId: randomUUID(),
      receivedAt,
      organizationId: org,
      domainId: null,
      direction: 'inbound',
      status: 'delivered',
      statusChangedAt: receivedAt,
      subject: 'Hello',
      envelopeFrom: 'sender@vendor.example',
      headerFrom: 'Sender <sender@vendor.example>',
      recipientCount: 1,
      attachmentCount: 0,
      sizeBytes: 1000,
      finalVerdict: 'clean',
      finalAction: 'deliver',
      riskScore: 10,
      internetMessageId: `<${randomUUID()}@vendor.example>`,
      lifecycleRound: 0,
      version: 3,
      statusReason: null,
      clientIp: '198.51.100.1',
      clientHelo: 'mx.vendor.example',
      mtaQueueId: 'QID1',
      recipients: ['alice@acme.example'],
      ...over,
    };
    this.messages.push(message);
    message.recipients.forEach((address, rcptSeq) => {
      this.recipients.push({
        id: this.id(),
        organizationId: org,
        messageId: id,
        receivedAt,
        rcptSeq,
        address,
        status: 'delivered',
        finalAction: 'deliver',
        direction: message.direction,
        userId: null,
      });
    });
    return message;
  }
}

const listRow = (m: WorldMessage): MessageListRow => ({
  id: m.id,
  receivedAt: m.receivedAt,
  organizationId: m.organizationId,
  domainId: m.domainId,
  direction: m.direction,
  status: m.status,
  statusChangedAt: m.statusChangedAt,
  subject: m.subject,
  envelopeFrom: m.envelopeFrom,
  headerFrom: m.headerFrom,
  recipientCount: m.recipientCount,
  attachmentCount: m.attachmentCount,
  sizeBytes: m.sizeBytes,
  finalVerdict: m.finalVerdict,
  finalAction: m.finalAction,
  riskScore: m.riskScore,
});

function matches(world: MessagesWorld, m: WorldMessage, f: ResolvedMessageFilters): boolean {
  const has = (values: readonly unknown[] | undefined, v: unknown) => !values || values.includes(v);
  const risk = f.riskScore;
  const score = m.riskScore;
  return (
    has(f.direction?.values, m.direction) &&
    has(f.status?.values, m.status) &&
    has(f.verdict?.values, m.finalVerdict) &&
    has(f.action?.values, m.finalAction) &&
    (f.domainId === undefined || m.domainId === f.domainId) &&
    has(f.sender?.values, m.envelopeFrom) &&
    has(f.headerFrom?.values, m.headerFrom) &&
    has(f.internetMessageId?.values, m.internetMessageId) &&
    (!risk ||
      (score !== null &&
        has(risk.values, score) &&
        (risk.gte === undefined || score >= risk.gte) &&
        (risk.lte === undefined || score <= risk.lte) &&
        (risk.gt === undefined || score > risk.gt) &&
        (risk.lt === undefined || score < risk.lt))) &&
    (f.hasAttachments?.values === undefined ||
      f.hasAttachments.values[0] === m.attachmentCount > 0) &&
    (f.recipient?.values === undefined ||
      world.recipients.some((r) => r.messageId === m.id && r.address === f.recipient!.values![0]))
  );
}

/** MessageDataRepository over the world (same method contract). */
export function messageDataDouble(world: MessagesWorld): Partial<MessageDataRepository> {
  const own = (scope: TenantScope) =>
    world.messages.filter((m) => m.organizationId === scope.organizationId);
  const key = (r: { receivedAt: Date; id: bigint }) => ({ at: r.receivedAt, id: r.id });
  return asyncDouble<MessageDataRepository>({
    indexPlan: (scope, input) =>
      keyset(
        own(scope).filter((m) => inRange(m.receivedAt, input.range)),
        key,
        input,
      ).map(listRow),
    verdictPlan: (scope, input) =>
      keyset(
        own(scope).filter(
          (m) => inRange(m.receivedAt, input.range) && m.finalVerdict === input.verdict,
        ),
        key,
        input,
      ).map(listRow),
    recipientRows: (scope, input) =>
      keyset(
        world.recipients.filter(
          (r) =>
            r.organizationId === scope.organizationId &&
            r.address === input.address &&
            inRange(r.receivedAt, input.range),
        ),
        key,
        input,
      ).map((r): RecipientKeyRow => ({
        id: r.id,
        receivedAt: r.receivedAt,
        messageId: r.messageId,
        organizationId: r.organizationId,
      })),
    messagesByKeys: (scope, _range, keys) =>
      own(scope)
        .filter((m) => keys.some((k) => k.id === m.id))
        .map(listRow),
    scanBoundary: (scope, input) => {
      const all = keyset(
        own(scope).filter((m) => inRange(m.receivedAt, input.range)),
        key,
        { ...input, take: Number.MAX_SAFE_INTEGER },
      );
      const at = all[input.budget - 1];
      return at ? key(at) : null;
    },
    scanPage: (scope, input) =>
      keyset(
        own(scope).filter(
          (m) => inRange(m.receivedAt, input.range) && matches(world, m, input.filters),
        ),
        key,
        input,
        input.boundary,
      ).map(listRow),
    publicIds: (scope, ids) =>
      new Map(
        own(scope)
          .filter((m) => ids.includes(m.id))
          .map((m) => [m.id, m.publicId]),
      ),
    domainPublicIds: (scope, ids) =>
      new Map(
        world.domains
          .filter((d) => d.organizationId === scope.organizationId && ids.includes(d.id))
          .map((d) => [d.id, d.publicId]),
      ),
    findDetail: (scope, publicId) => own(scope).find((m) => m.publicId === publicId) ?? null,
    findRef: (scope, publicId) => {
      const m = own(scope).find((x) => x.publicId === publicId);
      return m
        ? {
            id: m.id,
            publicId: m.publicId,
            receivedAt: m.receivedAt,
            organizationId: m.organizationId,
          }
        : null;
    },
    recipients: (scope, message, page) =>
      world.recipients
        .filter(
          (r) =>
            r.organizationId === scope.organizationId &&
            r.messageId === message.id &&
            (page.afterSeq === undefined || r.rcptSeq > page.afterSeq),
        )
        .sort((a, b) => a.rcptSeq - b.rcptSeq)
        .slice(0, page.take),
    deliveries: (scope, message, ids) =>
      world.deliveries.filter(
        (d) =>
          d.organizationId === scope.organizationId &&
          d.messageId === message.id &&
          ids.includes(d.recipientId),
      ),
    userPublicIds: (scope, ids) =>
      new Map(
        world.users
          .filter((u) => u.organizationId === scope.organizationId && ids.includes(u.id))
          .map((u) => [u.id, u.publicId]),
      ),
    scanRounds: (scope, message: MessageRef, ids) =>
      new Map(
        world.scans
          .filter(
            (s) =>
              s.organizationId === scope.organizationId &&
              s.messageId === message.id &&
              ids.includes(s.id),
          )
          .map((s) => [s.id, s.lifecycleRound]),
      ),
  });
}

export function attachmentsDouble(world: MessagesWorld): Partial<AttachmentsRepository> {
  return asyncDouble<AttachmentsRepository>({
    parts: (scope, message, page) =>
      world.attachments
        .filter(
          (a) =>
            a.organizationId === scope.organizationId &&
            a.messageId === message.id &&
            (page.afterPartIndex === undefined || a.partIndex > page.afterPartIndex),
        )
        .sort((a, b) => a.partIndex - b.partIndex)
        .slice(0, page.take),
    results: (scope, _message, ids) =>
      world.attachmentResults.filter(
        (r) => r.organizationId === scope.organizationId && ids.includes(r.attachmentId),
      ),
    search: (scope, input) =>
      keyset(
        world.attachments.filter(
          (a) =>
            a.organizationId === scope.organizationId &&
            a.sha256 === input.sha256 &&
            inRange(a.receivedAt, input.range),
        ),
        (a) => ({ at: a.receivedAt, id: a.id }),
        input,
      ).map((a): AttachmentSearchRow => ({
        id: a.id,
        receivedAt: a.receivedAt,
        organizationId: a.organizationId,
        messageId: a.messageId,
        partIndex: a.partIndex,
        filename: a.filename,
        sizeBytes: a.sizeBytes,
        detectedContentType: a.detectedContentType,
        sha256: a.sha256,
      })),
    latestVerdicts: (scope, rows) => {
      const out = new Map<bigint, string>();
      for (const r of [...world.attachmentResults].sort((a, b) => (a.scanId < b.scanId ? 1 : -1))) {
        if (r.organizationId !== scope.organizationId) continue;
        if (rows.some((x) => x.id === r.attachmentId) && !out.has(r.attachmentId)) {
          out.set(r.attachmentId, r.verdict);
        }
      }
      return out;
    },
  });
}

export function urlsDouble(world: MessagesWorld): Partial<UrlProtectionRepository> {
  const clickKey = (c: ClickRow) => ({ at: c.clickedAt, id: c.id });
  const filtered = (scope: TenantScope, range: { from: Date; to: Date }, f: ClickFilters = {}) =>
    world.clicks.filter(
      (c) =>
        c.organizationId === scope.organizationId &&
        inRange(c.clickedAt, range) &&
        (!f.decisions || f.decisions.length === 0 || f.decisions.includes(c.decision)) &&
        (!f.verdicts || f.verdicts.length === 0 || f.verdicts.includes(c.verdict ?? '')) &&
        (!f.message || c.messageId === f.message.id),
    );
  return asyncDouble<UrlProtectionRepository>({
    messageUrls: (scope, message, page) =>
      world.urls
        .filter(
          (u) =>
            u.organizationId === scope.organizationId &&
            u.messageId === message.id &&
            (page.afterSeq === undefined || u.urlSeq > page.afterSeq),
        )
        .sort((a, b) => a.urlSeq - b.urlSeq)
        .slice(0, page.take),
    results: (scope, message, seqs) =>
      world.urlResults.filter(
        (r) =>
          r.organizationId === scope.organizationId &&
          r.messageId === message.id &&
          seqs.includes(r.urlSeq),
      ),
    latestRewrite: () => null,
    clickCounts: (scope, message, seqs) => {
      const counts = new Map<string, { urlSeq: number; decision: string; count: number }>();
      for (const c of world.clicks) {
        if (c.organizationId !== scope.organizationId || c.messageId !== message.id) continue;
        if (!seqs.includes(c.urlSeq)) continue;
        const k = `${c.urlSeq}:${c.decision}`;
        const entry = counts.get(k) ?? { urlSeq: c.urlSeq, decision: c.decision, count: 0 };
        entry.count += 1;
        counts.set(k, entry);
      }
      return [...counts.values()];
    },
    clicks: (scope, input) =>
      keyset(filtered(scope, input.range, input.filters), clickKey, input, input.boundary ?? null),
    clicksBoundary: (scope, input) => {
      const all = keyset(filtered(scope, input.range), clickKey, {
        ...input,
        take: Number.MAX_SAFE_INTEGER,
      });
      const at = all[input.budget - 1];
      return at ? clickKey(at) : null;
    },
    clickHosts: (scope, clicks) =>
      new Map(
        world.urls
          .filter(
            (u) =>
              u.organizationId === scope.organizationId &&
              clicks.some((c) => c.messageId === u.messageId && c.urlSeq === u.urlSeq),
          )
          .map((u) => [
            `${u.messageId}:${u.urlSeq}`,
            { host: u.host, registrableDomain: u.registrableDomain },
          ]),
      ),
  });
}

export function suppressionsDouble(world: MessagesWorld): Partial<RecipientSuppressionsRepository> {
  const own = (scope: TenantScope) =>
    world.suppressions.filter((s) => s.organizationId === scope.organizationId);
  const match = (s: SuppressionRow, f: SuppressionFilters) =>
    (!f.reasons || f.reasons.length === 0 || f.reasons.includes(s.reason)) &&
    (f.address === undefined || s.address === f.address) &&
    (f.active === undefined ||
      f.active === (s.expiresAt === null || s.expiresAt.getTime() > f.now.getTime()));
  return asyncDouble<RecipientSuppressionsRepository>({
    list: (scope, page, filters) =>
      own(scope)
        .filter(
          (s) =>
            (page.beforeId === undefined || s.id < page.beforeId) &&
            (page.boundaryId === undefined ||
              page.boundaryId === null ||
              s.id >= page.boundaryId) &&
            match(s, filters),
        )
        .sort((a, b) => (a.id < b.id ? 1 : -1))
        .slice(0, page.take),
    boundary: (scope, beforeId, budget) => {
      const all = own(scope)
        .filter((s) => beforeId === undefined || s.id < beforeId)
        .sort((a, b) => (a.id < b.id ? 1 : -1));
      return all[budget - 1]?.id ?? null;
    },
    find: (scope, id) => own(scope).find((s) => s.id === id) ?? null,
    findByAddress: (_tx, scope, address) => own(scope).find((s) => s.address === address) ?? null,
    countCreatable: (_tx, scope) =>
      own(scope).filter((s) => s.reason === 'manual' || s.reason === 'unsubscribe').length,
    create: (_tx, scope, data) => {
      const row: SuppressionRow = {
        id: world.id(),
        organizationId: scope.organizationId,
        address: data.address,
        reason: data.reason,
        source: data.source,
        expiresAt: data.expiresAt,
        createdAt: new Date(),
        createdBy: null,
      };
      world.suppressions.push(row);
      return row;
    },
    lock: (_tx, scope, id) => own(scope).find((s) => s.id === id) ?? null,
    delete: (_tx, scope, id) => {
      const before = world.suppressions.length;
      world.suppressions = world.suppressions.filter(
        (s) => !(s.id === id && s.organizationId === scope.organizationId),
      );
      return before - world.suppressions.length;
    },
  });
}

/** AuditService that records entries in memory (actorFrom is the real one). */
export class RecordingAuditService extends AuditService {
  readonly entries: AuditEntry[] = [];
  constructor() {
    super({} as never);
  }
  override record(entry: AuditEntry): Promise<void> {
    this.entries.push(entry);
    return Promise.resolve();
  }
}

/** Overrides every WP2 repository (and audit, org lock, domain lookups) with the doubles. */
export function overrideMessagesData(
  builder: TestingModuleBuilder,
  world: MessagesWorld,
  audit: RecordingAuditService,
): TestingModuleBuilder {
  return builder
    .overrideProvider(MessageDataRepository)
    .useValue(messageDataDouble(world))
    .overrideProvider(AttachmentsRepository)
    .useValue(attachmentsDouble(world))
    .overrideProvider(UrlProtectionRepository)
    .useValue(urlsDouble(world))
    .overrideProvider(RecipientSuppressionsRepository)
    .useValue(suppressionsDouble(world))
    .overrideProvider(MessagesRepository)
    .useValue({
      publicIdMap: (scope: TenantScope, ids: readonly bigint[]) =>
        Promise.resolve(
          new Map(
            world.messages
              .filter((m) => m.organizationId === scope.organizationId && ids.includes(m.id))
              .map((m) => [m.id, m.publicId]),
          ),
        ),
    })
    .overrideProvider(DomainsRepository)
    .useValue({
      findByPublicId: (scope: TenantScope, publicId: string) =>
        Promise.resolve(
          world.domains.find(
            (d) => d.organizationId === scope.organizationId && d.publicId === publicId,
          ) ?? null,
        ),
    })
    .overrideProvider(AuditService)
    .useValue(audit)
    .overrideProvider(OrganizationLimitsService)
    .useValue({ lockOrganization: () => Promise.resolve() });
}

/** The parts of an OpenAPI operation the e2e suites assert (vendor extensions included). */
export interface OpenApiOperation {
  tags: string[];
  summary: string;
  description: string;
  parameters: Array<{ name: string; required?: boolean }>;
  responses: Record<
    string,
    {
      content: Record<
        string,
        { schema: { example?: Record<string, unknown> & { data?: unknown[] } } }
      >;
      headers: Record<string, unknown>;
    }
  >;
  [extension: `x-${string}`]: unknown;
}
