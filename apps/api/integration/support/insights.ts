/**
 * Fixtures of the step 6.1 WP3 integration suites (audit logs, reports, usage, billing, threat
 * intelligence): rows inserted directly on the writer (preconditions, as the other suites do),
 * replica visibility polling, EXPLAIN helpers and the cleanup of everything inserted. Message
 * metadata only: no content, no objects (the reports never read them).
 */
import { randomBytes, randomInt, randomUUID } from 'node:crypto';
import { PrismaReadService } from '@email-gateway/common';
import {
  type AuditActorType,
  type DeliveryStatus,
  type MessageAction,
  type MessageDirection,
  type MessageVerdict,
  Prisma,
  type QuarantinePrimaryEngine,
  type QuarantineReason,
  type ScanKind,
  type ScanStatus,
  type Severity,
  type ThreatCategory,
  type UrlClickDecision,
} from '@email-gateway/database';
import type { IntegrationApp } from './app';
import type { FixtureOrganization } from './fixtures';

export const POLL = { timeout: 20_000, interval: 200 };

/** A random id base per call: `email_messages.id` has no default (message identities). */
function idBase(): bigint {
  return 7_000_000_000_000_000n + BigInt(randomInt(0, 2 ** 40)) * 1_000_000n;
}

export interface MessageSpec {
  receivedAt: Date;
  direction: MessageDirection;
  verdict: MessageVerdict | null;
  action?: MessageAction | null;
  /** Internal `domains.id` (step 7.1 top domains); default NULL. */
  domainId?: bigint | null;
}

export interface InsertedMessage extends MessageSpec {
  id: bigint;
}

/** `email_messages` rows of `org` (metadata only), in chunks. */
export async function insertMessages(
  ctx: IntegrationApp,
  org: FixtureOrganization,
  specs: readonly MessageSpec[],
): Promise<InsertedMessage[]> {
  const base = idBase();
  const rows = specs.map((spec, i) => ({ ...spec, id: base + BigInt(i) }));
  for (let i = 0; i < rows.length; i += 2_000) {
    await ctx.prisma.emailMessage.createMany({
      data: rows.slice(i, i + 2_000).map((row) => ({
        id: row.id,
        receivedAt: row.receivedAt,
        organizationId: org.id,
        direction: row.direction,
        status: 'delivered',
        statusChangedAt: row.receivedAt,
        envelopeFrom: `sender@${org.slug}.example`,
        sizeBytes: 1024,
        recipientCount: 1,
        emlObjectKey: `org/${org.id.toString()}/eml/insights/${row.id.toString()}.eml`,
        emlSha256: 'a'.repeat(64),
        finalVerdict: row.verdict,
        finalAction: row.action ?? null,
        domainId: row.domainId ?? null,
      })),
    });
  }
  return rows;
}

export interface DeliverySpec {
  /** The message (its id and `received_at`) the delivery belongs to. */
  message: Pick<InsertedMessage, 'id' | 'receivedAt'>;
  status: DeliveryStatus;
  /** `delivered_at − received_at` in ms; NULL when omitted. */
  deliveredAfterMs?: number | null;
}

/** `email_deliveries` rows of `org` (one recipient each; no FK, partitioned). */
export async function insertDeliveries(
  ctx: IntegrationApp,
  org: FixtureOrganization,
  specs: readonly DeliverySpec[],
): Promise<void> {
  const base = idBase();
  for (let i = 0; i < specs.length; i += 2_000) {
    await ctx.prisma.emailDelivery.createMany({
      data: specs.slice(i, i + 2_000).map((spec, j) => ({
        receivedAt: spec.message.receivedAt,
        messageId: spec.message.id,
        recipientId: base + BigInt(i + j),
        organizationId: org.id,
        status: spec.status,
        deliveredAt:
          spec.deliveredAfterMs === undefined || spec.deliveredAfterMs === null
            ? null
            : new Date(spec.message.receivedAt.getTime() + spec.deliveredAfterMs),
      })),
    });
  }
}

export interface ScanRoundSpec {
  message: Pick<InsertedMessage, 'id' | 'receivedAt'>;
  status: ScanStatus;
  kind?: ScanKind;
  /** Distinct per message (unique (message_id, lifecycle_round, received_at)); default 0. */
  lifecycleRound?: number;
  /** `completed_at − received_at` in ms; NULL when omitted. */
  completedAfterMs?: number | null;
}

/** `email_scans` rounds of `org` (no FK, partitioned). */
export async function insertScanRounds(
  ctx: IntegrationApp,
  org: FixtureOrganization,
  specs: readonly ScanRoundSpec[],
): Promise<void> {
  for (let i = 0; i < specs.length; i += 2_000) {
    await ctx.prisma.emailScan.createMany({
      data: specs.slice(i, i + 2_000).map((spec) => ({
        receivedAt: spec.message.receivedAt,
        messageId: spec.message.id,
        organizationId: org.id,
        scanKind: spec.kind ?? 'initial',
        status: spec.status,
        lifecycleRound: spec.lifecycleRound ?? 0,
        completedAt:
          spec.completedAfterMs === undefined || spec.completedAfterMs === null
            ? null
            : new Date(spec.message.receivedAt.getTime() + spec.completedAfterMs),
      })),
    });
  }
}

/**
 * A `domains` row of `org` (deleted ones with status `deleted` and `deleted_at`); removed by the
 * fixtures' organization cleanup. Never writes the generated columns.
 */
export async function insertDomain(
  ctx: IntegrationApp,
  org: FixtureOrganization,
  name: string,
  options: { deleted?: boolean } = {},
): Promise<{ id: bigint; publicId: string; name: string }> {
  const now = new Date();
  return ctx.prisma.domain.create({
    data: {
      organizationId: org.id,
      name,
      status: options.deleted ? 'deleted' : 'active',
      deletedAt: options.deleted ? now : null,
      statusChangedAt: now,
    },
    select: { id: true, publicId: true, name: true },
  });
}

export interface QuarantineSpec {
  quarantinedAt: Date;
  reason: QuarantineReason;
  primaryEngine: QuarantinePrimaryEngine;
}

/** `quarantine_messages` entries of `org` (one per spec, each on its own message id). */
export async function insertQuarantineEntries(
  ctx: IntegrationApp,
  org: FixtureOrganization,
  specs: readonly QuarantineSpec[],
): Promise<void> {
  const base = idBase();
  await ctx.prisma.quarantineMessage.createMany({
    data: specs.map((spec, i) => ({
      organizationId: org.id,
      messageId: base + BigInt(i),
      messageReceivedAt: new Date(spec.quarantinedAt.getTime() - 5_000),
      recipientId: base + BigInt(i),
      rcptSeq: 0,
      recipientAddress: `rcpt${i}@${org.slug}.example`,
      direction: 'inbound',
      kind: 'quarantine',
      origin: 'policy',
      reason: spec.reason,
      status: 'held',
      envelopeFrom: `sender@${org.slug}.example`,
      primaryEngine: spec.primaryEngine,
      emlObjectKey: `org/${org.id.toString()}/eml/insights/q${i}.eml`,
      quarantinedAt: spec.quarantinedAt,
      expiresAt: new Date(spec.quarantinedAt.getTime() + 30 * 86_400_000),
      stateChangedAt: spec.quarantinedAt,
    })),
  });
}

export interface ClickSpec {
  clickedAt: Date;
  decision: UrlClickDecision;
}

/** `url_click_events` of `org` (no token material: only the key id). */
export async function insertClicks(
  ctx: IntegrationApp,
  org: FixtureOrganization,
  specs: readonly ClickSpec[],
): Promise<void> {
  const base = idBase();
  await ctx.prisma.urlClickEvent.createMany({
    data: specs.map((spec, i) => ({
      clickedAt: spec.clickedAt,
      publicId: randomUUID(),
      organizationId: org.id,
      messageId: base + BigInt(i),
      messageReceivedAt: new Date(spec.clickedAt.getTime() - 60_000),
      urlSeq: 0,
      decision: spec.decision,
      verdict: spec.decision === 'blocked' ? 'malicious' : 'clean',
      tokenKid: 1,
      durationMs: 12,
    })),
  });
}

export interface AuditSpec {
  createdAt: Date;
  action: string;
  resourceType?: string;
  resourceId?: string | null;
  actorType?: AuditActorType;
  actorId?: string | null;
  organizationId: bigint | null;
}

/** `audit_logs` rows with chosen instants (append-only by policy: never deleted). */
export async function insertAuditRows(
  ctx: IntegrationApp,
  specs: readonly AuditSpec[],
): Promise<void> {
  await ctx.prisma.auditLog.createMany({
    data: specs.map((s) => ({
      createdAt: s.createdAt,
      organizationId: s.organizationId,
      actorType: s.actorType ?? 'user',
      actorId: s.actorId ?? null,
      action: s.action,
      resourceType: s.resourceType ?? s.action.split('.')[0]!,
      resourceId: s.resourceId ?? null,
      correlationId: 'insights-fixture',
      sourceIp: '203.0.113.50',
      metadata: { fixture: true },
    })),
  });
}

/** A unique feed source per suite run (cleanup deletes by it). */
export const fixtureSource = (): string => `feed:it-${randomBytes(4).toString('hex')}`;

export async function insertPlatformIndicator(
  ctx: IntegrationApp,
  source: string,
  row: {
    type: 'url' | 'domain' | 'ip' | 'file_sha256';
    value: string;
    valueSha256: string;
    severity: Severity;
    category: ThreatCategory | null;
    expiresAt?: Date | null;
    organizationId?: bigint | null;
  },
): Promise<void> {
  const now = new Date();
  await ctx.prisma.threatIndicator.create({
    data: {
      organizationId: row.organizationId ?? null,
      indicatorType: row.type,
      value: row.value,
      valueSha256: row.valueSha256,
      source,
      severity: row.severity,
      confidence: 90,
      firstSeenAt: new Date(now.getTime() - 86_400_000),
      lastSeenAt: now,
      expiresAt: row.expiresAt ?? null,
      category: row.category,
      reason: 'insights fixture analyst note',
    },
  });
}

export async function insertSignature(
  ctx: IntegrationApp,
  source: string,
  sha256: string,
  severity: Severity,
  expiresAt: Date | null = null,
): Promise<void> {
  const now = new Date();
  await ctx.prisma.malwareSignature.create({
    data: {
      sha256,
      severity,
      source,
      firstSeenAt: new Date(now.getTime() - 86_400_000),
      lastSeenAt: now,
      expiresAt,
      reason: 'insights fixture analyst note',
    },
  });
}

export async function deleteThreatFixtures(ctx: IntegrationApp, source: string): Promise<void> {
  await ctx.prisma.threatIndicator.deleteMany({ where: { source } });
  await ctx.prisma.malwareSignature.deleteMany({ where: { source } });
}

/**
 * Deletes the message, delivery, scan round, quarantine and click rows of the organizations
 * (partition-safe). Domains go with the fixtures' organization cleanup.
 */
export async function deleteInsightFixtures(
  ctx: IntegrationApp,
  organizationIds: readonly bigint[],
): Promise<void> {
  const where = { organizationId: { in: [...organizationIds] } };
  await ctx.prisma.emailDelivery.deleteMany({ where });
  await ctx.prisma.emailScan.deleteMany({ where });
  await ctx.prisma.quarantineMessage.deleteMany({ where });
  await ctx.prisma.urlClickEvent.deleteMany({ where });
  await ctx.prisma.emailMessage.deleteMany({ where });
}

/** The replica client (reports and searches read it). */
export const reader = (ctx: IntegrationApp): PrismaReadService['client'] =>
  ctx.get(PrismaReadService).client;

interface ExplainTable {
  table_name?: string;
  access_type?: string;
  key?: string;
  partitions?: string[];
  using_index?: boolean;
  used_key_parts?: string[];
  rows_examined_per_scan?: number;
}

/** `EXPLAIN FORMAT=JSON` of a statement on the replica: the plan and its table nodes. */
export async function explain(
  ctx: IntegrationApp,
  sql: Prisma.Sql,
): Promise<{ plan: Record<string, unknown>; tables: ExplainTable[]; text: string }> {
  const rows = await reader(ctx).$queryRaw<Array<Record<string, string>>>(
    Prisma.sql`EXPLAIN FORMAT=JSON ${sql}`,
  );
  const text = Object.values(rows[0] ?? {})[0] ?? '';
  const plan = JSON.parse(text) as Record<string, unknown>;
  const tables: ExplainTable[] = [];
  const walk = (node: unknown): void => {
    if (Array.isArray(node)) node.forEach(walk);
    else if (node !== null && typeof node === 'object') {
      for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
        if (key === 'table' && value && typeof value === 'object') tables.push(value);
        walk(value);
      }
    }
  };
  walk(plan);
  return { plan, tables, text };
}

/** Partitions of a table (to show that a plan prunes). */
export async function partitionsOf(ctx: IntegrationApp, table: string): Promise<string[]> {
  const rows = await reader(ctx).$queryRaw<Array<{ name: string }>>`
    SELECT PARTITION_NAME AS name FROM information_schema.PARTITIONS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ${table} ORDER BY PARTITION_ORDINAL_POSITION`;
  return rows.map((r) => r.name);
}

export const DAY_MS = 86_400_000;
export const HOUR_MS = 3_600_000;

/** Midnight UTC `days` days before today. */
export function utcDay(daysAgo: number, now = new Date()): Date {
  return new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()) - daysAgo * DAY_MS,
  );
}

/** Polls `read` until it returns `expected` (usable in hooks, unlike `expect.poll`). */
export async function waitFor<T>(
  read: () => Promise<T>,
  expected: T,
  what = 'replica',
): Promise<void> {
  const deadline = Date.now() + POLL.timeout;
  let last: T | undefined;
  while (Date.now() < deadline) {
    last = await read();
    if (last === expected) return;
    await new Promise((resolve) => setTimeout(resolve, POLL.interval));
  }
  throw new Error(`${what}: expected ${String(expected)}, last ${String(last)}`);
}
