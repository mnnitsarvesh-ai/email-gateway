import { randomUUID } from 'node:crypto';
import { Prisma, PrismaClient, REGISTRY_PURGE_SQL } from '@email-gateway/database';
import { afterAll, describe, expect, it } from 'vitest';
import { stack } from './support/env';

/**
 * Asserts the physical MySQL schema produced by the migrations matches the data model in
 * docs/plan/steps/01-database.md (section 3) and ADR-0014: tables, partitioning, the absence of
 * foreign keys on partitioned tables, the tenancy column and the identity registry's unique key.
 */
const prisma = new PrismaClient({ datasourceUrl: stack.databaseUrl() });

afterAll(async () => {
  await prisma.$disconnect();
});

/** Partitioned tables and their RANGE COLUMNS partition column (D3). */
const PARTITIONED: Record<string, string> = {
  email_messages: 'received_at',
  email_recipients: 'received_at',
  email_attachments: 'received_at',
  email_scans: 'received_at',
  email_deliveries: 'received_at',
  email_headers: 'received_at',
  email_events: 'received_at',
  email_message_status_history: 'received_at',
  scan_engine_results: 'received_at',
  policy_execution_logs: 'received_at',
  delivery_attempts: 'received_at',
  email_archives: 'received_at',
  bounce_events: 'occurred_at',
  audit_logs: 'created_at',
  webhook_deliveries: 'event_occurred_at',
  message_outbox: 'created_at',
};

/** Tables with no `organization_id`: platform catalogs, the root, a join table, the ledger and
 * the maintenance job's watermarks. */
const NOT_TENANT_OWNED = [
  'organization_plans',
  'organizations',
  'permissions',
  'role_permissions',
  'ip_reputation',
  'domain_reputation',
  'url_reputation',
  'malware_signatures',
  'system_settings',
  'message_idempotency',
  'maintenance_watermarks',
];

/** Tenant-owned tables whose `organization_id` is nullable (platform-level rows), per D1. */
const NULLABLE_ORGANIZATION = [
  'roles',
  'threat_indicators',
  'yara_rules',
  'audit_logs',
  'login_audit_logs',
];

const TENANT_OWNED = [
  'organization_settings',
  'organization_limits',
  'organization_features',
  'organization_deployments',
  'users',
  'roles',
  'user_roles',
  'user_sessions',
  'api_keys',
  'login_audit_logs',
  'domains',
  'domain_verifications',
  'domain_dns_records',
  'domain_dkim_keys',
  'domain_mx_records',
  'domain_mail_servers',
  'domain_settings',
  'message_identities',
  'email_messages',
  'email_recipients',
  'email_headers',
  'email_attachments',
  'email_events',
  'email_message_status_history',
  'email_scans',
  'scan_engine_results',
  'threat_indicators',
  'yara_rules',
  'email_policies',
  'policy_versions',
  'policy_conditions',
  'policy_actions',
  'policy_exceptions',
  'policy_execution_logs',
  'delivery_routes',
  'email_deliveries',
  'delivery_attempts',
  'delivery_suppressions',
  'bounce_events',
  'quarantine_messages',
  'quarantine_actions',
  'quarantine_release_logs',
  'archive_settings',
  'archive_retention_policies',
  'email_archives',
  'archive_legal_holds',
  'message_outbox',
  'audit_logs',
  'webhook_subscriptions',
  'webhook_deliveries',
];

const ALL_TABLES = [...NOT_TENANT_OWNED, ...TENANT_OWNED];

describe('MySQL schema', () => {
  it('has exactly the 61 data-model tables plus _prisma_migrations', async () => {
    const rows = await prisma.$queryRaw<{ name: string }[]>`
      SELECT TABLE_NAME AS name FROM information_schema.TABLES
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'`;
    expect(ALL_TABLES).toHaveLength(61);
    expect(new Set(ALL_TABLES).size).toBe(61);
    expect(rows.map((r) => r.name).sort()).toEqual([...ALL_TABLES, '_prisma_migrations'].sort());
  });

  it('partitions the 16 high-volume tables by RANGE COLUMNS with a pmax partition', async () => {
    const rows = await prisma.$queryRaw<
      { tableName: string; method: string; expression: string; partitionName: string }[]
    >`
      SELECT TABLE_NAME AS tableName, PARTITION_METHOD AS method,
             PARTITION_EXPRESSION AS expression, PARTITION_NAME AS partitionName
      FROM information_schema.PARTITIONS
      WHERE TABLE_SCHEMA = DATABASE() AND PARTITION_NAME IS NOT NULL`;

    const partitionedTables = [...new Set(rows.map((r) => r.tableName))].sort();
    expect(partitionedTables).toEqual(Object.keys(PARTITIONED).sort());

    for (const [table, column] of Object.entries(PARTITIONED)) {
      const partitions = rows.filter((r) => r.tableName === table);
      for (const p of partitions) {
        expect(p.method, table).toBe('RANGE COLUMNS');
        expect(p.expression.replaceAll('`', ''), table).toBe(column);
      }
      expect(
        partitions.map((p) => p.partitionName),
        table,
      ).toContain('pmax');
    }
  });

  it('has no foreign keys to or from partitioned tables, but keeps them elsewhere', async () => {
    const rows = await prisma.$queryRaw<{ tableName: string; referencedTable: string }[]>`
      SELECT TABLE_NAME AS tableName, REFERENCED_TABLE_NAME AS referencedTable
      FROM information_schema.REFERENTIAL_CONSTRAINTS
      WHERE CONSTRAINT_SCHEMA = DATABASE()`;
    const usage = await prisma.$queryRaw<{ tableName: string; referencedTable: string }[]>`
      SELECT TABLE_NAME AS tableName, REFERENCED_TABLE_NAME AS referencedTable
      FROM information_schema.KEY_COLUMN_USAGE
      WHERE TABLE_SCHEMA = DATABASE() AND REFERENCED_TABLE_NAME IS NOT NULL`;

    expect(rows.length).toBeGreaterThan(0);
    for (const fk of [...rows, ...usage]) {
      expect(PARTITIONED, `${fk.tableName} -> ${fk.referencedTable}`).not.toHaveProperty(
        fk.tableName,
      );
      expect(PARTITIONED, `${fk.tableName} -> ${fk.referencedTable}`).not.toHaveProperty(
        fk.referencedTable,
      );
    }
  });

  it('has organization_id on every tenant-owned table, NOT NULL except the documented ones', async () => {
    const rows = await prisma.$queryRaw<{ tableName: string; nullable: string }[]>`
      SELECT TABLE_NAME AS tableName, IS_NULLABLE AS nullable
      FROM information_schema.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE() AND COLUMN_NAME = 'organization_id'`;
    const byTable = new Map(rows.map((r) => [r.tableName, r.nullable]));

    expect([...byTable.keys()].sort()).toEqual([...TENANT_OWNED].sort());
    for (const table of TENANT_OWNED) {
      expect(byTable.get(table), table).toBe(NULLABLE_ORGANIZATION.includes(table) ? 'YES' : 'NO');
    }
  });

  it('rejects a duplicate (organization_id, ingest_key) in the message identity registry', async () => {
    const suffix = randomUUID().slice(0, 8);
    const plan = await prisma.organizationPlan.create({
      data: { code: `it-${suffix}`, name: 'Schema test', defaultLimits: {}, defaultFeatures: {} },
    });
    const organization = await prisma.organization.create({
      data: {
        slug: `it-${suffix}`,
        name: 'Schema test',
        planId: plan.id,
        dataRegion: 'ap-south-1',
      },
    });
    const ingestKey = `it-${randomUUID()}`;
    const receivedAt = new Date();

    try {
      const first = await prisma.messageIdentity.create({
        data: { organizationId: organization.id, ingestKey, receivedAt },
      });
      expect(typeof first.id).toBe('bigint');
      expect(first.publicId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-/);

      const duplicate = prisma.messageIdentity.create({
        data: { organizationId: organization.id, ingestKey, receivedAt },
      });
      await expect(duplicate).rejects.toBeInstanceOf(Prisma.PrismaClientKnownRequestError);
      await expect(duplicate).rejects.toMatchObject({ code: 'P2002' });
    } finally {
      await prisma.messageIdentity.deleteMany({ where: { organizationId: organization.id } });
      await prisma.organization.deleteMany({ where: { id: organization.id } });
      await prisma.organizationPlan.deleteMany({ where: { id: plan.id } });
    }
  });
});

/** Creates a throwaway plan + organizations; `cleanup` removes everything they own. */
async function scratchOrganizations(count: number) {
  const suffix = randomUUID().slice(0, 8);
  const plan = await prisma.organizationPlan.create({
    data: { code: `it-${suffix}`, name: 'Schema test', defaultLimits: {}, defaultFeatures: {} },
  });
  const organizations = [];
  for (let i = 0; i < count; i += 1) {
    organizations.push(
      await prisma.organization.create({
        data: {
          slug: `it-${suffix}-${i}`,
          name: 'Schema test',
          planId: plan.id,
          dataRegion: 'ap-south-1',
        },
      }),
    );
  }
  const ids = organizations.map((o) => o.id);
  const cleanup = async () => {
    await prisma.threatIndicator.deleteMany({ where: { organizationId: { in: ids } } });
    await prisma.domain.deleteMany({ where: { organizationId: { in: ids } } });
    await prisma.organization.deleteMany({ where: { id: { in: ids } } });
    await prisma.organizationPlan.deleteMany({ where: { id: plan.id } });
  };
  return { suffix, ids, cleanup };
}

describe('tenant-safe unique keys', () => {
  it('lets two organizations hold a pending claim on one domain, but only one verified owner', async () => {
    const { suffix, ids, cleanup } = await scratchOrganizations(2);
    const [a, b] = ids as [bigint, bigint];
    const name = `it-${suffix}.example.test`;
    try {
      const claimA = await prisma.domain.create({ data: { organizationId: a, name } });
      const claimB = await prisma.domain.create({ data: { organizationId: b, name } });
      expect(claimA.verifiedName).toBeNull();
      expect(claimB.verifiedName).toBeNull();
      // A pending claim never resolves a tenant.
      expect(await prisma.domain.findUnique({ where: { verifiedName: name } })).toBeNull();

      // Only one claim per organization.
      await expect(
        prisma.domain.create({ data: { organizationId: a, name } }),
      ).rejects.toMatchObject({ code: 'P2002' });

      await prisma.domain.update({ where: { id: claimB.id }, data: { status: 'verified' } });
      const owner = await prisma.domain.findUnique({ where: { verifiedName: name } });
      expect(owner?.organizationId).toBe(b);

      // The second verification of the same name is rejected by the database.
      await expect(
        prisma.domain.update({ where: { id: claimA.id }, data: { status: 'verified' } }),
      ).rejects.toMatchObject({ code: 'P2002' });

      // Once the owner loses verification, the name is free to be verified by another tenant.
      await prisma.domain.update({ where: { id: claimB.id }, data: { status: 'failed' } });
      await prisma.domain.update({ where: { id: claimA.id }, data: { status: 'verified' } });
      expect(
        (await prisma.domain.findUnique({ where: { verifiedName: name } }))?.organizationId,
      ).toBe(a);
    } finally {
      await cleanup();
    }
  });

  it('refuses writes to the generated verified_name column', async () => {
    const { suffix, ids, cleanup } = await scratchOrganizations(1);
    try {
      await expect(
        prisma.domain.create({
          data: { organizationId: ids[0]!, name: `it-${suffix}.test`, verifiedName: 'x.test' },
        }),
      ).rejects.toThrow(/generated column/i);
    } finally {
      await cleanup();
    }
  });

  it('scopes threat indicator uniqueness by tenant, and dedupes platform rows', async () => {
    const { suffix, ids, cleanup } = await scratchOrganizations(2);
    const [a, b] = ids as [bigint, bigint];
    const valueSha256 = randomUUID().replaceAll('-', '').padEnd(64, '0');
    const now = new Date();
    const indicator = (organizationId: bigint | null) => ({
      organizationId,
      indicatorType: 'domain' as const,
      value: `it-${suffix}.bad.test`,
      valueSha256,
      source: 'analyst',
      severity: 'high' as const,
      confidence: 80,
      firstSeenAt: now,
      lastSeenAt: now,
    });
    let platformId: bigint | undefined;
    try {
      // Same source, type and value in two tenants: no collision, so nothing leaks across.
      const inA = await prisma.threatIndicator.create({ data: indicator(a) });
      const inB = await prisma.threatIndicator.create({ data: indicator(b) });
      expect(inA.orgScope).toBe(a);
      expect(inB.orgScope).toBe(b);

      // An upsert on the tenant-scoped key only ever touches the caller's own row.
      const upserted = await prisma.threatIndicator.upsert({
        where: {
          orgScope_source_indicatorType_valueSha256: {
            orgScope: b,
            source: 'analyst',
            indicatorType: 'domain',
            valueSha256,
          },
        },
        create: indicator(b),
        update: { confidence: 99 },
      });
      expect(upserted.id).toBe(inB.id);
      expect((await prisma.threatIndicator.findUnique({ where: { id: inA.id } }))?.confidence).toBe(
        80,
      );

      // Duplicates inside one tenant, and duplicate platform rows (NULL organization), collide.
      await expect(prisma.threatIndicator.create({ data: indicator(a) })).rejects.toMatchObject({
        code: 'P2002',
      });
      const platform = await prisma.threatIndicator.create({ data: indicator(null) });
      platformId = platform.id;
      expect(platform.orgScope).toBe(0n);
      await expect(prisma.threatIndicator.create({ data: indicator(null) })).rejects.toMatchObject({
        code: 'P2002',
      });
    } finally {
      if (platformId !== undefined) {
        await prisma.threatIndicator.deleteMany({ where: { id: platformId } });
      }
      await cleanup();
    }
  });
});

describe('message_identities retention purge', () => {
  it('deletes unreferenced registry rows and keeps rows an archive or quarantine row references', async () => {
    const { ids, cleanup } = await scratchOrganizations(1);
    const organizationId = ids[0]!;
    const receivedAt = new Date('2026-01-15T10:00:00Z');
    const mk = (i: number) =>
      prisma.messageIdentity.create({
        data: { organizationId, ingestKey: `it-${randomUUID()}-${i}`, receivedAt },
      });
    const [plain, archived, softDeleted, quarantined] = [
      await mk(0),
      await mk(1),
      await mk(2),
      await mk(3),
    ];
    const archive = (messageId: bigint, deletedAt: Date | null) =>
      prisma.emailArchive.create({
        data: {
          receivedAt,
          messageId,
          organizationId,
          archiveObjectKey: `it/${randomUUID()}`,
          sha256: '0'.repeat(64),
          sizeBytes: 1,
          retainUntil: new Date('2033-01-01T00:00:00Z'),
          archivedAt: receivedAt,
          deletedAt,
        },
      });
    try {
      await archive(archived.id, null);
      await archive(softDeleted.id, new Date());
      await prisma.quarantineMessage.create({
        data: {
          organizationId,
          messageId: quarantined.id,
          messageReceivedAt: receivedAt,
          recipientId: 1n,
          recipientAddress: 'user@example.test',
          reason: 'spam',
          envelopeFrom: 'sender@example.test',
          emlObjectKey: `it/${randomUUID()}`,
          quarantinedAt: receivedAt,
          expiresAt: new Date('2027-01-01T00:00:00Z'),
        },
      });

      // The exact statement the maintenance job runs, limited to this test's id range.
      const deleted = await prisma.$executeRawUnsafe(
        REGISTRY_PURGE_SQL,
        plain.id,
        quarantined.id + 1n,
      );
      expect(deleted).toBe(2);
      const left = await prisma.messageIdentity.findMany({
        where: { organizationId },
        select: { id: true },
        orderBy: { id: 'asc' },
      });
      expect(left.map((r) => r.id)).toEqual([archived.id, quarantined.id]);
    } finally {
      await prisma.quarantineMessage.deleteMany({ where: { organizationId } });
      await prisma.emailArchive.deleteMany({ where: { organizationId } });
      await prisma.messageIdentity.deleteMany({ where: { organizationId } });
      await cleanup();
    }
  });
});
