import { randomUUID } from 'node:crypto';
import { Prisma, PrismaClient, REGISTRY_PURGE_SQL } from '@email-gateway/database';
import { afterAll, describe, expect, it } from 'vitest';
import { stack } from './support/env';

/**
 * Asserts the physical MySQL schema produced by the migrations matches the data model in
 * docs/plan/steps/01-database.md (section 3) and ADR-0014: tables, partitioning, the absence of
 * foreign keys on partitioned tables, the tenancy column and the identity registry's unique key;
 * plus the identity/tenancy changes of docs/plan/steps/02-tenants-auth-rbac.md (D10).
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
  'user_tokens',
  'user_mfa_recovery_codes',
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
  it('has exactly the 63 data-model tables plus _prisma_migrations', async () => {
    const rows = await prisma.$queryRaw<{ name: string }[]>`
      SELECT TABLE_NAME AS name FROM information_schema.TABLES
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'`;
    expect(ALL_TABLES).toHaveLength(63);
    expect(new Set(ALL_TABLES).size).toBe(63);
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

interface ColumnInfo {
  tableName: string;
  columnName: string;
  columnType: string;
  nullable: string;
  columnDefault: string | null;
}

async function columns(tables: string[]): Promise<Map<string, ColumnInfo>> {
  const rows = await prisma.$queryRaw<ColumnInfo[]>`
    SELECT TABLE_NAME AS tableName, COLUMN_NAME AS columnName, COLUMN_TYPE AS columnType,
           IS_NULLABLE AS nullable, COLUMN_DEFAULT AS columnDefault
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN (${Prisma.join(tables)})`;
  return new Map(rows.map((r) => [`${r.tableName}.${r.columnName}`, r]));
}

/** Index name → ordered column list (and uniqueness) for one table. */
async function indexes(
  table: string,
): Promise<Map<string, { columns: string[]; unique: boolean }>> {
  const rows = await prisma.$queryRaw<
    { indexName: string; columnName: string; seq: number | bigint; nonUnique: number | bigint }[]
  >`
    SELECT INDEX_NAME AS indexName, COLUMN_NAME AS columnName, SEQ_IN_INDEX AS seq,
           NON_UNIQUE AS nonUnique
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ${table}
    ORDER BY INDEX_NAME, SEQ_IN_INDEX`;
  const out = new Map<string, { columns: string[]; unique: boolean }>();
  for (const r of rows) {
    const entry = out.get(r.indexName) ?? { columns: [], unique: Number(r.nonUnique) === 0 };
    entry.columns.push(r.columnName);
    out.set(r.indexName, entry);
  }
  return out;
}

const indexColumnSets = async (table: string) =>
  [...(await indexes(table)).values()].map((i) => ({ ...i, key: i.columns.join(',') }));

describe('identity and tenancy schema (step 1.2 + 1.3, D10)', () => {
  it('adds the new users, user_sessions, organizations and organization_settings columns', async () => {
    const cols = await columns([
      'users',
      'user_sessions',
      'organizations',
      'organization_settings',
    ]);
    const expectColumn = (key: string, type: string, nullable: 'YES' | 'NO') => {
      const col = cols.get(key);
      expect(col, key).toBeDefined();
      expect(col!.columnType, key).toBe(type);
      expect(col!.nullable, key).toBe(nullable);
    };
    expectColumn('users.email_verified_at', 'datetime(3)', 'YES');
    expectColumn('users.mfa_last_used_step', 'bigint unsigned', 'YES');
    expectColumn('users.status_reason', 'varchar(512)', 'YES');
    expectColumn('users.status_changed_at', 'datetime(3)', 'YES');

    expectColumn('user_sessions.authenticated_at', 'datetime(3)', 'NO');
    expectColumn('user_sessions.absolute_expires_at', 'datetime(3)', 'NO');
    expectColumn('user_sessions.mfa_authenticated', 'tinyint(1)', 'NO');
    expect(cols.get('user_sessions.mfa_authenticated')!.columnDefault).toBe('0');

    expectColumn('organizations.status_reason', 'varchar(512)', 'YES');
    expectColumn('organizations.status_changed_at', 'datetime(3)', 'YES');
    expectColumn('organizations.deletion_requested_at', 'datetime(3)', 'YES');
    expectColumn('organizations.deletion_requested_by_user_id', 'bigint unsigned', 'YES');
    expectColumn('organizations.deletion_reason', 'varchar(512)', 'YES');
    expectColumn('organizations.deletion_confirmed_at', 'datetime(3)', 'YES');
    expectColumn('organizations.deletion_confirmed_by_user_id', 'bigint unsigned', 'YES');
    expectColumn(
      'organizations.status_before_deletion',
      "enum('active','suspended','deleted','pending_deletion')",
      'YES',
    );
    expectColumn('organizations.purge_after', 'datetime(3)', 'YES');

    expectColumn('organization_settings.mfa_required', 'tinyint(1)', 'NO');
    expect(cols.get('organization_settings.mfa_required')!.columnDefault).toBe('0');
  });

  it('creates user_tokens and user_mfa_recovery_codes with the documented columns', async () => {
    const cols = await columns(['user_tokens', 'user_mfa_recovery_codes']);
    const shape = (table: string) =>
      Object.fromEntries(
        [...cols.values()]
          .filter((c) => c.tableName === table)
          .map((c) => [
            c.columnName,
            `${c.columnType} ${c.nullable === 'YES' ? 'NULL' : 'NOT NULL'}`,
          ]),
      );
    expect(shape('user_tokens')).toEqual({
      id: 'bigint unsigned NOT NULL',
      organization_id: 'bigint unsigned NOT NULL',
      user_id: 'bigint unsigned NOT NULL',
      purpose: "enum('invitation','password_reset','email_verification') NOT NULL",
      token_hash: 'char(64) NOT NULL',
      expires_at: 'datetime(3) NOT NULL',
      consumed_at: 'datetime(3) NULL',
      created_by_user_id: 'bigint unsigned NULL',
      created_ip: 'varchar(45) NULL',
      created_at: 'datetime(3) NOT NULL',
    });
    expect(shape('user_mfa_recovery_codes')).toEqual({
      id: 'bigint unsigned NOT NULL',
      organization_id: 'bigint unsigned NOT NULL',
      user_id: 'bigint unsigned NOT NULL',
      code_hash: 'char(64) NOT NULL',
      used_at: 'datetime(3) NULL',
      created_at: 'datetime(3) NOT NULL',
    });
  });

  it('has the new indexes, and (family_id, revoked_at) replaces (family_id)', async () => {
    const tokens = await indexColumnSets('user_tokens');
    expect(tokens).toContainEqual(expect.objectContaining({ key: 'token_hash', unique: true }));
    expect(tokens).toContainEqual(
      expect.objectContaining({ key: 'user_id,purpose,consumed_at', unique: false }),
    );
    expect(tokens).toContainEqual(expect.objectContaining({ key: 'expires_at', unique: false }));

    const codes = await indexColumnSets('user_mfa_recovery_codes');
    expect(codes).toContainEqual(
      expect.objectContaining({ key: 'user_id,code_hash', unique: true }),
    );

    const sessions = (await indexColumnSets('user_sessions')).map((i) => i.key);
    expect(sessions).toContain('family_id,revoked_at');
    expect(sessions).not.toContain('family_id');

    const organizations = (await indexColumnSets('organizations')).map((i) => i.key);
    expect(organizations).toContain('status,purge_after');
  });

  it('has the documented foreign keys (CASCADE from users, none for the deletion actors)', async () => {
    const rows = await prisma.$queryRaw<
      { tableName: string; columnName: string; referencedTable: string; deleteRule: string }[]
    >`
      SELECT k.TABLE_NAME AS tableName, k.COLUMN_NAME AS columnName,
             k.REFERENCED_TABLE_NAME AS referencedTable, r.DELETE_RULE AS deleteRule
      FROM information_schema.KEY_COLUMN_USAGE k
      JOIN information_schema.REFERENTIAL_CONSTRAINTS r
        ON r.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME
      WHERE k.TABLE_SCHEMA = DATABASE()
        AND k.TABLE_NAME IN ('user_tokens', 'user_mfa_recovery_codes', 'organizations')
        AND k.REFERENCED_TABLE_NAME IS NOT NULL`;
    const fks = rows
      .map((r) => `${r.tableName}.${r.columnName} -> ${r.referencedTable} ${r.deleteRule}`)
      .sort();
    expect(fks).toEqual(
      [
        'organizations.plan_id -> organization_plans RESTRICT',
        'user_mfa_recovery_codes.organization_id -> organizations RESTRICT',
        'user_mfa_recovery_codes.user_id -> users CASCADE',
        'user_tokens.created_by_user_id -> users SET NULL',
        'user_tokens.organization_id -> organizations RESTRICT',
        'user_tokens.user_id -> users CASCADE',
      ].sort(),
    );
  });

  it('appends rate_limited to the login outcome enum', async () => {
    const cols = await columns(['login_audit_logs']);
    expect(cols.get('login_audit_logs.outcome')!.columnType).toBe(
      "enum('success','failure','locked','mfa_required','mfa_failure','rate_limited')",
    );
  });

  it('enforces unique token hashes and removes tokens and recovery codes with their user', async () => {
    const { suffix, ids, cleanup } = await scratchOrganizations(1);
    const organizationId = ids[0]!;
    try {
      const user = await prisma.user.create({
        data: { organizationId, email: `it-${suffix}@example.test`, displayName: 'Schema test' },
      });
      const tokenHash = randomUUID().replaceAll('-', '').padEnd(64, 'a');
      const token = {
        organizationId,
        userId: user.id,
        purpose: 'password_reset' as const,
        tokenHash,
        expiresAt: new Date(Date.now() + 60_000),
      };
      await prisma.userToken.create({ data: token });
      await expect(
        prisma.userToken.create({ data: { ...token, purpose: 'invitation' } }),
      ).rejects.toMatchObject({ code: 'P2002' });

      const codeHash = randomUUID().replaceAll('-', '').padEnd(64, 'b');
      await prisma.userMfaRecoveryCode.create({
        data: { organizationId, userId: user.id, codeHash },
      });
      await expect(
        prisma.userMfaRecoveryCode.create({ data: { organizationId, userId: user.id, codeHash } }),
      ).rejects.toMatchObject({ code: 'P2002' });

      await prisma.user.delete({ where: { id: user.id } });
      expect(await prisma.userToken.count({ where: { organizationId } })).toBe(0);
      expect(await prisma.userMfaRecoveryCode.count({ where: { organizationId } })).toBe(0);
    } finally {
      await prisma.userToken.deleteMany({ where: { organizationId } });
      await prisma.userMfaRecoveryCode.deleteMany({ where: { organizationId } });
      await prisma.user.deleteMany({ where: { organizationId } });
      await cleanup();
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
