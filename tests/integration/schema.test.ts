import { randomUUID } from 'node:crypto';
import {
  type DomainStatus,
  Prisma,
  PrismaClient,
  REGISTRY_PURGE_SQL,
} from '@email-gateway/database';
import { afterAll, describe, expect, it } from 'vitest';
import { stack } from './support/env';

/**
 * Asserts the physical MySQL schema produced by the migrations matches the data model in
 * docs/plan/steps/01-database.md (section 3) and ADR-0014: tables, partitioning, the absence of
 * foreign keys on partitioned tables, the tenancy column and the identity registry's unique key;
 * plus the identity/tenancy changes of docs/plan/steps/02-tenants-auth-rbac.md (D10), the
 * domain onboarding changes of docs/plan/steps/03-domain-onboarding.md (§3), the SMTP gateway
 * tables of docs/plan/steps/04-smtp-gateway.md (§3), the mail routing and delivery tracking
 * changes of docs/plan/steps/05-routing.md (§3) and the MIME ingestion changes of
 * docs/plan/steps/06-mime-ingestion.md (§3).
 */
const prisma = new PrismaClient({ datasourceUrl: stack.databaseUrl() });

afterAll(async () => {
  await prisma.$disconnect();
});

/** Partitioned tables and their RANGE COLUMNS partition column (D3, step 2.3 §3, step 3.1 §3). */
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
  delivery_reinjections: 'received_at',
  delivery_status_events: 'received_at',
  email_message_parses: 'received_at',
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
  'mail_destination_presets',
  'stream_cursors',
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
  'domain_recipient_addresses',
  'smtp_connectors',
  'smtp_connector_networks',
  'message_identities',
  'email_messages',
  'email_recipients',
  'email_headers',
  'email_attachments',
  'email_events',
  'email_message_status_history',
  'email_message_parses',
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
  'delivery_reinjections',
  'delivery_status_events',
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
  it('has exactly the 71 data-model tables plus _prisma_migrations', async () => {
    const rows = await prisma.$queryRaw<{ name: string }[]>`
      SELECT TABLE_NAME AS name FROM information_schema.TABLES
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'`;
    expect(ALL_TABLES).toHaveLength(71);
    expect(new Set(ALL_TABLES).size).toBe(71);
    expect(rows.map((r) => r.name).sort()).toEqual([...ALL_TABLES, '_prisma_migrations'].sort());
  });

  it('partitions the 19 high-volume tables by RANGE COLUMNS with a pmax partition', async () => {
    expect(Object.keys(PARTITIONED)).toHaveLength(19);
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
    // Networks cascade with their connector; recipient addresses cascade with their domain.
    await prisma.smtpConnector.deleteMany({ where: { organizationId: { in: ids } } });
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

  it('refuses writes to the generated verified_name and live_name columns', async () => {
    const { suffix, ids, cleanup } = await scratchOrganizations(1);
    try {
      await expect(
        prisma.domain.create({
          data: { organizationId: ids[0]!, name: `it-${suffix}.test`, verifiedName: 'x.test' },
        }),
      ).rejects.toThrow(/generated column/i);
      await expect(
        prisma.domain.create({
          data: { organizationId: ids[0]!, name: `it-${suffix}.test`, liveName: 'x.test' },
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

describe('domain onboarding schema (step 2.1, §3)', () => {
  it('appends active, suspended and deleted to the domain status enum and adds DnsCheckOutcome', async () => {
    const cols = await columns(['domains', 'domain_verifications', 'domain_dns_records']);
    expect(cols.get('domains.status')!.columnType).toBe(
      "enum('pending_verification','verified','failed','disabled','active','suspended','deleted')",
    );
    expect(cols.get('domains.status')!.columnDefault).toBe('pending_verification');
    const outcome = "enum('valid','invalid','missing','indeterminate')";
    expect(cols.get('domain_verifications.last_outcome')!.columnType).toBe(outcome);
    expect(cols.get('domain_dns_records.last_outcome')!.columnType).toBe(outcome);
  });

  it('adds the lifecycle, scheduling, evidence and key-custody columns', async () => {
    const cols = await columns([
      'domains',
      'domain_verifications',
      'domain_dns_records',
      'domain_dkim_keys',
    ]);
    const expectColumn = (key: string, type: string, nullable: 'YES' | 'NO') => {
      const col = cols.get(key);
      expect(col, key).toBeDefined();
      expect(`${col!.columnType} ${col!.nullable}`, key).toBe(`${type} ${nullable}`);
    };
    expectColumn('domains.status_reason', 'varchar(512)', 'YES');
    expectColumn('domains.status_changed_at', 'datetime(3)', 'YES');
    expectColumn('domains.activated_at', 'datetime(3)', 'YES');
    expectColumn('domains.deleted_at', 'datetime(3)', 'YES');
    expectColumn('domains.next_check_at', 'datetime(3)', 'YES');
    expectColumn('domains.last_checked_at', 'datetime(3)', 'YES');
    expectColumn('domains.check_failures', 'int unsigned', 'NO');
    expect(cols.get('domains.check_failures')!.columnDefault).toBe('0');
    expectColumn('domains.verified_name', 'varchar(253)', 'YES');
    expectColumn('domains.live_name', 'varchar(253)', 'YES');

    expectColumn('domain_verifications.evidence', 'json', 'YES');

    expectColumn('domain_dns_records.record_key', 'varchar(191)', 'NO');
    expectColumn('domain_dns_records.dkim_key_id', 'bigint unsigned', 'YES');
    expectColumn('domain_dns_records.last_error', 'varchar(512)', 'YES');
    expectColumn('domain_dns_records.evidence', 'json', 'YES');
    expectColumn('domain_dns_records.status_changed_at', 'datetime(3)', 'YES');

    expectColumn('domain_dkim_keys.private_key_ciphertext', 'text', 'YES');
    expectColumn('domain_dkim_keys.private_key_ref', 'varchar(512)', 'YES');
    expectColumn('domain_dkim_keys.retire_after', 'datetime(3)', 'YES');
  });

  it('defines verified_name and live_name as STORED generated columns', async () => {
    const rows = await prisma.$queryRaw<
      { columnName: string; extra: string; expression: string }[]
    >`
      SELECT COLUMN_NAME AS columnName, EXTRA AS extra, GENERATION_EXPRESSION AS expression
      FROM information_schema.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'domains'
        AND COLUMN_NAME IN ('verified_name', 'live_name')
      ORDER BY COLUMN_NAME`;
    // information_schema escapes the quotes and prints the charset introducer.
    const normalize = (sql: string) =>
      sql.replaceAll('`', '').replaceAll('_utf8mb4', '').replaceAll("\\'", "'");
    expect(rows.map((r) => [r.columnName, r.extra, normalize(r.expression)])).toEqual([
      ['live_name', 'STORED GENERATED', "if((status = 'deleted'),NULL,name)"],
      [
        'verified_name',
        'STORED GENERATED',
        "if((status in ('verified','active','suspended')),name,NULL)",
      ],
    ]);
  });

  it('derives verified_name and live_name from the status', async () => {
    const { suffix, ids, cleanup } = await scratchOrganizations(1);
    const name = `it-${suffix}.gen.test`;
    try {
      const domain = await prisma.domain.create({ data: { organizationId: ids[0]!, name } });
      const expected: Record<
        DomainStatus,
        { verifiedName: string | null; liveName: string | null }
      > = {
        pending_verification: { verifiedName: null, liveName: name },
        failed: { verifiedName: null, liveName: name },
        disabled: { verifiedName: null, liveName: name },
        verified: { verifiedName: name, liveName: name },
        active: { verifiedName: name, liveName: name },
        suspended: { verifiedName: name, liveName: name },
        deleted: { verifiedName: null, liveName: null },
      };
      for (const [status, generated] of Object.entries(expected)) {
        const row = await prisma.domain.update({
          where: { id: domain.id },
          data: { status: status as DomainStatus },
          select: { verifiedName: true, liveName: true },
        });
        expect(row, status).toEqual(generated);
      }
    } finally {
      await cleanup();
    }
  });

  it('lets an organization re-add a deleted name, but never hold two live rows for it', async () => {
    const { suffix, ids, cleanup } = await scratchOrganizations(1);
    const organizationId = ids[0]!;
    const name = `it-${suffix}.readd.test`;
    try {
      const first = await prisma.domain.create({ data: { organizationId, name } });
      await expect(prisma.domain.create({ data: { organizationId, name } })).rejects.toMatchObject({
        code: 'P2002',
      });

      await prisma.domain.update({
        where: { id: first.id },
        data: { status: 'deleted', deletedAt: new Date() },
      });
      const second = await prisma.domain.create({ data: { organizationId, name } });
      expect(second.liveName).toBe(name);
      // The compound unique key addresses the live row only.
      const live = await prisma.domain.findUnique({
        where: { organizationId_liveName: { organizationId, liveName: name } },
        select: { id: true },
      });
      expect(live?.id).toBe(second.id);

      // Several deleted rows of the same name may exist (history).
      await prisma.domain.update({ where: { id: second.id }, data: { status: 'deleted' } });
      const third = await prisma.domain.create({ data: { organizationId, name } });
      expect(await prisma.domain.count({ where: { organizationId, name } })).toBe(3);

      // Un-deleting the old row while another live row exists is rejected.
      await expect(
        prisma.domain.update({ where: { id: first.id }, data: { status: 'pending_verification' } }),
      ).rejects.toMatchObject({ code: 'P2002' });
      expect(third.liveName).toBe(name);
    } finally {
      await cleanup();
    }
  });

  it('keeps verified ownership globally unique across active and suspended states', async () => {
    const { suffix, ids, cleanup } = await scratchOrganizations(2);
    const [a, b] = ids as [bigint, bigint];
    const name = `it-${suffix}.owner.test`;
    try {
      const owner = await prisma.domain.create({
        data: { organizationId: a, name, status: 'active' },
      });
      const claim = await prisma.domain.create({ data: { organizationId: b, name } });
      for (const status of ['verified', 'active', 'suspended'] as const) {
        await expect(
          prisma.domain.update({ where: { id: claim.id }, data: { status } }),
          status,
        ).rejects.toMatchObject({ code: 'P2002' });
      }
      await prisma.domain.update({ where: { id: owner.id }, data: { status: 'suspended' } });
      await expect(
        prisma.domain.update({ where: { id: claim.id }, data: { status: 'verified' } }),
      ).rejects.toMatchObject({ code: 'P2002' });

      // Deleting the owner's domain frees the name for the other organization.
      await prisma.domain.update({ where: { id: owner.id }, data: { status: 'deleted' } });
      await prisma.domain.update({ where: { id: claim.id }, data: { status: 'verified' } });
      expect(
        (await prisma.domain.findUnique({ where: { verifiedName: name } }))?.organizationId,
      ).toBe(b);
    } finally {
      await cleanup();
    }
  });

  it('keeps record_key unique per domain and unlinks DNS records from a deleted DKIM key', async () => {
    const { suffix, ids, cleanup } = await scratchOrganizations(1);
    const organizationId = ids[0]!;
    try {
      const d1 = await prisma.domain.create({
        data: { organizationId, name: `it-${suffix}.rk1.test` },
      });
      const d2 = await prisma.domain.create({
        data: { organizationId, name: `it-${suffix}.rk2.test` },
      });
      const key = await prisma.domainDkimKey.create({
        data: {
          organizationId,
          domainId: d1.id,
          selector: 'egr20261102abcd',
          algorithm: 'rsa_2048',
          publicKey: 'MIIB',
          privateKeyCiphertext: 'v1:ciphertext',
        },
      });
      expect(key.privateKeyRef).toBeNull();
      const record = (domainId: bigint, recordKey: string, dkimKeyId: bigint | null = null) => ({
        organizationId,
        domainId,
        recordKey,
        purpose: 'dkim' as const,
        recordType: 'TXT' as const,
        host: `egr20261102abcd._domainkey.it-${suffix}.test`,
        expectedValue: 'v=DKIM1; k=rsa; p=MIIB',
        dkimKeyId,
      });
      const row = await prisma.domainDnsRecord.create({
        data: record(d1.id, 'dkim:egr20261102abcd', key.id),
      });
      await expect(
        prisma.domainDnsRecord.create({ data: record(d1.id, 'dkim:egr20261102abcd') }),
      ).rejects.toMatchObject({ code: 'P2002' });
      // The same key on another domain is fine.
      await prisma.domainDnsRecord.create({ data: record(d2.id, 'dkim:egr20261102abcd') });

      await prisma.domainDkimKey.delete({ where: { id: key.id } });
      const after = await prisma.domainDnsRecord.findUniqueOrThrow({ where: { id: row.id } });
      expect(after.dkimKeyId).toBeNull();
    } finally {
      await cleanup();
    }
  });

  it('has the step 2.1 indexes, and (organization_id, live_name) replaces (organization_id, name)', async () => {
    const domains = await indexColumnSets('domains');
    expect(domains).toContainEqual(
      expect.objectContaining({ key: 'organization_id,live_name', unique: true }),
    );
    expect(domains).toContainEqual(expect.objectContaining({ key: 'verified_name', unique: true }));
    expect(domains).toContainEqual(
      expect.objectContaining({ key: 'next_check_at', unique: false }),
    );
    expect(domains).toContainEqual(
      expect.objectContaining({ key: 'organization_id,status', unique: false }),
    );
    expect(domains.map((i) => i.key)).not.toContain('organization_id,name');

    const records = await indexColumnSets('domain_dns_records');
    expect(records).toContainEqual(
      expect.objectContaining({ key: 'domain_id,record_key', unique: true }),
    );
    expect(records).toContainEqual(expect.objectContaining({ key: 'dkim_key_id', unique: false }));

    const keys = await indexColumnSets('domain_dkim_keys');
    expect(keys).toContainEqual(
      expect.objectContaining({ key: 'status,retire_after', unique: false }),
    );
  });

  it('links domain_dns_records.dkim_key_id to domain_dkim_keys with ON DELETE SET NULL', async () => {
    const rows = await prisma.$queryRaw<{ referencedTable: string; deleteRule: string }[]>`
      SELECT k.REFERENCED_TABLE_NAME AS referencedTable, r.DELETE_RULE AS deleteRule
      FROM information_schema.KEY_COLUMN_USAGE k
      JOIN information_schema.REFERENTIAL_CONSTRAINTS r
        ON r.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME
      WHERE k.TABLE_SCHEMA = DATABASE() AND k.TABLE_NAME = 'domain_dns_records'
        AND k.COLUMN_NAME = 'dkim_key_id'`;
    expect(rows).toEqual([{ referencedTable: 'domain_dkim_keys', deleteRule: 'SET NULL' }]);
  });
});

describe('SMTP gateway schema (step 2.2, §3)', () => {
  /** 4- or 16-byte big-endian address, as the api stores range_start/range_end. */
  const ipv4 = (address: string) => Buffer.from(address.split('.').map((part) => Number(part)));

  it('has the step 2.2 unique keys and indexes', async () => {
    const connectors = await indexColumnSets('smtp_connectors');
    for (const key of ['public_id', 'sasl_username', 'cert_fingerprint_sha256']) {
      expect(connectors, key).toContainEqual(expect.objectContaining({ key, unique: true }));
    }
    expect(connectors).toContainEqual(
      expect.objectContaining({ key: 'organization_id,name', unique: true }),
    );
    expect(connectors).toContainEqual(
      expect.objectContaining({ key: 'organization_id,status', unique: false }),
    );

    const networks = await indexColumnSets('smtp_connector_networks');
    expect(networks).toContainEqual(
      expect.objectContaining({ key: 'connector_id,cidr', unique: true }),
    );
    expect(networks).toContainEqual(
      expect.objectContaining({ key: 'ip_version,range_start', unique: false }),
    );

    const recipients = await indexColumnSets('domain_recipient_addresses');
    expect(recipients).toContainEqual(
      expect.objectContaining({ key: 'domain_id,local_part', unique: true }),
    );
    expect(recipients).toContainEqual(
      expect.objectContaining({ key: 'organization_id', unique: false }),
    );
  });

  it('declares the column types of the data model', async () => {
    const cols = await columns([
      'smtp_connectors',
      'smtp_connector_networks',
      'domain_recipient_addresses',
    ]);
    const type = (table: string, column: string) => cols.get(`${table}.${column}`)?.columnType;
    expect(type('smtp_connectors', 'auth_type')).toBe(
      "enum('sasl','source_ip','client_certificate')",
    );
    expect(type('smtp_connectors', 'status')).toBe("enum('active','disabled')");
    expect(type('smtp_connectors', 'cert_fingerprint_sha256')).toBe('char(64)');
    expect(type('smtp_connectors', 'secret_hash')).toBe('varchar(255)');
    expect(type('smtp_connector_networks', 'range_start')).toBe('varbinary(16)');
    expect(type('smtp_connector_networks', 'range_end')).toBe('varbinary(16)');
    expect(type('smtp_connector_networks', 'ip_version')).toBe('tinyint unsigned');
    expect(type('smtp_connector_networks', 'cidr')).toBe('varchar(49)');
    expect(type('domain_recipient_addresses', 'local_part')).toBe('varchar(64)');
  });

  it('cascades networks with their connector and recipients with their domain; restricts organizations', async () => {
    const rows = await prisma.$queryRaw<
      { tableName: string; columnName: string; referencedTable: string; deleteRule: string }[]
    >`
      SELECT k.TABLE_NAME AS tableName, k.COLUMN_NAME AS columnName,
             k.REFERENCED_TABLE_NAME AS referencedTable, r.DELETE_RULE AS deleteRule
      FROM information_schema.KEY_COLUMN_USAGE k
      JOIN information_schema.REFERENTIAL_CONSTRAINTS r
        ON r.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME
      WHERE k.TABLE_SCHEMA = DATABASE()
        AND k.TABLE_NAME IN ('smtp_connectors', 'smtp_connector_networks', 'domain_recipient_addresses')
      ORDER BY k.TABLE_NAME, k.COLUMN_NAME`;
    expect(rows.map((r) => [r.tableName, r.columnName, r.referencedTable, r.deleteRule])).toEqual([
      ['domain_recipient_addresses', 'created_by_user_id', 'users', 'SET NULL'],
      ['domain_recipient_addresses', 'domain_id', 'domains', 'CASCADE'],
      ['domain_recipient_addresses', 'organization_id', 'organizations', 'RESTRICT'],
      ['smtp_connector_networks', 'connector_id', 'smtp_connectors', 'CASCADE'],
      ['smtp_connector_networks', 'organization_id', 'organizations', 'RESTRICT'],
      ['smtp_connectors', 'created_by_user_id', 'users', 'SET NULL'],
      ['smtp_connectors', 'organization_id', 'organizations', 'RESTRICT'],
    ]);
  });

  it('keeps SASL usernames and certificate fingerprints globally unique, NULLs never collide', async () => {
    const { suffix, ids, cleanup } = await scratchOrganizations(2);
    const [a, b] = ids as [bigint, bigint];
    const username = `egc-it${suffix}`;
    const fingerprint = randomUUID().replaceAll('-', '').padEnd(64, '0');
    try {
      await prisma.smtpConnector.create({
        data: { organizationId: a, name: 'sasl', authType: 'sasl', saslUsername: username },
      });
      await expect(
        prisma.smtpConnector.create({
          data: { organizationId: b, name: 'sasl', authType: 'sasl', saslUsername: username },
        }),
      ).rejects.toMatchObject({ code: 'P2002' });
      await prisma.smtpConnector.create({
        data: {
          organizationId: a,
          name: 'cert',
          authType: 'client_certificate',
          certFingerprintSha256: fingerprint,
        },
      });
      await expect(
        prisma.smtpConnector.create({
          data: {
            organizationId: b,
            name: 'cert',
            authType: 'client_certificate',
            certFingerprintSha256: fingerprint,
          },
        }),
      ).rejects.toMatchObject({ code: 'P2002' });
      // Several source_ip connectors without a username or fingerprint; names unique per org.
      await prisma.smtpConnector.create({
        data: { organizationId: a, name: 'ip-1', authType: 'source_ip' },
      });
      const second = await prisma.smtpConnector.create({
        data: { organizationId: a, name: 'ip-2', authType: 'source_ip' },
      });
      expect(second).toMatchObject({ status: 'active', requireTls: true, saslUsername: null });
      await expect(
        prisma.smtpConnector.create({
          data: { organizationId: a, name: 'ip-1', authType: 'source_ip' },
        }),
      ).rejects.toMatchObject({ code: 'P2002' });
      await prisma.smtpConnector.create({
        data: { organizationId: b, name: 'ip-1', authType: 'source_ip' },
      });
    } finally {
      await cleanup();
    }
  });

  it('answers the design range lookup from (ip_version, range_start) and cascades networks', async () => {
    const { ids, cleanup } = await scratchOrganizations(1);
    const organizationId = ids[0]!;
    // Test-only 240.0.0.0/4 space (reserved), so no real connector row can interfere.
    try {
      const connector = await prisma.smtpConnector.create({
        data: { organizationId, name: 'ranges', authType: 'source_ip' },
      });
      const network = (cidr: string, start: string, end: string) => ({
        organizationId,
        connectorId: connector.id,
        cidr,
        ipVersion: 4,
        rangeStart: ipv4(start),
        rangeEnd: ipv4(end),
      });
      await prisma.smtpConnectorNetwork.createMany({
        data: [
          network('240.10.0.0/16', '240.10.0.0', '240.10.255.255'),
          network('240.20.0.0/24', '240.20.0.0', '240.20.0.255'),
        ],
      });
      await expect(
        prisma.smtpConnectorNetwork.create({
          data: network('240.10.0.0/16', '240.10.0.0', '240.10.255.255'),
        }),
      ).rejects.toMatchObject({ code: 'P2002' });

      const lookup = async (ip: string) => {
        const rows = await prisma.$queryRaw<{ cidr: string; rangeEnd: Uint8Array }[]>`
          SELECT cidr, range_end AS rangeEnd FROM smtp_connector_networks
          WHERE ip_version = 4 AND range_start <= ${ipv4(ip)}
            AND connector_id = ${connector.id}
          ORDER BY range_start DESC LIMIT 1`;
        const row = rows[0];
        return row && Buffer.compare(Buffer.from(row.rangeEnd), ipv4(ip)) >= 0 ? row.cidr : null;
      };
      expect(await lookup('240.10.3.4')).toBe('240.10.0.0/16');
      expect(await lookup('240.20.0.255')).toBe('240.20.0.0/24');
      expect(await lookup('240.20.1.0')).toBeNull();
      expect(await lookup('240.9.255.255')).toBeNull();

      await prisma.smtpConnector.delete({ where: { id: connector.id } });
      expect(await prisma.smtpConnectorNetwork.count({ where: { organizationId } })).toBe(0);
    } finally {
      await cleanup();
    }
  });

  it('keeps recipient local parts unique per domain and removes them with the domain', async () => {
    const { suffix, ids, cleanup } = await scratchOrganizations(1);
    const organizationId = ids[0]!;
    try {
      const one = await prisma.domain.create({
        data: { organizationId, name: `it-${suffix}.rcpt-one.test` },
      });
      const two = await prisma.domain.create({
        data: { organizationId, name: `it-${suffix}.rcpt-two.test` },
      });
      await prisma.domainRecipientAddress.create({
        data: { organizationId, domainId: one.id, localPart: 'alice' },
      });
      await expect(
        prisma.domainRecipientAddress.create({
          data: { organizationId, domainId: one.id, localPart: 'alice' },
        }),
      ).rejects.toMatchObject({ code: 'P2002' });
      await prisma.domainRecipientAddress.create({
        data: { organizationId, domainId: two.id, localPart: 'alice' },
      });
      const found = await prisma.domainRecipientAddress.findUnique({
        where: { domainId_localPart: { domainId: one.id, localPart: 'alice' } },
      });
      expect(found?.organizationId).toBe(organizationId);

      await prisma.domain.delete({ where: { id: one.id } });
      expect(await prisma.domainRecipientAddress.count({ where: { organizationId } })).toBe(1);
    } finally {
      await cleanup();
    }
  });
});

describe('mail routing and delivery tracking schema (step 2.3, §3)', () => {
  const STATUS =
    "enum('pending','in_progress','delivered','deferred','bounced','failed','suppressed','queued','expired','unknown')";

  it('adds the destination, recipient and delivery columns with the data-model types', async () => {
    const cols = await columns([
      'domain_mail_servers',
      'email_recipients',
      'email_deliveries',
      'delivery_reinjections',
      'delivery_status_events',
      'mail_destination_presets',
      'stream_cursors',
    ]);
    const col = (table: string, column: string) => cols.get(`${table}.${column}`);
    expect(col('domain_mail_servers', 'public_id')).toMatchObject({
      columnType: 'char(36)',
      nullable: 'NO',
    });
    expect(col('domain_mail_servers', 'provider')).toMatchObject({
      columnType: "enum('custom','microsoft_365','google_workspace')",
      nullable: 'NO',
      columnDefault: 'custom',
    });
    expect(col('domain_mail_servers', 'tls_verify_names')).toMatchObject({
      columnType: 'varchar(512)',
      nullable: 'YES',
    });
    expect(col('email_recipients', 'direction')).toMatchObject({
      columnType: "enum('inbound','outbound','internal')",
      nullable: 'YES',
    });
    expect(col('email_deliveries', 'status')?.columnType).toBe(STATUS);
    for (const [column, type] of [
      ['reinjection_id', 'bigint unsigned'],
      ['direction', "enum('inbound','outbound','internal')"],
      ['destination_key', 'varchar(300)'],
      ['status_changed_at', 'datetime(3)'],
      ['last_signal_at', 'datetime(3)'],
      ['enhanced_status', 'varchar(16)'],
      ['last_error_class', 'varchar(32)'],
      ['failure_reason', 'varchar(64)'],
      ['dsn_queue_id', 'varchar(32)'],
    ] as const) {
      expect(col('email_deliveries', column), column).toMatchObject({
        columnType: type,
        nullable: 'YES',
      });
    }
    expect(col('delivery_reinjections', 'listener')?.columnType).toBe(
      "enum('reinject_inbound','reinject_outbound')",
    );
    expect(col('delivery_reinjections', 'status')).toMatchObject({
      columnType: "enum('pending','in_progress','queued','failed')",
      columnDefault: 'pending',
    });
    expect(col('delivery_reinjections', 'idempotency_key')?.columnType).toBe('char(64)');
    expect(col('delivery_status_events', 'source')?.columnType).toBe(
      "enum('planner','reinjection','postfix_log','bounce_notice','reconciler')",
    );
    expect(col('delivery_status_events', 'from_status')).toMatchObject({
      columnType: STATUS,
      nullable: 'YES',
    });
    expect(col('delivery_status_events', 'to_status')).toMatchObject({
      columnType: STATUS,
      nullable: 'NO',
    });
    expect(col('delivery_status_events', 'detail')?.columnType).toBe('varchar(1024)');
    expect(col('mail_destination_presets', 'host_patterns')?.columnType).toBe('json');
    expect(col('mail_destination_presets', 'max_servers')?.columnType).toBe('tinyint unsigned');
    expect(col('stream_cursors', 'file_offset')?.columnType).toBe('bigint unsigned');
  });

  it('has the step 2.3 keys and indexes; unique keys of partitioned tables end with received_at', async () => {
    const servers = await indexColumnSets('domain_mail_servers');
    expect(servers).toContainEqual(expect.objectContaining({ key: 'public_id', unique: true }));
    expect(servers).toContainEqual(expect.objectContaining({ key: 'host,port', unique: false }));

    const deliveries = await indexColumnSets('email_deliveries');
    expect(deliveries).toContainEqual(
      expect.objectContaining({ key: 'outbound_queue_id', unique: false }),
    );
    expect(deliveries).toContainEqual(
      expect.objectContaining({ key: 'organization_id,received_at,id', unique: false }),
    );

    const reinjections = await indexColumnSets('delivery_reinjections');
    expect(reinjections).toContainEqual(
      expect.objectContaining({ key: 'id,received_at', unique: true }),
    );
    expect(reinjections).toContainEqual(
      expect.objectContaining({ key: 'message_id,idempotency_key,received_at', unique: true }),
    );
    for (const key of ['status,next_attempt_at', 'queue_id', 'public_id']) {
      expect(reinjections, key).toContainEqual(expect.objectContaining({ key, unique: false }));
    }
    const events = await indexColumnSets('delivery_status_events');
    expect(events).toContainEqual(
      expect.objectContaining({ key: 'delivery_id,signal_key,received_at', unique: true }),
    );
    expect(events).toContainEqual(
      expect.objectContaining({ key: 'message_id,received_at', unique: false }),
    );
    for (const index of [...reinjections, ...events].filter((i) => i.unique)) {
      expect(index.columns.at(-1), index.key).toBe('received_at');
    }
    const presets = await indexColumnSets('mail_destination_presets');
    expect(presets).toContainEqual(expect.objectContaining({ key: 'provider', unique: true }));
  });

  it('generates distinct public ids for destination servers and refuses duplicates', async () => {
    const suffix = randomUUID().slice(0, 8);
    const plan = await prisma.organizationPlan.create({
      data: {
        code: `it-${suffix}`,
        name: 'Routing schema',
        defaultLimits: {},
        defaultFeatures: {},
      },
    });
    const organization = await prisma.organization.create({
      data: {
        slug: `it-${suffix}`,
        name: 'Routing schema',
        planId: plan.id,
        dataRegion: 'ap-south-1',
      },
    });
    const organizationId = organization.id;
    try {
      const domain = await prisma.domain.create({
        data: { organizationId, name: `it-${suffix}.test` },
      });
      const server = (host: string, publicId?: string) =>
        prisma.domainMailServer.create({
          data: {
            organizationId,
            domainId: domain.id,
            role: 'inbound_destination',
            host,
            ...(publicId ? { publicId } : {}),
          },
        });
      const a = await server('mx1.example.test');
      const b = await server('mx2.example.test');
      expect(a.publicId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-/);
      expect(a.publicId).not.toBe(b.publicId);
      expect(a.provider).toBe('custom');
      expect(a.tlsVerifyNames).toBeNull();
      await expect(server('mx3.example.test', a.publicId)).rejects.toMatchObject({
        code: 'P2002',
      });
    } finally {
      await prisma.domain.deleteMany({ where: { organizationId } });
      await prisma.organization.deleteMany({ where: { id: organizationId } });
      await prisma.organizationPlan.deleteMany({ where: { id: plan.id } });
    }
  });

  it('dedupes reinjection groups and status signals per partition key', async () => {
    const organizationId = 999_999_001n;
    const receivedAt = new Date();
    const messageId = BigInt(Date.now()) * 1000n + BigInt(Math.floor(Math.random() * 1000));
    const reinjection = {
      receivedAt,
      messageId,
      organizationId,
      listener: 'reinject_outbound' as const,
      direction: 'outbound' as const,
      destinationKey: 'mx:example.test',
      emlObjectKey: `org/${organizationId}/eml/x.eml`,
      recipientCount: 1,
      recipientSetSha256: 'a'.repeat(64),
      idempotencyKey: 'b'.repeat(64),
      approvalEventId: randomUUID(),
      nextAttemptAt: receivedAt,
    };
    const event = {
      receivedAt,
      deliveryId: messageId,
      messageId,
      recipientId: messageId,
      organizationId,
      source: 'planner' as const,
      signalKey: 'c'.repeat(64),
      occurredAt: receivedAt,
      toStatus: 'pending' as const,
      applied: true,
    };
    try {
      const row = await prisma.deliveryReinjection.create({ data: reinjection });
      expect(row.publicId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-/);
      expect(row.status).toBe('pending');
      await expect(prisma.deliveryReinjection.create({ data: reinjection })).rejects.toMatchObject({
        code: 'P2002',
      });
      await prisma.deliveryStatusEvent.create({ data: event });
      await expect(prisma.deliveryStatusEvent.create({ data: event })).rejects.toMatchObject({
        code: 'P2002',
      });
    } finally {
      await prisma.deliveryReinjection.deleteMany({ where: { organizationId } });
      await prisma.deliveryStatusEvent.deleteMany({ where: { organizationId } });
    }
  });
});

describe('MIME ingestion schema (step 3.1, §3)', () => {
  const PARSE_STATUS =
    "enum('parsing','parsed','parsed_with_defects','parse_limit_exceeded','parse_failed')";

  it('creates email_message_parses with the data-model column types', async () => {
    const cols = await columns(['email_message_parses']);
    const col = (column: string) => cols.get(`email_message_parses.${column}`);
    for (const [column, type, nullable] of [
      ['id', 'bigint unsigned', 'NO'],
      ['received_at', 'datetime(3)', 'NO'],
      ['message_id', 'bigint unsigned', 'NO'],
      ['organization_id', 'bigint unsigned', 'NO'],
      ['status', PARSE_STATUS, 'NO'],
      ['attempts', 'smallint unsigned', 'NO'],
      ['parser_version', 'varchar(32)', 'NO'],
      ['event_id', 'char(36)', 'YES'],
      ['failure_reason', 'varchar(64)', 'YES'],
      ['limits_exceeded', 'json', 'YES'],
      ['defects', 'json', 'YES'],
      ['part_count', 'smallint unsigned', 'YES'],
      ['attachment_count', 'smallint unsigned', 'YES'],
      ['max_depth', 'tinyint unsigned', 'YES'],
      ['header_count', 'int unsigned', 'YES'],
      ['bytes_read', 'bigint unsigned', 'YES'],
      ['decoded_bytes', 'bigint unsigned', 'YES'],
      ['text_body_object_key', 'varchar(512)', 'YES'],
      ['html_body_object_key', 'varchar(512)', 'YES'],
      ['text_body_sha256', 'char(64)', 'YES'],
      ['html_body_sha256', 'char(64)', 'YES'],
      ['text_body_size_bytes', 'int unsigned', 'YES'],
      ['html_body_size_bytes', 'int unsigned', 'YES'],
      ['text_body_charset', 'varchar(64)', 'YES'],
      ['html_body_charset', 'varchar(64)', 'YES'],
      ['structure', 'json', 'YES'],
      ['started_at', 'datetime(3)', 'NO'],
      ['completed_at', 'datetime(3)', 'YES'],
      ['duration_ms', 'int unsigned', 'YES'],
      ['created_at', 'datetime(3)', 'NO'],
      ['updated_at', 'datetime(3)', 'NO'],
    ] as const) {
      expect(col(column), column).toMatchObject({ columnType: type, nullable });
    }
    expect(cols.size).toBe(31);
    expect(col('attempts')?.columnDefault).toBe('0');
  });

  it('adds the nullable attachment metadata columns to email_attachments', async () => {
    const cols = await columns(['email_attachments']);
    for (const [column, type] of [
      ['part_path', 'varchar(128)'],
      ['depth', 'tinyint unsigned'],
      ['disposition', "enum('attachment','inline')"],
      ['encoded_size_bytes', 'int unsigned'],
      ['original_filename', 'varchar(1024)'],
      ['flags', 'json'],
      ['archive_info', 'json'],
    ] as const) {
      expect(cols.get(`email_attachments.${column}`), column).toMatchObject({
        columnType: type,
        nullable: 'YES',
        columnDefault: null,
      });
    }
  });

  it('has the step 3.1 keys and indexes; unique keys end with received_at; no foreign keys', async () => {
    const parses = await indexColumnSets('email_message_parses');
    expect(parses).toContainEqual(expect.objectContaining({ key: 'id,received_at', unique: true }));
    expect(parses).toContainEqual(
      expect.objectContaining({ key: 'message_id,received_at', unique: true }),
    );
    expect(parses).toContainEqual(
      expect.objectContaining({ key: 'organization_id,received_at,id', unique: false }),
    );
    expect(parses).toContainEqual(
      expect.objectContaining({ key: 'status,updated_at', unique: false }),
    );
    expect(parses).toHaveLength(4);
    for (const index of parses.filter((i) => i.unique)) {
      expect(index.columns.at(-1), index.key).toBe('received_at');
    }
    // email_attachments keeps its keys unchanged.
    const attachments = await indexColumnSets('email_attachments');
    expect(attachments).toContainEqual(
      expect.objectContaining({ key: 'message_id,part_index,received_at', unique: true }),
    );

    const fks = await prisma.$queryRaw<{ n: bigint }[]>`
      SELECT COUNT(*) AS n FROM information_schema.KEY_COLUMN_USAGE
      WHERE TABLE_SCHEMA = DATABASE() AND REFERENCED_TABLE_NAME IS NOT NULL
        AND (TABLE_NAME = 'email_message_parses' OR REFERENCED_TABLE_NAME = 'email_message_parses')`;
    expect(Number(fks[0]?.n)).toBe(0);
  });

  it('keeps one parse row per message and partition key', async () => {
    const organizationId = 999_999_002n;
    const receivedAt = new Date();
    const messageId = BigInt(Date.now()) * 1000n + BigInt(Math.floor(Math.random() * 1000));
    const row = {
      receivedAt,
      messageId,
      organizationId,
      status: 'parsing' as const,
      attempts: 1,
      parserVersion: 'it-1',
      startedAt: receivedAt,
    };
    try {
      const created = await prisma.emailMessageParse.create({ data: row });
      expect(created.status).toBe('parsing');
      await expect(prisma.emailMessageParse.create({ data: row })).rejects.toMatchObject({
        code: 'P2002',
      });
      // The final transition is a conditional update on status = 'parsing' (M3.9.1).
      const finalize = () =>
        prisma.emailMessageParse.updateMany({
          where: { messageId, receivedAt, organizationId, status: 'parsing' },
          data: {
            status: 'parsed',
            limitsExceeded: [],
            defects: ['missing_boundary'],
            completedAt: new Date(),
          },
        });
      expect((await finalize()).count).toBe(1);
      expect((await finalize()).count).toBe(0);
    } finally {
      await prisma.emailMessageParse.deleteMany({ where: { organizationId } });
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
