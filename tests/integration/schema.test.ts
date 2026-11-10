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
 * changes of docs/plan/steps/05-routing.md (§3), the MIME ingestion changes of
 * docs/plan/steps/06-mime-ingestion.md (§3), the message lifecycle changes of
 * docs/plan/steps/08-message-lifecycle.md (§3.1, §3.2), the scan pipeline, attachment scanning
 * and URL protection tables of steps 4.1–4.3 (docs/plan/steps/09-rspamd.md,
 * 10-attachment-scanning.md, 11-url-protection.md, §3 each), the phishing/BEC tables of step 4.4
 * (12-phishing-bec.md §3), the DLP tables of step 4.5 (13-dlp.md §3) and the sandbox engine
 * tables and columns of step 4.6 (14-sandbox.md §3).
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
  // Step 4.1 §3: authentication results of a scan round.
  email_auth_results: 'received_at',
  // Step 4.2 §3: per-attachment results and sandbox submissions of a scan round.
  attachment_scan_results: 'received_at',
  sandbox_submissions: 'received_at',
  // Step 4.3 §3: URLs of a message, their results, rewrites, inspections and clicks.
  message_urls: 'received_at',
  url_scan_results: 'received_at',
  url_rewrites: 'received_at',
  url_dynamic_inspections: 'received_at',
  url_click_events: 'clicked_at',
  // Step 4.4 §3: the BEC result of a scan round.
  bec_scan_results: 'received_at',
  // Step 4.5 §3: the DLP result of a scan round and its evidence metadata.
  dlp_scan_results: 'received_at',
  dlp_evidence: 'received_at',
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
  'message_consumer_progress',
  'maintenance_watermarks',
  'mail_destination_presets',
  'stream_cursors',
  // Step 4.2 §3.5: signature component versions (platform catalog).
  'scan_signature_versions',
  // Step 4.6 §3: artifacts of a (platform-level) sandbox analysis; reached through the analysis.
  'sandbox_artifacts',
];

/** Tenant-owned tables whose `organization_id` is nullable (platform-level rows), per D1. */
const NULLABLE_ORGANIZATION = [
  'roles',
  'threat_indicators',
  'yara_rules',
  'audit_logs',
  'login_audit_logs',
  // Step 4.2 §3.4: NULL = a rescan job over every organization.
  'attachment_rescan_jobs',
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
  // Step 4.1 §3.
  'email_auth_results',
  'scan_engine_settings',
  // Step 4.2 §3.
  'attachment_scan_results',
  'sandbox_submissions',
  'attachment_rescan_jobs',
  // Step 4.3 §3.
  'message_urls',
  'url_scan_results',
  'url_rewrites',
  'url_dynamic_inspections',
  'url_click_events',
  // Step 4.4 §3.
  'bec_scan_results',
  'bec_executive_profiles',
  'bec_vendor_profiles',
  'bec_trusted_senders',
  'bec_feedback',
  'bec_suppression_rules',
  'bec_contact_history',
  // Step 4.5 §3.
  'dlp_scan_results',
  'dlp_evidence',
  'dlp_policies',
  'dlp_policy_rules',
  'dlp_exceptions',
  'dlp_custom_patterns',
  'dlp_keyword_dictionaries',
  'dlp_compliance_settings',
  // Step 4.6 §3: platform-level, content-addressed analyses; organization_id (NOT NULL) is the
  // dispatching organization (task/result routing only; tenants read through their submissions).
  'sandbox_analyses',
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
  'api_idempotency_keys',
];

const ALL_TABLES = [...NOT_TENANT_OWNED, ...TENANT_OWNED];

describe('MySQL schema', () => {
  it('has exactly the 101 data-model tables plus _prisma_migrations', async () => {
    const rows = await prisma.$queryRaw<{ name: string }[]>`
      SELECT TABLE_NAME AS name FROM information_schema.TABLES
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'`;
    expect(ALL_TABLES).toHaveLength(101);
    expect(new Set(ALL_TABLES).size).toBe(101);
    expect(rows.map((r) => r.name).sort()).toEqual([...ALL_TABLES, '_prisma_migrations'].sort());
  });

  it('partitions the 30 high-volume tables by RANGE COLUMNS with a pmax partition', async () => {
    expect(Object.keys(PARTITIONED)).toHaveLength(30);
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

describe('event relay schema (step 3.2, §4)', () => {
  it('adds the reconciliation columns to message_outbox', async () => {
    const cols = await columns(['message_outbox']);
    expect(cols.get('message_outbox.redrive_count')).toMatchObject({
      columnType: 'smallint unsigned',
      nullable: 'NO',
      columnDefault: '0',
    });
    expect(cols.get('message_outbox.last_redriven_at')).toMatchObject({
      columnType: 'datetime(3)',
      nullable: 'YES',
      columnDefault: null,
    });
    expect(cols.size).toBe(15);
  });

  it('indexes last_redriven_at and keeps the outbox keys unchanged', async () => {
    const outbox = await indexColumnSets('message_outbox');
    expect(outbox).toContainEqual(expect.objectContaining({ key: 'id,created_at', unique: true }));
    expect(outbox).toContainEqual(
      expect.objectContaining({ key: 'published_at,id', unique: false }),
    );
    expect(outbox).toContainEqual(
      expect.objectContaining({ key: 'last_redriven_at', unique: false }),
    );
    // Review round 1: the planner's approval provenance lookup.
    expect(outbox).toContainEqual(expect.objectContaining({ key: 'event_id', unique: false }));
    expect(outbox).toHaveLength(4);
  });

  it('adds message_consumer_progress keyed like the ledger (review round 1)', async () => {
    const cols = await columns(['message_consumer_progress']);
    expect(cols.get('message_consumer_progress.state')).toMatchObject({
      columnType: "enum('retrying','dead_lettered')",
      nullable: 'NO',
    });
    expect(cols.get('message_consumer_progress.reason')).toMatchObject({
      columnType: 'varchar(48)',
      nullable: 'YES',
    });
    expect(cols.get('message_consumer_progress.updated_at')).toMatchObject({
      columnType: 'datetime(3)',
      nullable: 'NO',
    });
    expect(cols.size).toBe(7);
    const keys = await indexColumnSets('message_consumer_progress');
    expect(keys).toContainEqual(
      expect.objectContaining({ key: 'consumer,event_id', unique: true }),
    );
    expect(keys).toContainEqual(expect.objectContaining({ key: 'updated_at', unique: false }));
    expect(keys).toHaveLength(2);
  });
});

describe('message lifecycle schema (step 3.3, §3.1, §3.2)', () => {
  const STATES =
    "enum('received','persisted','scanning','scanned','scan_failed','policy_evaluated'," +
    "'approved','quarantined','held_for_review','rejected','delivery_pending','delivery_retry'," +
    "'delivered','archived','expired')";

  it('replaces MessageStatus by the fifteen lifecycle states in L2 order', async () => {
    const cols = await columns(['email_messages', 'email_message_status_history']);
    expect(cols.get('email_messages.status')).toMatchObject({
      columnType: STATES,
      nullable: 'NO',
      columnDefault: 'received',
    });
    expect(cols.get('email_message_status_history.from_status')).toMatchObject({
      columnType: STATES,
      nullable: 'YES',
    });
    expect(cols.get('email_message_status_history.to_status')).toMatchObject({
      columnType: STATES,
      nullable: 'NO',
    });
  });

  it('adds lifecycle_round and status_reason to email_messages', async () => {
    const cols = await columns(['email_messages']);
    expect(cols.get('email_messages.lifecycle_round')).toMatchObject({
      columnType: 'smallint unsigned',
      nullable: 'NO',
      columnDefault: '0',
    });
    expect(cols.get('email_messages.status_reason')).toMatchObject({
      columnType: 'varchar(64)',
      nullable: 'YES',
      columnDefault: null,
    });
    // 27 since step 3.3; step 4.1 §3 adds client_name.
    expect(cols.size).toBe(28);
  });

  it('adds the actor, correlation, idempotency and occurrence columns to the history', async () => {
    const cols = await columns(['email_message_status_history']);
    const col = (column: string) => cols.get(`email_message_status_history.${column}`);
    for (const [column, type, nullable, columnDefault] of [
      ['lifecycle_round', 'smallint unsigned', 'NO', '0'],
      ['actor_role', 'varchar(32)', 'NO', 'legacy'],
      ['actor_service', 'varchar(64)', 'NO', 'legacy'],
      ['actor_type', "enum('system','user','api_key')", 'NO', 'system'],
      ['actor_id', 'varchar(64)', 'YES', null],
      ['correlation_id', 'varchar(128)', 'YES', null],
      ['transition_key', 'char(64)', 'YES', null],
      ['state_event_id', 'char(36)', 'YES', null],
      ['occurred_at', 'datetime(3)', 'YES', null],
    ] as const) {
      expect(col(column), column).toMatchObject({ columnType: type, nullable, columnDefault });
    }
    expect(cols.size).toBe(20);
  });

  it('keys the history by (message_id, version) and (message_id, transition_key), both ending with received_at', async () => {
    const keys = await indexColumnSets('email_message_status_history');
    expect(
      keys
        .filter((k) => k.unique)
        .map((k) => k.key)
        .sort(),
    ).toEqual(
      [
        'id,received_at',
        'message_id,transition_key,received_at',
        'message_id,version,received_at',
      ].sort(),
    );
    expect(keys).toHaveLength(3);
  });

  it('refuses a second history row with the same transition key, but not legacy NULL keys', async () => {
    const organizationId = 999_999_033n;
    const receivedAt = new Date();
    const messageId = BigInt(Date.now()) * 1000n + BigInt(Math.floor(Math.random() * 1000));
    const row = (version: number, transitionKey: string | null) => ({
      receivedAt,
      messageId,
      organizationId,
      version,
      fromStatus: version === 0 ? null : ('persisted' as const),
      toStatus: version === 0 ? ('received' as const) : ('approved' as const),
      reasonCode: 'dev_passthrough',
      changedAt: receivedAt,
      transitionKey,
    });
    try {
      const legacy = await prisma.emailMessageStatusHistory.create({ data: row(0, null) });
      expect(legacy).toMatchObject({
        actorRole: 'legacy',
        actorService: 'legacy',
        actorType: 'system',
        lifecycleRound: 0,
      });
      await prisma.emailMessageStatusHistory.create({ data: row(1, null) });
      await prisma.emailMessageStatusHistory.create({ data: row(2, 'a'.repeat(64)) });
      await expect(
        prisma.emailMessageStatusHistory.create({ data: row(3, 'a'.repeat(64)) }),
      ).rejects.toMatchObject({ code: 'P2002' });
      // The retired step 1.1 values are refused (strict mode).
      await expect(
        prisma.$executeRawUnsafe(
          `INSERT INTO email_message_status_history
             (received_at, message_id, organization_id, version, to_status, changed_at)
           VALUES (?, ?, ?, 9, 'delivery_queued', ?)`,
          receivedAt,
          messageId,
          organizationId,
          receivedAt,
        ),
      ).rejects.toThrow(/to_status/);
    } finally {
      await prisma.emailMessageStatusHistory.deleteMany({ where: { organizationId } });
    }
  });

  it('creates api_idempotency_keys with a case-sensitive key unique per organization', async () => {
    const cols = await columns(['api_idempotency_keys']);
    const col = (column: string) => cols.get(`api_idempotency_keys.${column}`);
    for (const [column, type, nullable] of [
      ['id', 'bigint unsigned', 'NO'],
      ['organization_id', 'bigint unsigned', 'NO'],
      ['idempotency_key', 'varchar(128)', 'NO'],
      ['operation', 'varchar(64)', 'NO'],
      ['principal', 'varchar(80)', 'NO'],
      ['request_sha256', 'char(64)', 'NO'],
      ['resource_id', 'varchar(64)', 'NO'],
      ['status_code', 'smallint unsigned', 'NO'],
      ['response', 'json', 'NO'],
      ['created_at', 'datetime(3)', 'NO'],
      ['expires_at', 'datetime(3)', 'NO'],
    ] as const) {
      expect(col(column), column).toMatchObject({ columnType: type, nullable });
    }
    expect(cols.size).toBe(11);
    const keys = await indexColumnSets('api_idempotency_keys');
    expect(keys.map((k) => [k.key, k.unique]).sort()).toEqual(
      [
        ['id', true],
        ['organization_id,idempotency_key', true],
        ['expires_at', false],
      ].sort(),
    );

    const organizationId = 999_999_034n;
    const record = (idempotencyKey: string) => ({
      organizationId,
      idempotencyKey,
      operation: 'message.rescan',
      principal: 'user:schema-test',
      requestSha256: 'a'.repeat(64),
      resourceId: randomUUID(),
      statusCode: 202,
      response: { ok: true },
      expiresAt: new Date(Date.now() + 86_400_000),
    });
    try {
      await prisma.apiIdempotencyKey.create({ data: record('Key-1') });
      await prisma.apiIdempotencyKey.create({ data: record('key-1') });
      await expect(
        prisma.apiIdempotencyKey.create({ data: record('Key-1') }),
      ).rejects.toMatchObject({ code: 'P2002' });
      expect(
        await prisma.apiIdempotencyKey.count({
          where: { organizationId, idempotencyKey: 'Key-1' },
        }),
      ).toBe(1);
    } finally {
      await prisma.apiIdempotencyKey.deleteMany({ where: { organizationId } });
    }
  });

  it('stores the five Postfix queue-id columns case-sensitively (utf8mb4_bin, L15)', async () => {
    const rows = await prisma.$queryRaw<
      { tableName: string; columnName: string; charset: string; collation: string; type: string }[]
    >`
      SELECT TABLE_NAME AS tableName, COLUMN_NAME AS columnName,
             CHARACTER_SET_NAME AS charset, COLLATION_NAME AS collation, COLUMN_TYPE AS type
      FROM information_schema.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE() AND COLLATION_NAME = 'utf8mb4_bin'
      ORDER BY TABLE_NAME, COLUMN_NAME`;
    expect(rows.map((r) => `${r.tableName}.${r.columnName}`)).toEqual([
      'api_idempotency_keys.idempotency_key',
      'delivery_reinjections.queue_id',
      'delivery_status_events.queue_id',
      'email_deliveries.dsn_queue_id',
      'email_deliveries.outbound_queue_id',
      'email_messages.mta_queue_id',
    ]);
    for (const r of rows) expect(r.charset, r.columnName).toBe('utf8mb4');
    for (const r of rows.filter((x) => x.columnName !== 'idempotency_key')) {
      expect(r.type, `${r.tableName}.${r.columnName}`).toBe('varchar(32)');
    }

    const organizationId = 999_999_035n;
    const receivedAt = new Date();
    const messageId = BigInt(Date.now()) * 1000n + BigInt(Math.floor(Math.random() * 1000));
    const event = (deliveryId: bigint, queueId: string) => ({
      receivedAt,
      deliveryId,
      messageId,
      recipientId: deliveryId,
      organizationId,
      source: 'postfix_log' as const,
      signalKey: 'd'.repeat(64),
      occurredAt: receivedAt,
      toStatus: 'queued' as const,
      applied: true,
      queueId,
    });
    try {
      await prisma.deliveryStatusEvent.create({ data: event(1n, '4jKFxV5fmHz12JnW') });
      await prisma.deliveryStatusEvent.create({ data: event(2n, '4jKFxV5fMHz12Jnw') });
      const matches = await prisma.deliveryStatusEvent.findMany({
        where: { organizationId, queueId: '4jKFxV5fmHz12JnW' },
        select: { deliveryId: true },
      });
      expect(matches.map((m) => m.deliveryId)).toEqual([1n]);
    } finally {
      await prisma.deliveryStatusEvent.deleteMany({ where: { organizationId } });
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

describe('scan pipeline schema (step 4.1, docs/plan/steps/09-rspamd.md §3)', () => {
  const uniqueSets = async (table: string) =>
    [...(await indexes(table)).entries()]
      .filter(([, i]) => i.unique)
      .map(([name, i]) => `${name}(${i.columns.join(',')})`)
      .sort();

  it('stores the XFORWARD client host name on email_messages', async () => {
    const cols = await columns(['email_messages']);
    expect(cols.get('email_messages.client_name')).toMatchObject({
      columnType: 'varchar(255)',
      nullable: 'YES',
      columnDefault: null,
    });
  });

  it('identifies a scan round by (message, lifecycle round): one email_scans row per round', async () => {
    const cols = await columns(['email_scans']);
    expect(cols.get('email_scans.lifecycle_round')).toMatchObject({
      columnType: 'smallint unsigned',
      nullable: 'NO',
      columnDefault: '0',
    });
    expect(cols.get('email_scans.scan_verdict')?.columnType).toBe(
      "enum('clean','spam','suspicious','malicious','unknown','timeout','error')",
    );
    for (const column of ['required_engines', 'reason_codes']) {
      expect(cols.get(`email_scans.${column}`)?.columnType, column).toBe('json');
    }
    expect(cols.get('email_scans.trigger_event_id')?.columnType).toBe('char(36)');
    expect(cols.get('email_scans.deadline_at')?.columnType).toBe('datetime(3)');
    const idx = await indexes('email_scans');
    const unique = [...idx.values()].filter((i) => i.unique).map((i) => i.columns.join(','));
    expect(unique).toContain('message_id,lifecycle_round,received_at');
    expect(unique).not.toContain('message_id,scan_kind,attempt,received_at');
    expect([...idx.values()].map((i) => i.columns.join(','))).toContain('status,deadline_at');
  });

  it('keeps one final result per round and engine (generated final_engine) and only failed attempts as non-final rows', async () => {
    const cols = await columns(['scan_engine_results']);
    expect(cols.get('scan_engine_results.outcome')?.columnType).toBe(
      "enum('clean','suspicious','malicious','error','timeout','skipped','spam','unknown')",
    );
    expect(cols.get('scan_engine_results.is_final')).toMatchObject({
      columnType: 'tinyint(1)',
      nullable: 'NO',
      columnDefault: '1',
    });
    const generated = await prisma.$queryRaw<{ extra: string; expression: string }[]>`
      SELECT EXTRA AS extra, GENERATION_EXPRESSION AS expression FROM information_schema.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scan_engine_results'
        AND COLUMN_NAME = 'final_engine'`;
    expect(generated[0]?.extra).toBe('VIRTUAL GENERATED');
    expect(generated[0]?.expression).toMatch(/if\(\(`is_final` = 1\),`engine`,NULL\)/i);
    const unique = (await uniqueSets('scan_engine_results')).map((u) => u.replace(/^[^(]+/, ''));
    expect(unique).toEqual(
      expect.arrayContaining([
        '(scan_id,engine,attempt,received_at)',
        '(scan_id,final_engine,received_at)',
      ]),
    );
    expect(unique).not.toContain('(scan_id,engine,received_at)');
    const checks = await prisma.$queryRaw<{ clause: string }[]>`
      SELECT cc.CHECK_CLAUSE AS clause FROM information_schema.CHECK_CONSTRAINTS cc
      WHERE cc.CONSTRAINT_SCHEMA = DATABASE()
        AND cc.CONSTRAINT_NAME = 'scan_engine_results_attempt_outcome_check'`;
    expect(checks).toHaveLength(1);
    expect(checks[0]!.clause).toMatch(/is_final/);
  });

  it('has email_auth_results (one row per round and engine) and scan_engine_settings (one row per organization and engine)', async () => {
    const auth = await columns(['email_auth_results']);
    const outcome = "enum('pass','fail','softfail','neutral','none','temperror','permerror')";
    for (const column of ['spf', 'dkim', 'dmarc', 'arc']) {
      expect(auth.get(`email_auth_results.${column}`)?.columnType, column).toBe(outcome);
    }
    expect(auth.get('email_auth_results.dmarc_policy')?.columnType).toBe(
      "enum('none','quarantine','reject')",
    );
    expect((await uniqueSets('email_auth_results')).map((u) => u.replace(/^[^(]+/, ''))).toContain(
      '(scan_id,engine,received_at)',
    );
    const settings = await columns(['scan_engine_settings']);
    expect(settings.get('scan_engine_settings.settings')?.columnType).toBe('json');
    expect(settings.get('scan_engine_settings.version')).toMatchObject({
      columnType: 'int unsigned',
      nullable: 'NO',
      columnDefault: '1',
    });
    expect(
      (await uniqueSets('scan_engine_settings')).map((u) => u.replace(/^[^(]+/, '')),
    ).toContain('(organization_id,engine)');
  });
});

describe('attachment scanning schema (step 4.2, docs/plan/steps/10-attachment-scanning.md §3)', () => {
  const uniqueSets = async (table: string) =>
    [...(await indexes(table)).values()]
      .filter((i) => i.unique)
      .map((i) => i.columns.join(','))
      .sort();
  const indexSets = async (table: string) =>
    [...(await indexes(table)).values()].map((i) => i.columns.join(','));
  const foreignKeys = async (table: string) =>
    prisma.$queryRaw<{ columnName: string; referenced: string; onDelete: string }[]>`
      SELECT k.COLUMN_NAME AS columnName, k.REFERENCED_TABLE_NAME AS referenced,
             r.DELETE_RULE AS onDelete
      FROM information_schema.KEY_COLUMN_USAGE k
      JOIN information_schema.REFERENTIAL_CONSTRAINTS r
        ON r.CONSTRAINT_SCHEMA = k.TABLE_SCHEMA AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME
      WHERE k.TABLE_SCHEMA = DATABASE() AND k.TABLE_NAME = ${table}
        AND k.REFERENCED_TABLE_NAME IS NOT NULL
      ORDER BY k.COLUMN_NAME`;

  it('evolves malware_signatures into the known-threat hash catalog (A17)', async () => {
    const cols = await columns(['malware_signatures']);
    expect(cols.get('malware_signatures.added_by_user_id')).toMatchObject({
      columnType: 'bigint unsigned',
      nullable: 'YES',
    });
    expect(cols.get('malware_signatures.reason')).toMatchObject({
      columnType: 'varchar(512)',
      nullable: 'YES',
    });
    expect(cols.get('malware_signatures.expires_at')).toMatchObject({
      columnType: 'datetime(3)',
      nullable: 'YES',
    });
    expect(await uniqueSets('malware_signatures')).toContain('sha256');
    expect(await indexSets('malware_signatures')).toContain('source,created_at');
    expect(await foreignKeys('malware_signatures')).toEqual([
      { columnName: 'added_by_user_id', referenced: 'users', onDelete: 'SET NULL' },
    ]);
  });

  it('has attachment_scan_results: one row per (scan, attachment), no content columns (A18)', async () => {
    const cols = await columns(['attachment_scan_results']);
    expect(cols.get('attachment_scan_results.verdict')?.columnType).toBe(
      "enum('clean','suspicious','malicious','unknown')",
    );
    expect(cols.get('attachment_scan_results.cache_result')?.columnType).toBe(
      "enum('hit','miss','bypass')",
    );
    expect(cols.get('attachment_scan_results.known_hash_severity')).toMatchObject({
      columnType: "enum('low','medium','high','critical')",
      nullable: 'YES',
    });
    expect(cols.get('attachment_scan_results.sha256')?.columnType).toBe('char(64)');
    expect(cols.get('attachment_scan_results.detected_type')?.columnType).toBe('varchar(32)');
    expect(cols.get('attachment_scan_results.type_family')?.columnType).toBe('varchar(16)');
    expect(cols.get('attachment_scan_results.content_version')?.columnType).toBe('char(16)');
    expect(cols.get('attachment_scan_results.reason_codes')).toMatchObject({
      columnType: 'json',
      nullable: 'NO',
    });
    const names = [...cols.keys()].map((k) => k.split('.')[1]!);
    for (const forbidden of ['filename', 'original_filename', 'content', 'object_key', 'body']) {
      expect(names, forbidden).not.toContain(forbidden);
    }
    expect(await uniqueSets('attachment_scan_results')).toEqual(
      ['id,received_at', 'scan_id,attachment_id,received_at'].sort(),
    );
    expect(await indexSets('attachment_scan_results')).toEqual(
      expect.arrayContaining(['organization_id,sha256', 'message_id,received_at']),
    );
  });

  it('has sandbox_submissions: pending by default, unique per (scan, attachment), 4.6 columns nullable (A11)', async () => {
    const cols = await columns(['sandbox_submissions']);
    expect(cols.get('sandbox_submissions.status')).toMatchObject({
      // Step 4.6 §3 appended `skipped`.
      columnType: "enum('pending','submitted','completed','failed','expired','skipped')",
      nullable: 'NO',
      columnDefault: 'pending',
    });
    expect(cols.get('sandbox_submissions.attachment_verdict')?.columnType).toBe(
      "enum('suspicious','unknown')",
    );
    expect(cols.get('sandbox_submissions.object_key')?.columnType).toBe('varchar(512)');
    expect(cols.get('sandbox_submissions.requested_event_id')?.columnType).toBe('char(36)');
    for (const reserved of ['external_ref', 'sandbox_verdict', 'completed_at']) {
      expect(cols.get(`sandbox_submissions.${reserved}`)?.nullable, reserved).toBe('YES');
    }
    expect(await uniqueSets('sandbox_submissions')).toEqual(
      ['id,received_at', 'scan_id,attachment_id,received_at'].sort(),
    );
    expect(await indexSets('sandbox_submissions')).toEqual(
      expect.arrayContaining(['status,created_at', 'sha256']),
    );
  });

  it('has attachment_rescan_jobs (A13) with a unique dedupe key and its foreign keys', async () => {
    const cols = await columns(['attachment_rescan_jobs']);
    expect(cols.get('attachment_rescan_jobs.trigger')?.columnType).toBe(
      "enum('signature_update','admin')",
    );
    expect(cols.get('attachment_rescan_jobs.status')).toMatchObject({
      columnType: "enum('pending','running','completed','cancelled','failed','skipped')",
      columnDefault: 'pending',
    });
    expect(cols.get('attachment_rescan_jobs.organization_id')?.nullable).toBe('YES');
    expect(cols.get('attachment_rescan_jobs.dedupe_key')?.nullable).toBe('YES');
    for (const counter of ['selected_count', 'requested_count', 'skipped_count']) {
      expect(cols.get(`attachment_rescan_jobs.${counter}`), counter).toMatchObject({
        columnType: 'int unsigned',
        columnDefault: '0',
      });
    }
    expect(await uniqueSets('attachment_rescan_jobs')).toEqual(
      expect.arrayContaining(['public_id', 'dedupe_key']),
    );
    expect(await indexSets('attachment_rescan_jobs')).toContain('status,created_at');
    expect(await foreignKeys('attachment_rescan_jobs')).toEqual([
      { columnName: 'organization_id', referenced: 'organizations', onDelete: 'RESTRICT' },
      { columnName: 'requested_by_user_id', referenced: 'users', onDelete: 'SET NULL' },
    ]);
  });

  it('has scan_signature_versions unique per (engine, component, version) (A13)', async () => {
    expect(await uniqueSets('scan_signature_versions')).toContain('engine,component,version');
    expect(await indexSets('scan_signature_versions')).toContain('engine,component,first_seen_at');
  });

  it('rejects a second attachment_scan_results row for the same (scan, attachment, received_at)', async () => {
    const receivedAt = new Date();
    const scanId = BigInt(Date.now()) * 1000n + BigInt(Math.floor(Math.random() * 1000));
    const row = {
      receivedAt,
      messageId: 1n,
      organizationId: 1n,
      scanId,
      attachmentId: 1n,
      partIndex: 0,
      sha256: 'a'.repeat(64),
      sizeBytes: 1,
      detectedType: 'pdf',
      typeFamily: 'document',
      typeMismatch: false,
      verdict: 'clean' as const,
      reasonCodes: ['clean.no_findings'],
      cacheResult: 'miss' as const,
      durationMs: 1,
    };
    try {
      await prisma.attachmentScanResult.create({ data: row });
      await expect(prisma.attachmentScanResult.create({ data: row })).rejects.toMatchObject({
        code: 'P2002',
      });
    } finally {
      await prisma.attachmentScanResult.deleteMany({ where: { scanId } });
    }
  });
});

describe('URL protection schema (step 4.3, docs/plan/steps/11-url-protection.md §3)', () => {
  const uniqueSets = async (table: string) =>
    [...(await indexes(table)).values()]
      .filter((i) => i.unique)
      .map((i) => i.columns.join(','))
      .sort();
  const indexSets = async (table: string) =>
    [...(await indexes(table)).values()].map((i) => i.columns.join(','));
  const foreignKeys = async (table: string) =>
    prisma.$queryRaw<{ columnName: string; referenced: string; onDelete: string }[]>`
      SELECT k.COLUMN_NAME AS columnName, k.REFERENCED_TABLE_NAME AS referenced,
             r.DELETE_RULE AS onDelete
      FROM information_schema.KEY_COLUMN_USAGE k
      JOIN information_schema.REFERENTIAL_CONSTRAINTS r
        ON r.CONSTRAINT_SCHEMA = k.TABLE_SCHEMA AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME
      WHERE k.TABLE_SCHEMA = DATABASE() AND k.TABLE_NAME = ${table}
        AND k.REFERENCED_TABLE_NAME IS NOT NULL
      ORDER BY k.COLUMN_NAME`;
  const URL_VERDICT_ENUM = "enum('clean','suspicious','malicious','unknown')";
  const CONTENT_COLUMNS = ['body', 'content', 'html', 'title', 'anchor_text', 'text', 'page'];
  const uniqueId = () => BigInt(Date.now()) * 1000n + BigInt(Math.floor(Math.random() * 1000));

  it('evolves threat_indicators into the platform URL/domain/IP feed (U6, U16)', async () => {
    const cols = await columns(['threat_indicators']);
    expect(cols.get('threat_indicators.added_by_user_id')).toMatchObject({
      columnType: 'bigint unsigned',
      nullable: 'YES',
    });
    expect(cols.get('threat_indicators.reason')).toMatchObject({
      columnType: 'varchar(512)',
      nullable: 'YES',
    });
    expect(cols.get('threat_indicators.category')).toMatchObject({
      columnType: "enum('phishing','malware','spam','scam','c2','other')",
      nullable: 'YES',
    });
    expect(await indexSets('threat_indicators')).toContain('source,created_at');
    expect(await uniqueSets('threat_indicators')).toContain(
      'org_scope,source,indicator_type,value_sha256',
    );
    expect(await foreignKeys('threat_indicators')).toEqual([
      { columnName: 'added_by_user_id', referenced: 'users', onDelete: 'SET NULL' },
      { columnName: 'organization_id', referenced: 'organizations', onDelete: 'RESTRICT' },
    ]);
  });

  it('has message_urls: one row per URL of a message, unique by seq and by identity hash (U3, U5)', async () => {
    const cols = await columns(['message_urls']);
    expect(cols.get('message_urls.url')?.columnType).toBe('varchar(2048)');
    expect(cols.get('message_urls.url_sha256')?.columnType).toBe('char(64)');
    expect(cols.get('message_urls.url_seq')?.columnType).toBe('smallint unsigned');
    expect(cols.get('message_urls.host')?.columnType).toBe('varchar(253)');
    expect(cols.get('message_urls.host_kind')?.columnType).toBe("enum('domain','ipv4','ipv6')");
    expect(cols.get('message_urls.truncated')).toMatchObject({ columnDefault: '0' });
    expect(cols.get('message_urls.sources')).toMatchObject({ columnType: 'json', nullable: 'NO' });
    expect(cols.get('message_urls.extractor_version')?.columnType).toBe('varchar(16)');
    const names = [...cols.keys()].map((k) => k.split('.')[1]!);
    for (const forbidden of CONTENT_COLUMNS) expect(names, forbidden).not.toContain(forbidden);
    expect(await uniqueSets('message_urls')).toEqual(
      [
        'id,received_at',
        'message_id,url_seq,received_at',
        'message_id,url_sha256,received_at',
      ].sort(),
    );
    const idx = await indexes('message_urls');
    expect([...idx.values()].map((i) => i.columns.join(','))).toEqual(
      expect.arrayContaining(['organization_id,url_sha256', 'organization_id,registrable_domain']),
    );
  });

  it('has url_scan_results: one row per (scan, url_seq), reusing the UrlVerdict enum (U10)', async () => {
    const cols = await columns(['url_scan_results']);
    expect(cols.get('url_scan_results.verdict')?.columnType).toBe(URL_VERDICT_ENUM);
    expect(cols.get('url_scan_results.fetch_status')?.columnType).toBe(
      "enum('not_attempted','completed','error','blocked')",
    );
    expect(cols.get('url_scan_results.fetch_cache')?.columnType).toBe("enum('hit','miss','none')");
    expect(cols.get('url_scan_results.hop_count')).toMatchObject({
      columnType: 'tinyint unsigned',
      columnDefault: '0',
    });
    expect(cols.get('url_scan_results.final_url')?.columnType).toBe('varchar(2048)');
    for (const json of ['reason_codes', 'reputation']) {
      expect(cols.get(`url_scan_results.${json}`), json).toMatchObject({
        columnType: 'json',
        nullable: 'NO',
      });
    }
    const names = [...cols.keys()].map((k) => k.split('.')[1]!);
    for (const forbidden of CONTENT_COLUMNS) expect(names, forbidden).not.toContain(forbidden);
    expect(await uniqueSets('url_scan_results')).toEqual(
      ['id,received_at', 'scan_id,url_seq,received_at'].sort(),
    );
    expect(await indexSets('url_scan_results')).toEqual(
      expect.arrayContaining(['message_id,received_at', 'organization_id,url_sha256']),
    );
  });

  it('has url_rewrites: one row per round with an S3 reference or a skip reason (U11)', async () => {
    const cols = await columns(['url_rewrites']);
    expect(cols.get('url_rewrites.status')?.columnType).toBe("enum('rewritten','skipped')");
    expect(cols.get('url_rewrites.object_key')).toMatchObject({
      columnType: 'varchar(512)',
      nullable: 'YES',
    });
    expect(cols.get('url_rewrites.skip_reason')?.columnType).toBe('varchar(32)');
    expect(cols.get('url_rewrites.settings_version')?.columnType).toBe('varchar(96)');
    expect(cols.get('url_rewrites.dkim_signed')).toMatchObject({ columnDefault: '0' });
    expect(await uniqueSets('url_rewrites')).toEqual(
      ['id,received_at', 'scan_id,received_at'].sort(),
    );
    expect(await indexSets('url_rewrites')).toContain('message_id,lifecycle_round,received_at');
  });

  it('has url_dynamic_inspections: pending by default, unique per (scan, url_seq) (U15)', async () => {
    const cols = await columns(['url_dynamic_inspections']);
    expect(cols.get('url_dynamic_inspections.status')).toMatchObject({
      columnType: "enum('pending','completed','failed','expired')",
      nullable: 'NO',
      columnDefault: 'pending',
    });
    expect(cols.get('url_dynamic_inspections.verdict')).toMatchObject({
      columnType: URL_VERDICT_ENUM,
      nullable: 'YES',
    });
    expect(cols.get('url_dynamic_inspections.requested_event_id')?.columnType).toBe('char(36)');
    expect(await uniqueSets('url_dynamic_inspections')).toEqual(
      ['id,received_at', 'scan_id,url_seq,received_at'].sort(),
    );
    expect(await indexSets('url_dynamic_inspections')).toEqual(
      expect.arrayContaining(['status,created_at', 'organization_id,url_sha256']),
    );
  });

  it('has url_click_events partitioned by clicked_at, without URL or client address columns (U14)', async () => {
    const cols = await columns(['url_click_events']);
    expect(cols.get('url_click_events.decision')?.columnType).toBe(
      "enum('allowed','warned','blocked','continued','expired','not_found')",
    );
    expect(cols.get('url_click_events.public_id')?.columnType).toBe('char(36)');
    expect(cols.get('url_click_events.client_network')).toMatchObject({
      columnType: 'varchar(49)',
      nullable: 'YES',
    });
    const names = [...cols.keys()].map((k) => k.split('.')[1]!);
    for (const forbidden of ['url', 'client_ip', 'user_agent', 'user_id', 'email']) {
      expect(names, forbidden).not.toContain(forbidden);
    }
    expect(await uniqueSets('url_click_events')).toEqual(['id,clicked_at']);
    expect(await indexSets('url_click_events')).toEqual(
      expect.arrayContaining([
        'organization_id,clicked_at',
        'message_id,message_received_at',
        'public_id',
      ]),
    );
  });

  it('rejects a second message_urls row for the same message and identity hash or seq', async () => {
    const receivedAt = new Date();
    const messageId = uniqueId();
    const row = {
      receivedAt,
      messageId,
      organizationId: 1n,
      urlSeq: 0,
      url: 'https://clean-site.test/a',
      urlSha256: 'a'.repeat(64),
      scheme: 'https',
      host: 'clean-site.test',
      registrableDomain: 'clean-site.test',
      hostKind: 'domain' as const,
      sources: { html_href: 1 },
      occurrences: 1,
      firstLifecycleRound: 1,
      extractorVersion: 'url-extract/1',
    };
    try {
      await prisma.messageUrl.create({ data: row });
      await expect(prisma.messageUrl.create({ data: { ...row, urlSeq: 1 } })).rejects.toMatchObject(
        { code: 'P2002' },
      );
      await expect(
        prisma.messageUrl.create({ data: { ...row, urlSha256: 'b'.repeat(64) } }),
      ).rejects.toMatchObject({ code: 'P2002' });
      // createMany with skipDuplicates is how the engine stores URLs (U16): a duplicate is skipped.
      const result = await prisma.messageUrl.createMany({
        data: [row, { ...row, urlSeq: 1, urlSha256: 'b'.repeat(64) }],
        skipDuplicates: true,
      });
      expect(result.count).toBe(1);
    } finally {
      await prisma.messageUrl.deleteMany({ where: { messageId } });
    }
  });

  it('rejects a second url_dynamic_inspections row for the same (scan, url_seq, received_at)', async () => {
    const scanId = uniqueId();
    const row = {
      receivedAt: new Date(),
      messageId: 1n,
      organizationId: 1n,
      scanId,
      urlSeq: 0,
      urlSha256: 'a'.repeat(64),
      requestedEventId: randomUUID(),
    };
    try {
      const created = await prisma.urlDynamicInspection.create({ data: row });
      expect(created.status).toBe('pending');
      await expect(prisma.urlDynamicInspection.create({ data: row })).rejects.toMatchObject({
        code: 'P2002',
      });
    } finally {
      await prisma.urlDynamicInspection.deleteMany({ where: { scanId } });
    }
  });
});

describe('phishing and BEC schema (step 4.4, docs/plan/steps/12-phishing-bec.md §3)', () => {
  const uniqueSets = async (table: string) =>
    [...(await indexes(table)).values()]
      .filter((i) => i.unique)
      .map((i) => i.columns.join(','))
      .sort();
  const indexSets = async (table: string) =>
    [...(await indexes(table)).values()].map((i) => i.columns.join(','));
  const foreignKeys = async (table: string) =>
    prisma.$queryRaw<{ columnName: string; referenced: string; onDelete: string }[]>`
      SELECT k.COLUMN_NAME AS columnName, k.REFERENCED_TABLE_NAME AS referenced,
             r.DELETE_RULE AS onDelete
      FROM information_schema.KEY_COLUMN_USAGE k
      JOIN information_schema.REFERENTIAL_CONSTRAINTS r
        ON r.CONSTRAINT_SCHEMA = k.TABLE_SCHEMA AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME
      WHERE k.TABLE_SCHEMA = DATABASE() AND k.TABLE_NAME = ${table}
        AND k.REFERENCED_TABLE_NAME IS NOT NULL
      ORDER BY k.COLUMN_NAME`;
  const BEC_VERDICT_ENUM = "enum('clean','suspicious','malicious','unknown','skipped')";
  const CONTENT_COLUMNS = ['body', 'content', 'html', 'text', 'excerpt', 'subject', 'span_text'];
  const TENANT_TABLES = [
    'bec_executive_profiles',
    'bec_vendor_profiles',
    'bec_trusted_senders',
    'bec_feedback',
    'bec_suppression_rules',
    'bec_contact_history',
  ];
  const uniqueId = () => BigInt(Date.now()) * 1000n + BigInt(Math.floor(Math.random() * 1000));

  it('has bec_scan_results: one row per scan, versions, scores, verdicts and JSON evidence (B14)', async () => {
    const cols = await columns(['bec_scan_results']);
    expect(cols.get('bec_scan_results.scan_id')?.columnType).toBe('bigint unsigned');
    expect(cols.get('bec_scan_results.lifecycle_round')?.columnType).toBe('smallint unsigned');
    expect(cols.get('bec_scan_results.engine_version')?.columnType).toBe('varchar(64)');
    expect(cols.get('bec_scan_results.rules_version')?.columnType).toBe('varchar(16)');
    expect(cols.get('bec_scan_results.settings_version')?.columnType).toBe('varchar(96)');
    expect(cols.get('bec_scan_results.lexicon_version')?.columnType).toBe('varchar(16)');
    expect(cols.get('bec_scan_results.text_version')?.columnType).toBe('varchar(16)');
    for (const score of ['deterministic_score', 'score']) {
      expect(cols.get(`bec_scan_results.${score}`)?.columnType, score).toBe('tinyint unsigned');
    }
    for (const verdict of ['deterministic_verdict', 'verdict']) {
      expect(cols.get(`bec_scan_results.${verdict}`), verdict).toMatchObject({
        columnType: BEC_VERDICT_ENUM,
        nullable: 'NO',
      });
    }
    for (const json of ['inputs', 'rules']) {
      expect(cols.get(`bec_scan_results.${json}`), json).toMatchObject({
        columnType: 'json',
        nullable: 'NO',
      });
    }
    for (const json of ['features', 'identity', 'ai', 'ai_shadow']) {
      expect(cols.get(`bec_scan_results.${json}`), json).toMatchObject({
        columnType: 'json',
        nullable: 'YES',
      });
    }
    const names = [...cols.keys()].map((k) => k.split('.')[1]!);
    for (const forbidden of CONTENT_COLUMNS) expect(names, forbidden).not.toContain(forbidden);
    expect(await uniqueSets('bec_scan_results')).toEqual(
      ['id,received_at', 'scan_id,received_at'].sort(),
    );
    expect(await indexSets('bec_scan_results')).toEqual(
      expect.arrayContaining(['message_id,received_at', 'organization_id,received_at']),
    );
    expect(await foreignKeys('bec_scan_results')).toEqual([]);
  });

  it('has the tenant profile, trust, feedback and suppression tables with their unique keys', async () => {
    const cols = await columns(TENANT_TABLES);
    for (const table of TENANT_TABLES) {
      expect(cols.get(`${table}.organization_id`), table).toMatchObject({
        columnType: 'bigint unsigned',
        nullable: 'NO',
      });
      if (table !== 'bec_contact_history') {
        expect(cols.get(`${table}.public_id`)?.columnType, table).toBe('char(36)');
        expect(await uniqueSets(table), table).toContain('public_id');
      }
    }
    expect(cols.get('bec_executive_profiles.normalized_name')?.columnType).toBe('varchar(160)');
    expect(cols.get('bec_executive_profiles.enabled')).toMatchObject({ columnDefault: '1' });
    expect(cols.get('bec_executive_profiles.version')).toMatchObject({
      columnType: 'int unsigned',
      columnDefault: '1',
    });
    expect(await uniqueSets('bec_executive_profiles')).toContain('organization_id,normalized_name');
    expect(await indexSets('bec_executive_profiles')).toContain('organization_id,enabled');
    expect(cols.get('bec_vendor_profiles.payment_change_sensitive')).toMatchObject({
      columnDefault: '1',
    });
    expect(await uniqueSets('bec_vendor_profiles')).toContain('organization_id,normalized_name');
    expect(cols.get('bec_trusted_senders.kind')?.columnType).toBe("enum('address','domain')");
    expect(cols.get('bec_trusted_senders.value')?.columnType).toBe('varchar(320)');
    expect(cols.get('bec_trusted_senders.expires_at')).toMatchObject({ nullable: 'YES' });
    expect(await uniqueSets('bec_trusted_senders')).toContain('organization_id,kind,value');
    expect(await indexSets('bec_trusted_senders')).toContain('organization_id,expires_at');
    expect(cols.get('bec_feedback.kind')?.columnType).toBe(
      "enum('false_positive','false_negative')",
    );
    expect(cols.get('bec_feedback.note')).toMatchObject({
      columnType: 'varchar(500)',
      nullable: 'YES',
    });
    expect(await uniqueSets('bec_feedback')).toContain('scan_id,created_by_user_id,kind');
    expect(await indexSets('bec_feedback')).toContain('organization_id,created_at');
    expect(cols.get('bec_suppression_rules.sender_scope')?.columnType).toBe(
      "enum('address','domain')",
    );
    expect(cols.get('bec_suppression_rules.expires_at')).toMatchObject({ nullable: 'NO' });
    expect(await uniqueSets('bec_suppression_rules')).toContain(
      'organization_id,reason_code,sender_scope,sender_value',
    );
    expect(await indexSets('bec_suppression_rules')).toContain('organization_id,expires_at');
  });

  it('keeps bec_contact_history to keyed hashes and aggregate counts (B12, ADR-0035)', async () => {
    const cols = await columns(['bec_contact_history']);
    expect([...cols.keys()].map((k) => k.split('.')[1]!).sort()).toEqual(
      [
        'id',
        'organization_id',
        'scope',
        'key_hash',
        'message_count',
        'inbound_count',
        'outbound_count',
        'infra',
        'first_seen_at',
        'last_seen_at',
        'created_at',
        'updated_at',
      ].sort(),
    );
    expect(cols.get('bec_contact_history.scope')?.columnType).toBe("enum('sender','pair')");
    expect(cols.get('bec_contact_history.key_hash')?.columnType).toBe('char(64)');
    expect(await uniqueSets('bec_contact_history')).toContain('organization_id,scope,key_hash');
    expect(await indexSets('bec_contact_history')).toContain('organization_id,last_seen_at');
  });

  it('references organizations (RESTRICT, no cascade) and users (SET NULL) only', async () => {
    const userColumns: Record<string, string[]> = {
      bec_executive_profiles: ['created_by_user_id', 'updated_by_user_id'],
      bec_vendor_profiles: ['created_by_user_id', 'updated_by_user_id'],
      bec_trusted_senders: ['created_by_user_id'],
      bec_feedback: ['created_by_user_id'],
      bec_suppression_rules: ['created_by_user_id'],
      bec_contact_history: [],
    };
    for (const table of TENANT_TABLES) {
      expect(await foreignKeys(table), table).toEqual(
        [
          { columnName: 'organization_id', referenced: 'organizations', onDelete: 'RESTRICT' },
          ...userColumns[table]!.map((columnName) => ({
            columnName,
            referenced: 'users',
            onDelete: 'SET NULL',
          })),
        ].sort((a, b) => (a.columnName < b.columnName ? -1 : 1)),
      );
    }
  });

  it('rejects a second bec_scan_results row for the same scan', async () => {
    const scanId = uniqueId();
    const row = {
      receivedAt: new Date(),
      messageId: 1n,
      organizationId: 1n,
      scanId,
      lifecycleRound: 0,
      engineVersion: 'bec/1;lex=00000000;fm=00000000;br=00000000',
      rulesVersion: 'bec-map/1',
      settingsVersion: 'bec-map/1;p=000000000000;t=none',
      lexiconVersion: '00000000',
      textVersion: 'bec-text/1',
      deterministicScore: 0,
      score: 0,
      deterministicVerdict: 'clean' as const,
      verdict: 'clean' as const,
      inputs: { auth: 'available', url: 'available', text: 'complete', history: 'disabled' },
      rules: [],
      durationMs: 3,
    };
    try {
      await prisma.becScanResult.create({ data: row });
      await expect(prisma.becScanResult.create({ data: row })).rejects.toMatchObject({
        code: 'P2002',
      });
    } finally {
      await prisma.becScanResult.deleteMany({ where: { scanId } });
    }
  });

  it('refuses to delete an organization that still has BEC tenant rows (no cascade)', async () => {
    const suffix = randomUUID().slice(0, 8);
    const plan = await prisma.organizationPlan.create({
      data: {
        code: `it-bec-${suffix}`,
        name: 'BEC schema test',
        defaultLimits: {},
        defaultFeatures: {},
      },
    });
    const organization = await prisma.organization.create({
      data: {
        slug: `it-bec-${suffix}`,
        name: 'BEC schema test',
        planId: plan.id,
        dataRegion: 'ap-south-1',
      },
    });
    try {
      await prisma.becTrustedSender.create({
        data: {
          publicId: randomUUID(),
          organizationId: organization.id,
          kind: 'domain',
          value: 'vendor.example',
          reason: 'schema test',
        },
      });
      await expect(
        prisma.becTrustedSender.create({
          data: {
            publicId: randomUUID(),
            organizationId: organization.id,
            kind: 'domain',
            value: 'vendor.example',
            reason: 'duplicate',
          },
        }),
      ).rejects.toMatchObject({ code: 'P2002' });
      await expect(
        prisma.organization.delete({ where: { id: organization.id } }),
      ).rejects.toBeInstanceOf(Prisma.PrismaClientKnownRequestError);
    } finally {
      await prisma.becTrustedSender.deleteMany({ where: { organizationId: organization.id } });
      await prisma.organization.deleteMany({ where: { id: organization.id } });
      await prisma.organizationPlan.deleteMany({ where: { id: plan.id } });
    }
  });
});

describe('data loss prevention schema (step 4.5, docs/plan/steps/13-dlp.md §3)', () => {
  const uniqueSets = async (table: string) =>
    [...(await indexes(table)).values()]
      .filter((i) => i.unique)
      .map((i) => i.columns.join(','))
      .sort();
  const indexSets = async (table: string) =>
    [...(await indexes(table)).values()].map((i) => i.columns.join(','));
  const foreignKeys = async (table: string) =>
    prisma.$queryRaw<{ columnName: string; referenced: string; onDelete: string }[]>`
      SELECT k.COLUMN_NAME AS columnName, k.REFERENCED_TABLE_NAME AS referenced,
             r.DELETE_RULE AS onDelete
      FROM information_schema.KEY_COLUMN_USAGE k
      JOIN information_schema.REFERENTIAL_CONSTRAINTS r
        ON r.CONSTRAINT_SCHEMA = k.TABLE_SCHEMA AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME
      WHERE k.TABLE_SCHEMA = DATABASE() AND k.TABLE_NAME = ${table}
        AND k.REFERENCED_TABLE_NAME IS NOT NULL
      ORDER BY k.COLUMN_NAME`;
  const ACTION_ENUM = "enum('allow','alert','require_approval','quarantine','block')";
  const SEVERITY_ENUM = "enum('low','medium','high','critical')";
  const PARTITIONED_TABLES = ['dlp_scan_results', 'dlp_evidence'];
  const TENANT_TABLES = [
    'dlp_policies',
    'dlp_policy_rules',
    'dlp_exceptions',
    'dlp_custom_patterns',
    'dlp_keyword_dictionaries',
    'dlp_compliance_settings',
  ];
  const uniqueId = () => BigInt(Date.now()) * 1000n + BigInt(Math.floor(Math.random() * 1000));
  const columnNames = async (table: string) =>
    [...(await columns([table])).keys()].map((k) => k.split('.')[1]!).sort();

  it('has dlp_scan_results: one row per scan, versions, verdict, action and masked JSON (D10, D19)', async () => {
    expect(await columnNames('dlp_scan_results')).toEqual(
      [
        'id',
        'received_at',
        'message_id',
        'organization_id',
        'scan_id',
        'lifecycle_round',
        'direction',
        'engine_version',
        'rules_version',
        'settings_version',
        'policy_version',
        'extractor_version',
        'verdict',
        'action',
        'action_source',
        'matched_policy_id',
        'matched_rule_id',
        'coverage',
        'coverage_detail',
        'categories',
        'findings',
        'policy',
        'finding_count',
        'evidence_status',
        'duration_ms',
        'created_at',
      ].sort(),
    );
    const cols = await columns(['dlp_scan_results']);
    const type = (column: string) => cols.get(`dlp_scan_results.${column}`);
    expect(type('scan_id')?.columnType).toBe('bigint unsigned');
    expect(type('lifecycle_round')?.columnType).toBe('smallint unsigned');
    expect(type('direction')?.columnType).toBe("enum('inbound','outbound','internal')");
    expect(type('engine_version')?.columnType).toBe('varchar(96)');
    expect(type('rules_version')?.columnType).toBe('varchar(16)');
    expect(type('settings_version')?.columnType).toBe('varchar(96)');
    expect(type('policy_version')?.columnType).toBe('varchar(32)');
    expect(type('extractor_version')?.columnType).toBe('varchar(32)');
    expect(type('verdict')).toMatchObject({
      columnType: "enum('clean','suspicious','unknown','skipped')",
      nullable: 'NO',
    });
    expect(type('action')).toMatchObject({ columnType: ACTION_ENUM, nullable: 'NO' });
    expect(type('action_source')?.columnType).toBe("enum('none','tenant_policy','default_policy')");
    for (const column of ['matched_policy_id', 'matched_rule_id']) {
      expect(type(column), column).toMatchObject({
        columnType: 'bigint unsigned',
        nullable: 'YES',
      });
    }
    expect(type('coverage')?.columnType).toBe("enum('complete','partial')");
    for (const json of ['coverage_detail', 'categories', 'findings', 'policy']) {
      expect(type(json), json).toMatchObject({ columnType: 'json', nullable: 'NO' });
    }
    expect(type('finding_count')?.columnType).toBe('int unsigned');
    expect(type('evidence_status')?.columnType).toBe("enum('none','stored','disabled','failed')");
    expect(await uniqueSets('dlp_scan_results')).toEqual(
      ['id,received_at', 'scan_id,received_at'].sort(),
    );
    expect(await indexSets('dlp_scan_results')).toEqual(
      expect.arrayContaining([
        'message_id,received_at',
        'organization_id,received_at',
        'organization_id,action,received_at',
      ]),
    );
    expect(await foreignKeys('dlp_scan_results')).toEqual([]);
  });

  it('has dlp_evidence: object reference, wrapped key and purge state, never content (D16)', async () => {
    expect(await columnNames('dlp_evidence')).toEqual(
      [
        'id',
        'received_at',
        'organization_id',
        'message_id',
        'scan_id',
        'object_key',
        'object_sha256',
        'object_size_bytes',
        'wrapped_key',
        'key_id',
        'algorithm',
        'match_count',
        'expires_at',
        'purged_at',
        'purge_reason',
        'created_at',
      ].sort(),
    );
    const cols = await columns(['dlp_evidence']);
    const type = (column: string) => cols.get(`dlp_evidence.${column}`);
    expect(type('object_key')).toMatchObject({ columnType: 'varchar(512)', nullable: 'YES' });
    expect(type('object_sha256')).toMatchObject({ columnType: 'char(64)', nullable: 'NO' });
    expect(type('object_size_bytes')?.columnType).toBe('int unsigned');
    expect(type('wrapped_key')).toMatchObject({ columnType: 'varchar(255)', nullable: 'YES' });
    expect(type('key_id')?.columnType).toBe('varchar(16)');
    expect(type('algorithm')?.columnType).toBe('varchar(32)');
    expect(type('match_count')?.columnType).toBe('smallint unsigned');
    expect(type('expires_at')).toMatchObject({ columnType: 'datetime(3)', nullable: 'NO' });
    expect(type('purged_at')).toMatchObject({ columnType: 'datetime(3)', nullable: 'YES' });
    expect(type('purge_reason')).toMatchObject({
      columnType: "enum('retention','tenant_request','organization_deleted')",
      nullable: 'YES',
    });
    expect(await uniqueSets('dlp_evidence')).toEqual(
      ['id,received_at', 'scan_id,received_at'].sort(),
    );
    expect(await indexSets('dlp_evidence')).toEqual(
      expect.arrayContaining([
        'message_id,received_at',
        'organization_id,purged_at,expires_at',
        'expires_at',
      ]),
    );
    expect(await foreignKeys('dlp_evidence')).toEqual([]);
  });

  it('has no column that could hold message content (only masked JSON in dlp_scan_results.findings)', async () => {
    const tables = [...PARTITIONED_TABLES, ...TENANT_TABLES];
    const cols = await columns(tables);
    const forbidden =
      /^(body|content|html|text|excerpt|subject|span_text|value_raw|raw_value|matched_value|context|evidence_text|extracted_text|sample)$/;
    for (const key of cols.keys()) {
      const column = key.split('.')[1]!;
      expect(column, key).not.toMatch(forbidden);
    }
    // Free-text and JSON columns are tenant configuration or masked results only; the evidence
    // row has no TEXT/BLOB/JSON column at all (its content lives encrypted in S3).
    const wide = [...cols.values()].filter((c) => /text|blob/.test(c.columnType));
    expect(wide.map((c) => `${c.tableName}.${c.columnName}`)).toEqual([]);
    const evidenceJson = [...cols.values()].filter(
      (c) => c.tableName === 'dlp_evidence' && c.columnType === 'json',
    );
    expect(evidenceJson).toEqual([]);
  });

  it('has the tenant policy, rule, exception, pattern, dictionary and compliance tables (D8, D9, D11, D12, D17)', async () => {
    const cols = await columns(TENANT_TABLES);
    for (const table of TENANT_TABLES) {
      expect(cols.get(`${table}.organization_id`), table).toMatchObject({
        columnType: 'bigint unsigned',
        nullable: 'NO',
      });
      expect(cols.get(`${table}.version`), table).toMatchObject({
        columnType: 'int unsigned',
        columnDefault: '1',
      });
      if (table !== 'dlp_compliance_settings') {
        expect(cols.get(`${table}.public_id`)?.columnType, table).toBe('char(36)');
        expect(await uniqueSets(table), table).toContain('public_id');
        expect(cols.get(`${table}.enabled`), table).toMatchObject({
          columnType: 'tinyint(1)',
          columnDefault: '1',
        });
      }
    }
    // dlp_policies
    expect(cols.get('dlp_policies.mode')).toMatchObject({
      columnType: "enum('enforce','monitor')",
      columnDefault: 'enforce',
    });
    expect(cols.get('dlp_policies.priority')).toMatchObject({
      columnType: 'smallint unsigned',
      columnDefault: '100',
    });
    expect(cols.get('dlp_policies.directions')?.columnType).toBe('json');
    expect(cols.get('dlp_policies.description')).toMatchObject({
      columnType: 'varchar(512)',
      nullable: 'YES',
    });
    expect(await uniqueSets('dlp_policies')).toContain('organization_id,name');
    expect(await indexSets('dlp_policies')).toContain('organization_id,enabled,priority');
    // dlp_policy_rules
    expect(cols.get('dlp_policy_rules.action')?.columnType).toBe(ACTION_ENUM);
    expect(cols.get('dlp_policy_rules.conditions')?.columnType).toBe('json');
    expect(await uniqueSets('dlp_policy_rules')).toContain('policy_id,name');
    expect(await indexSets('dlp_policy_rules')).toContain('organization_id,policy_id,priority');
    // dlp_exceptions
    expect(cols.get('dlp_exceptions.scope')?.columnType).toBe(
      "enum('sender_address','sender_domain','recipient_address','recipient_domain')",
    );
    expect(cols.get('dlp_exceptions.value')?.columnType).toBe('varchar(320)');
    expect(cols.get('dlp_exceptions.target_key')).toMatchObject({
      columnType: 'varchar(48)',
      nullable: 'NO',
    });
    expect(cols.get('dlp_exceptions.filters')).toMatchObject({
      columnType: 'json',
      nullable: 'YES',
    });
    expect(cols.get('dlp_exceptions.reason')).toMatchObject({
      columnType: 'varchar(512)',
      nullable: 'NO',
    });
    expect(cols.get('dlp_exceptions.expires_at')).toMatchObject({ nullable: 'NO' });
    for (const column of ['policy_id', 'rule_id']) {
      expect(cols.get(`dlp_exceptions.${column}`), column).toMatchObject({ nullable: 'YES' });
    }
    expect(await uniqueSets('dlp_exceptions')).toContain('organization_id,scope,value,target_key');
    expect(await indexSets('dlp_exceptions')).toContain('organization_id,expires_at');
    // dlp_custom_patterns
    expect(cols.get('dlp_custom_patterns.pattern')?.columnType).toBe('varchar(512)');
    expect(cols.get('dlp_custom_patterns.validator')).toMatchObject({
      columnType: "enum('none','luhn','verhoeff','mod97','gstin')",
      columnDefault: 'none',
    });
    expect(cols.get('dlp_custom_patterns.severity')?.columnType).toBe(SEVERITY_ENUM);
    expect(cols.get('dlp_custom_patterns.base_confidence')?.columnType).toBe('decimal(3,2)');
    expect(cols.get('dlp_custom_patterns.mask_style')).toMatchObject({
      columnType: "enum('last4','full')",
      columnDefault: 'last4',
    });
    expect(cols.get('dlp_custom_patterns.context_keywords')?.columnType).toBe('json');
    expect(await uniqueSets('dlp_custom_patterns')).toContain('organization_id,name');
    // dlp_keyword_dictionaries
    expect(cols.get('dlp_keyword_dictionaries.category')?.columnType).toBe(
      "enum('confidential','financial','personal_info','source_code','custom')",
    );
    expect(cols.get('dlp_keyword_dictionaries.terms')?.columnType).toBe('json');
    expect(cols.get('dlp_keyword_dictionaries.term_count')?.columnType).toBe('smallint unsigned');
    expect(cols.get('dlp_keyword_dictionaries.severity')?.columnType).toBe(SEVERITY_ENUM);
    expect(cols.get('dlp_keyword_dictionaries.base_confidence')).toMatchObject({
      columnType: 'decimal(3,2)',
      columnDefault: '0.70',
    });
    expect(cols.get('dlp_keyword_dictionaries.min_matches')).toMatchObject({
      columnType: 'smallint unsigned',
      columnDefault: '1',
    });
    expect(await uniqueSets('dlp_keyword_dictionaries')).toContain('organization_id,name');
    // dlp_compliance_settings
    expect(await uniqueSets('dlp_compliance_settings')).toContain('organization_id');
    expect(cols.get('dlp_compliance_settings.aadhaar_enabled')).toMatchObject({
      columnType: 'tinyint(1)',
      columnDefault: '0',
    });
    expect(cols.get('dlp_compliance_settings.aadhaar_attested')).toMatchObject({
      columnDefault: '0',
    });
    expect(cols.get('dlp_compliance_settings.aadhaar_basis')).toMatchObject({
      columnType:
        "enum('regulatory_obligation','uidai_authorised_entity','data_protection_policy','other')",
      nullable: 'YES',
    });
    expect(cols.get('dlp_compliance_settings.aadhaar_reference')).toMatchObject({
      columnType: 'varchar(256)',
      nullable: 'YES',
    });
    for (const column of ['aadhaar_recorded_at', 'aadhaar_review_due_at']) {
      expect(cols.get(`dlp_compliance_settings.${column}`), column).toMatchObject({
        columnType: 'datetime(3)',
        nullable: 'YES',
      });
    }
  });

  it('references organizations (RESTRICT), users (SET NULL) and policies/rules (RESTRICT) only', async () => {
    const audit = ['created_by_user_id', 'updated_by_user_id'];
    const expected: Record<string, { columnName: string; referenced: string; onDelete: string }[]> =
      {
        dlp_policies: [],
        dlp_policy_rules: [
          { columnName: 'policy_id', referenced: 'dlp_policies', onDelete: 'RESTRICT' },
        ],
        dlp_exceptions: [
          { columnName: 'policy_id', referenced: 'dlp_policies', onDelete: 'RESTRICT' },
          { columnName: 'rule_id', referenced: 'dlp_policy_rules', onDelete: 'RESTRICT' },
        ],
        dlp_custom_patterns: [],
        dlp_keyword_dictionaries: [],
        dlp_compliance_settings: [],
      };
    for (const table of TENANT_TABLES) {
      const users = table === 'dlp_compliance_settings' ? ['aadhaar_recorded_by_user_id'] : audit;
      expect(await foreignKeys(table), table).toEqual(
        [
          { columnName: 'organization_id', referenced: 'organizations', onDelete: 'RESTRICT' },
          ...users.map((columnName) => ({ columnName, referenced: 'users', onDelete: 'SET NULL' })),
          ...expected[table]!,
        ].sort((a, b) => (a.columnName < b.columnName ? -1 : 1)),
      );
    }
  });

  it('rejects a second dlp_scan_results and dlp_evidence row for the same (scan, received_at)', async () => {
    const scanId = uniqueId();
    const receivedAt = new Date();
    const result = {
      receivedAt,
      messageId: 1n,
      organizationId: 1n,
      scanId,
      lifecycleRound: 0,
      direction: 'outbound' as const,
      engineVersion: 'dlp/1;dict=00000000;data=00000000;ext=dlp-extract/1',
      rulesVersion: 'dlp-map/1',
      settingsVersion: 'dlp-map/1;p=000000000000;t=none',
      policyVersion: 'pol/1;h=000000000000',
      extractorVersion: 'dlp-extract/1',
      verdict: 'clean' as const,
      action: 'allow' as const,
      actionSource: 'none' as const,
      coverage: 'complete' as const,
      coverageDetail: [],
      categories: [],
      findings: [],
      policy: { winner: null, matched: [], exceptionsApplied: [] },
      findingCount: 0,
      evidenceStatus: 'none' as const,
      durationMs: 3,
    };
    const evidence = {
      receivedAt,
      organizationId: 1n,
      messageId: 1n,
      scanId,
      objectKey: `org/1/dlp-evidence/2026/11/${scanId}-${randomUUID()}.bin`,
      objectSha256: 'a'.repeat(64),
      objectSizeBytes: 128,
      wrappedKey: 'v1.k1.aaaa.bbbb.cccc',
      keyId: 'k1',
      algorithm: 'dlp-evidence/1',
      matchCount: 1,
      expiresAt: new Date(receivedAt.getTime() + 30 * 86_400_000),
    };
    try {
      await prisma.dlpScanResult.create({ data: result });
      await expect(prisma.dlpScanResult.create({ data: result })).rejects.toMatchObject({
        code: 'P2002',
      });
      await prisma.dlpEvidence.create({ data: evidence });
      await expect(prisma.dlpEvidence.create({ data: evidence })).rejects.toMatchObject({
        code: 'P2002',
      });
      // A rescan round has another scan id: both rows are accepted.
      await prisma.dlpScanResult.create({ data: { ...result, scanId: scanId + 1n } });
      // Crypto-shredding clears the wrapped key, then the object key (D16).
      const shredded = await prisma.dlpEvidence.updateMany({
        where: { scanId, receivedAt },
        data: { wrappedKey: null, purgedAt: new Date(), purgeReason: 'retention' },
      });
      expect(shredded.count).toBe(1);
      await prisma.dlpEvidence.updateMany({ where: { scanId }, data: { objectKey: null } });
    } finally {
      await prisma.dlpScanResult.deleteMany({ where: { scanId: { in: [scanId, scanId + 1n] } } });
      await prisma.dlpEvidence.deleteMany({ where: { scanId } });
    }
  });

  it('refuses to delete an organization (or a policy with rules) that still has DLP rows (no cascade)', async () => {
    const suffix = randomUUID().slice(0, 8);
    const plan = await prisma.organizationPlan.create({
      data: {
        code: `it-dlp-${suffix}`,
        name: 'DLP schema test',
        defaultLimits: {},
        defaultFeatures: {},
      },
    });
    const organization = await prisma.organization.create({
      data: {
        slug: `it-dlp-${suffix}`,
        name: 'DLP schema test',
        planId: plan.id,
        dataRegion: 'ap-south-1',
      },
    });
    const organizationId = organization.id;
    try {
      const policy = await prisma.dlpPolicy.create({
        data: {
          publicId: randomUUID(),
          organizationId,
          name: 'Outbound cards',
          directions: ['outbound', 'internal'],
        },
      });
      const rule = await prisma.dlpPolicyRule.create({
        data: {
          publicId: randomUUID(),
          organizationId,
          policyId: policy.id,
          name: 'cards',
          priority: 10,
          conditions: { selectors: { categories: ['payment_card'] } },
          action: 'quarantine',
        },
      });
      const exception = {
        organizationId,
        scope: 'recipient_domain' as const,
        value: 'partner.example',
        ruleId: rule.id,
        targetKey: `rule:${rule.id}`,
        reason: 'schema test',
        expiresAt: new Date(Date.now() + 86_400_000),
      };
      await prisma.dlpException.create({ data: { ...exception, publicId: randomUUID() } });
      await expect(
        prisma.dlpException.create({ data: { ...exception, publicId: randomUUID() } }),
      ).rejects.toMatchObject({ code: 'P2002' });
      await prisma.dlpCustomPattern.create({
        data: {
          publicId: randomUUID(),
          organizationId,
          name: 'employee id',
          pattern: 'EMP-[0-9]{6}',
          contextKeywords: ['employee'],
          severity: 'medium',
          baseConfidence: new Prisma.Decimal('0.80'),
        },
      });
      await prisma.dlpKeywordDictionary.create({
        data: {
          publicId: randomUUID(),
          organizationId,
          name: 'projects',
          category: 'confidential',
          terms: ['project falcon'],
          termCount: 1,
          severity: 'high',
        },
      });
      await prisma.dlpComplianceSettings.create({ data: { organizationId } });
      await expect(
        prisma.dlpComplianceSettings.create({ data: { organizationId } }),
      ).rejects.toMatchObject({ code: 'P2002' });
      // RESTRICT: the rule and its exception block the policy, every row blocks the organization.
      await expect(prisma.dlpPolicy.delete({ where: { id: policy.id } })).rejects.toBeInstanceOf(
        Prisma.PrismaClientKnownRequestError,
      );
      await expect(
        prisma.organization.delete({ where: { id: organizationId } }),
      ).rejects.toBeInstanceOf(Prisma.PrismaClientKnownRequestError);
    } finally {
      await prisma.dlpException.deleteMany({ where: { organizationId } });
      await prisma.dlpPolicyRule.deleteMany({ where: { organizationId } });
      await prisma.dlpPolicy.deleteMany({ where: { organizationId } });
      await prisma.dlpCustomPattern.deleteMany({ where: { organizationId } });
      await prisma.dlpKeywordDictionary.deleteMany({ where: { organizationId } });
      await prisma.dlpComplianceSettings.deleteMany({ where: { organizationId } });
      await prisma.organization.deleteMany({ where: { id: organizationId } });
      await prisma.organizationPlan.deleteMany({ where: { id: plan.id } });
    }
  });
});

describe('sandbox engine schema (step 4.6, docs/plan/steps/14-sandbox.md §3)', () => {
  const uniqueSets = async (table: string) =>
    [...(await indexes(table)).values()]
      .filter((i) => i.unique)
      .map((i) => i.columns.join(','))
      .sort();
  const indexSets = async (table: string) =>
    [...(await indexes(table)).values()].map((i) => i.columns.join(','));
  const foreignKeys = async (table: string) =>
    prisma.$queryRaw<{ columnName: string; referenced: string; onDelete: string }[]>`
      SELECT k.COLUMN_NAME AS columnName, k.REFERENCED_TABLE_NAME AS referenced,
             r.DELETE_RULE AS onDelete
      FROM information_schema.KEY_COLUMN_USAGE k
      JOIN information_schema.REFERENTIAL_CONSTRAINTS r
        ON r.CONSTRAINT_SCHEMA = k.TABLE_SCHEMA AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME
      WHERE k.TABLE_SCHEMA = DATABASE() AND k.TABLE_NAME = ${table}
        AND k.REFERENCED_TABLE_NAME IS NOT NULL
      ORDER BY k.COLUMN_NAME`;

  const analysisRow = (overrides: Partial<Prisma.SandboxAnalysisUncheckedCreateInput> = {}) => {
    const sha256 = randomUUID().replaceAll('-', '').padEnd(64, 'a').slice(0, 64);
    return {
      publicId: randomUUID(),
      sha256,
      sizeBytes: 1024,
      detectedType: 'script_js',
      profile: 'static' as const,
      analysisKey: '0123456789abcdef',
      dedupeKey: `${sha256}:0123456789abcdef`,
      organizationId: 1n,
      deadlineAt: new Date(Date.now() + 900_000),
      expiresAt: new Date(Date.now() + 180 * 86_400_000),
      ...overrides,
    };
  };

  it('has sandbox_analyses with exactly the §3 columns, types and nullability', async () => {
    const cols = await columns(['sandbox_analyses']);
    const expected: Record<string, [string, 'YES' | 'NO']> = {
      id: ['bigint unsigned', 'NO'],
      public_id: ['char(36)', 'NO'],
      sha256: ['char(64)', 'NO'],
      size_bytes: ['int unsigned', 'NO'],
      detected_type: ['varchar(32)', 'NO'],
      profile: ["enum('static','execute','browser')", 'NO'],
      analysis_key: ['char(16)', 'NO'],
      dedupe_key: ['varchar(81)', 'YES'],
      status: ["enum('pending','dispatched','completed','not_executed','failed','expired')", 'NO'],
      organization_id: ['bigint unsigned', 'NO'],
      sample_object_key: ['varchar(512)', 'YES'],
      sample_deleted_at: ['datetime(3)', 'YES'],
      requested_event_id: ['char(36)', 'YES'],
      result_event_id: ['char(36)', 'YES'],
      result_token_sha256: ['char(64)', 'YES'],
      dispatched_at: ['datetime(3)', 'YES'],
      deadline_at: ['datetime(3)', 'NO'],
      completed_at: ['datetime(3)', 'YES'],
      verdict: ["enum('clean','suspicious','malicious','unknown','error','timeout')", 'YES'],
      reason_codes: ['json', 'YES'],
      report: ['json', 'YES'],
      backend: ['varchar(32)', 'YES'],
      backend_version: ['varchar(64)', 'YES'],
      isolation: ['varchar(16)', 'YES'],
      executed: ['tinyint(1)', 'YES'],
      controller_version: ['varchar(64)', 'YES'],
      analyzer_version: ['varchar(64)', 'YES'],
      map_version: ['varchar(16)', 'YES'],
      not_executed_reason: ['varchar(48)', 'YES'],
      error_code: ['varchar(48)', 'YES'],
      duration_ms: ['int unsigned', 'YES'],
      reuse_until: ['datetime(3)', 'YES'],
      expires_at: ['datetime(3)', 'NO'],
      created_at: ['datetime(3)', 'NO'],
      updated_at: ['datetime(3)', 'NO'],
    };
    expect([...cols.keys()].map((k) => k.split('.')[1]).sort()).toEqual(
      Object.keys(expected).sort(),
    );
    for (const [column, [type, nullable]] of Object.entries(expected)) {
      expect(cols.get(`sandbox_analyses.${column}`), column).toMatchObject({
        columnType: type,
        nullable,
      });
    }
    expect(cols.get('sandbox_analyses.status')?.columnDefault).toBe('pending');
    expect(await uniqueSets('sandbox_analyses')).toEqual(['dedupe_key', 'id', 'public_id']);
    expect(await indexSets('sandbox_analyses')).toEqual(
      expect.arrayContaining([
        'status,deadline_at',
        'sha256',
        'expires_at',
        'sample_deleted_at,status',
      ]),
    );
    expect(await foreignKeys('sandbox_analyses')).toEqual([]);
  });

  it('has sandbox_artifacts with the §3 columns, a unique (analysis, seq) and RESTRICT to the analysis', async () => {
    const cols = await columns(['sandbox_artifacts']);
    const expected: Record<string, [string, 'YES' | 'NO']> = {
      id: ['bigint unsigned', 'NO'],
      analysis_id: ['bigint unsigned', 'NO'],
      seq: ['smallint unsigned', 'NO'],
      kind: ["enum('screenshot','process_log','network_log','static_report','dropped_file')", 'NO'],
      content_type: ['varchar(64)', 'NO'],
      object_key: ['varchar(512)', 'NO'],
      object_sha256: ['char(64)', 'NO'],
      plain_sha256: ['char(64)', 'NO'],
      size_bytes: ['int unsigned', 'NO'],
      wrapped_key: ['varchar(256)', 'YES'],
      key_id: ['varchar(16)', 'NO'],
      algorithm: ['varchar(32)', 'NO'],
      expires_at: ['datetime(3)', 'NO'],
      purged_at: ['datetime(3)', 'YES'],
      purge_reason: ['varchar(32)', 'YES'],
      object_deleted_at: ['datetime(3)', 'YES'],
      created_at: ['datetime(3)', 'NO'],
    };
    expect([...cols.keys()].map((k) => k.split('.')[1]).sort()).toEqual(
      Object.keys(expected).sort(),
    );
    for (const [column, [type, nullable]] of Object.entries(expected)) {
      expect(cols.get(`sandbox_artifacts.${column}`), column).toMatchObject({
        columnType: type,
        nullable,
      });
    }
    expect(await uniqueSets('sandbox_artifacts')).toEqual(['analysis_id,seq', 'id']);
    expect(await indexSets('sandbox_artifacts')).toContain('expires_at,purged_at');
    expect(await foreignKeys('sandbox_artifacts')).toEqual([
      { columnName: 'analysis_id', referenced: 'sandbox_analyses', onDelete: 'RESTRICT' },
    ]);
  });

  it('extends sandbox_submissions with the four nullable 4.6 columns and an analysis_id index', async () => {
    const cols = await columns(['sandbox_submissions']);
    expect(cols.get('sandbox_submissions.analysis_id')).toMatchObject({
      columnType: 'bigint unsigned',
      nullable: 'YES',
    });
    expect(cols.get('sandbox_submissions.skip_reason')).toMatchObject({
      columnType: 'varchar(48)',
      nullable: 'YES',
    });
    expect(cols.get('sandbox_submissions.sandbox_reason_codes')).toMatchObject({
      columnType: 'json',
      nullable: 'YES',
    });
    expect(cols.get('sandbox_submissions.settings_version')).toMatchObject({
      columnType: 'varchar(96)',
      nullable: 'YES',
    });
    expect(await indexSets('sandbox_submissions')).toContain('analysis_id');
    expect(await foreignKeys('sandbox_submissions')).toEqual([]);
  });

  it('stores no content-like column: no TEXT/BLOB in the sandbox tables', async () => {
    const rows = await prisma.$queryRaw<{ tableName: string; columnName: string }[]>`
      SELECT TABLE_NAME AS tableName, COLUMN_NAME AS columnName
      FROM information_schema.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME IN ('sandbox_analyses', 'sandbox_artifacts', 'sandbox_submissions')
        AND DATA_TYPE IN ('text', 'mediumtext', 'longtext', 'blob', 'mediumblob', 'longblob',
                          'tinytext', 'tinyblob', 'binary', 'varbinary')`;
    expect(rows).toEqual([]);
  });

  it('allows many NULL dedupe keys, rejects a duplicate dedupe key and blocks deleting an analysis with artifacts', async () => {
    const first = analysisRow();
    const nullA = analysisRow({ dedupeKey: null });
    const nullB = analysisRow({ dedupeKey: null });
    const ids: bigint[] = [];
    try {
      const a = await prisma.sandboxAnalysis.create({ data: first });
      ids.push(a.id);
      expect(a.status).toBe('pending');
      expect(a.publicId).toBe(first.publicId);
      // Superseded / failed analyses release the key: many NULLs are allowed.
      ids.push((await prisma.sandboxAnalysis.create({ data: nullA })).id);
      ids.push((await prisma.sandboxAnalysis.create({ data: nullB })).id);
      // A concurrent dispatcher with the same dedupe key gets P2002 (it re-reads and links).
      await expect(
        prisma.sandboxAnalysis.create({
          data: analysisRow({ sha256: first.sha256, dedupeKey: first.dedupeKey }),
        }),
      ).rejects.toMatchObject({ code: 'P2002' });
      // The public id (task id) is unique.
      await expect(
        prisma.sandboxAnalysis.create({
          data: analysisRow({ publicId: first.publicId, dedupeKey: null }),
        }),
      ).rejects.toMatchObject({ code: 'P2002' });
      // A defaulted public id is a UUIDv7.
      const { publicId: _unused, ...withoutPublicId } = analysisRow({ dedupeKey: null });
      const defaulted = await prisma.sandboxAnalysis.create({ data: withoutPublicId });
      ids.push(defaulted.id);
      expect(defaulted.publicId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-/);

      const artifact = {
        analysisId: a.id,
        seq: 0,
        kind: 'static_report' as const,
        contentType: 'application/json',
        objectKey: `artifacts/2026/11/${first.publicId}/0123456789abcdef/0-static_report.bin`,
        objectSha256: 'b'.repeat(64),
        plainSha256: 'c'.repeat(64),
        sizeBytes: 100,
        wrappedKey: 'x1.k1.AAAA.BBBB.CCCC.DDDD',
        keyId: 'k1',
        algorithm: 'sandbox-artifact/1',
        expiresAt: new Date(Date.now() + 30 * 86_400_000),
      };
      await prisma.sandboxArtifact.create({ data: artifact });
      await expect(prisma.sandboxArtifact.create({ data: artifact })).rejects.toMatchObject({
        code: 'P2002',
      });
      // RESTRICT: the sweeper must delete the artifacts first.
      await expect(prisma.sandboxAnalysis.delete({ where: { id: a.id } })).rejects.toBeInstanceOf(
        Prisma.PrismaClientKnownRequestError,
      );
      // Crypto-shredding: the wrapped key can be nulled.
      const shredded = await prisma.sandboxArtifact.update({
        where: { analysisId_seq: { analysisId: a.id, seq: 0 } },
        data: { wrappedKey: null, purgedAt: new Date(), purgeReason: 'retention' },
      });
      expect(shredded.wrappedKey).toBeNull();
    } finally {
      await prisma.sandboxArtifact.deleteMany({ where: { analysisId: { in: ids } } });
      await prisma.sandboxAnalysis.deleteMany({ where: { id: { in: ids } } });
    }
  });

  it('accepts the skipped status and the 4.6 columns on a sandbox_submissions row', async () => {
    const receivedAt = new Date();
    const scanId = BigInt(Date.now()) * 1000n + BigInt(Math.floor(Math.random() * 1000));
    try {
      const row = await prisma.sandboxSubmission.create({
        data: {
          receivedAt,
          messageId: 1n,
          organizationId: 1n,
          scanId,
          attachmentId: 1n,
          partIndex: 0,
          sha256: 'd'.repeat(64),
          sizeBytes: 10,
          detectedType: 'script_js',
          objectKey: 'org/1/part/x',
          attachmentVerdict: 'suspicious',
          reasonCodes: ['type.mismatch'],
          requestedEventId: randomUUID(),
        },
      });
      expect(row.status).toBe('pending');
      expect(row.analysisId).toBeNull();
      const skipped = await prisma.sandboxSubmission.update({
        where: { id_receivedAt: { id: row.id, receivedAt } },
        data: {
          status: 'skipped',
          skipReason: 'tenant_disabled',
          sandboxReasonCodes: ['sandbox.tenant_disabled'],
          settingsVersion: 'sandbox-map/1;p=0123456789ab;t=none',
          completedAt: new Date(),
        },
      });
      expect(skipped).toMatchObject({ status: 'skipped', skipReason: 'tenant_disabled' });
    } finally {
      await prisma.sandboxSubmission.deleteMany({ where: { scanId } });
    }
  });
});
