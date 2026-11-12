import { spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  DEMO,
  DEMO_POLICY_DSL_VERSION,
  MAIL_DESTINATION_PRESETS,
  PERMISSIONS,
  PLATFORM_ORGANIZATION_SLUG,
  PrismaClient,
  RETIRED_ROLE_KEYS,
  SYSTEM_ROLE_KEYS,
  SYSTEM_ROLES,
} from '@email-gateway/database';
import { afterAll, describe, expect, it } from 'vitest';
import { stack } from './support/env';

/**
 * db:seed (step 1.1 D7, step 1.2/1.3 D8 and D10) against the dev schema, with the DML account:
 * the catalog (58 permissions since step 6.1, the 9 system roles incl. mailbox_user (step 5.3 Q25), the platform organization, the step 2.3
 * destination provider presets), the retired
 * role-key remap, and idempotency (running it twice leaves the same row counts). The seeded
 * rows are dev data and are deliberately left in place.
 */
const SEED_CLI = fileURLToPath(
  new URL('../../packages/database/dist/seed/cli.js', import.meta.url),
);
/** Relative `<KEY>_FILE` paths in .env are relative to the repository root, like compose. */
const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));
const prisma = new PrismaClient({ datasourceUrl: stack.databaseUrl() });

afterAll(async () => {
  await prisma.$disconnect();
});

function seed(args: string[] = [], env: Record<string, string> = {}) {
  const result = spawnSync(process.execPath, [SEED_CLI, ...args], {
    cwd: REPO_ROOT,
    env: { ...process.env, LOG_LEVEL: 'warn', ...env },
    encoding: 'utf8',
    timeout: 60_000,
  });
  return { status: result.status, output: `${result.stdout}${result.stderr}` };
}

async function counts() {
  const demo = await prisma.organization.findUnique({ where: { slug: 'demo' } });
  const organizationId = demo?.id ?? 0n;
  const platform = await prisma.organization.findUnique({
    where: { slug: PLATFORM_ORGANIZATION_SLUG },
  });
  const platformId = platform?.id ?? 0n;
  return {
    permissions: await prisma.permission.count(),
    systemRoles: await prisma.role.count({ where: { organizationId: null, isSystem: true } }),
    rolePermissions: await prisma.rolePermission.count(),
    plans: await prisma.organizationPlan.count(),
    systemSettings: await prisma.systemSetting.count(),
    destinationPresets: await prisma.mailDestinationPreset.count(),
    demoOrganizations: await prisma.organization.count({
      where: { slug: { in: ['demo', 'platform'] } },
    }),
    demoUsers: await prisma.user.count({ where: { organizationId } }),
    demoUserRoles: await prisma.userRole.count({ where: { organizationId } }),
    demoLimits: await prisma.organizationLimit.count({ where: { organizationId } }),
    demoFeatures: await prisma.organizationFeature.count({ where: { organizationId } }),
    demoDeployments: await prisma.organizationDeployment.count({ where: { organizationId } }),
    demoDomains: await prisma.domain.count({ where: { organizationId } }),
    demoMailServers: await prisma.domainMailServer.count({ where: { organizationId } }),
    demoPolicies: await prisma.emailPolicy.count({ where: { organizationId } }),
    demoPolicyVersions: await prisma.policyVersion.count({ where: { organizationId } }),
    demoPolicySettings: await prisma.policySettings.count({ where: { organizationId } }),
    demoQuarantineSettings: await prisma.quarantineSettings.count({ where: { organizationId } }),
    demoLegacyPolicyRows:
      (await prisma.policyCondition.count({ where: { organizationId } })) +
      (await prisma.policyAction.count({ where: { organizationId } })),
    platformUsers: await prisma.user.count({ where: { organizationId: platformId } }),
    platformUserRoles: await prisma.userRole.count({ where: { organizationId: platformId } }),
    platformSettings: await prisma.organizationSetting.count({
      where: { organizationId: platformId },
    }),
    platformLimits: await prisma.organizationLimit.count({
      where: { organizationId: platformId },
    }),
    platformFeatures: await prisma.organizationFeature.count({
      where: { organizationId: platformId },
    }),
    platformDeployments: await prisma.organizationDeployment.count({
      where: { organizationId: platformId },
    }),
  };
}

describe('db:seed', () => {
  it('is idempotent: a second run leaves identical row counts', { timeout: 120_000 }, async () => {
    const first = seed();
    expect(first.status, first.output).toBe(0);
    const afterFirst = await counts();

    const second = seed();
    expect(second.status, second.output).toBe(0);
    expect(await counts()).toEqual(afterFirst);

    expect(afterFirst).toMatchObject({
      permissions: 58,
      systemRoles: 9,
      destinationPresets: 2,
      plans: expect.any(Number) as unknown,
      demoOrganizations: 2,
      demoUsers: 2,
      demoUserRoles: 2,
      demoLimits: 11,
      demoFeatures: 11,
      demoDeployments: 1,
      demoDomains: 1,
      demoPolicies: 1,
      platformUsers: 1,
      platformUserRoles: 1,
      platformSettings: 1,
      platformLimits: 11,
      platformFeatures: 11,
      platformDeployments: 1,
    });
    expect(afterFirst.plans).toBeGreaterThanOrEqual(4);
    // Step 5.2 §3: one policy-dsl/1 version on a fresh database; a database migrated from the
    // step 1.1 seed also keeps its retired legacy version 1 (superseded, never deleted).
    expect([1, 2]).toContain(afterFirst.demoPolicyVersions);
    expect(afterFirst.demoPolicySettings).toBe(1);
    // Step 5.3 §3 Seed: the demo organization's quarantine settings (`{}` = every default).
    expect(afterFirst.demoQuarantineSettings).toBe(1);
    const quarantineSettings = await prisma.quarantineSettings.findFirstOrThrow({
      where: { organization: { slug: 'demo' } },
    });
    expect(quarantineSettings.settings).toEqual({});
    expect(quarantineSettings.settingsSha256).toBe(createHash('sha256').update('{}').digest('hex'));
    expect(quarantineSettings.rowVersion).toBe(1);

    // Step 2.2 (D6): the SMTP recipient limits are materialized from the plan (demo = standard).
    const demo = await prisma.organization.findUniqueOrThrow({ where: { slug: 'demo' } });
    const smtpLimits = await prisma.organizationLimit.findMany({
      where: {
        organizationId: demo.id,
        limitKey: {
          in: [
            'inbound_recipients_per_minute',
            'outbound_recipients_per_minute',
            'outbound_recipients_per_day',
          ],
        },
      },
      select: { limitKey: true, limitValue: true, source: true },
      orderBy: { limitKey: 'asc' },
    });
    expect(smtpLimits).toEqual([
      { limitKey: 'inbound_recipients_per_minute', limitValue: 3_000n, source: 'plan' },
      { limitKey: 'outbound_recipients_per_day', limitValue: 50_000n, source: 'plan' },
      { limitKey: 'outbound_recipients_per_minute', limitValue: 300n, source: 'plan' },
    ]);
    const standard = await prisma.organizationPlan.findUniqueOrThrow({
      where: { code: 'standard' },
    });
    expect(standard.defaultLimits).toMatchObject({
      inbound_recipients_per_minute: 3_000,
      outbound_recipients_per_minute: 300,
      outbound_recipients_per_day: 50_000,
      outbound_recipients_per_domain_per_minute: 150,
    });
    // Step 2.3 (R11): the per-destination-domain limit is materialized like the other limits
    // (demo = standard: 300 / 2; platform = enterprise: 1 200 / 2).
    const platformOrg = await prisma.organization.findUniqueOrThrow({
      where: { slug: PLATFORM_ORGANIZATION_SLUG },
    });
    const domainLimit = (organizationId: bigint) =>
      prisma.organizationLimit.findUniqueOrThrow({
        where: {
          organizationId_limitKey: {
            organizationId,
            limitKey: 'outbound_recipients_per_domain_per_minute',
          },
        },
        select: { limitValue: true, source: true },
      });
    expect(await domainLimit(demo.id)).toEqual({ limitValue: 150n, source: 'plan' });
    expect(await domainLimit(platformOrg.id)).toEqual({ limitValue: 600n, source: 'plan' });

    // Step 2.3 (R2): destination provider presets are platform configuration data.
    const presets = await prisma.mailDestinationPreset.findMany({ orderBy: { provider: 'asc' } });
    expect(presets.map((p) => p.provider).sort()).toEqual(['google_workspace', 'microsoft_365']);
    for (const def of MAIL_DESTINATION_PRESETS) {
      const row = presets.find((p) => p.provider === def.provider)!;
      expect(row, def.provider).toMatchObject({
        displayName: def.displayName,
        hostPatterns: [...def.hostPatterns],
        hostHint: def.hostHint,
        defaultServers: def.defaultServers === null ? null : [...def.defaultServers],
        port: 25,
        tlsMode: 'verify',
        tlsVerifyNames: def.tlsVerifyNames,
        maxServers: def.maxServers,
        documentationUrl: def.documentationUrl,
        enabled: true,
      });
      for (const pattern of row.hostPatterns as string[])
        expect(() => new RegExp(pattern)).not.toThrow();
    }
    // The demo destination stays the custom mail.gateway.test server, now with a public id.
    const servers = await prisma.domainMailServer.findMany({
      where: { organizationId: demo.id, role: 'inbound_destination' },
      select: { host: true, port: true, provider: true, publicId: true, tlsVerifyNames: true },
    });
    expect(servers).toHaveLength(1);
    expect(servers[0]).toMatchObject({
      host: 'mail.gateway.test',
      port: 25,
      provider: 'custom',
      tlsVerifyNames: null,
    });
    expect(servers[0]!.publicId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );

    // The demo domain is the owner of its name (tenant resolution key) and active (step 2.1).
    const domain = await prisma.domain.findUnique({
      where: { verifiedName: DEMO.domain },
    });
    expect(domain?.status).toBe('active');
    expect(domain?.verifiedAt).toBeInstanceOf(Date);
    expect(domain?.activatedAt).toBeInstanceOf(Date);
    expect(domain?.liveName).toBe(DEMO.domain);
    // Scheduled for the api's domain-check job, which materializes its configuration (D11, D12).
    expect(domain?.nextCheckAt).toBeInstanceOf(Date);
  });

  it('moves a demo domain seeded before step 2.1 (verified) to active, keeping its row', async () => {
    const demo = await prisma.organization.findUniqueOrThrow({ where: { slug: 'demo' } });
    const domain = await prisma.domain.findUniqueOrThrow({
      where: {
        organizationId_liveName: { organizationId: demo.id, liveName: DEMO.domain },
      },
    });
    // Simulate the step 1.1 seed state (never scheduled for checks).
    await prisma.domain.update({
      where: { id: domain.id },
      data: { status: 'verified', activatedAt: null, nextCheckAt: null },
    });
    const before = Date.now();
    const result = seed();
    expect(result.status, result.output).toBe(0);
    const after = await prisma.domain.findUniqueOrThrow({ where: { id: domain.id } });
    expect(after.status).toBe('active');
    expect(after.activatedAt).toBeInstanceOf(Date);
    expect(after.verifiedAt).toEqual(domain.verifiedAt);
    // Made due, so the domain-check job materializes its configuration (D11, D12).
    expect(after.nextCheckAt!.getTime()).toBeGreaterThanOrEqual(before - 1000);
    expect(after.nextCheckAt!.getTime()).toBeLessThanOrEqual(Date.now() + 1000);
    expect(await prisma.domain.count({ where: { organizationId: demo.id } })).toBe(1);

    // A scheduled row keeps its time on a re-seed.
    const scheduled = new Date(Date.UTC(2099, 0, 1));
    await prisma.domain.update({ where: { id: domain.id }, data: { nextCheckAt: scheduled } });
    expect(seed().status).toBe(0);
    const again = await prisma.domain.findUniqueOrThrow({ where: { id: domain.id } });
    expect(again.nextCheckAt).toEqual(scheduled);
    await prisma.domain.update({ where: { id: domain.id }, data: { nextCheckAt: new Date() } });
  });

  it('seeds the demo policy as a published, active policy-dsl/1 version (step 5.2 §3)', async () => {
    expect(seed().status).toBe(0);
    const demo = await prisma.organization.findUniqueOrThrow({ where: { slug: 'demo' } });
    const policy = await prisma.emailPolicy.findUniqueOrThrow({
      where: { organizationId_name: { organizationId: demo.id, name: DEMO.policy.name } },
    });
    const versions = await prisma.policyVersion.findMany({
      where: { organizationId: demo.id, policyId: policy.id },
      orderBy: { version: 'asc' },
    });
    const legacy = versions.filter((v) => v.dslVersion === null);
    const dsl = versions.filter((v) => v.dslVersion !== null);
    // Legacy (step 1.1) versions are retired by the migration, never deleted or reactivated.
    for (const v of legacy) expect(v.status).toBe('superseded');
    expect(dsl).toHaveLength(1);
    const version = dsl[0]!;
    // Version 1 on a fresh database, the next number after the legacy rows otherwise.
    expect(version.version).toBe(Math.max(0, ...legacy.map((v) => v.version)) + 1);

    // The definition verbatim from the design (§3) and its canonical hash.
    const expected = {
      dslVersion: 'policy-dsl/1',
      direction: 'inbound',
      priority: 100,
      rules: [
        {
          id: 'quarantine-malware-phishing',
          priority: 10,
          when: { field: 'risk.verdict', op: 'in', value: ['malware', 'phishing'] },
          actions: [{ type: 'QUARANTINE' }, { type: 'TAG', label: 'sample-policy' }],
        },
      ],
    };
    expect(version.definition).toEqual(expected);
    const canonical =
      '{"direction":"inbound","dslVersion":"policy-dsl/1","priority":100,"rules":[{"actions":' +
      '[{"type":"QUARANTINE"},{"label":"sample-policy","type":"TAG"}],"id":"quarantine-malware-' +
      'phishing","priority":10,"when":{"field":"risk.verdict","op":"in","value":["malware",' +
      '"phishing"]}}]}';
    expect(version.definitionSha256).toBe(createHash('sha256').update(canonical).digest('hex'));
    expect(version).toMatchObject({
      status: 'published',
      dslVersion: DEMO_POLICY_DSL_VERSION,
      references: { departmentIds: [], userIds: [] },
      hasOverrideRules: false,
      ruleCount: 1,
    });
    expect(version.publishedAt).toBeInstanceOf(Date);
    expect(policy).toMatchObject({
      status: 'active',
      activeVersionId: version.id,
      direction: 'inbound',
      priority: 100,
      deletedAt: null,
    });
    // The retired relational rows are never written for a DSL version.
    expect(await prisma.policyCondition.count({ where: { policyVersionId: version.id } })).toBe(0);
    expect(await prisma.policyAction.count({ where: { policyVersionId: version.id } })).toBe(0);

    const settings = await prisma.policySettings.findUniqueOrThrow({
      where: { organizationId: demo.id },
    });
    expect(settings.settings).toEqual({});
    expect(settings.settingsSha256).toBe(createHash('sha256').update('{}').digest('hex'));
    expect(settings.generation).toBeGreaterThanOrEqual(1n);

    // Re-seeding changes nothing (no new version, no generation or row_version bump).
    expect(seed().status).toBe(0);
    expect(
      await prisma.policySettings.findUniqueOrThrow({ where: { organizationId: demo.id } }),
    ).toMatchObject({ generation: settings.generation, rowVersion: settings.rowVersion });
    expect(await prisma.emailPolicy.findUniqueOrThrow({ where: { id: policy.id } })).toMatchObject({
      rowVersion: policy.rowVersion,
      activeVersionId: version.id,
    });
    expect(await prisma.policyVersion.count({ where: { policyId: policy.id } })).toBe(
      versions.length,
    );

    // The state the migration leaves a legacy policy in (pointer cleared, disabled): the seed
    // re-activates its DSL version and bumps the generation exactly once (P12).
    await prisma.emailPolicy.update({
      where: { id: policy.id },
      data: { activeVersionId: null, status: 'disabled' },
    });
    expect(seed().status).toBe(0);
    expect(await prisma.emailPolicy.findUniqueOrThrow({ where: { id: policy.id } })).toMatchObject({
      status: 'active',
      activeVersionId: version.id,
    });
    expect(
      (await prisma.policySettings.findUniqueOrThrow({ where: { organizationId: demo.id } }))
        .generation,
    ).toBe(settings.generation + 1n);
    expect(await prisma.policyVersion.count({ where: { policyId: policy.id } })).toBe(
      versions.length,
    );
  });

  it('seeds exactly the 58 permissions and the 9 system roles (D8 + mailbox_user, 5.3), with their permissions', async () => {
    expect(seed().status).toBe(0);
    const permissions = await prisma.permission.findMany({ select: { key: true } });
    expect(permissions.map((p) => p.key).sort()).toEqual(PERMISSIONS.map((p) => p.key).sort());

    const roles = await prisma.role.findMany({
      where: { organizationId: null },
      select: {
        key: true,
        name: true,
        isSystem: true,
        permissions: { select: { permission: { select: { key: true } } } },
      },
    });
    expect(roles.map((r) => r.key).sort()).toEqual([...SYSTEM_ROLE_KEYS].sort());
    for (const def of SYSTEM_ROLES) {
      const row = roles.find((r) => r.key === def.key)!;
      expect(row.isSystem, def.key).toBe(true);
      expect(row.name, def.key).toBe(def.name);
      expect(row.permissions.map((p) => p.permission.key).sort(), def.key).toEqual(
        [...def.permissions].sort(),
      );
    }
    // Step 2.2: SMTP connector permissions.
    const holders = (key: string) =>
      roles
        .filter((r) => r.permissions.some((p) => p.permission.key === key))
        .map((r) => r.key)
        .sort();
    expect(holders('connector:manage')).toEqual([
      'domain_admin',
      'organization_admin',
      'super_admin',
    ]);
    expect(holders('connector:read')).toEqual(
      [
        'compliance_auditor',
        'domain_admin',
        'organization_admin',
        'platform_admin',
        'read_only_user',
        'super_admin',
      ].sort(),
    );
    for (const retired of Object.keys(RETIRED_ROLE_KEYS)) {
      expect(roles.map((r) => r.key)).not.toContain(retired);
    }
    // Step 2.3 (R13): destination changes and delivery status.
    expect(holders('domain:routing_manage')).toEqual([
      'domain_admin',
      'organization_admin',
      'super_admin',
    ]);
    // Every built-in role reads delivery status, except the end-user role (step 5.3 Q15).
    expect(holders('delivery:read')).toEqual(
      SYSTEM_ROLE_KEYS.filter((k) => k !== 'mailbox_user').sort(),
    );
    // Step 3.3 (L10.2): the administrative rescan.
    expect(holders('message:rescan')).toEqual([
      'organization_admin',
      'security_analyst',
      'super_admin',
    ]);

    // Step 2.1 D14: DKIM rotation is granted to domain, organization and super admins only.
    const rotators = roles
      .filter((r) => r.permissions.some((p) => p.permission.key === 'domain:dkim_rotate'))
      .map((r) => r.key)
      .sort();
    expect(rotators).toEqual(['domain_admin', 'organization_admin', 'super_admin']);

    // Step 3.2 (Q9): dead-letter replay is a platform operation of the two platform admin roles.
    expect(holders('platform:dead_letter_replay')).toEqual(['platform_admin', 'super_admin']);
    // Step 4.1 (S13, S16): tenant scan thresholds and the platform-only classifier training.
    expect(holders('scan:settings_manage')).toEqual([
      'organization_admin',
      'security_analyst',
      'super_admin',
    ]);
    expect(holders('platform:scan_training')).toEqual(['platform_admin', 'super_admin']);
    // Step 4.2 (A13, A16, A17): the known-threat hash catalog and bulk attachment rescans.
    expect(holders('platform:threat_intel_manage')).toEqual(['platform_admin', 'super_admin']);
    expect(holders('platform:scan_rescan')).toEqual(['platform_admin', 'super_admin']);
    // Step 4.4 (B18): the BEC tenant permissions.
    expect(holders('bec:read')).toEqual([
      'compliance_auditor',
      'organization_admin',
      'security_analyst',
      'super_admin',
    ]);
    for (const key of ['bec:manage', 'bec:feedback']) {
      expect(holders(key), key).toEqual(['organization_admin', 'security_analyst', 'super_admin']);
    }
    expect(holders('bec:feedback_export')).toEqual(['organization_admin', 'super_admin']);
    // Step 4.5 (D21): the DLP tenant permissions; never read-only (read_only_user and
    // platform_admin hold none of them).
    for (const key of ['dlp:read', 'dlp:evidence_read']) {
      expect(holders(key), key).toEqual([
        'compliance_auditor',
        'organization_admin',
        'security_analyst',
        'super_admin',
      ]);
    }
    expect(holders('dlp:manage')).toEqual([
      'organization_admin',
      'security_analyst',
      'super_admin',
    ]);
    expect(holders('dlp:compliance_manage')).toEqual(['organization_admin', 'super_admin']);
    for (const role of [
      'read_only_user',
      'platform_admin',
      'quarantine_reviewer',
      'domain_admin',
    ]) {
      const keys = roles.find((r) => r.key === role)!.permissions.map((p) => p.permission.key);
      expect(
        keys.filter((k) => k.startsWith('dlp:')),
        role,
      ).toEqual([]);
    }
    // Step 5.3 (Q25): the quarantine permission matrix and the end-user role.
    expect(holders('quarantine:read')).toEqual([
      'compliance_auditor',
      'domain_admin',
      'organization_admin',
      'platform_admin',
      'quarantine_reviewer',
      'read_only_user',
      'security_analyst',
      'super_admin',
    ]);
    expect(holders('quarantine:preview')).toEqual([
      'organization_admin',
      'security_analyst',
      'super_admin',
    ]);
    for (const key of [
      'quarantine:release',
      'quarantine:approve',
      'quarantine:reject',
      'quarantine:delete',
    ]) {
      expect(holders(key), key).toEqual([
        'organization_admin',
        'quarantine_reviewer',
        'security_analyst',
        'super_admin',
      ]);
    }
    expect(holders('quarantine:manage')).toEqual([
      'organization_admin',
      'security_analyst',
      'super_admin',
    ]);
    expect(holders('quarantine:download')).toEqual(['organization_admin', 'super_admin']);
    expect(holders('quarantine:request_release')).toEqual([
      'organization_admin',
      'quarantine_reviewer',
      'super_admin',
    ]);
    expect(holders('quarantine:self')).toEqual([
      'mailbox_user',
      'organization_admin',
      'super_admin',
    ]);
    const mailbox = roles.find((r) => r.key === 'mailbox_user')!;
    expect(mailbox).toMatchObject({ name: 'Mailbox User', isSystem: true });
    expect(mailbox.permissions.map((p) => p.permission.key)).toEqual(['quarantine:self']);
    // Step 6.1 (§3.6): the permissions of the new REST routes.
    expect(holders('threat_intel:read')).toEqual([
      'organization_admin',
      'platform_admin',
      'security_analyst',
      'super_admin',
    ]);
    expect(holders('billing:read')).toEqual([
      'compliance_auditor',
      'organization_admin',
      'super_admin',
    ]);
    expect(holders('delivery:suppression_manage')).toEqual([
      'domain_admin',
      'organization_admin',
      'super_admin',
    ]);
  });

  it('seeds the platform organization with mandatory MFA and the demo users', async () => {
    const demoEmails = ['admin@gateway.test', 'analyst@gateway.test', 'operator@gateway.test'];
    const accountState = async () =>
      prisma.user.findMany({
        where: { email: { in: demoEmails } },
        select: { email: true, status: true, passwordHash: true, mfaEnabled: true },
        orderBy: { email: 'asc' },
      });
    // The demo users may already have been activated locally (invitation, password reset): the
    // seed must leave existing accounts exactly as they are (upsert with `update: {}`).
    const before = await accountState();
    expect(seed().status).toBe(0);
    const after = await accountState();
    for (const previous of before) {
      expect(
        after.find((u) => u.email === previous.email),
        previous.email,
      ).toEqual(previous);
    }
    const platform = await prisma.organization.findUniqueOrThrow({
      where: { slug: PLATFORM_ORGANIZATION_SLUG },
      include: { settings: true, plan: true, deployments: true },
    });
    expect(platform).toMatchObject({
      kind: 'platform',
      status: 'active',
      dataRegion: 'ap-south-1',
    });
    expect(platform.plan.code).toBe('enterprise');
    expect(platform.settings?.mfaRequired).toBe(true);
    expect(platform.deployments.filter((d) => d.deploymentMode === 'saas')).toHaveLength(1);

    const demo = await prisma.organization.findUniqueOrThrow({
      where: { slug: 'demo' },
      include: { settings: true },
    });
    expect(demo.settings?.mfaRequired).toBe(false);

    const users = await prisma.user.findMany({
      where: { email: { in: demoEmails } },
      select: {
        email: true,
        status: true,
        passwordHash: true,
        organizationId: true,
        userRoles: { select: { role: { select: { key: true } } } },
      },
    });
    const byEmail = new Map(users.map((u) => [u.email, u]));
    const expectUser = (email: string, organizationId: bigint, roleKey: string) => {
      const user = byEmail.get(email);
      expect(user, email).toBeDefined();
      expect(user!.organizationId, email).toBe(organizationId);
      expect(
        user!.userRoles.map((r) => r.role.key),
        email,
      ).toContain(roleKey);
      // The seed creates users as invited without a password; an invited account never has one
      // (accepting the invitation sets the password and activates it).
      if (user!.status === 'invited') expect(user!.passwordHash, email).toBeNull();
    };
    expectUser('admin@gateway.test', demo.id, 'organization_admin');
    expectUser('analyst@gateway.test', demo.id, 'security_analyst');
    expectUser('operator@gateway.test', platform.id, 'super_admin');
  });

  it('remaps assignments of retired role keys and deletes the retired roles', async () => {
    const suffix = randomUUID().slice(0, 8);
    const plan = await prisma.organizationPlan.create({
      data: { code: `it-${suffix}`, name: 'Seed test', defaultLimits: {}, defaultFeatures: {} },
    });
    const organization = await prisma.organization.create({
      data: { slug: `it-${suffix}`, name: 'Seed test', planId: plan.id, dataRegion: 'ap-south-1' },
    });
    const organizationId = organization.id;
    try {
      const mkUser = (name: string) =>
        prisma.user.create({
          data: { organizationId, email: `${name}-${suffix}@example.test`, displayName: name },
        });
      const granter = await mkUser('granter');
      const both = await mkUser('both');
      const reviewer = await mkUser('reviewer');

      // A retired system role as step 1.1 seeded it (organization_id NULL). The seed below
      // deletes it again, so the test leaves no role behind even if an assertion fails later.
      const retiredRole = async (key: string) =>
        (await prisma.role.findFirst({ where: { organizationId: null, key } })) ??
        (await prisma.role.create({ data: { key, name: key, isSystem: true } }));
      const tenantAdmin = await retiredRole('tenant_admin');
      const securityAdmin = await retiredRole('security_admin');
      const helpdesk = await retiredRole('helpdesk');
      const userRead = await prisma.permission.findUniqueOrThrow({ where: { key: 'user:read' } });
      await prisma.rolePermission.createMany({
        data: [{ roleId: tenantAdmin.id, permissionId: userRead.id }],
        skipDuplicates: true,
      });
      await prisma.userRole.createMany({
        data: [
          // Both retired roles map to organization_admin: one assignment must result.
          {
            userId: both.id,
            roleId: tenantAdmin.id,
            organizationId,
            grantedByUserId: granter.id,
          },
          { userId: both.id, roleId: securityAdmin.id, organizationId },
          { userId: reviewer.id, roleId: helpdesk.id, organizationId },
        ],
      });

      const result = seed(['--catalog-only']);
      expect(result.status, result.output).toBe(0);

      const roleKeysOf = async (userId: bigint) =>
        (
          await prisma.userRole.findMany({
            where: { userId },
            select: {
              organizationId: true,
              grantedByUserId: true,
              role: { select: { key: true, organizationId: true } },
            },
          })
        ).map((r) => ({
          key: r.role.key,
          system: r.role.organizationId === null,
          organizationId: r.organizationId,
          grantedByUserId: r.grantedByUserId,
        }));
      expect(await roleKeysOf(both.id)).toEqual([
        {
          key: 'organization_admin',
          system: true,
          organizationId,
          grantedByUserId: granter.id,
        },
      ]);
      expect(await roleKeysOf(reviewer.id)).toEqual([
        { key: 'quarantine_reviewer', system: true, organizationId, grantedByUserId: null },
      ]);
      expect(
        await prisma.role.count({
          where: { organizationId: null, key: { in: Object.keys(RETIRED_ROLE_KEYS) } },
        }),
      ).toBe(0);
      expect(
        await prisma.rolePermission.count({
          where: { roleId: { in: [tenantAdmin.id, securityAdmin.id, helpdesk.id] } },
        }),
      ).toBe(0);
    } finally {
      await prisma.user.deleteMany({ where: { organizationId } });
      await prisma.organization.deleteMany({ where: { id: organizationId } });
      await prisma.organizationPlan.deleteMany({ where: { id: plan.id } });
    }
  });

  it('seeds the catalog, including the platform organization, with --catalog-only --allow-production', () => {
    const result = seed(['--catalog-only', '--allow-production'], {
      APP_ENV: 'production',
      NODE_ENV: 'production',
    });
    expect(result.status, result.output).toBe(0);
    expect(result.output).not.toContain('demo data seeded');
  });

  it('refuses to seed demo data in production', () => {
    const result = seed([], { APP_ENV: 'production' });
    expect(result.status).toBe(1);
    expect(result.output).toContain('refusing to seed');
  });
});
