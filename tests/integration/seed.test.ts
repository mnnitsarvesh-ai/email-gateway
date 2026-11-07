import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  DEMO,
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
 * the catalog (45 permissions since step 4.4, the 8 system roles, the platform organization, the step 2.3
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
      permissions: 45,
      systemRoles: 8,
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
      demoPolicyVersions: 1,
      platformUsers: 1,
      platformUserRoles: 1,
      platformSettings: 1,
      platformLimits: 11,
      platformFeatures: 11,
      platformDeployments: 1,
    });
    expect(afterFirst.plans).toBeGreaterThanOrEqual(4);

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

  it('seeds exactly the 45 permissions and the 8 system roles of D8, with their permissions', async () => {
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
    expect(holders('delivery:read')).toEqual([...SYSTEM_ROLE_KEYS].sort());
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
