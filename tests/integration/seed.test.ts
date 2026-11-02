import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { PrismaClient } from '@email-gateway/database';
import { afterAll, describe, expect, it } from 'vitest';
import { stack } from './support/env';

/**
 * db:seed (D7) against the dev schema, with the DML account: running it twice leaves the same
 * row counts. The seeded rows are dev data and are deliberately left in place.
 */
const SEED_CLI = fileURLToPath(
  new URL('../../packages/database/dist/seed/cli.js', import.meta.url),
);
const prisma = new PrismaClient({ datasourceUrl: stack.databaseUrl() });

afterAll(async () => {
  await prisma.$disconnect();
});

function seed(args: string[] = [], env: Record<string, string> = {}) {
  const result = spawnSync(process.execPath, [SEED_CLI, ...args], {
    env: { ...process.env, LOG_LEVEL: 'warn', ...env },
    encoding: 'utf8',
    timeout: 60_000,
  });
  return { status: result.status, output: `${result.stdout}${result.stderr}` };
}

async function counts() {
  const demo = await prisma.organization.findUnique({ where: { slug: 'demo' } });
  const organizationId = demo?.id ?? 0n;
  return {
    permissions: await prisma.permission.count(),
    systemRoles: await prisma.role.count({ where: { organizationId: null, isSystem: true } }),
    rolePermissions: await prisma.rolePermission.count(),
    plans: await prisma.organizationPlan.count(),
    systemSettings: await prisma.systemSetting.count(),
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
      systemRoles: 8,
      plans: expect.any(Number) as unknown,
      demoOrganizations: 2,
      demoUsers: 2,
      demoUserRoles: 2,
      demoDeployments: 1,
      demoDomains: 1,
      demoPolicies: 1,
      demoPolicyVersions: 1,
    });
    expect(afterFirst.permissions).toBeGreaterThanOrEqual(26);
    expect(afterFirst.plans).toBeGreaterThanOrEqual(4);

    // The demo domain is the verified owner of its name (tenant resolution key).
    const domain = await prisma.domain.findUnique({
      where: { verifiedName: stack.relayDomain() },
    });
    expect(domain?.status).toBe('verified');
  });

  it('refuses to seed demo data in production', () => {
    const result = seed([], { APP_ENV: 'production' });
    expect(result.status).toBe(1);
    expect(result.output).toContain('refusing to seed');
  });
});
