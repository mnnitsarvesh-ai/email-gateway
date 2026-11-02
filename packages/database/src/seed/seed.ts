import { createHash } from 'node:crypto';
import { type Prisma, type PrismaClient } from '@prisma/client';
import {
  DEMO,
  PERMISSIONS,
  PLANS,
  type PlanDef,
  SYSTEM_ROLES,
  SYSTEM_SETTINGS,
  permissionCategory,
} from './catalog';

/**
 * Idempotent seeding (D7). Everything is an upsert on a natural unique key, or a find-then-
 * create/update inside the same transaction where the key cannot be expressed as a unique
 * constraint (system roles have organization_id NULL, and NULLs never collide in MySQL).
 * Running it twice leaves identical row counts.
 */

type Tx = Prisma.TransactionClient;

const TX_OPTIONS = { timeout: 60_000, maxWait: 10_000 } as const;

export interface CatalogSummary {
  permissions: number;
  roles: number;
  rolePermissions: number;
  plans: number;
  systemSettings: number;
}

export async function seedCatalog(prisma: PrismaClient): Promise<CatalogSummary> {
  return prisma.$transaction(async (tx) => {
    for (const p of PERMISSIONS) {
      const data = { description: p.description, category: permissionCategory(p.key) };
      await tx.permission.upsert({
        where: { key: p.key },
        create: { key: p.key, ...data },
        update: data,
      });
    }
    const permissionIds = new Map(
      (await tx.permission.findMany({ select: { id: true, key: true } })).map((p) => [p.key, p.id]),
    );

    let rolePermissions = 0;
    for (const role of SYSTEM_ROLES) {
      const data = { name: role.name, description: role.description, isSystem: true };
      const existing = await tx.role.findFirst({
        where: { organizationId: null, key: role.key },
        select: { id: true },
      });
      const { id: roleId } = existing
        ? await tx.role.update({ where: { id: existing.id }, data, select: { id: true } })
        : await tx.role.create({ data: { key: role.key, ...data }, select: { id: true } });

      const wanted = role.permissions.map((key) => {
        const id = permissionIds.get(key);
        if (id === undefined)
          throw new Error(`Role ${role.key} references unknown permission ${key}`);
        return id;
      });
      // System roles are code-owned: the mapping is synchronised exactly.
      await tx.rolePermission.deleteMany({ where: { roleId, permissionId: { notIn: wanted } } });
      await tx.rolePermission.createMany({
        data: wanted.map((permissionId) => ({ roleId, permissionId })),
        skipDuplicates: true,
      });
      rolePermissions += wanted.length;
    }

    for (const plan of PLANS) {
      const data = {
        name: plan.name,
        description: plan.description,
        isActive: true,
        defaultLimits: plan.limits,
        defaultFeatures: plan.features,
      };
      await tx.organizationPlan.upsert({
        where: { code: plan.code },
        create: { code: plan.code, ...data },
        update: data,
      });
    }

    for (const setting of SYSTEM_SETTINGS) {
      // Create only: never overwrite a value an operator has changed.
      await tx.systemSetting.upsert({
        where: { key: setting.key },
        create: {
          key: setting.key,
          value: setting.value as Prisma.InputJsonValue,
          description: setting.description,
        },
        update: {},
      });
    }

    return {
      permissions: PERMISSIONS.length,
      roles: SYSTEM_ROLES.length,
      rolePermissions,
      plans: PLANS.length,
      systemSettings: SYSTEM_SETTINGS.length,
    };
  }, TX_OPTIONS);
}

async function planByCode(tx: Tx, code: string): Promise<{ id: bigint; def: PlanDef }> {
  const def = PLANS.find((p) => p.code === code);
  const row = await tx.organizationPlan.findUnique({ where: { code }, select: { id: true } });
  if (!def || !row) throw new Error(`Plan ${code} is missing: seed the catalog first`);
  return { id: row.id, def };
}

/** Stable JSON (sorted keys) so the definition hash does not depend on key order. */
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a < b ? -1 : a > b ? 1 : 0,
    );
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export interface DemoSummary {
  platformOrganizationId: bigint;
  organizationId: bigint;
  domainId: bigint;
  userIds: bigint[];
  policyId: bigint;
}

export async function seedDemo(
  prisma: PrismaClient,
  options: { environment: string },
): Promise<DemoSummary> {
  return prisma.$transaction(async (tx) => {
    const platformPlan = await planByCode(tx, DEMO.platformOrganization.plan);
    const platform = await tx.organization.upsert({
      where: { slug: DEMO.platformOrganization.slug },
      create: {
        slug: DEMO.platformOrganization.slug,
        name: DEMO.platformOrganization.name,
        kind: 'platform',
        planId: platformPlan.id,
        dataRegion: DEMO.dataRegion,
      },
      update: {},
      select: { id: true, kind: true },
    });
    if (platform.kind !== 'platform') {
      throw new Error(
        `Organization slug ${DEMO.platformOrganization.slug} exists but is not kind=platform`,
      );
    }

    const plan = await planByCode(tx, DEMO.organization.plan);
    const org = await tx.organization.upsert({
      where: { slug: DEMO.organization.slug },
      create: {
        slug: DEMO.organization.slug,
        name: DEMO.organization.name,
        kind: 'customer',
        planId: plan.id,
        dataRegion: DEMO.dataRegion,
      },
      update: {},
      select: { id: true },
    });
    const organizationId = org.id;

    await tx.organizationSetting.upsert({
      where: { organizationId },
      create: {
        organizationId,
        timezone: 'Asia/Kolkata',
        locale: 'en',
        quarantineRetentionDays: plan.def.limits.quarantine_retention_days,
        notificationEmail: DEMO.users[0]!.email,
      },
      update: {},
    });
    for (const [limitKey, value] of Object.entries(plan.def.limits)) {
      await tx.organizationLimit.upsert({
        where: { organizationId_limitKey: { organizationId, limitKey } },
        create: { organizationId, limitKey, limitValue: BigInt(value), source: 'plan' },
        update: {},
      });
    }
    for (const [featureKey, enabled] of Object.entries(plan.def.features)) {
      await tx.organizationFeature.upsert({
        where: { organizationId_featureKey: { organizationId, featureKey } },
        create: { organizationId, featureKey, enabled, source: 'plan' },
        update: {},
      });
    }
    const deployment = await tx.organizationDeployment.findFirst({
      where: { organizationId, deploymentMode: 'saas' },
      select: { id: true },
    });
    if (!deployment) {
      await tx.organizationDeployment.create({
        data: {
          organizationId,
          deploymentMode: 'saas',
          region: DEMO.dataRegion,
          environment: options.environment,
          status: 'active',
          provisionedAt: new Date(),
        },
      });
    }

    // Verified ownership is globally unique (domains.verified_name); a pending claim is not.
    const owner = await tx.domain.findUnique({
      where: { verifiedName: DEMO.domain },
      select: { organizationId: true },
    });
    if (owner && owner.organizationId !== organizationId) {
      throw new Error(`Domain ${DEMO.domain} already belongs to another organization`);
    }
    const existingDomain = await tx.domain.findUnique({
      where: { organizationId_name: { organizationId, name: DEMO.domain } },
      select: { id: true, organizationId: true },
    });
    const domain =
      existingDomain ??
      (await tx.domain.create({
        data: {
          organizationId,
          name: DEMO.domain,
          status: 'verified',
          inboundEnabled: true,
          verifiedAt: new Date(),
        },
        select: { id: true, organizationId: true },
      }));
    const domainId = domain.id;
    await tx.domainSetting.upsert({
      where: { domainId },
      create: {
        organizationId,
        domainId,
        rejectUnknownRecipients: false,
        recipientValidation: 'none',
      },
      update: {},
    });
    const mailServer = await tx.domainMailServer.findFirst({
      where: { domainId, role: 'inbound_destination' },
      select: { id: true },
    });
    if (!mailServer) {
      await tx.domainMailServer.create({
        data: {
          organizationId,
          domainId,
          role: 'inbound_destination',
          host: DEMO.inboundMailServer.host,
          port: DEMO.inboundMailServer.port,
          priority: 10,
          tlsMode: 'opportunistic',
        },
      });
    }

    const userIds: bigint[] = [];
    for (const user of DEMO.users) {
      const role = await tx.role.findFirst({
        where: { organizationId: null, key: user.role },
        select: { id: true },
      });
      if (!role) throw new Error(`System role ${user.role} is missing: seed the catalog first`);
      // Invited, no password: passwords and MFA arrive with step 1.3.
      const row = await tx.user.upsert({
        where: { organizationId_email: { organizationId, email: user.email } },
        create: {
          organizationId,
          email: user.email,
          displayName: user.displayName,
          status: 'invited',
        },
        update: {},
        select: { id: true },
      });
      await tx.userRole.upsert({
        where: { userId_roleId: { userId: row.id, roleId: role.id } },
        create: { userId: row.id, roleId: role.id, organizationId },
        update: {},
      });
      userIds.push(row.id);
    }

    const policy = await tx.emailPolicy.upsert({
      where: { organizationId_name: { organizationId, name: DEMO.policy.name } },
      create: {
        organizationId,
        name: DEMO.policy.name,
        description: DEMO.policy.description,
        direction: 'inbound',
        priority: DEMO.policy.priority,
        status: 'active',
        createdByUserId: userIds[0] ?? null,
      },
      update: {},
      select: { id: true, activeVersionId: true },
    });
    const definition = {
      conditions: [{ group: 0, ...DEMO.policy.condition, negate: false }],
      actions: [DEMO.policy.action],
    };
    const version = await tx.policyVersion.upsert({
      where: { policyId_version: { policyId: policy.id, version: 1 } },
      create: {
        organizationId,
        policyId: policy.id,
        version: 1,
        status: 'published',
        definition,
        definitionSha256: createHash('sha256').update(canonicalJson(definition)).digest('hex'),
        changeNote: 'Seeded sample policy',
        publishedAt: new Date(),
        publishedByUserId: userIds[0] ?? null,
      },
      update: {},
      select: { id: true },
    });
    await tx.policyCondition.upsert({
      where: { policyVersionId_seq: { policyVersionId: version.id, seq: 1 } },
      create: {
        organizationId,
        policyVersionId: version.id,
        seq: 1,
        groupSeq: 0,
        field: DEMO.policy.condition.field,
        operator: DEMO.policy.condition.operator,
        value: DEMO.policy.condition.value,
      },
      update: {},
    });
    await tx.policyAction.upsert({
      where: { policyVersionId_seq: { policyVersionId: version.id, seq: 1 } },
      create: {
        organizationId,
        policyVersionId: version.id,
        seq: 1,
        action: DEMO.policy.action.action,
        params: DEMO.policy.action.params,
      },
      update: {},
    });
    if (policy.activeVersionId === null) {
      await tx.emailPolicy.update({
        where: { id: policy.id },
        data: { activeVersionId: version.id },
      });
    }

    return {
      platformOrganizationId: platform.id,
      organizationId,
      domainId,
      userIds,
      policyId: policy.id,
    };
  }, TX_OPTIONS);
}
