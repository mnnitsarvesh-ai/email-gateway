import { createHash } from 'node:crypto';
import { type DomainStatus, Prisma, type PrismaClient } from '@prisma/client';
import {
  DEMO,
  MAIL_DESTINATION_PRESETS,
  PERMISSIONS,
  PLANS,
  PLATFORM_ORGANIZATION,
  type PlanDef,
  RETIRED_ROLE_KEYS,
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

/** Statuses the api's domain-check job keeps checking (step 2.1 D11); never NULL-scheduled. */
const CHECKED_DOMAIN_STATUSES: ReadonlySet<DomainStatus> = new Set([
  'pending_verification',
  'verified',
  'active',
  'suspended',
]);

export interface CatalogOptions {
  /** `organization_deployments.environment` of the platform org; default APP_ENV or `local`. */
  environment?: string;
}

export interface CatalogSummary {
  permissions: number;
  roles: number;
  rolePermissions: number;
  /** Retired step-1.1 system roles deleted by this run (0 once migrated). */
  retiredRolesRemoved: number;
  /** User-role assignments moved from a retired role to its replacement by this run. */
  userRolesRemapped: number;
  plans: number;
  systemSettings: number;
  /** Destination provider presets upserted (step 2.3 R2). */
  destinationPresets: number;
  platformOrganizationId: bigint;
}

/**
 * The catalog: permissions, the 8 system roles (D8) and the migration of retired role keys,
 * plans, system settings and the platform organization (D10). Safe in every environment; one
 * transaction.
 */
export async function seedCatalog(
  prisma: PrismaClient,
  options: CatalogOptions = {},
): Promise<CatalogSummary> {
  const environment = options.environment ?? process.env.APP_ENV ?? 'local';
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
    const roleIds = new Map<string, bigint>();
    for (const role of SYSTEM_ROLES) {
      const data = { name: role.name, description: role.description, isSystem: true };
      const existing = await tx.role.findFirst({
        where: { organizationId: null, key: role.key },
        select: { id: true },
      });
      const { id: roleId } = existing
        ? await tx.role.update({ where: { id: existing.id }, data, select: { id: true } })
        : await tx.role.create({ data: { key: role.key, ...data }, select: { id: true } });
      roleIds.set(role.key, roleId);

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

    const retired = await migrateRetiredRoles(tx, roleIds);

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

    // Destination provider presets (step 2.3 R2): code-owned platform configuration, so every
    // run synchronises them exactly (an operator disables a preset in code, not in the table).
    for (const preset of MAIL_DESTINATION_PRESETS) {
      const data = {
        displayName: preset.displayName,
        hostPatterns: [...preset.hostPatterns],
        hostHint: preset.hostHint,
        defaultServers:
          preset.defaultServers === null
            ? Prisma.DbNull
            : preset.defaultServers.map((server) => ({ ...server })),
        port: preset.port,
        tlsMode: preset.tlsMode,
        tlsVerifyNames: preset.tlsVerifyNames,
        maxServers: preset.maxServers,
        documentationUrl: preset.documentationUrl,
        enabled: true,
      };
      await tx.mailDestinationPreset.upsert({
        where: { provider: preset.provider },
        create: { provider: preset.provider, ...data },
        update: data,
      });
    }

    const platformOrganizationId = await ensurePlatformOrganization(tx, environment);

    return {
      permissions: PERMISSIONS.length,
      roles: SYSTEM_ROLES.length,
      rolePermissions,
      retiredRolesRemoved: retired.rolesRemoved,
      userRolesRemapped: retired.userRolesRemapped,
      plans: PLANS.length,
      systemSettings: SYSTEM_SETTINGS.length,
      destinationPresets: MAIL_DESTINATION_PRESETS.length,
      platformOrganizationId,
    };
  }, TX_OPTIONS);
}

/**
 * Moves the assignments of every retired step-1.1 system role (RETIRED_ROLE_KEYS) to its
 * replacement, keeping `organization_id` and `granted_by_user_id` and skipping users who already
 * hold the replacement, then deletes the retired role's assignments, permissions and row. Only
 * system roles (organization_id NULL) are touched; a custom role with the same key is not.
 */
async function migrateRetiredRoles(
  tx: Tx,
  roleIds: ReadonlyMap<string, bigint>,
): Promise<{ rolesRemoved: number; userRolesRemapped: number }> {
  let rolesRemoved = 0;
  let userRolesRemapped = 0;
  for (const [retiredKey, targetKey] of Object.entries(RETIRED_ROLE_KEYS)) {
    const retired = await tx.role.findFirst({
      where: { organizationId: null, key: retiredKey },
      select: { id: true },
    });
    if (!retired) continue;
    const targetId = roleIds.get(targetKey);
    if (targetId === undefined) {
      throw new Error(`Retired role ${retiredKey} maps to unknown role ${targetKey}`);
    }
    const assignments = await tx.userRole.findMany({
      where: { roleId: retired.id },
      select: { userId: true, organizationId: true, grantedByUserId: true },
    });
    if (assignments.length > 0) {
      const { count } = await tx.userRole.createMany({
        data: assignments.map((a) => ({ ...a, roleId: targetId })),
        skipDuplicates: true,
      });
      userRolesRemapped += count;
    }
    await tx.userRole.deleteMany({ where: { roleId: retired.id } });
    await tx.rolePermission.deleteMany({ where: { roleId: retired.id } });
    await tx.role.delete({ where: { id: retired.id } });
    rolesRemoved += 1;
  }
  return { rolesRemoved, userRolesRemapped };
}

/**
 * The platform organization (D10): created if missing, never re-pointed. Its settings always
 * require MFA (D7, D12: it cannot be turned off for the platform org).
 */
async function ensurePlatformOrganization(tx: Tx, environment: string): Promise<bigint> {
  const def = PLATFORM_ORGANIZATION;
  const plan = await planByCode(tx, def.plan);
  const platform = await tx.organization.upsert({
    where: { slug: def.slug },
    create: {
      slug: def.slug,
      name: def.name,
      kind: 'platform',
      status: 'active',
      planId: plan.id,
      deploymentMode: 'saas',
      dataRegion: def.dataRegion,
    },
    update: {},
    select: { id: true, kind: true },
  });
  if (platform.kind !== 'platform') {
    throw new Error(`Organization slug ${def.slug} exists but is not kind=platform`);
  }
  const organizationId = platform.id;
  await tx.organizationSetting.upsert({
    where: { organizationId },
    create: {
      organizationId,
      quarantineRetentionDays: plan.def.limits.quarantine_retention_days,
      mfaRequired: def.mfaRequired,
    },
    update: { mfaRequired: def.mfaRequired },
  });
  await materializePlan(tx, organizationId, plan.def);
  await ensureSaasDeployment(tx, organizationId, def.dataRegion, environment);
  return organizationId;
}

/**
 * Materializes a plan's limits and features (`source = plan`): missing rows are created, rows
 * that still follow the plan are updated to its current values, and overrides are kept.
 */
async function materializePlan(tx: Tx, organizationId: bigint, plan: PlanDef): Promise<void> {
  const limits = Object.entries(plan.limits);
  await tx.organizationLimit.createMany({
    data: limits.map(([limitKey, value]) => ({
      organizationId,
      limitKey,
      limitValue: BigInt(value),
      source: 'plan' as const,
    })),
    skipDuplicates: true,
  });
  for (const [limitKey, value] of limits) {
    await tx.organizationLimit.updateMany({
      where: { organizationId, limitKey, source: 'plan', limitValue: { not: BigInt(value) } },
      data: { limitValue: BigInt(value) },
    });
  }
  const features = Object.entries(plan.features);
  await tx.organizationFeature.createMany({
    data: features.map(([featureKey, enabled]) => ({
      organizationId,
      featureKey,
      enabled,
      source: 'plan' as const,
    })),
    skipDuplicates: true,
  });
  for (const [featureKey, enabled] of features) {
    await tx.organizationFeature.updateMany({
      where: { organizationId, featureKey, source: 'plan', enabled: { not: enabled } },
      data: { enabled },
    });
  }
}

/** One active `saas` deployment row per organization, created if none exists. */
async function ensureSaasDeployment(
  tx: Tx,
  organizationId: bigint,
  region: string,
  environment: string,
): Promise<void> {
  const deployment = await tx.organizationDeployment.findFirst({
    where: { organizationId, deploymentMode: 'saas' },
    select: { id: true },
  });
  if (!deployment) {
    await tx.organizationDeployment.create({
      data: {
        organizationId,
        deploymentMode: 'saas',
        region,
        environment,
        status: 'active',
        provisionedAt: new Date(),
      },
    });
  }
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
    const platform = await tx.organization.findUnique({
      where: { slug: PLATFORM_ORGANIZATION.slug },
      select: { id: true },
    });
    if (!platform) {
      throw new Error(`Platform organization is missing: seed the catalog first`);
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
        mfaRequired: false,
      },
      update: {},
    });
    await materializePlan(tx, organizationId, plan.def);
    await ensureSaasDeployment(tx, organizationId, DEMO.dataRegion, options.environment);

    // Verified ownership is globally unique (domains.verified_name); a pending claim is not.
    const owner = await tx.domain.findUnique({
      where: { verifiedName: DEMO.domain },
      select: { organizationId: true },
    });
    if (owner && owner.organizationId !== organizationId) {
      throw new Error(`Domain ${DEMO.domain} already belongs to another organization`);
    }
    // The organization's live (non-deleted) row for the name; a deleted demo row stays history.
    const existingDomain = await tx.domain.findUnique({
      where: { organizationId_liveName: { organizationId, liveName: DEMO.domain } },
      select: { id: true, status: true, verifiedAt: true, activatedAt: true, nextCheckAt: true },
    });
    const now = new Date();
    let domainId: bigint;
    if (!existingDomain) {
      // Step 2.1: the demo domain is active (verified + activated), so it resolves on the mail path.
      const created = await tx.domain.create({
        data: {
          organizationId,
          name: DEMO.domain,
          status: 'active',
          inboundEnabled: true,
          verifiedAt: now,
          activatedAt: now,
          statusChangedAt: now,
          // Due at once: the api's domain-check job materializes its ownership record, DKIM key
          // and DNS record rows (step 2.1 D12), then rechecks it on the D11 schedule.
          nextCheckAt: now,
        },
        select: { id: true },
      });
      domainId = created.id;
    } else {
      domainId = existingDomain.id;
      // A demo row seeded before step 2.1 is `verified`: move only that row to `active`, once.
      // Any other status (suspended or failed by a developer) is left alone.
      if (existingDomain.status === 'verified') {
        await tx.domain.updateMany({
          where: { id: domainId, status: 'verified' },
          data: {
            status: 'active',
            activatedAt: existingDomain.activatedAt ?? now,
            verifiedAt: existingDomain.verifiedAt ?? now,
            statusChangedAt: now,
          },
        });
      }
      // A demo row seeded before step 2.1 was never scheduled: make it due (D11, D12). A row
      // the domain-check job already scheduled keeps its time; checks never stop for a checked
      // status, so a NULL here means "never scheduled".
      if (
        existingDomain.nextCheckAt === null &&
        CHECKED_DOMAIN_STATUSES.has(existingDomain.status)
      ) {
        await tx.domain.updateMany({
          where: { id: domainId, nextCheckAt: null },
          data: { nextCheckAt: now },
        });
      }
    }
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
          provider: DEMO.inboundMailServer.provider,
          priority: 10,
          tlsMode: 'opportunistic',
        },
      });
    }

    const userIds: bigint[] = [];
    let demoAdminId: bigint | null = null;
    for (const user of DEMO.users) {
      const userOrganizationId = user.organization === 'platform' ? platform.id : organizationId;
      const role = await tx.role.findFirst({
        where: { organizationId: null, key: user.role },
        select: { id: true },
      });
      if (!role) throw new Error(`System role ${user.role} is missing: seed the catalog first`);
      // Invited, no password: they activate through an invitation (step 1.3).
      const row = await tx.user.upsert({
        where: {
          organizationId_email: { organizationId: userOrganizationId, email: user.email },
        },
        create: {
          organizationId: userOrganizationId,
          email: user.email,
          displayName: user.displayName,
          status: 'invited',
        },
        update: {},
        select: { id: true },
      });
      await tx.userRole.upsert({
        where: { userId_roleId: { userId: row.id, roleId: role.id } },
        create: { userId: row.id, roleId: role.id, organizationId: userOrganizationId },
        update: {},
      });
      if (demoAdminId === null && user.organization === 'demo') demoAdminId = row.id;
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
        createdByUserId: demoAdminId,
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
        publishedByUserId: demoAdminId,
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
