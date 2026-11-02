/**
 * Database fixtures for the API integration suites (WP3, reused by WP4/WP5). Every name is
 * unique per call, so suites can run against a shared, seeded database. `cleanup()` deletes what
 * the fixtures created (and what tests registered) in foreign-key-safe order; it never touches
 * the seeded platform organization itself, and `audit_logs` rows stay (append-only by policy).
 */
import { randomBytes, randomUUID } from 'node:crypto';
import {
  type FeatureKey,
  type OrganizationKind,
  PLANS,
  PLATFORM_ORGANIZATION_SLUG,
  type UserStatus,
} from '@email-gateway/database';
import { PasswordHasher } from '../../src/crypto/password-hasher';
import { SecretBox } from '../../src/crypto/secret-box';
import { generateTotpSecret, totpCode, totpStep } from '../../src/crypto/totp';
import type { IntegrationApp } from './app';

export interface FixtureOrganization {
  id: bigint;
  publicId: string;
  slug: string;
  name: string;
  kind: OrganizationKind;
  planCode: string;
}

export interface FixtureUser {
  id: bigint;
  publicId: string;
  email: string;
  displayName: string;
  /** The plain password (fixtures only). */
  password: string;
  organization: FixtureOrganization;
  roles: string[];
  /** Base32 TOTP secret when created with `mfa: true`. */
  totpSecret?: string;
}

export interface CreateOrganizationOptions {
  planCode?: string;
  kind?: OrganizationKind;
  /** Overrides of the plan's feature flags. */
  features?: Partial<Record<FeatureKey, boolean>>;
  mfaRequired?: boolean;
  status?: 'active' | 'suspended';
}

export interface CreateUserOptions {
  /** System role keys, or custom role keys of the organization. */
  roles: string[];
  password?: string;
  mfa?: boolean;
  status?: UserStatus;
  email?: string;
  displayName?: string;
  emailVerified?: boolean;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** A unique, lower-case suffix for names, slugs and emails. */
export function uniqueSuffix(): string {
  return `${Date.now().toString(36)}${randomBytes(3).toString('hex')}`;
}

/** A password that satisfies the policy and is unique per call. */
export function strongPassword(): string {
  return `Fx-${randomBytes(12).toString('base64url')}-9q`;
}

export class Fixtures {
  private readonly organizations = new Set<bigint>();
  private readonly platformUsers = new Set<bigint>();
  private readonly emails = new Set<string>();
  private readonly cleanups: Array<() => Promise<unknown>> = [];
  private readonly lastStep = new Map<string, number>();
  private platform: FixtureOrganization | undefined;

  constructor(private readonly ctx: IntegrationApp) {}

  private get prisma() {
    return this.ctx.prisma;
  }

  async createOrganization(options: CreateOrganizationOptions = {}): Promise<FixtureOrganization> {
    const planCode = options.planCode ?? 'standard';
    const planDef = PLANS.find((p) => p.code === planCode);
    if (!planDef) throw new Error(`Unknown plan ${planCode}`);
    const plan = await this.prisma.organizationPlan.findUniqueOrThrow({
      where: { code: planCode },
      select: { id: true },
    });
    const suffix = uniqueSuffix();
    const slug = `it-${suffix}`;
    const kind = options.kind ?? 'customer';
    const org = await this.prisma.organization.create({
      data: {
        slug,
        name: `Integration ${suffix}`,
        kind,
        status: options.status ?? 'active',
        planId: plan.id,
        dataRegion: 'ap-south-1',
      },
      select: { id: true, publicId: true, slug: true, name: true },
    });
    this.organizations.add(org.id);
    await this.prisma.organizationSetting.create({
      data: { organizationId: org.id, mfaRequired: options.mfaRequired ?? false },
    });
    await this.prisma.organizationLimit.createMany({
      data: Object.entries(planDef.limits).map(([limitKey, value]) => ({
        organizationId: org.id,
        limitKey,
        limitValue: BigInt(value),
      })),
    });
    await this.prisma.organizationFeature.createMany({
      data: Object.entries({ ...planDef.features, ...options.features }).map(
        ([featureKey, enabled]) => ({ organizationId: org.id, featureKey, enabled: !!enabled }),
      ),
    });
    await this.prisma.organizationDeployment.create({
      data: {
        organizationId: org.id,
        deploymentMode: 'saas',
        region: 'ap-south-1',
        environment: this.ctx.config.APP_ENV,
        status: 'active',
      },
    });
    return { ...org, kind, planCode };
  }

  /** The seeded platform organization (never deleted by `cleanup`). */
  async platformOrg(): Promise<FixtureOrganization> {
    if (this.platform) return this.platform;
    const org = await this.prisma.organization.findUniqueOrThrow({
      where: { slug: PLATFORM_ORGANIZATION_SLUG },
      select: {
        id: true,
        publicId: true,
        slug: true,
        name: true,
        plan: { select: { code: true } },
      },
    });
    this.platform = {
      id: org.id,
      publicId: org.publicId,
      slug: org.slug,
      name: org.name,
      kind: 'platform',
      planCode: org.plan.code,
    };
    return this.platform;
  }

  async createUser(org: FixtureOrganization, options: CreateUserOptions): Promise<FixtureUser> {
    const suffix = uniqueSuffix();
    const email = (options.email ?? `user-${suffix}@example.test`).toLowerCase();
    const status = options.status ?? 'active';
    const password = options.password ?? strongPassword();
    const passwordHash =
      status === 'invited' ? null : await this.ctx.get(PasswordHasher).hash(password);
    const user = await this.prisma.user.create({
      data: {
        organizationId: org.id,
        email,
        displayName: options.displayName ?? `User ${suffix}`,
        status,
        passwordHash,
        emailVerifiedAt:
          options.emailVerified === false || status === 'invited' ? null : new Date(),
      },
      select: { id: true, publicId: true, displayName: true },
    });
    this.emails.add(email);
    if (org.kind === 'platform') this.platformUsers.add(user.id);

    for (const key of options.roles) {
      const role = await this.prisma.role.findFirst({
        where: { key, OR: [{ organizationId: null }, { organizationId: org.id }] },
        select: { id: true },
      });
      if (!role) throw new Error(`Unknown role ${key}`);
      await this.prisma.userRole.create({
        data: { userId: user.id, roleId: role.id, organizationId: org.id },
      });
    }

    let totpSecret: string | undefined;
    if (options.mfa) {
      totpSecret = generateTotpSecret();
      await this.prisma.user.update({
        where: { id: user.id },
        data: {
          mfaEnabled: true,
          mfaSecretCiphertext: this.ctx.get(SecretBox).encrypt(totpSecret, `mfa:user:${user.id}`),
        },
      });
    }
    return {
      ...user,
      email,
      password,
      organization: org,
      roles: options.roles,
      ...(totpSecret && { totpSecret }),
    };
  }

  async createPlatformUser(
    roles: string[],
    options: Omit<CreateUserOptions, 'roles'> = { mfa: true },
  ): Promise<FixtureUser> {
    return this.createUser(await this.platformOrg(), { mfa: true, ...options, roles });
  }

  /**
   * A TOTP code for the user that the server has not seen yet. Codes are accepted for the
   * current step ± 1 and at most once per step (replay protection), so consecutive calls use
   * increasing steps and wait for the next 30-second step only when all three are used.
   */
  async totpNow(user: FixtureUser): Promise<string> {
    if (!user.totpSecret) throw new Error('The user has no TOTP secret');
    return this.totpFor(user.totpSecret);
  }

  /** As `totpNow`, for a secret obtained from the API (enrollment). */
  async totpFor(secret: string): Promise<string> {
    for (;;) {
      const current = totpStep(Date.now());
      const step = Math.max(current - 1, (this.lastStep.get(secret) ?? -1) + 1);
      if (step <= current + 1) {
        this.lastStep.set(secret, step);
        return totpCode(secret, step);
      }
      await sleep(1_000);
    }
  }

  /** Tracks an organization created through the API so `cleanup` removes it. */
  trackOrganization(id: bigint): void {
    this.organizations.add(id);
  }

  /** Tracks a platform-organization user created through the API. */
  trackPlatformUser(id: bigint): void {
    this.platformUsers.add(id);
  }

  /** Runs before the built-in deletes (e.g. domains or policies a suite inserted). */
  registerCleanup(fn: () => Promise<unknown>): void {
    this.cleanups.push(fn);
  }

  async cleanup(): Promise<void> {
    for (const fn of this.cleanups.reverse()) await fn();
    this.cleanups.length = 0;
    const orgs = [...this.organizations];
    const users = [...this.platformUsers];
    const emails = [...this.emails];
    const byOrgOrUser = { OR: [{ organizationId: { in: orgs } }, { userId: { in: users } }] };
    const p = this.prisma;
    await p.loginAuditLog.deleteMany({
      where: { OR: [...byOrgOrUser.OR, { emailAttempted: { in: emails } }] },
    });
    await p.userToken.deleteMany({ where: byOrgOrUser });
    await p.userMfaRecoveryCode.deleteMany({ where: byOrgOrUser });
    await p.userSession.deleteMany({ where: byOrgOrUser });
    await p.apiKey.deleteMany({
      where: { OR: [{ organizationId: { in: orgs } }, { createdByUserId: { in: users } }] },
    });
    await p.userRole.deleteMany({ where: byOrgOrUser });
    await p.role.deleteMany({ where: { organizationId: { in: orgs } } });
    await p.user.deleteMany({
      where: { OR: [{ organizationId: { in: orgs } }, { id: { in: users } }] },
    });
    await p.organizationLimit.deleteMany({ where: { organizationId: { in: orgs } } });
    await p.organizationFeature.deleteMany({ where: { organizationId: { in: orgs } } });
    await p.organizationSetting.deleteMany({ where: { organizationId: { in: orgs } } });
    await p.organizationDeployment.deleteMany({ where: { organizationId: { in: orgs } } });
    await p.archiveLegalHold.deleteMany({ where: { organizationId: { in: orgs } } });
    await p.organization.deleteMany({
      where: { id: { in: orgs }, slug: { not: PLATFORM_ORGANIZATION_SLUG } },
    });
    this.organizations.clear();
    this.platformUsers.clear();
    this.emails.clear();
  }
}

export function createFixtures(ctx: IntegrationApp): Fixtures {
  return new Fixtures(ctx);
}

/** A random UUID that matches no row (404 paths). */
export const unknownId = (): string => randomUUID();
