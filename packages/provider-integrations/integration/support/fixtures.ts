import { randomUUID } from 'node:crypto';
import { PrismaClient } from '@email-gateway/database';

/** Values from the repository .env (loaded by vitest.integration.config.ts). Never printed. */
export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set (see .env)`);
  return value;
}

/**
 * Synthetic `it-prov-<suffix>-*` organizations on the MySQL writer (never an existing
 * organization, §1.4.6) and cleanup of every row the tests create.
 */
export class Fixtures {
  readonly prisma: PrismaClient;
  readonly suffix = randomUUID().slice(0, 8);
  readonly organizationIds: bigint[] = [];
  private planId: bigint | undefined;

  constructor() {
    const url = requireEnv('DATABASE_URL');
    this.prisma = new PrismaClient({ datasourceUrl: url });
  }

  name(label: string): string {
    return `it-prov-${this.suffix}-${label}.test`;
  }

  async organization(label: string): Promise<bigint> {
    if (this.planId === undefined) {
      const plan = await this.prisma.organizationPlan.create({
        data: {
          code: `it-prov-${this.suffix}`,
          name: 'provider-integrations integration',
          defaultLimits: {},
          defaultFeatures: {},
        },
      });
      this.planId = plan.id;
    }
    const org = await this.prisma.organization.create({
      data: {
        slug: `it-prov-${this.suffix}-${label}`,
        name: `Provider ${label}`,
        planId: this.planId,
        dataRegion: 'ap-south-1',
      },
    });
    this.organizationIds.push(org.id);
    return org.id;
  }

  async domain(organizationId: bigint, name: string) {
    return this.prisma.domain.create({
      data: { organizationId, name, status: 'active', outboundEnabled: true },
    });
  }

  async cleanup(): Promise<void> {
    const ids = this.organizationIds;
    try {
      if (ids.length > 0) {
        const where = { organizationId: { in: ids } };
        await this.prisma.providerConnectionDomain.deleteMany({ where });
        await this.prisma.providerConnectionGrant.deleteMany({ where });
        await this.prisma.providerConnection.deleteMany({ where });
        await this.prisma.domain.deleteMany({ where });
        await this.prisma.organization.deleteMany({ where: { id: { in: ids } } });
      }
      if (this.planId !== undefined)
        await this.prisma.organizationPlan.deleteMany({ where: { id: this.planId } });
    } finally {
      await this.prisma.$disconnect();
    }
  }
}
