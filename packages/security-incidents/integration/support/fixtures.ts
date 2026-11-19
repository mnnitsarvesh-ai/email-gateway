import { randomUUID } from 'node:crypto';
import { PrismaClient } from '@email-gateway/database';

/** Values from the repository's .env (loaded by vitest.integration.config.ts). Never printed. */
export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set (see .env)`);
  return value;
}

/**
 * Synthetic `it-ato-si-<run>-*` organizations, users and ATO account rows on the real MySQL writer,
 * and removal of every row the IncidentStore writes for them. Never touches pre-existing data.
 */
export class Fixtures {
  readonly prisma: PrismaClient = new PrismaClient({ datasourceUrl: requireEnv('DATABASE_URL') });
  readonly suffix = randomUUID().slice(0, 8);
  readonly organizationIds: bigint[] = [];
  private planId: bigint | undefined;

  async organization(label: string): Promise<bigint> {
    if (this.planId === undefined) {
      const plan = await this.prisma.organizationPlan.create({
        data: {
          code: `it-ato-si-${this.suffix}`,
          name: 'security-incidents integration',
          defaultLimits: {},
          defaultFeatures: {},
        },
      });
      this.planId = plan.id;
    }
    const org = await this.prisma.organization.create({
      data: {
        slug: `it-ato-si-${this.suffix}-${label}`,
        name: `Incidents ${label}`,
        planId: this.planId,
        dataRegion: 'ap-south-1',
      },
    });
    this.organizationIds.push(org.id);
    return org.id;
  }

  async user(organizationId: bigint, label: string, status: 'active' | 'disabled' = 'active') {
    return this.prisma.user.create({
      data: {
        organizationId,
        email: `${label}-${this.suffix}@it-si.example.test`,
        displayName: `IT ${label}`,
        status,
      },
      select: { id: true, publicId: true },
    });
  }

  /** An `ato_accounts` row (the subject of an ATO incident). */
  async account(organizationId: bigint, label: string) {
    const now = new Date();
    return this.prisma.atoAccount.create({
      data: {
        organizationId,
        kind: 'mailbox',
        subjectHash: randomUUID().replace(/-/g, '').padEnd(64, '0'),
        address: `${label}-${this.suffix}@it-si.example.test`,
        firstSeenAt: now,
        lastSeenAt: now,
      },
      select: { id: true, publicId: true },
    });
  }

  async cleanup(): Promise<void> {
    const ids = this.organizationIds;
    if (ids.length > 0) {
      const where = { organizationId: { in: ids } };
      await this.prisma.securityIncidentLink.deleteMany({ where });
      await this.prisma.securityIncidentEvent.deleteMany({ where });
      await this.prisma.securityIncident.deleteMany({ where });
      await this.prisma.messageOutbox.deleteMany({ where });
      await this.prisma.auditLog.deleteMany({ where });
      await this.prisma.atoAccount.deleteMany({ where });
      await this.prisma.user.deleteMany({ where });
      await this.prisma.organization.deleteMany({ where: { id: { in: ids } } });
    }
    if (this.planId !== undefined) {
      await this.prisma.organizationPlan.delete({ where: { id: this.planId } });
    }
    await this.prisma.$disconnect();
  }
}
