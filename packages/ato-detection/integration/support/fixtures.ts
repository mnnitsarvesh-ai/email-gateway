import { createHash, randomUUID } from 'node:crypto';
import { PrismaClient } from '@email-gateway/database';
import { ruleByCode } from '../../src/rules/catalogue';
import type { SignalCandidate } from '../../src/rules/types';

/** Values from the repository's .env (loaded by vitest.integration.config.ts). Never printed. */
export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set (see .env)`);
  return value;
}

export type Tx = Parameters<Parameters<PrismaClient['$transaction']>[0]>[0];

/**
 * Synthetic `it-ato-<run>-*` organizations and users on the real MySQL writer (D21), and removal of
 * every row the ATO and incident stores write for them. Never touches pre-existing data: every
 * delete is scoped to the organizations this instance created.
 */
export class Fixtures {
  readonly prisma: PrismaClient = new PrismaClient({ datasourceUrl: requireEnv('DATABASE_URL') });
  readonly suffix = randomUUID().slice(0, 8);
  readonly organizationIds: bigint[] = [];
  private planId: bigint | undefined;

  tx<T>(fn: (tx: Tx) => Promise<T>): Promise<T> {
    return this.prisma.$transaction(fn, { timeout: 120_000, maxWait: 30_000 });
  }

  async organization(label: string): Promise<bigint> {
    if (this.planId === undefined) {
      const plan = await this.prisma.organizationPlan.create({
        data: {
          code: `it-ato-${this.suffix}`,
          name: 'ato-detection integration',
          defaultLimits: {},
          defaultFeatures: {},
        },
      });
      this.planId = plan.id;
    }
    const org = await this.prisma.organization.create({
      data: {
        slug: `it-ato-${this.suffix}-${label}`,
        name: `ATO ${label}`,
        planId: this.planId,
        dataRegion: 'ap-south-1',
      },
    });
    this.organizationIds.push(org.id);
    return org.id;
  }

  async user(organizationId: bigint, label: string) {
    return this.prisma.user.create({
      data: {
        organizationId,
        email: `${label}-${this.suffix}@it-ato.example.test`,
        displayName: `IT ${label}`,
        status: 'active',
      },
      select: { id: true, publicId: true },
    });
  }

  /** An API key row of the organization created by `createdByUserId` (no usable secret). */
  async apiKey(organizationId: bigint, createdByUserId: bigint, label: string) {
    const prefix = createHash('sha256').update(`${this.suffix}:${label}`).digest('hex');
    return this.prisma.apiKey.create({
      data: {
        organizationId,
        name: `it-ato ${label}`,
        keyPrefix: `itato${prefix.slice(0, 11)}`,
        keyHash: createHash('sha256').update(`unused:${prefix}`).digest('hex'),
        scopes: ['ato:respond'],
        createdByUserId,
      },
      select: { id: true, publicId: true },
    });
  }

  address(label: string): string {
    return `${label}-${this.suffix}@it-ato.example.test`;
  }

  async cleanup(): Promise<void> {
    const ids = this.organizationIds;
    if (ids.length > 0) {
      const where = { organizationId: { in: ids } };
      const p = this.prisma;
      await p.atoResponseActionLog.deleteMany({ where });
      await p.atoResponseAction.deleteMany({ where });
      await p.atoSmtpRestriction.deleteMany({ where });
      await p.atoIncidentDetail.deleteMany({ where });
      await p.securityIncidentLink.deleteMany({ where });
      await p.securityIncidentEvent.deleteMany({ where });
      await p.securityIncident.deleteMany({ where });
      await p.atoTrustedContext.deleteMany({ where });
      await p.atoRiskOverride.deleteMany({ where });
      await p.atoRiskSignal.deleteMany({ where });
      await p.atoRiskScore.deleteMany({ where });
      await p.atoAuthEvent.deleteMany({ where });
      await p.atoAccountActivityDaily.deleteMany({ where });
      await p.atoAccountBaseline.deleteMany({ where });
      await p.atoAccountIdentity.deleteMany({ where });
      await p.atoAccount.deleteMany({ where });
      await p.atoSettingsVersion.deleteMany({ where });
      await p.atoSetting.deleteMany({ where });
      await p.notificationAlertWindow.deleteMany({ where });
      await p.messageOutbox.deleteMany({ where });
      await p.auditLog.deleteMany({ where });
      await p.apiKey.deleteMany({ where });
      await p.user.deleteMany({ where });
      await p.organization.deleteMany({ where: { id: { in: ids } } });
    }
    if (this.planId !== undefined) {
      await this.prisma.organizationPlan.delete({ where: { id: this.planId } });
    }
    await this.prisma.$disconnect();
  }
}

/** A signal candidate of a catalogue rule with its default weight (store tests). */
export function candidate(
  code: string,
  overrides: Partial<SignalCandidate> & { subject?: string } = {},
): SignalCandidate {
  const rule = ruleByCode(code);
  if (!rule) throw new Error(`unknown rule ${code}`);
  const { subject, ...rest } = overrides;
  return {
    code,
    category: rule.category,
    strength: rule.strength,
    weight: rule.defaultWeight,
    dedupeKey: createHash('sha256')
      .update(`${code}|${subject ?? 'default'}`)
      .digest('hex'),
    dedupeWindowMinutes: 60,
    evidence: { count: 1 },
    sourceKind: 'window',
    sourceRef: null,
    messageRef: null,
    authEventRef: null,
    informational: false,
    ...rest,
  };
}

/** A 64-hex dedupe key for auth events. */
export const hex64 = (label: string): string => createHash('sha256').update(label).digest('hex');
