/**
 * Account takeover integration support (step 8.4 §10.4): synthetic `it-ato-*` organizations with
 * the feature `ato_detection` enabled (D21: never a pre-existing organization), analysts,
 * an administrator, a read-only auditor and an API key; rows written by the **library stores**
 * of the running api (`IncidentStores`: the same `AtoStore` / `IncidentStore` the worker uses),
 * and removal of every ATO and incident row of those organizations before the generic fixture
 * cleanup. Nothing here is used by production code.
 */
import { createHash, randomUUID } from 'node:crypto';
import { ruleByCode, type SignalCandidate } from '@email-gateway/ato-detection';
import type { AtoAccount, Prisma } from '@email-gateway/database';
import { IncidentStores } from '../../src/modules/incidents/incident-stores';
import type { IntegrationApp } from './app';
import type { FixtureOrganization, FixtureUser, Fixtures } from './fixtures';
import { bearer, loginWithMfa } from './http';

export type Tx = Prisma.TransactionClient;

export interface AtoTenant {
  org: FixtureOrganization;
  analyst: FixtureUser;
  analyst2: FixtureUser;
  admin: FixtureUser;
  auditor: FixtureUser;
  analystAuth: Record<string, string>;
  analyst2Auth: Record<string, string>;
  adminAuth: Record<string, string>;
  auditorAuth: Record<string, string>;
  /** An API key with every ATO permission. */
  apiKey: Record<string, string>;
}

/** A signal candidate of a catalogue rule with its default weight. */
export function candidate(
  code: string,
  subject = 'default',
  overrides: Partial<SignalCandidate> = {},
): SignalCandidate {
  const rule = ruleByCode(code);
  if (!rule) throw new Error(`unknown rule ${code}`);
  return {
    code,
    category: rule.category,
    strength: rule.strength,
    weight: rule.defaultWeight,
    dedupeKey: createHash('sha256').update(`${code}|${subject}`).digest('hex'),
    dedupeWindowMinutes: 60,
    evidence: { count: 1 },
    sourceKind: 'window',
    sourceRef: null,
    messageRef: null,
    authEventRef: null,
    informational: false,
    ...overrides,
  };
}

export const hex64 = (label: string): string => createHash('sha256').update(label).digest('hex');

/** Deletes every ATO and incident row of the organizations (the stores' tables, outbox, audit). */
export async function deleteAtoRows(
  prisma: IntegrationApp['prisma'],
  ids: readonly bigint[],
): Promise<void> {
  if (ids.length === 0) return;
  const where = { organizationId: { in: [...ids] } };
  await prisma.atoResponseActionLog.deleteMany({ where });
  await prisma.atoResponseAction.deleteMany({ where });
  await prisma.atoSmtpRestriction.deleteMany({ where });
  await prisma.atoIncidentDetail.deleteMany({ where });
  await prisma.securityIncidentLink.deleteMany({ where });
  await prisma.securityIncidentEvent.deleteMany({ where });
  await prisma.securityIncident.deleteMany({ where });
  await prisma.atoTrustedContext.deleteMany({ where });
  await prisma.atoRiskOverride.deleteMany({ where });
  await prisma.atoRiskSignal.deleteMany({ where });
  await prisma.atoRiskScore.deleteMany({ where });
  await prisma.atoAuthEvent.deleteMany({ where });
  await prisma.atoAccountActivityDaily.deleteMany({ where });
  await prisma.atoAccountBaseline.deleteMany({ where });
  await prisma.atoAccountIdentity.deleteMany({ where });
  await prisma.atoAccount.deleteMany({ where });
  await prisma.atoSettingsVersion.deleteMany({ where });
  await prisma.atoSetting.deleteMany({ where });
  await prisma.messageOutbox.deleteMany({ where });
  await prisma.auditLog.deleteMany({ where });
}

/** The ATO seeding and HTTP helpers of one suite. */
export class AtoSeeder {
  readonly orgIds: bigint[] = [];

  constructor(
    readonly ctx: IntegrationApp,
    readonly fx: Fixtures,
  ) {
    // The live ato-worker records the fixture users' sign-ins (auth event, gateway_user account)
    // asynchronously, possibly after this delete ran: rerun it when the organization delete
    // conflicts.
    fx.registerCleanup(() => deleteAtoRows(ctx.prisma, this.orgIds), { rerunOnConflict: true });
  }

  get stores(): IncidentStores {
    return this.ctx.get(IncidentStores);
  }

  tx<T>(fn: (tx: Tx) => Promise<T>): Promise<T> {
    return this.ctx.prisma.$transaction(fn, { timeout: 120_000, maxWait: 30_000 });
  }

  /** A synthetic organization (`it-ato-…`) with ATO enabled, its users, sessions and an API key. */
  async tenant(options: { enabled?: boolean } = {}): Promise<AtoTenant> {
    const org = await this.fx.createOrganization({ planCode: 'enterprise' });
    const slug = `it-ato-${org.slug.slice(3)}`;
    await this.ctx.prisma.organization.update({ where: { id: org.id }, data: { slug } });
    org.slug = slug;
    this.orgIds.push(org.id);
    await this.setFeature(org.id, options.enabled ?? true);
    const analyst = await this.fx.createUser(org, { roles: ['security_analyst'], mfa: true });
    const analyst2 = await this.fx.createUser(org, { roles: ['security_analyst'], mfa: true });
    const admin = await this.fx.createUser(org, { roles: ['organization_admin'] });
    const auditor = await this.fx.createUser(org, { roles: ['compliance_auditor'] });
    // MFA verification may refuse a code at a 30-second step boundary under load: retry (each
    // attempt uses a later, unused step).
    const auth = async (u: FixtureUser) => {
      for (let attempt = 1; ; attempt += 1) {
        try {
          return bearer((await loginWithMfa(this.ctx, this.fx, u)).accessToken);
        } catch (error) {
          if (attempt >= 3) throw error;
        }
      }
    };
    const key = await this.fx.createApiKey(org, [
      'ato:read',
      'ato:manage',
      'ato:respond',
      'ato:configure',
    ]);
    return {
      org,
      analyst,
      analyst2,
      admin,
      auditor,
      analystAuth: await auth(analyst),
      analyst2Auth: await auth(analyst2),
      adminAuth: await auth(admin),
      auditorAuth: await auth(auditor),
      apiKey: { 'X-API-Key': key },
    };
  }

  async setFeature(organizationId: bigint, enabled: boolean): Promise<void> {
    await this.ctx.prisma.organizationFeature.upsert({
      where: { organizationId_featureKey: { organizationId, featureKey: 'ato_detection' } },
      create: { organizationId, featureKey: 'ato_detection', enabled },
      update: { enabled },
    });
  }

  async mailbox(
    organizationId: bigint,
    label: string = randomUUID().slice(0, 8),
  ): Promise<AtoAccount> {
    return this.tx((t) =>
      this.stores.ato.ensureAccount(t, {
        organizationId,
        subject: { kind: 'mailbox', address: `${label}@it-ato.example.test` },
        at: new Date(),
      }),
    );
  }

  /** An auth event of the account through the store. */
  async authEvent(
    organizationId: bigint,
    account: AtoAccount,
    at: Date,
    over: { outcome?: 'success' | 'failure'; ip?: string; country?: string } = {},
  ) {
    return this.tx((t) =>
      this.stores.ato.recordAuthEvent(t, {
        organizationId,
        accountId: account.id,
        source: 'portal_login',
        channel: 'portal',
        outcome: over.outcome ?? 'success',
        failureCode: over.outcome === 'failure' ? 'invalid_password' : null,
        occurredAt: at,
        ip: over.ip ?? '203.0.113.45',
        ipPrefix: '203.0.113.0/24',
        geo: over.country
          ? {
              status: 'located',
              country: over.country,
              region: null,
              city: null,
              latitude: null,
              longitude: null,
              accuracyKm: null,
              asn: 64501,
              asnOrg: 'EXAMPLE-AS',
              anonymizerFlags: 0,
            }
          : null,
        reputation: null,
        device: null,
        mechanism: null,
        sourceRef: null,
        dedupeKey: hex64(`${account.id}|${at.getTime()}|${randomUUID()}`),
      }),
    );
  }

  /** Signals → rescore → incident policy in one transaction, as the worker's detect role does. */
  async detect(
    organizationId: bigint,
    account: AtoAccount,
    codes: string[],
    authEvents: Array<{ id: bigint; occurredAt: Date }> = [],
  ) {
    const store = this.stores.ato;
    return this.tx(async (t) => {
      const settings = await store.ensureSettings(t, organizationId);
      const [locked] = await store.lockAccounts(t, organizationId, [account.id]);
      const recorded = await store.recordSignals(t, {
        organizationId,
        account: locked!,
        candidates: codes.map((c) => candidate(c, randomUUID())),
        settingsVersion: settings.version,
        at: new Date(),
      });
      const rescore = await store.rescore(t, {
        organizationId,
        accountId: account.id,
        trigger: 'signal',
        settings,
      });
      const policy = await store.applyIncidentPolicy(t, {
        organizationId,
        accountId: account.id,
        rescore,
        settings,
        evidence: {
          signals: recorded.created.map((s) => ({ id: s.id, detectedAt: s.detectedAt })),
          authEvents,
          messages: [],
          codes: recorded.created.map((s) => s.ruleCode),
        },
        newStrongSignal: recorded.created.some((s) => s.strength === 'strong'),
        context: { hasAtoPolicyRule: false, providerActions: new Set<string>() },
      });
      return { recorded, rescore, policy };
    });
  }

  /** Ends the learning period (signals are scored, not informational). */
  async endLearning(organizationId: bigint): Promise<void> {
    await this.tx((t) => this.stores.ato.ensureSettings(t, organizationId));
    await this.ctx.prisma.atoSetting.update({
      where: { organizationId },
      data: { learningStartedAt: new Date(Date.now() - 60 * 86_400_000) },
    });
  }

  /** An account with an open ATO incident (strong + correlated signals). */
  async compromised(organizationId: bigint, label?: string) {
    await this.endLearning(organizationId);
    const account = await this.mailbox(organizationId, label);
    const event = await this.authEvent(organizationId, account, new Date(), { country: 'DE' });
    const result = await this.detect(
      organizationId,
      account,
      [
        'ato.geo.impossible_travel',
        'ato.ti.malicious_ip_success',
        'ato.outbound.volume_spike',
        'ato.access.new_asn',
      ],
      [{ id: event.id, occurredAt: event.occurredAt }],
    );
    if (!result.policy.incident)
      throw new Error(`no incident opened (score ${result.rescore.result.score})`);
    return { account, incident: result.policy.incident, event };
  }
}
