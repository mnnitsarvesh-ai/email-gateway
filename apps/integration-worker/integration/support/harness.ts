import { randomBytes, randomUUID } from 'node:crypto';
import { AdvisoryLocks, MetricsService } from '@email-gateway/common';
import { Prisma, PrismaClient } from '@email-gateway/database';
import { createLogger } from '@email-gateway/logger';
import {
  credentialFingerprint,
  GOOGLE_MAIL_FLOW_PROFILE,
  M365_MAIL_FLOW_PROFILE,
  type PermissionProfile,
  type PlatformCredentials,
  ProviderCredentialCipher,
  type ProviderCredential,
  testing,
} from '@email-gateway/provider-integrations';
import type { ProbeResolver } from '../../src/checks/dns';
import type { SmtpProbeOptions, SmtpProbeResult } from '../../src/checks/smtp-probe';
import { type ComponentDeps, IntegrationComponents } from '../../src/components';
import { loadWorkerConfig, type WorkerConfig } from '../../src/config';
import type { HealthFaults } from '../../src/health/health-runner';
import { IntegrationMetrics } from '../../src/metrics/integration-metrics';

/** Values from the repository .env (loaded by vitest.integration.config.ts). Never printed. */
export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set (see .env)`);
  return value;
}

/** An injectable clock (§10.3). */
export class TestClock {
  constructor(private current = new Date()) {}
  now = (): Date => new Date(this.current.getTime());
  advance(ms: number): void {
    this.current = new Date(this.current.getTime() + ms);
  }
  set(date: Date): void {
    this.current = new Date(date.getTime());
  }
}

/** A resolver answering from a table (no DNS traffic). */
export class TableResolver implements ProbeResolver {
  readonly a = new Map<string, string[]>();
  readonly txtRecords = new Map<string, string[]>();
  readonly cnames = new Map<string, string[]>();
  addresses(host: string): Promise<string[]> {
    return Promise.resolve(this.a.get(host) ?? []);
  }
  txt(name: string): Promise<string[]> {
    return Promise.resolve(this.txtRecords.get(name) ?? []);
  }
  cname(name: string): Promise<string[]> {
    return Promise.resolve(this.cnames.get(name) ?? []);
  }
}

const logger = createLogger({ service: 'integration-worker-it', level: 'warn', version: 'test' });

/**
 * Synthetic `it-prov-<suffix>-*` organizations, connections, grants and gateway rows on the
 * MySQL writer (§10.3), an in-process provider fake and worker
 * components wired to both with an injected clock. Cleans up every row it created.
 */
export class Harness {
  readonly prisma: PrismaClient;
  readonly fake = new testing.FakeProviderServer();
  readonly clock = new TestClock();
  readonly resolver = new TableResolver();
  readonly suffix = randomUUID().slice(0, 8);
  readonly organizationIds: bigint[] = [];
  readonly key = randomBytes(32).toString('hex');
  readonly cipher: ProviderCredentialCipher;
  private planId: bigint | undefined;
  private readonly components: IntegrationComponents[] = [];
  private readonly locks: AdvisoryLocks[] = [];

  constructor() {
    const url = requireEnv('DATABASE_URL');
    this.prisma = new PrismaClient({ datasourceUrl: url });
    this.cipher = ProviderCredentialCipher.fromConfig({
      PROVIDER_CREDENTIAL_ENCRYPTION_KEY: this.key,
    });
  }

  async start(): Promise<void> {
    await this.fake.start();
  }

  name(label: string): string {
    return `it-prov-${this.suffix}-${label}.test`;
  }

  config(overrides: Record<string, string> = {}): Readonly<WorkerConfig> {
    return loadWorkerConfig({
      APP_ENV: 'ci',
      DATABASE_URL: requireEnv('DATABASE_URL'),
      PROVIDER_CREDENTIAL_ENCRYPTION_KEY: this.key,
      GATEWAY_MX_HOSTS: '10:mx1.mail-gateway.test,20:mx2.mail-gateway.test',
      GATEWAY_SPF_INCLUDE: '_spf.mail-gateway.test',
      PROVIDER_ALLOW_HTTP_ENDPOINTS: 'true',
      INTEGRATION_HEALTH_INTERVAL_SECONDS: '900',
      INTEGRATION_HEALTH_TICK_SECONDS: '60',
      ...overrides,
    });
  }

  /** Worker components scoped to this harness's organizations (loops are not started). */
  worker(
    options: {
      config?: Record<string, string>;
      platform?: PlatformCredentials;
      probeSmtp?: (o: SmtpProbeOptions) => Promise<SmtpProbeResult>;
      healthFaults?: HealthFaults;
      reader?: PrismaClient;
    } = {},
  ): { components: IntegrationComponents; metrics: IntegrationMetrics; service: MetricsService } {
    const config = this.config(options.config);
    const service = new MetricsService({ service: 'integration-worker-it' });
    const metrics = new IntegrationMetrics(service);
    const locks = new AdvisoryLocks(requireEnv('DATABASE_URL'));
    this.locks.push(locks);
    const deps: ComponentDeps = {
      writer: this.prisma,
      reader: () => options.reader ?? this.prisma,
      locks,
      metrics,
      logger,
      organizationIds: this.organizationIds,
      nameSuffix: `:${this.suffix}`,
      provider: {
        endpoints: this.fake.endpoints(),
        retry: { retries: 0 },
        ...(options.platform ? { platform: options.platform } : {}),
      },
      resolver: this.resolver,
      now: this.clock.now,
      ...(options.probeSmtp ? { probeSmtp: options.probeSmtp } : {}),
      ...(options.healthFaults ? { healthFaults: options.healthFaults } : {}),
    };
    const components = new IntegrationComponents(config, deps);
    this.components.push(components);
    return { components, metrics, service };
  }

  async organization(label: string): Promise<bigint> {
    if (this.planId === undefined) {
      const plan = await this.prisma.organizationPlan.create({
        data: {
          code: `it-prov-${this.suffix}`,
          name: 'integration-worker integration',
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

  async domain(
    organizationId: bigint,
    name: string,
    status: 'active' | 'pending_verification' = 'active',
  ) {
    return this.prisma.domain.create({
      data: { organizationId, name, status, outboundEnabled: true },
    });
  }

  async connection(
    organizationId: bigint,
    provider: 'microsoft_365' | 'google_workspace',
    data: Partial<Prisma.ProviderConnectionUncheckedCreateInput> = {},
  ) {
    return this.prisma.providerConnection.create({
      data: {
        organizationId,
        provider,
        displayName: `conn-${randomUUID().slice(0, 8)}`,
        status: 'connecting',
        ...data,
      },
    });
  }

  /** A grant in `verifying` with an encrypted customer credential (or none for platform methods). */
  async grant(
    connection: { id: bigint; publicId: string; organizationId: bigint; provider: string },
    input: {
      authMethod:
        | 'customer_app_secret'
        | 'customer_service_account'
        | 'platform_app'
        | 'platform_service_account';
      credential?: ProviderCredential;
      clientId?: string;
      claimedTenantId?: string;
      subjectEmail?: string;
      status?: 'verifying' | 'active' | 'error';
      expiresAt?: Date;
      keyCipher?: ProviderCredentialCipher;
      /**
       * Another registered profile (step 8.5: the ATO profiles; step API-1: the mailbox-access
       * profiles); default the mail-flow one.
       */
      profile?: PermissionProfile;
    },
  ) {
    const profile =
      input.profile ??
      (connection.provider === 'microsoft_365' ? M365_MAIL_FLOW_PROFILE : GOOGLE_MAIL_FLOW_PROFILE);
    const created = await this.prisma.providerConnectionGrant.create({
      data: {
        organizationId: connection.organizationId,
        connectionId: connection.id,
        profile: profile.key,
        profileVersion: profile.version,
        authMethod: input.authMethod,
        status: input.status ?? 'verifying',
        clientId: input.clientId ?? null,
        subjectEmail: input.subjectEmail ?? null,
        claimedTenantId: input.claimedTenantId ?? null,
        requestedPermissions: [...profile.permissions],
        verifyRequestedAt: this.clock.now(),
        credentialVersion: input.credential ? 1 : 0,
        credentialExpiresAt: input.expiresAt ?? null,
      },
    });
    if (input.credential) {
      const sealed = (input.keyCipher ?? this.cipher).encryptCredential(input.credential, {
        organizationId: connection.organizationId,
        connectionPublicId: connection.publicId,
        grantPublicId: created.publicId,
        credentialVersion: 1,
      });
      return this.prisma.providerConnectionGrant.update({
        where: { id: created.id },
        data: {
          credentialCiphertext: sealed.ciphertext,
          credentialKeyId: sealed.keyId,
          credentialFingerprint: credentialFingerprint({
            clientId: input.clientId ?? 'sa',
            credentialVersion: 1,
          }),
          credentialSetAt: this.clock.now(),
        },
      });
    }
    return created;
  }

  async user(organizationId: bigint) {
    return this.prisma.user.create({
      data: {
        organizationId,
        email: `admin-${randomUUID().slice(0, 8)}@${this.name('users')}`,
        displayName: 'Integration admin',
      },
    });
  }

  async link(connection: { id: bigint; organizationId: bigint }, domainId: bigint) {
    return this.prisma.providerConnectionDomain.create({
      data: { organizationId: connection.organizationId, connectionId: connection.id, domainId },
    });
  }

  /** Stored step 2.1 DNS observations (mx records of both gateway hosts and spf). */
  async dnsRecords(
    organizationId: bigint,
    domainId: bigint,
    status: 'valid' | 'invalid' = 'valid',
    checkedAt: Date = this.clock.now(),
  ): Promise<void> {
    const rows = [
      { recordKey: 'mx:mx1.mail-gateway.test', purpose: 'mx' as const, recordType: 'MX' as const },
      { recordKey: 'mx:mx2.mail-gateway.test', purpose: 'mx' as const, recordType: 'MX' as const },
      { recordKey: 'spf', purpose: 'spf' as const, recordType: 'TXT' as const },
    ];
    for (const row of rows) {
      await this.prisma.domainDnsRecord.create({
        data: {
          organizationId,
          domainId,
          ...row,
          host: 'it',
          expectedValue: 'x',
          status,
          lastCheckedAt: checkedAt,
        },
      });
    }
  }

  async destination(
    organizationId: bigint,
    domainId: bigint,
    provider: 'microsoft_365' | 'google_workspace' | 'custom',
    host: string,
  ) {
    return this.prisma.domainMailServer.create({
      data: {
        organizationId,
        domainId,
        role: 'inbound_destination',
        host,
        port: 25,
        priority: 10,
        tlsMode: 'verify',
        provider,
      },
    });
  }

  /** Sets up a Microsoft tenant and a customer app with the given Graph roles in the fake. */
  m365Tenant(options: {
    domains: { name: string; isVerified?: boolean; mxHost?: string }[];
    roles?: string[];
  }) {
    const tenantId = testing.testGuid();
    const clientId = testing.testGuid();
    const secret = testing.testClientSecret();
    this.fake.addMicrosoftTenant({
      tenantId,
      displayName: `Tenant ${tenantId.slice(0, 4)}`,
      domains: options.domains.map((d) => ({
        name: d.name,
        isVerified: d.isVerified ?? true,
        mxHost: d.mxHost ?? `${d.name.replace(/\./g, '-')}.mail.protection.outlook.com`,
      })),
    });
    this.fake.addMicrosoftApp({ clientId, secret, homeTenantId: tenantId });
    this.fake.consent(tenantId, clientId, options.roles ?? [...M365_MAIL_FLOW_PROFILE.permissions]);
    return { tenantId, clientId, secret };
  }

  async cleanup(): Promise<void> {
    for (const c of this.components) await c.stop().catch(() => undefined);
    for (const l of this.locks) await l.close().catch(() => undefined);
    const ids = this.organizationIds;
    try {
      if (ids.length > 0) {
        const where = { organizationId: { in: ids } };
        await this.prisma.auditLog.deleteMany({ where });
        await this.prisma.messageOutbox.deleteMany({ where });
        await this.prisma
          .$executeRaw`DELETE FROM email_deliveries WHERE organization_id IN (${Prisma.join(ids)})`;
        await this.prisma.providerProbeObservation.deleteMany({ where });
        await this.prisma.providerRelayCounter.deleteMany({ where });
        await this.prisma.providerHealthEvent.deleteMany({ where });
        await this.prisma.providerHealthCheck.deleteMany({ where });
        await this.prisma.providerValidationRun.deleteMany({ where });
        await this.prisma.providerConsentState.deleteMany({ where });
        await this.prisma.providerConnectionDomain.deleteMany({ where });
        await this.prisma.providerConnectionGrant.deleteMany({ where });
        await this.prisma.smtpConnector.deleteMany({ where });
        // Step 8.5: ATO integrations bound to fixture connections (ato.identity_provider tests).
        await this.prisma.atoProviderIntegration.deleteMany({ where });
        await this.prisma.providerConnection.deleteMany({ where });
        await this.prisma.domainDnsRecord.deleteMany({ where });
        await this.prisma.domainMailServer.deleteMany({ where });
        await this.prisma.domain.deleteMany({ where });
        await this.prisma.user.deleteMany({ where });
        // On a full stack (main schema, running event-relay and webhook-worker) the health
        // transitions are consumed asynchronously: the fanout may still add an
        // `integration_unhealthy` alert window for a fixture organization while we clean up.
        for (let attempt = 0; ; attempt += 1) {
          await this.prisma.notificationAlertWindow.deleteMany({ where });
          try {
            await this.prisma.organization.deleteMany({ where: { id: { in: ids } } });
            break;
          } catch (error) {
            if (attempt >= 10) throw error;
            await new Promise((r) => setTimeout(r, 1_000));
          }
        }
      }
      if (this.planId !== undefined) {
        await this.prisma.organizationPlan.deleteMany({ where: { id: this.planId } });
      }
    } finally {
      await this.fake.stop();
      await this.prisma.$disconnect();
    }
  }
}

/** A never-aborted signal for direct component calls. */
export const signal = (): AbortSignal => new AbortController().signal;
