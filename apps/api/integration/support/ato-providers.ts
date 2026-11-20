/**
 * Identity-provider integration support (step 8.5 §11.4): synthetic step 8.2 connections written
 * to 8.2's real tables (`provider_connections`, `provider_connection_domains`,
 * `provider_connection_grants`) exactly as the integration-worker leaves them once a tenant and a
 * grant verified (status `active`, bound tenant key, provider-verified linked domain, active ATO
 * telemetry grant with its observed permissions), an MFA administrator holding `ato:configure`,
 * probe reports, mailbox items and in-flight provider actions inserted the way the ato-worker
 * writes them, and the cleanup through the organization purge of both steps (the 8.5 rows first,
 * then 8.2's). Synthetic data only: example domains, random tenant ids, no credential. Nothing
 * here is used by production code.
 */
import { createHash, randomUUID } from 'node:crypto';
import { PROVIDER_STREAMS } from '@email-gateway/ato-detection';
import type {
  AtoAccount,
  AtoAccountIdentity,
  AtoProviderIntegration,
  AtoProviderMailboxItem,
  AtoResponseAction,
} from '@email-gateway/database';
import {
  GOOGLE_PROFILES,
  MICROSOFT_PROFILES,
  type ProbeReport,
  STREAM_ROLES,
} from '@email-gateway/idp-adapters';
import { systemScope } from '../../src/auth-contracts/tenant-scope';
import { AtoProviderTenantDataRepository } from '../../src/modules/tenant-data/ato-provider-tenant-data.repository';
import { ProviderTenantDataRepository } from '../../src/modules/tenant-data/provider-tenant-data.repository';
import type { IntegrationApp } from './app';
import type { FixtureOrganization, Fixtures } from './fixtures';
import { bearer, loginWithMfa } from './http';
import { insertDomain } from './smtp';

const MICROSOFT_OBSERVED = [
  'AuditLog.Read.All',
  'Directory.Read.All',
  'IdentityRiskEvent.Read.All',
  'User.Read.All',
  'MailboxSettings.Read',
];
const GOOGLE_OBSERVED = [
  'https://www.googleapis.com/auth/admin.reports.audit.readonly',
  'https://www.googleapis.com/auth/admin.directory.user.readonly',
  'https://www.googleapis.com/auth/gmail.settings.basic',
];

export interface SeededConnection {
  id: bigint;
  publicId: string;
  tenantId: string;
  domain: string;
}

/** A probe report with every offered stream available and an active telemetry grant. */
export function probeReport(
  provider: 'microsoft_entra' | 'google_workspace' = 'microsoft_entra',
): ProbeReport {
  return {
    ok: true,
    checkedAt: new Date().toISOString(),
    directoryRefHash: null,
    streams: Object.fromEntries(
      PROVIDER_STREAMS.map((s) => [
        s,
        {
          availability:
            STREAM_ROLES[provider][s].role === 'unsupported' ? 'not_offered' : 'available',
        },
      ]),
    ) as ProbeReport['streams'],
    actions: {
      revoke_sessions: { availability: 'available', rollback: false, confirmation: 'synchronous' },
      require_mfa: { availability: 'not_configured', rollback: true, confirmation: 'polling' },
      require_password_reset: {
        availability: 'available',
        rollback: false,
        confirmation: 'synchronous',
      },
      suspend_account: { availability: 'available', rollback: true, confirmation: 'polling' },
      remove_forwarding_rule: {
        availability: 'available',
        rollback: true,
        confirmation: 'polling',
      },
      revoke_oauth_grant: {
        availability: 'missing_permission',
        rollback: false,
        confirmation: 'synchronous',
      },
    },
    grants: [
      {
        profile:
          provider === 'microsoft_entra' ? MICROSOFT_PROFILES.telemetry : GOOGLE_PROFILES.telemetry,
        status: 'active',
        missingPermissions: [],
      },
    ],
  };
}

export const sha256 = (value: string): string =>
  createHash('sha256').update(value, 'utf8').digest('hex');

/** The provider seeding helpers of one suite. */
export class ProviderSeeder {
  private readonly orgs: bigint[] = [];

  constructor(
    readonly ctx: IntegrationApp,
    readonly fx: Fixtures,
  ) {
    // Registered after the AtoSeeder, so it runs first (cleanups run in reverse): the 8.5 rows,
    // then 8.2's connection rows, before the 8.4 rows and the organizations go.
    fx.registerCleanup(
      async () => {
        const ato = ctx.get(AtoProviderTenantDataRepository);
        const conn = ctx.get(ProviderTenantDataRepository);
        for (const id of this.orgs) {
          await ato.purgeOrganization(systemScope(id));
          await conn.purgeOrganization(systemScope(id));
        }
      },
      { rerunOnConflict: true },
    );
  }

  /** An administrator of the organization with an MFA session (`ato:configure`, every ATO key). */
  async admin(org: FixtureOrganization): Promise<Record<string, string>> {
    const user = await this.fx.createUser(org, { roles: ['organization_admin'], mfa: true });
    for (let attempt = 1; ; attempt += 1) {
      try {
        return bearer((await loginWithMfa(this.ctx, this.fx, user)).accessToken);
      } catch (error) {
        if (attempt >= 3) throw error;
      }
    }
  }

  /**
   * An active 8.2 connection with a provider-verified linked domain and an ATO telemetry grant
   * (`active` unless `grant` says otherwise; `null` = no grant row).
   */
  async connection(
    org: FixtureOrganization,
    options: {
      provider?: 'microsoft_365' | 'google_workspace';
      grant?: 'active' | 'verifying' | 'error' | null;
      status?: 'active' | 'configuring' | 'disabled';
      /** Reuse this provider tenant (directory) id; a fresh random one otherwise. */
      tenantId?: string;
    } = {},
  ): Promise<SeededConnection> {
    if (!this.orgs.includes(org.id)) this.orgs.push(org.id);
    const provider = options.provider ?? 'microsoft_365';
    const tenantId =
      options.tenantId ??
      (provider === 'microsoft_365' ? randomUUID() : `C0${randomUUID().slice(0, 7)}`);
    const domain = await insertDomain(this.ctx, org, { label: 'ato-idp' });
    const status = options.status ?? 'active';
    const connection = await this.ctx.prisma.providerConnection.create({
      data: {
        organizationId: org.id,
        provider,
        displayName: `EXAMPLE ${provider} ${randomUUID().slice(0, 8)}`,
        status,
        externalTenantId: tenantId,
        externalTenantName: 'EXAMPLE directory',
        tenantVerifiedAt: new Date(),
        // Unique platform-wide (8.2 I10); a reused tenant id gets a distinct key so the suite can
        // model a directory still monitored by a stale integration of another organization.
        activeTenantKey:
          status === 'disabled' ? null : `${provider}:${tenantId}:${randomUUID().slice(0, 8)}`,
      },
    });
    await this.ctx.prisma.providerConnectionDomain.create({
      data: {
        organizationId: org.id,
        connectionId: connection.id,
        domainId: domain.id,
        providerVerification: 'verified',
        providerCheckedAt: new Date(),
      },
    });
    const grant = options.grant === undefined ? 'active' : options.grant;
    if (grant !== null) {
      const microsoft = provider === 'microsoft_365';
      await this.ctx.prisma.providerConnectionGrant.create({
        data: {
          organizationId: org.id,
          connectionId: connection.id,
          profile: microsoft ? MICROSOFT_PROFILES.telemetry : GOOGLE_PROFILES.telemetry,
          profileVersion: 1,
          authMethod: microsoft ? 'platform_app' : 'platform_service_account',
          status: grant,
          subjectEmail: microsoft ? null : `admin@${domain.name}`,
          requestedPermissions: microsoft ? MICROSOFT_OBSERVED : GOOGLE_OBSERVED,
          observedPermissions:
            grant === 'active' ? (microsoft ? MICROSOFT_OBSERVED : GOOGLE_OBSERVED) : [],
          verifiedAt: grant === 'active' ? new Date() : null,
        },
      });
    }
    return { id: connection.id, publicId: connection.publicId, tenantId, domain: domain.name };
  }

  /** What the ato-worker's probe writes: the report and the health of the integration. */
  async probed(
    integrationPublicId: string,
    provider: 'microsoft_entra' | 'google_workspace' = 'microsoft_entra',
  ): Promise<AtoProviderIntegration> {
    return this.ctx.prisma.atoProviderIntegration.update({
      where: { publicId: integrationPublicId },
      data: {
        healthDetail: probeReport(provider) as never,
        healthStatus: 'healthy',
        healthCheckedAt: new Date(),
      },
    });
  }

  /** A provider identity of the account resolved by the integration (as the worker upserts it). */
  async identity(
    account: AtoAccount,
    integration: AtoProviderIntegration,
  ): Promise<AtoAccountIdentity> {
    const externalId = randomUUID();
    return this.ctx.prisma.atoAccountIdentity.create({
      data: {
        organizationId: account.organizationId,
        accountId: account.id,
        provider: integration.provider,
        externalId,
        externalIdHash: sha256(`${integration.provider}|${externalId}`),
        userPrincipalName: account.address,
        firstSeenAt: new Date(),
        lastSeenAt: new Date(),
        integrationId: integration.id,
        primaryEmailDomain: account.address?.split('@')[1] ?? null,
        directoryStatus: 'active',
        directoryStatusAt: new Date(),
      },
    });
  }

  /** A mailbox state item of the account (as the worker's snapshot store writes it). */
  async item(
    account: AtoAccount,
    integration: AtoProviderIntegration,
    over: {
      kind?: 'forwarding' | 'inbox_rule' | 'delegate';
      state?: 'present' | 'removed';
      removedAt?: Date | null;
    } = {},
  ): Promise<AtoProviderMailboxItem> {
    const now = new Date();
    return this.ctx.prisma.atoProviderMailboxItem.create({
      data: {
        organizationId: account.organizationId,
        integrationId: integration.id,
        accountId: account.id,
        identityExternalIdHash: sha256(randomUUID()),
        itemKind: over.kind ?? 'inbox_rule',
        itemHash: sha256(randomUUID()),
        providerItemRef: 'EXAMPLE-rule-id',
        targetDomain: 'external-example.net',
        traits: ['forwards', 'forwards_external'],
        enabled: true,
        state: over.state ?? 'present',
        source: 'snapshot',
        firstSeenAt: now,
        lastSeenAt: now,
        removedAt: over.removedAt ?? null,
        emittedSeq: 1n,
        lastChange: over.state === 'removed' ? 'removed' : 'added',
      },
    });
  }

  /** An in-flight provider action of the integration (the respond role picked it, no outbox). */
  async inFlightAction(
    account: AtoAccount,
    integration: AtoProviderIntegration,
  ): Promise<AtoResponseAction> {
    return this.ctx.prisma.atoResponseAction.create({
      data: {
        organizationId: account.organizationId,
        accountId: account.id,
        actionType: 'suspend_account',
        provider: integration.provider,
        impact: 'high',
        target: { scope: 'mailbox', accountPublicId: account.publicId },
        params: {},
        status: 'executing',
        requiresApproval: true,
        authorization: 'manual',
        requestedByType: 'system',
        requestReason: 'Integration test: in-flight provider action',
        executedAt: new Date(),
        providerStatus: 'pending',
        providerReference: `msgraph:suspend_account:${randomUUID()}`,
        integrationId: integration.id,
        dedupeHash: sha256(randomUUID()),
      },
    });
  }
}
