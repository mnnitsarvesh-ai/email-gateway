import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { type GrantRef, isMailFlowGrant } from '@email-gateway/provider-integrations';
import type { ProviderRuntime } from '../providers/provider-runtime';
import { systemAudit } from '../shared/db';
import { isUniqueViolation } from '../shared/errors';
import { bindingProofDomainWhere, evaluateBinding } from './binding';

/** What one `settle` call did. */
export type TenantBindingResult =
  'bound' | 'already_bound' | 'unproven' | 'tenant_bound_elsewhere' | 'tenant_mismatch' | 'skipped';

class BindingRefused extends Error {
  constructor(readonly code: 'tenant_bound_elsewhere' | 'tenant_mismatch' | 'skipped') {
    super(code);
    this.name = 'BindingRefused';
  }
}

/**
 * Tenant binding on proof of control (D4, I6, I10; review finding of the step 8.2 closer).
 *
 * A grant's tenant is a CLAIM: for Microsoft `platform_app` it is the `tenant` query value of the
 * unsigned admin-consent redirect, for Google `platform_service_account` the delegated admin the
 * customer names. The shared operator app (or service account) gets a token for every tenant that
 * ever consented (or delegated) to it, so a working token proves nothing about who the caller is.
 * The connection is therefore bound to the provider tenant (`external_tenant_id`,
 * `external_tenant_name`, `tenant_verified_at` and the platform-wide unique `active_tenant_key`)
 * only when at least one of the organization's own linked domains, TXT-verified at the gateway
 * (`domains.status` `verified` or `active` with `ownership_method = 'dns_txt'`, which only that
 * organization can have; step API-4 B3.5/B4, ADR-0107: a domain proven through the provider
 * tenant never proves the tenant, `bindingProofDomainWhere`), is `verified` in the
 * claimed tenant by a provider check made AFTER the grant's current verification
 * (`provider_checked_at >= grant.verified_at`; a result from an earlier claim never counts). The
 * provider tenant identity is read again right before binding (one directory call); a tenant
 * other than the claim is `tenant_mismatch`, a tenant bound by another connection is
 * `tenant_bound_elsewhere` (the grant errs with the code, audited). I10 is evaluated afterwards in
 * the same transaction. Connections that are already bound are only re-evaluated (I10).
 */
export class TenantBinder {
  constructor(
    private readonly writer: PrismaClient,
    private readonly options: { runtime: ProviderRuntime; logger: Logger; now: () => Date },
  ) {}

  async settle(
    connectionId: bigint,
    signal: AbortSignal,
    correlationId: string,
  ): Promise<TenantBindingResult> {
    const connection = await this.writer.providerConnection.findUnique({
      where: { id: connectionId },
      select: {
        id: true,
        publicId: true,
        organizationId: true,
        provider: true,
        status: true,
        externalTenantId: true,
        activeTenantKey: true,
        grants: {
          where: { status: 'active' },
          select: {
            id: true,
            publicId: true,
            organizationId: true,
            profile: true,
            authMethod: true,
            claimedTenantId: true,
            verifiedAt: true,
          },
          orderBy: { id: 'asc' },
        },
      },
    });
    if (!connection || connection.status === 'disabled') return 'skipped';
    const organizationId = connection.organizationId;
    if (connection.activeTenantKey !== null) {
      await this.evaluate(connectionId, correlationId);
      return 'already_bound';
    }
    const grant = connection.grants.find(
      (g) => g.organizationId === organizationId && isMailFlowGrant(g),
    );
    if (!grant || grant.verifiedAt === null) return 'unproven';
    const proven = await this.writer.providerConnectionDomain.count({
      where: {
        connectionId,
        organizationId,
        providerVerification: 'verified',
        providerCheckedAt: { gte: grant.verifiedAt },
        domain: bindingProofDomainWhere(organizationId),
      },
    });
    if (proven === 0) return 'unproven';

    const ref: GrantRef = {
      organizationId,
      connectionPublicId: connection.publicId,
      profile: grant.profile,
    };
    const provider = connection.provider;
    const identity = await this.options.runtime.directories[provider].tenant(ref, signal);
    const tenantId =
      provider === 'microsoft_365' ? identity.tenantId.toLowerCase() : identity.tenantId;
    const now = this.options.now();
    try {
      if (
        (provider === 'microsoft_365' &&
          grant.claimedTenantId !== null &&
          grant.claimedTenantId.toLowerCase() !== tenantId) ||
        (connection.externalTenantId !== null && connection.externalTenantId !== tenantId)
      ) {
        throw new BindingRefused('tenant_mismatch');
      }
      await this.writer.$transaction(async (tx) => {
        const [row] = await tx.$queryRaw<
          Array<{ status: string; active_tenant_key: string | null }>
        >`SELECT status, active_tenant_key FROM provider_connections
           WHERE id = ${connectionId} AND organization_id = ${organizationId} FOR UPDATE`;
        if (!row || row.status === 'disabled' || row.active_tenant_key !== null) {
          throw new BindingRefused('skipped');
        }
        const live = await tx.providerConnectionGrant.count({
          where: { id: grant.id, organizationId, status: 'active' },
        });
        if (live === 0) throw new BindingRefused('skipped');
        await tx.providerConnection.updateMany({
          where: { id: connectionId, organizationId },
          data: {
            externalTenantId: tenantId,
            externalTenantName: identity.displayName.slice(0, 256),
            tenantVerifiedAt: now,
            // I10: one provider tenant binds to at most one non-disabled connection.
            activeTenantKey: `${provider}:${tenantId}`.slice(0, 100),
            rowVersion: { increment: 1 },
          },
        });
        await systemAudit(tx, {
          organizationId,
          action: 'integration.tenant_bound',
          resourceId: connection.publicId,
          correlationId,
          metadata: {
            connectionId: connection.publicId,
            grantId: grant.publicId,
            provider,
            authMethod: grant.authMethod,
            provenDomains: proven,
          },
          at: now,
        });
        await evaluateBinding(tx, connectionId, { now, correlationId });
      });
      return 'bound';
    } catch (error) {
      const code = isUniqueViolation(error)
        ? ('tenant_bound_elsewhere' as const)
        : error instanceof BindingRefused
          ? error.code
          : null;
      if (code === null) throw error;
      if (code === 'skipped') return 'skipped';
      await this.refuse(connection, grant, code, correlationId);
      return code;
    }
  }

  private async evaluate(connectionId: bigint, correlationId: string): Promise<void> {
    const now = this.options.now();
    await this.writer.$transaction((tx) =>
      evaluateBinding(tx, connectionId, { now, correlationId }),
    );
  }

  /** The grant errs with the refusal code (it may be re-verified after the cause is fixed). */
  private async refuse(
    connection: { publicId: string; organizationId: bigint; provider: string },
    grant: { id: bigint; publicId: string; profile: string },
    code: 'tenant_bound_elsewhere' | 'tenant_mismatch',
    correlationId: string,
  ): Promise<void> {
    const now = this.options.now();
    await this.writer.$transaction(async (tx) => {
      const changed = await tx.providerConnectionGrant.updateMany({
        where: { id: grant.id, organizationId: connection.organizationId, status: 'active' },
        data: {
          status: 'error',
          lastErrorCode: code,
          consecutiveFailures: { increment: 1 },
          rowVersion: { increment: 1 },
        },
      });
      if (changed.count === 0) return;
      await systemAudit(tx, {
        organizationId: connection.organizationId,
        action: 'integration.grant_verification_failed',
        resourceId: connection.publicId,
        correlationId,
        metadata: {
          connectionId: connection.publicId,
          grantId: grant.publicId,
          provider: connection.provider,
          profile: grant.profile,
          errorCode: code,
        },
        at: now,
      });
    });
    this.options.logger.warn(
      { connectionId: connection.publicId, grantId: grant.publicId, errorCode: code },
      'provider tenant not bound',
    );
  }
}
