import { randomUUID } from 'node:crypto';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import {
  comparePermissions,
  type GrantRef,
  type IntegrationProvider,
  profileByKey,
  type ProviderAuthMethod,
} from '@email-gateway/provider-integrations';
import type { CheckRunner } from '../checks/checks';
import { loadConnection } from '../checks/context';
import type { IntegrationMetrics } from '../metrics/integration-metrics';
import type { ProviderRuntime } from '../providers/provider-runtime';
import { orgFilter, systemAudit } from '../shared/db';
import {
  errorCode,
  errorFields,
  isTransientProviderError,
  isUniqueViolation,
} from '../shared/errors';
import { evaluateBinding } from './binding';
import type { TenantBinder } from './tenant-binding';

/** A verification is retried this often on provider unavailability before the grant errs. */
export const VERIFY_MAX_TRANSIENT_FAILURES = 8;
/** Lease of a claimed verification (a crashed worker's claim expires). */
export const VERIFY_LEASE_MS = 120_000;
const RETRY_BASE_MS = 30_000;
const RETRY_MAX_MS = 30 * 60_000;

export type VerificationResult = 'active' | 'error' | 'retry' | 'lost' | 'skipped';

interface ClaimedGrant {
  id: bigint;
  organizationId: bigint;
  connectionId: bigint;
}

class VerificationFailure extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = 'VerificationFailure';
  }
}

export interface GrantVerifierOptions {
  runtime: ProviderRuntime;
  checks: CheckRunner;
  binder: TenantBinder;
  metrics: IntegrationMetrics;
  logger: Logger;
  now: () => Date;
  organizationIds?: readonly bigint[];
}

/**
 * D3.4, D4, I10 (tasks role): verifies grants in `verifying`. Claims with `FOR UPDATE SKIP
 * LOCKED` and a lease; for each grant: a fresh token for the claimed (Microsoft) or delegated
 * (Google) tenant, the provider tenant identity (must equal the claim and any earlier binding),
 * the permission comparison (missing = error, excess = recorded and reported by health). Success
 * makes the grant `active` in one transaction with its audit row; the tenant stays a CLAIM (the
 * connection `configuring`, its linked domains re-checked) until `TenantBinder` binds it on proof
 * of control: a linked, TXT-verified gateway domain verified in that tenant (the tenant fields and
 * the platform-wide unique `active_tenant_key`; a duplicate makes the grant `error`
 * `tenant_bound_elsewhere`), then I10. A connection that is already bound to the same tenant stays
 * bound (re-verification). Provider unavailability keeps the grant `verifying` with back-off.
 */
export class GrantVerifier {
  constructor(
    private readonly writer: PrismaClient,
    private readonly options: GrantVerifierOptions,
  ) {}

  /** Claims up to `limit` grants and verifies them; returns the number claimed. */
  async runOnce(limit: number, signal: AbortSignal): Promise<number> {
    const claimed = await this.claim(limit);
    for (const grant of claimed) {
      if (signal.aborted) break;
      await this.verify(grant, signal).catch((error: unknown) => {
        this.options.logger.warn(
          { grantId: grant.id.toString(), ...errorFields(error) },
          'grant verification failed unexpectedly; retried after the lease',
        );
      });
    }
    return claimed.length;
  }

  async claim(limit: number): Promise<ClaimedGrant[]> {
    const now = this.options.now();
    const until = new Date(now.getTime() + VERIFY_LEASE_MS);
    return this.writer.$transaction(async (tx) => {
      const rows = await tx.$queryRaw<
        Array<{ id: bigint; organization_id: bigint; connection_id: bigint }>
      >`SELECT g.id, g.organization_id, g.connection_id
          FROM provider_connection_grants g
         WHERE g.status = 'verifying'
           AND (g.verify_claimed_until IS NULL OR g.verify_claimed_until < ${now})
           ${orgFilter('g.organization_id', this.options.organizationIds)}
         ORDER BY g.verify_requested_at, g.id
         LIMIT ${limit}
         FOR UPDATE SKIP LOCKED`;
      if (rows.length === 0) return [];
      await tx.providerConnectionGrant.updateMany({
        where: { id: { in: rows.map((r) => BigInt(r.id)) } },
        data: { verifyClaimedUntil: until },
      });
      return rows.map((r) => ({
        id: BigInt(r.id),
        organizationId: BigInt(r.organization_id),
        connectionId: BigInt(r.connection_id),
      }));
    });
  }

  async verify(claimed: ClaimedGrant, signal: AbortSignal): Promise<VerificationResult> {
    const grant = await this.writer.providerConnectionGrant.findFirst({
      where: { id: claimed.id, organizationId: claimed.organizationId, status: 'verifying' },
      select: {
        id: true,
        publicId: true,
        profile: true,
        authMethod: true,
        claimedTenantId: true,
        consecutiveFailures: true,
        rowVersion: true,
        connection: {
          select: {
            id: true,
            publicId: true,
            organizationId: true,
            provider: true,
            status: true,
            externalTenantId: true,
          },
        },
      },
    });
    if (!grant || grant.connection.organizationId !== claimed.organizationId) return 'skipped';
    const connection = grant.connection;
    const provider = connection.provider;
    const correlationId = randomUUID();
    const report = (result: VerificationResult) => {
      this.options.metrics.grantVerifications.inc({ provider, result });
      return result;
    };
    if (connection.status === 'disabled') {
      return report(
        await this.fail(grant, claimed, 'connection_disabled', correlationId, { provider }),
      );
    }
    const ref: GrantRef = {
      organizationId: claimed.organizationId,
      connectionPublicId: connection.publicId,
      profile: grant.profile,
    };
    const profile = profileByKey(grant.profile);
    try {
      if (!profile || profile.provider !== provider)
        throw new VerificationFailure('profile_unknown');
      // A verification always uses a fresh token (new consent, new credential).
      this.options.runtime.tokens.invalidate(grant.publicId);
      const token = await this.options.runtime.tokens.getAccessToken(ref, signal);
      const tenant = await this.options.runtime.directories[provider].tenant(ref, signal);
      const tenantId =
        provider === 'microsoft_365' ? tenant.tenantId.toLowerCase() : tenant.tenantId;
      if (
        provider === 'microsoft_365' &&
        grant.claimedTenantId &&
        grant.claimedTenantId.toLowerCase() !== tenantId
      ) {
        throw new VerificationFailure('tenant_mismatch');
      }
      if (connection.externalTenantId && connection.externalTenantId !== tenantId) {
        throw new VerificationFailure('tenant_mismatch');
      }
      const { missing, excess } = comparePermissions(profile, token.observedPermissions);
      if (missing.length > 0) {
        return report(
          await this.fail(grant, claimed, 'permissions_missing', correlationId, {
            provider,
            permissions: { observed: token.observedPermissions, missing, excess },
          }),
        );
      }
      const outcome = await this.bind(grant, claimed, {
        provider,
        tenantId,
        tenantName: tenant.displayName,
        observed: token.observedPermissions,
        excess,
        correlationId,
      });
      if (outcome === 'active') {
        await this.checkDomains(claimed.connectionId, signal, correlationId).catch(
          (error: unknown) => {
            this.options.logger.warn(
              { connectionId: claimed.connectionId.toString(), ...errorFields(error) },
              'provider domain check or tenant binding after verification failed; retried',
            );
          },
        );
      }
      return report(outcome);
    } catch (error) {
      if (error instanceof VerificationFailure) {
        return report(await this.fail(grant, claimed, error.code, correlationId, { provider }));
      }
      if (
        isTransientProviderError(error) &&
        grant.consecutiveFailures + 1 < VERIFY_MAX_TRANSIENT_FAILURES
      ) {
        await this.retryLater(grant, claimed);
        return report('retry');
      }
      return report(await this.fail(grant, claimed, errorCode(error), correlationId, { provider }));
    }
  }

  private async bind(
    grant: {
      id: bigint;
      publicId: string;
      profile: string;
      authMethod: ProviderAuthMethod;
      rowVersion: number;
      connection: { id: bigint; publicId: string };
    },
    claimed: ClaimedGrant,
    facts: {
      provider: IntegrationProvider;
      tenantId: string;
      tenantName: string;
      observed: string[];
      excess: string[];
      correlationId: string;
    },
  ): Promise<VerificationResult> {
    const now = this.options.now();
    let bound = false;
    try {
      return await this.writer.$transaction(async (tx) => {
        const version = await this.options.runtime.grants.updateGrantStatus(
          grant.id,
          grant.rowVersion,
          {
            status: 'active',
            lastErrorCode: null,
            observedPermissions: [...facts.observed].sort(),
            missingPermissions: null,
            excessPermissions: facts.excess.length > 0 ? facts.excess : null,
            verifiedAt: now,
            verifyClaimedUntil: null,
            lastTokenAt: now,
            consecutiveFailures: 'reset',
          },
          tx,
        );
        if (version === null) return 'lost' as const;
        const [conn] = await tx.$queryRaw<
          Array<{
            status: string;
            external_tenant_id: string | null;
            active_tenant_key: string | null;
          }>
        >`
          SELECT status, external_tenant_id, active_tenant_key FROM provider_connections
           WHERE id = ${claimed.connectionId} AND organization_id = ${claimed.organizationId}
           FOR UPDATE`;
        if (!conn || conn.status === 'disabled')
          throw new VerificationFailure('connection_disabled');
        if (conn.external_tenant_id && conn.external_tenant_id !== facts.tenantId) {
          throw new VerificationFailure('tenant_mismatch');
        }
        bound = conn.active_tenant_key !== null && conn.external_tenant_id === facts.tenantId;
        await tx.providerConnection.updateMany({
          where: { id: claimed.connectionId, organizationId: claimed.organizationId },
          data: bound
            ? {
                // Re-verification of a bound connection (new credential, new consent).
                externalTenantName: facts.tenantName.slice(0, 256),
                tenantVerifiedAt: now,
                rowVersion: { increment: 1 },
              }
            : {
                // The tenant is only CLAIMED until a linked domain proves control
                // (TenantBinder): nothing about it is stored on the connection yet.
                ...(conn.status === 'draft' || conn.status === 'connecting'
                  ? { status: 'configuring' as const }
                  : {}),
                rowVersion: { increment: 1 },
              },
        });
        if (!bound) {
          // Provider results of an earlier claim never count as proof: every link is re-checked.
          await tx.providerConnectionDomain.updateMany({
            where: { connectionId: claimed.connectionId, organizationId: claimed.organizationId },
            data: { providerVerification: 'unknown', providerCheckedAt: null },
          });
        }
        await systemAudit(tx, {
          organizationId: claimed.organizationId,
          action: 'integration.grant_verified',
          resourceId: grant.connection.publicId,
          correlationId: facts.correlationId,
          metadata: {
            connectionId: grant.connection.publicId,
            grantId: grant.publicId,
            provider: facts.provider,
            profile: grant.profile,
            authMethod: grant.authMethod,
            excessPermissions: facts.excess,
            tenantBinding: bound ? 'bound' : 'pending_domain_proof',
          },
          at: now,
        });
        if (bound) {
          await evaluateBinding(tx, claimed.connectionId, {
            now,
            correlationId: facts.correlationId,
          });
        }
        return 'active' as const;
      });
    } catch (error) {
      if (isUniqueViolation(error)) {
        return this.fail(grant, claimed, 'tenant_bound_elsewhere', facts.correlationId, {
          provider: facts.provider,
        });
      }
      if (error instanceof VerificationFailure) {
        return this.fail(grant, claimed, error.code, facts.correlationId, {
          provider: facts.provider,
        });
      }
      throw error;
    }
  }

  private async retryLater(
    grant: { id: bigint; consecutiveFailures: number },
    claimed: ClaimedGrant,
  ): Promise<void> {
    const delay = Math.min(RETRY_MAX_MS, RETRY_BASE_MS * 2 ** grant.consecutiveFailures);
    await this.writer.providerConnectionGrant.updateMany({
      where: { id: grant.id, organizationId: claimed.organizationId, status: 'verifying' },
      data: {
        verifyClaimedUntil: new Date(this.options.now().getTime() + delay),
        consecutiveFailures: { increment: 1 },
        lastErrorCode: 'provider_unavailable',
      },
    });
  }

  /** The grant ends `error` with a code (re-read row_version: the CAS may have moved). */
  private async fail(
    grant: { id: bigint; publicId: string; profile: string; connection: { publicId: string } },
    claimed: ClaimedGrant,
    code: string,
    correlationId: string,
    extra: {
      provider: IntegrationProvider;
      permissions?: { observed: string[]; missing: string[]; excess: string[] };
    },
  ): Promise<VerificationResult> {
    const now = this.options.now();
    return this.writer.$transaction(async (tx) => {
      const current = await tx.providerConnectionGrant.findFirst({
        where: { id: grant.id, organizationId: claimed.organizationId },
        select: { status: true, rowVersion: true },
      });
      if (!current || current.status !== 'verifying') return 'lost' as const;
      const version = await this.options.runtime.grants.updateGrantStatus(
        grant.id,
        current.rowVersion,
        {
          status: 'error',
          lastErrorCode: code.slice(0, 64),
          verifyClaimedUntil: null,
          consecutiveFailures: 'increment',
          ...(extra.permissions
            ? {
                observedPermissions: [...extra.permissions.observed].sort(),
                missingPermissions: extra.permissions.missing,
                excessPermissions:
                  extra.permissions.excess.length > 0 ? extra.permissions.excess : null,
              }
            : {}),
        },
        tx,
      );
      if (version === null) return 'lost' as const;
      await systemAudit(tx, {
        organizationId: claimed.organizationId,
        action: 'integration.grant_verification_failed',
        resourceId: grant.connection.publicId,
        correlationId,
        metadata: {
          connectionId: grant.connection.publicId,
          grantId: grant.publicId,
          provider: extra.provider,
          profile: grant.profile,
          errorCode: code.slice(0, 64),
          ...(extra.permissions ? { missingPermissions: extra.permissions.missing } : {}),
        },
        at: now,
      });
      return 'error' as const;
    });
  }

  /**
   * Provider domain checks right after the grant verification, then the tenant binding on proof
   * of control and I10 (D4, `TenantBinder`). Failures are retried by the domain-check task.
   */
  private async checkDomains(
    connectionId: bigint,
    signal: AbortSignal,
    correlationId: string,
  ): Promise<void> {
    const connection = await loadConnection(this.writer, connectionId);
    if (!connection) return;
    if (connection.domains.length > 0) {
      await this.options.checks.checkProviderDomains(connection, signal);
    }
    await this.options.binder.settle(connectionId, signal, correlationId);
  }
}
