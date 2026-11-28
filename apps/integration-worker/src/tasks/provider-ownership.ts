import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import {
  type GrantRef,
  type IntegrationProvider,
  isMailFlowGrant,
  type ProviderDomainStatus,
} from '@email-gateway/provider-integrations';
import type { IntegrationMetrics } from '../metrics/integration-metrics';
import type { ProviderRuntime } from '../providers/provider-runtime';
import { orgFilter } from '../shared/db';
import { errorCode, errorFields } from '../shared/errors';

/** A claimed row whose check was interrupted (crash, abort) is claimed again after this. */
export const PROVIDER_OWNERSHIP_RETRY_MS = 60_000;
/** Rows read per claim for each slot of the batch (one check per connection per tick). */
const CLAIM_OVERSCAN = 5;

/** `domain_verifications.provider_result` (Prisma `DomainProviderCheckResult`). */
export type ProviderOwnershipResult = 'verified' | 'unverified' | 'absent' | 'alias' | 'error';

/**
 * Codes written to `provider_error_code` when the check is refused before any provider call
 * (B3.3: the preconditions are re-checked by the worker; the api's request only chose the row).
 */
export type OwnershipPreconditionCode =
  | 'organization_mismatch'
  | 'domain_not_pending'
  | 'connection_not_found'
  | 'connection_disabled'
  | 'connection_not_bound'
  | 'mail_flow_grant_inactive';

/** What one row's check did (tests, logs). */
export interface ProviderOwnershipOutcome {
  verificationId: bigint;
  result: ProviderOwnershipResult | 'skipped';
  errorCode: string | null;
}

class Precondition extends Error {
  constructor(readonly code: OwnershipPreconditionCode) {
    super(code);
    this.name = 'OwnershipPrecondition';
  }
}

/**
 * Domain ownership through the organization's bound provider tenant (step API-4 B3.3,
 * ADR-0107; tasks role). Claims pending `domain_verifications` rows of method `provider_tenant`
 * that have no provider answer yet (`provider_checked_at IS NULL`, `FOR UPDATE SKIP LOCKED`, at
 * most `batch` rows and at most one per provider connection per tick); `last_checked_at` and
 * `attempts` record the claim, so an interrupted check is claimed again after a minute, never in
 * a tight loop. For each row it re-checks the organization echo of the verification, domain and
 * connection rows, that the domain is still `pending_verification`, that the connection is bound
 * on proof of control (`external_tenant_id`, `tenant_verified_at`, `active_tenant_key`) and not
 * `disabled`, and that its read-only `*.mail_flow` grant is `active`; then it asks the provider
 * through the existing directory (`ProviderDirectory.domain`, the 8.2 Graph / Admin SDK clients
 * with their retry and `Retry-After` rules). It writes only `provider_result` (`verified` only
 * when Microsoft lists the domain as verified with `Email` in `supportedServices`, or Google as a
 * verified primary or secondary domain — the directory's own rule; `unverified`, `absent`,
 * `alias` as reported; a refused precondition or a provider / HTTP failure is `error` with
 * `provider_error_code`) and `provider_checked_at`. It never changes the domain row: the api's
 * `DomainCheckScheduler` applies the ownership win (B3.4). Logs carry public ids and codes only
 * (never a token, credential or provider body).
 */
export class ProviderOwnershipTask {
  constructor(
    private readonly writer: PrismaClient,
    private readonly options: {
      runtime: ProviderRuntime;
      metrics: IntegrationMetrics;
      logger: Logger;
      now: () => Date;
      /** PROVIDER_OWNERSHIP_CHECK_BATCH. */
      batch: number;
      organizationIds?: readonly bigint[];
    },
  ) {}

  /** One pass: claims and checks; returns the outcome of every claimed row. */
  async runOnce(signal: AbortSignal): Promise<ProviderOwnershipOutcome[]> {
    const claimed = await this.claim();
    const out: ProviderOwnershipOutcome[] = [];
    for (const id of claimed) {
      if (signal.aborted) break;
      try {
        out.push(await this.check(id, signal));
      } catch (error) {
        // A database failure: the claim stamp makes the row eligible again after the delay.
        this.options.logger.warn(
          { verificationId: id.toString(), ...errorFields(error) },
          'provider ownership check failed; retried',
        );
      }
    }
    return out;
  }

  /** Claims up to `batch` unchecked rows, at most one per provider connection. */
  private async claim(): Promise<bigint[]> {
    const now = this.options.now();
    const retryBefore = new Date(now.getTime() - PROVIDER_OWNERSHIP_RETRY_MS);
    const batch = this.options.batch;
    return this.writer.$transaction(async (tx) => {
      const rows = await tx.$queryRaw<Array<{ id: bigint; provider_connection_id: bigint | null }>>`
        SELECT id, provider_connection_id
          FROM domain_verifications
         WHERE method = 'provider_tenant'
           AND status = 'pending'
           AND provider_checked_at IS NULL
           AND expires_at > ${now}
           AND (last_checked_at IS NULL OR last_checked_at < ${retryBefore})
           ${orgFilter('organization_id', this.options.organizationIds)}
         ORDER BY id
         LIMIT ${batch * CLAIM_OVERSCAN}
         FOR UPDATE SKIP LOCKED`;
      const seen = new Set<string>();
      const chosen: bigint[] = [];
      for (const row of rows) {
        const id = BigInt(row.id);
        // Rows without a connection are refused one by one (each is its own "connection").
        const key =
          row.provider_connection_id === null
            ? `row:${id.toString()}`
            : BigInt(row.provider_connection_id).toString();
        if (seen.has(key)) continue;
        seen.add(key);
        chosen.push(id);
        if (chosen.length >= batch) break;
      }
      if (chosen.length === 0) return [];
      await tx.domainVerification.updateMany({
        where: { id: { in: chosen }, method: 'provider_tenant', providerCheckedAt: null },
        data: { lastCheckedAt: now, attempts: { increment: 1 } },
      });
      return chosen;
    });
  }

  private async check(id: bigint, signal: AbortSignal): Promise<ProviderOwnershipOutcome> {
    const verification = await this.writer.domainVerification.findUnique({
      where: { id },
      select: {
        id: true,
        organizationId: true,
        domainId: true,
        method: true,
        status: true,
        providerConnectionId: true,
        providerCheckedAt: true,
      },
    });
    if (
      verification === null ||
      verification.id !== id ||
      verification.method !== 'provider_tenant' ||
      verification.status !== 'pending' ||
      verification.providerCheckedAt !== null
    ) {
      return { verificationId: id, result: 'skipped', errorCode: null };
    }
    const organizationId = verification.organizationId;
    let provider: IntegrationProvider | 'unknown' = 'unknown';
    let domainPublicId: string | null = null;
    let connectionPublicId: string | null = null;
    let result: ProviderOwnershipResult;
    let code: string | null = null;
    try {
      const domain = await this.writer.domain.findUnique({
        where: { id: verification.domainId },
        select: { id: true, organizationId: true, publicId: true, name: true, status: true },
      });
      if (
        domain === null ||
        domain.id !== verification.domainId ||
        domain.organizationId !== organizationId
      ) {
        throw new Precondition('organization_mismatch');
      }
      domainPublicId = domain.publicId;
      if (domain.status !== 'pending_verification') throw new Precondition('domain_not_pending');
      if (verification.providerConnectionId === null) {
        throw new Precondition('connection_not_found');
      }
      const connection = await this.writer.providerConnection.findUnique({
        where: { id: verification.providerConnectionId },
        select: {
          id: true,
          publicId: true,
          organizationId: true,
          provider: true,
          status: true,
          externalTenantId: true,
          tenantVerifiedAt: true,
          activeTenantKey: true,
          grants: {
            where: { status: 'active' },
            select: { organizationId: true, profile: true, status: true },
            orderBy: { id: 'asc' },
          },
        },
      });
      if (connection === null || connection.id !== verification.providerConnectionId) {
        throw new Precondition('connection_not_found');
      }
      if (connection.organizationId !== organizationId) {
        throw new Precondition('organization_mismatch');
      }
      provider = connection.provider;
      connectionPublicId = connection.publicId;
      if (connection.status === 'disabled') throw new Precondition('connection_disabled');
      if (
        connection.externalTenantId === null ||
        connection.tenantVerifiedAt === null ||
        connection.activeTenantKey === null
      ) {
        throw new Precondition('connection_not_bound');
      }
      const grant = connection.grants.find(
        (g) => g.organizationId === organizationId && g.status === 'active' && isMailFlowGrant(g),
      );
      if (!grant) throw new Precondition('mail_flow_grant_inactive');
      const ref: GrantRef = {
        organizationId,
        connectionPublicId: connection.publicId,
        profile: grant.profile,
      };
      try {
        const status: ProviderDomainStatus = await this.options.runtime.directories[
          connection.provider
        ].domain(ref, domain.name, signal);
        result = status.status;
      } catch (error) {
        if (signal.aborted) throw error;
        result = 'error';
        code = errorCode(error, 'provider_error');
      }
    } catch (error) {
      if (!(error instanceof Precondition)) throw error;
      result = 'error';
      code = error.code;
    }

    const now = this.options.now();
    const written = await this.writer.domainVerification.updateMany({
      where: {
        id,
        organizationId,
        method: 'provider_tenant',
        status: 'pending',
        providerCheckedAt: null,
      },
      data: { providerResult: result, providerCheckedAt: now, providerErrorCode: code },
    });
    if (written.count === 0) return { verificationId: id, result: 'skipped', errorCode: null };
    this.options.metrics.ownershipChecks.inc({ provider, result });
    this.options.logger.info(
      { domainId: domainPublicId, connectionId: connectionPublicId, provider, result, code },
      'provider ownership check recorded',
    );
    return { verificationId: id, result, errorCode: code };
  }
}
