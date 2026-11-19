import { type Prisma } from '@email-gateway/database';
import {
  isMailFlowGrant,
  type ProviderConnectionStatus,
} from '@email-gateway/provider-integrations';
import { systemAudit } from '../shared/db';

/** Statuses that are still being set up (I10 may promote them). */
const SETUP_STATUSES: ReadonlySet<ProviderConnectionStatus> = new Set([
  'draft',
  'connecting',
  'configuring',
]);

export interface BindingOutcome {
  from: ProviderConnectionStatus;
  to: ProviderConnectionStatus;
}

/**
 * I10 (D4): a connection becomes `active` only when its mail-flow grant is `active`, the provider
 * tenant is bound on proof of control (`active_tenant_key`, set by `TenantBinder`), and at least
 * one linked domain is `active` at the gateway (TXT-verified) **and** `verified` in the provider
 * tenant; with the grant and tenant but no such domain it is
 * `configuring`. Runs inside the caller's transaction with the connection row locked. Never
 * demotes an `active` connection (health reports problems, I1) and never touches `disabled`.
 * A status change bumps `row_version` (it binds impact tokens) and is audited
 * (`integration.connection_bound`, actor system). Returns the change, or null.
 */
export async function evaluateBinding(
  tx: Prisma.TransactionClient,
  connectionId: bigint,
  input: { now: Date; correlationId: string },
): Promise<BindingOutcome | null> {
  const [row] = await tx.$queryRaw<
    Array<{
      organization_id: bigint;
      public_id: string;
      provider: string;
      status: ProviderConnectionStatus;
      external_tenant_id: string | null;
      tenant_verified_at: Date | null;
      active_tenant_key: string | null;
      next_health_check_at: Date | null;
    }>
  >`SELECT organization_id, public_id, provider, status, external_tenant_id, tenant_verified_at,
           active_tenant_key, next_health_check_at
      FROM provider_connections WHERE id = ${connectionId} FOR UPDATE`;
  if (!row || !SETUP_STATUSES.has(row.status)) return null;
  const organizationId = BigInt(row.organization_id);
  const grants = await tx.providerConnectionGrant.findMany({
    where: { connectionId, organizationId, status: 'active' },
    select: { profile: true },
  });
  const grantActive = grants.some((g) => isMailFlowGrant(g));
  // Bound = proven (TenantBinder): a tenant id left over from a released binding does not count.
  const tenantVerified =
    row.external_tenant_id !== null &&
    row.tenant_verified_at !== null &&
    row.active_tenant_key !== null;
  if (!grantActive || !tenantVerified) return null;
  const verifiedDomains = await tx.providerConnectionDomain.count({
    where: {
      connectionId,
      organizationId,
      providerVerification: 'verified',
      domain: { organizationId, status: 'active' },
    },
  });
  const next: ProviderConnectionStatus = verifiedDomains > 0 ? 'active' : 'configuring';
  if (next === row.status) return null;
  await tx.providerConnection.updateMany({
    where: { id: connectionId, organizationId },
    data: {
      status: next,
      rowVersion: { increment: 1 },
      // The health role starts checking a bound connection at once.
      ...(row.next_health_check_at === null ? { nextHealthCheckAt: input.now } : {}),
    },
  });
  await systemAudit(tx, {
    organizationId,
    action: 'integration.connection_bound',
    resourceId: row.public_id,
    correlationId: input.correlationId,
    metadata: {
      connectionId: row.public_id,
      provider: row.provider,
      fromStatus: row.status,
      status: next,
      verifiedDomains,
    },
    at: input.now,
  });
  return { from: row.status, to: next };
}
