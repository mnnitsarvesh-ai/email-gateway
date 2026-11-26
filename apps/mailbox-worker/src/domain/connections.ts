import { uuidv7 } from '@email-gateway/common';
import type {
  ApiModeFeedMode,
  ApiModeHealthStatus,
  ApiModeInventoryStatus,
  IntegrationProvider,
  ProviderConnectionStatus,
  ProviderGrantStatus,
} from '@email-gateway/database';
import { MAILBOX_PROFILE_KEYS } from '@email-gateway/mailbox-api';
import type { Db } from '../shared/db';
import { InconsistentReadError } from '../shared/errors';

/** The `*.mailbox_remediation` profile of a provider (D4). */
export const mailboxProfileOf = (provider: IntegrationProvider): string =>
  MAILBOX_PROFILE_KEYS[provider];

export interface ApiConnectionRef {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  provider: IntegrationProvider;
}

export interface MailboxGrant {
  publicId: string;
  profile: string;
  status: ProviderGrantStatus;
  /** Google: the delegated administrator (Directory subject). */
  subjectEmail: string | null;
}

/** Everything the feeds, inventory and health roles re-check about one API connection. */
export interface ConnectionContext extends ApiConnectionRef {
  providerConnectionId: bigint;
  providerConnectionPublicId: string;
  providerConnectionStatus: ProviderConnectionStatus;
  /** 8.2 I10: the tenant is bound (`active_tenant_key` and `external_tenant_id` set). */
  bound: boolean;
  feedsEnabled: boolean;
  feedMode: ApiModeFeedMode;
  inventoryStatus: ApiModeInventoryStatus;
  healthStatus: ApiModeHealthStatus;
  healthAlertedAt: Date | null;
  throttledUntil: Date | null;
  grant: MailboxGrant | null;
  /** Domains linked to the 8.2 connection (`provider_connection_domains`). */
  linkedDomainIds: bigint[];
}

/** The connection may call providers: 8.2 connection active and bound, grant active. */
export const connectionUsable = (ctx: ConnectionContext): boolean =>
  ctx.providerConnectionStatus === 'active' && ctx.bound;

export const grantActive = (ctx: ConnectionContext): boolean => ctx.grant?.status === 'active';

/**
 * The API-mode row of an 8.2 provider connection, created lazily (D7 step 1, §3.2): `INSERT
 * IGNORE` on the unique `provider_connection_id`, then the row. The provider connection must
 * belong to `organizationId` (tenant from trusted rows only, N3); null otherwise.
 */
export async function ensureApiConnection(
  db: Db,
  providerConnectionId: bigint,
  organizationId: bigint,
): Promise<ApiConnectionRef | null> {
  const pc = await db.providerConnection.findUnique({
    where: { id: providerConnectionId },
    select: { id: true, organizationId: true, provider: true },
  });
  if (!pc || pc.organizationId !== organizationId) return null;
  const existing = await db.apiModeConnection.findUnique({
    where: { providerConnectionId },
    select: { id: true, publicId: true, organizationId: true, provider: true },
  });
  if (existing) {
    if (existing.organizationId !== organizationId) {
      throw new InconsistentReadError('api_mode_connections');
    }
    return existing;
  }
  await db.$executeRaw`
    INSERT IGNORE INTO api_mode_connections
      (public_id, organization_id, provider_connection_id, provider, created_at, updated_at)
    VALUES (${uuidv7()}, ${organizationId}, ${providerConnectionId}, ${pc.provider}, NOW(3), NOW(3))`;
  const row = await db.apiModeConnection.findUnique({
    where: { providerConnectionId },
    select: { id: true, publicId: true, organizationId: true, provider: true },
  });
  if (!row || row.organizationId !== organizationId) {
    throw new InconsistentReadError('api_mode_connections');
  }
  return row;
}

/** The context of one API connection (writer reads, organization echo-checked); null if gone. */
export async function loadConnectionContext(
  db: Db,
  apiConnectionId: bigint,
): Promise<ConnectionContext | null> {
  const row = await db.apiModeConnection.findUnique({
    where: { id: apiConnectionId },
    select: {
      id: true,
      publicId: true,
      organizationId: true,
      provider: true,
      feedsEnabled: true,
      feedMode: true,
      inventoryStatus: true,
      healthStatus: true,
      healthAlertedAt: true,
      throttledUntil: true,
      providerConnection: {
        select: {
          id: true,
          publicId: true,
          organizationId: true,
          provider: true,
          status: true,
          activeTenantKey: true,
          externalTenantId: true,
          domains: { select: { domainId: true, organizationId: true } },
        },
      },
    },
  });
  if (!row) return null;
  const pc = row.providerConnection;
  if (pc.organizationId !== row.organizationId || pc.provider !== row.provider) {
    throw new InconsistentReadError('provider_connections');
  }
  const profile = mailboxProfileOf(row.provider);
  const grant = await db.providerConnectionGrant.findUnique({
    where: { connectionId_profile: { connectionId: pc.id, profile } },
    select: {
      publicId: true,
      profile: true,
      status: true,
      subjectEmail: true,
      organizationId: true,
    },
  });
  if (grant && grant.organizationId !== row.organizationId) {
    throw new InconsistentReadError('provider_connection_grants');
  }
  return {
    id: row.id,
    publicId: row.publicId,
    organizationId: row.organizationId,
    provider: row.provider,
    providerConnectionId: pc.id,
    providerConnectionPublicId: pc.publicId,
    providerConnectionStatus: pc.status,
    bound: pc.activeTenantKey !== null && pc.externalTenantId !== null,
    feedsEnabled: row.feedsEnabled,
    feedMode: row.feedMode,
    inventoryStatus: row.inventoryStatus,
    healthStatus: row.healthStatus,
    healthAlertedAt: row.healthAlertedAt,
    throttledUntil: row.throttledUntil,
    grant: grant
      ? {
          publicId: grant.publicId,
          profile: grant.profile,
          status: grant.status,
          subjectEmail: grant.subjectEmail?.toLowerCase() ?? null,
        }
      : null,
    linkedDomainIds: pc.domains
      .filter((d) => d.organizationId === row.organizationId)
      .map((d) => d.domainId),
  };
}

/**
 * D4 revocation handling: the mailbox-access grant is not `active`. Feeds stop (`feed_status =
 * revoked`, cursors, subscription ids and client-state hashes cleared; Graph subscriptions expire
 * at the provider and their notifications no longer match), inventory stops (`inventory_status =
 * unavailable`). Journal detect scanning is unaffected. Idempotent; returns the mailboxes changed.
 */
export async function applyGrantRevocation(
  db: Db,
  ctx: Pick<ConnectionContext, 'id' | 'organizationId' | 'grant'>,
  now: Date,
): Promise<number> {
  const code = ctx.grant === null ? 'mailbox_access_missing' : `mailbox_access_${ctx.grant.status}`;
  const changed = await db.$executeRaw`
    UPDATE api_mailboxes
    SET feed_status = 'revoked', feed_cursor = NULL, subscription_id = NULL,
        subscription_expires_at = NULL, client_state_hash = NULL, sync_requested_at = NULL,
        next_sync_at = NULL, lease_until = NULL, last_error_code = ${code}, updated_at = ${now}
    WHERE api_connection_id = ${ctx.id} AND organization_id = ${ctx.organizationId}
      AND (feed_status NOT IN ('off', 'revoked') OR subscription_id IS NOT NULL
           OR feed_cursor IS NOT NULL)`;
  await db.$executeRaw`
    UPDATE api_mode_connections
    SET inventory_status = 'unavailable', inventory_requested_at = NULL,
        last_error_code = ${code}, updated_at = ${now}
    WHERE id = ${ctx.id} AND organization_id = ${ctx.organizationId}
      AND (inventory_status <> 'unavailable' OR inventory_requested_at IS NOT NULL
           OR last_error_code IS NULL OR last_error_code <> ${code})`;
  return changed;
}
