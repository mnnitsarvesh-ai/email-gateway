import { uuidv7 } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import {
  API_FAMILIES,
  identityHash,
  providerActionStateSchema,
  validateActionState,
  type ActionStateStore,
  type ApiFamily,
  type MailboxItemKind,
  type MailboxItemRow,
  type MailboxItemWrite,
  type MailboxStateStore,
  type ProviderActionState,
  type ProviderIdentityRef,
  type RateBudget,
} from '@email-gateway/idp-adapters';
import { sha256Hex } from '@email-gateway/ato-detection';
import { big } from '../shared/db';
import { InconsistentReadError } from '../shared/errors';

const DAY_MS = 86_400_000;

/** A MySQL deadlock (1213), lock wait timeout (1205) or Prisma's write conflict (P2034). */
export function isLockConflict(error: unknown): boolean {
  const e = error as { code?: unknown; meta?: { code?: unknown }; message?: unknown } | null;
  if (e?.code === 'P2034') return true;
  const mysql = e?.meta?.code;
  if (mysql === '1213' || mysql === '1205' || mysql === 1213 || mysql === 1205) return true;
  return e?.code === 'P2010' && typeof e.message === 'string' && /\b(1213|1205)\b/.test(e.message);
}

/** Runs an idempotent statement again after a lost deadlock (at most three attempts). */
async function retryLockConflict<T>(fn: () => Promise<T>): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await fn();
    } catch (error) {
      if (attempt >= 3 || !isLockConflict(error)) throw error;
      await new Promise((resolve) => setTimeout(resolve, 25 * attempt + Math.random() * 50));
    }
  }
}
/** Removed items stay visible to diffs and the api for this long (D8.3, §5.2). */
export const REMOVED_ITEM_VISIBLE_DAYS = 30;
const MAX_TRAITS = 16;

/** The subset of an ioredis MULTI the rate budget uses. */
export interface BudgetPipeline {
  incr(key: string): BudgetPipeline;
  expire(key: string, seconds: number): BudgetPipeline;
  exec(): Promise<Array<[Error | null, unknown]> | null>;
}

/** The subset of ioredis the rate budget uses. */
export interface BudgetRedis {
  multi(): BudgetPipeline;
}

/**
 * `RateBudget` over Redis (D7.5): per integration, API family and epoch second one counter
 * `ato:idp:rb:{integrationId}:{family}:s{epochSecond}` (`INCR` + `EXPIRE 5`, one MULTI). A take
 * above the family's per-second limit answers `exhausted`; the adapter waits ≤ 1 s and then ends
 * the page early or fails the action `rate_budget` (retryable). Shared by every worker replica.
 */
export class RedisRateBudget implements RateBudget {
  constructor(
    private readonly redis: BudgetRedis,
    private readonly limits: Readonly<Record<ApiFamily, number>>,
    private readonly now: () => number = Date.now,
  ) {}

  static key(integrationId: string, family: ApiFamily, epochSecond: number): string {
    return `ato:idp:rb:${integrationId}:${family}:s${String(epochSecond)}`;
  }

  async take(
    integrationId: string,
    family: ApiFamily,
    _signal: AbortSignal,
  ): Promise<'ok' | 'exhausted'> {
    if (!/^[1-9][0-9]{0,19}$/.test(integrationId) || !API_FAMILIES.includes(family)) {
      throw new Error('rate_budget_key_invalid');
    }
    const key = RedisRateBudget.key(integrationId, family, Math.floor(this.now() / 1000));
    const result = await this.redis.multi().incr(key).expire(key, 5).exec();
    const count = Number(result?.[0]?.[1] ?? Number.NaN);
    if (!Number.isFinite(count)) throw new Error('rate_budget_unavailable');
    return count <= this.limits[family] ? 'ok' : 'exhausted';
  }
}

interface ItemRow {
  public_id: string;
  identity_external_id_hash: string;
  item_kind: MailboxItemKind;
  item_hash: string;
  provider_item_ref: string | null;
  target_domain: string | null;
  traits: unknown;
  enabled: number | boolean | null;
  state: 'present' | 'removed';
  source: 'snapshot' | 'audit';
  first_seen_at: Date;
  last_seen_at: Date;
  removed_at: Date | null;
  last_change: 'added' | 'changed' | 'removed';
  emitted_seq: bigint | number;
  organization_id: bigint | number;
  integration_id: bigint | number;
}

const traitsOf = (value: unknown): string[] => {
  const raw = typeof value === 'string' ? (JSON.parse(value) as unknown) : value;
  return Array.isArray(raw)
    ? raw.filter((t): t is string => typeof t === 'string').slice(0, MAX_TRAITS)
    : [];
};

const iso = (d: Date | string): string => new Date(d).toISOString();
const asDate = (value: string): Date => {
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) throw new Error('mailbox_item_time_invalid');
  return new Date(ms);
};

/**
 * `MailboxStateStore` over `ato_provider_mailbox_items` (D8.3, §5.2) for one integration of one
 * organization (every read is echo-checked). Items carry hashes, kinds, target domains and trait
 * codes only, never an address. Cursor-confirmed state: a write with a change sets `emitted_seq`
 * (the page's cursor seq) and `last_change`; an unchanged item only moves `last_seen_at` (and its
 * descriptive fields). The adapter treats rows with `emitted_seq` above the committed cursor's seq
 * as not yet known. `account_id` is filled from the identity mapping when it exists (the runner
 * fills it for identities it maps later in the page transaction).
 */
export class MysqlMailboxStateStore implements MailboxStateStore {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly scope: { organizationId: bigint; integrationId: bigint },
    private readonly now: () => Date = () => new Date(),
  ) {}

  private check(integrationId: string): bigint {
    if (integrationId !== this.scope.integrationId.toString()) {
      throw new InconsistentReadError('ato_provider_mailbox_items');
    }
    return this.scope.integrationId;
  }

  private row(r: ItemRow): MailboxItemRow {
    if (
      big(r.organization_id) !== this.scope.organizationId ||
      big(r.integration_id) !== this.scope.integrationId
    ) {
      throw new InconsistentReadError('ato_provider_mailbox_items');
    }
    return {
      publicId: r.public_id,
      identityHash: r.identity_external_id_hash,
      kind: r.item_kind,
      itemHash: r.item_hash,
      providerItemRef: r.provider_item_ref,
      targetDomain: r.target_domain,
      traits: traitsOf(r.traits),
      enabled: r.enabled === null ? null : Boolean(r.enabled),
      state: r.state,
      source: r.source,
      firstSeenAt: iso(r.first_seen_at),
      lastSeenAt: iso(r.last_seen_at),
      removedAt: r.removed_at ? iso(r.removed_at) : null,
      lastChange: r.last_change,
      emittedSeq: BigInt(r.emitted_seq),
    };
  }

  async load(integrationId: string, identityHashValue: string): Promise<MailboxItemRow[]> {
    const id = this.check(integrationId);
    const cutoff = new Date(this.now().getTime() - REMOVED_ITEM_VISIBLE_DAYS * DAY_MS);
    const rows = await this.prisma.$queryRaw<ItemRow[]>`
      SELECT public_id, identity_external_id_hash, item_kind, item_hash, provider_item_ref,
             target_domain, traits, enabled, state, source, first_seen_at, last_seen_at,
             removed_at, last_change, emitted_seq, organization_id, integration_id
      FROM ato_provider_mailbox_items
      WHERE integration_id = ${id} AND organization_id = ${this.scope.organizationId}
        AND identity_external_id_hash = ${identityHashValue}
        AND (state = 'present' OR removed_at >= ${cutoff})
      ORDER BY id`;
    return rows.map((r) => this.row(r));
  }

  /** The gateway account mapped to a provider identity (8.4 `ato_account_identities`), if any. */
  private async accountOf(identity: ProviderIdentityRef): Promise<bigint | null> {
    const mapped = await this.prisma.atoAccountIdentity.findUnique({
      where: {
        organizationId_provider_externalIdHash: {
          organizationId: this.scope.organizationId,
          provider: identity.provider,
          externalIdHash: sha256Hex(identity.externalId),
        },
      },
      select: { organizationId: true, accountId: true },
    });
    return mapped && mapped.organizationId === this.scope.organizationId ? mapped.accountId : null;
  }

  async write(
    integrationId: string,
    identity: ProviderIdentityRef,
    items: MailboxItemWrite[],
    emittedSeq: bigint,
  ): Promise<void> {
    const id = this.check(integrationId);
    if (items.length === 0) return;
    const hash = identityHash(identity.provider, identity.externalId);
    const accountId = await this.accountOf(identity);
    const now = this.now();
    for (const item of items) {
      const traits = JSON.stringify([...item.traits].slice(0, MAX_TRAITS));
      const changed = item.change !== null;
      // An idempotent upsert, retried when it loses a deadlock against a page transaction.
      await retryLockConflict(
        () => this.prisma.$executeRaw`
        INSERT INTO ato_provider_mailbox_items
          (public_id, organization_id, integration_id, account_id, identity_external_id_hash,
           item_kind, item_hash, provider_item_ref, target_domain, traits, enabled, state, source,
           first_seen_at, last_seen_at, removed_at, emitted_seq, last_change, created_at, updated_at)
        VALUES (${uuidv7()}, ${this.scope.organizationId}, ${id}, ${accountId}, ${hash},
                ${item.kind}, ${item.itemHash}, ${item.providerItemRef?.slice(0, 255) ?? null},
                ${item.targetDomain?.slice(0, 253) ?? null}, ${traits}, ${item.enabled},
                ${item.state}, ${item.source}, ${asDate(item.firstSeenAt)},
                ${asDate(item.lastSeenAt)},
                ${item.removedAt === null ? null : asDate(item.removedAt)}, ${emittedSeq},
                ${item.change ?? 'added'}, ${now}, ${now})
        ON DUPLICATE KEY UPDATE
          account_id = COALESCE(account_id, VALUES(account_id)),
          provider_item_ref = VALUES(provider_item_ref),
          target_domain = VALUES(target_domain),
          traits = VALUES(traits),
          enabled = VALUES(enabled),
          state = VALUES(state),
          source = VALUES(source),
          first_seen_at = VALUES(first_seen_at),
          last_seen_at = VALUES(last_seen_at),
          removed_at = VALUES(removed_at),
          emitted_seq = IF(${changed}, VALUES(emitted_seq), emitted_seq),
          last_change = IF(${changed}, VALUES(last_change), last_change),
          updated_at = VALUES(updated_at)`,
      );
    }
  }

  async priorityIdentities(integrationId: string, limit: number): Promise<ProviderIdentityRef[]> {
    const id = this.check(integrationId);
    const rows = await this.prisma.atoAccountIdentity.findMany({
      where: {
        organizationId: this.scope.organizationId,
        integrationId: id,
        mailboxRefreshRequestedAt: { not: null },
      },
      orderBy: [{ mailboxRefreshRequestedAt: 'asc' }, { id: 'asc' }],
      take: Math.max(1, Math.min(limit, 100)),
      select: {
        organizationId: true,
        provider: true,
        externalId: true,
        userPrincipalName: true,
        account: { select: { address: true, organizationId: true } },
      },
    });
    const out: ProviderIdentityRef[] = [];
    for (const r of rows) {
      if (r.organizationId !== this.scope.organizationId) {
        throw new InconsistentReadError('ato_account_identities');
      }
      if (r.provider !== 'microsoft_entra' && r.provider !== 'google_workspace') continue;
      const address =
        r.account && r.account.organizationId === this.scope.organizationId
          ? r.account.address
          : null;
      out.push({
        provider: r.provider,
        externalId: r.externalId,
        ...(r.userPrincipalName ? { userPrincipalName: r.userPrincipalName } : {}),
        ...(address ? { primaryEmail: address } : {}),
      });
    }
    return out;
  }

  async clearPriority(integrationId: string, identityHashes: string[]): Promise<void> {
    const id = this.check(integrationId);
    if (identityHashes.length === 0) return;
    const wanted = new Set(identityHashes);
    const rows = await this.prisma.atoAccountIdentity.findMany({
      where: {
        organizationId: this.scope.organizationId,
        integrationId: id,
        mailboxRefreshRequestedAt: { not: null },
      },
      select: { id: true, provider: true, externalId: true },
      take: 500,
    });
    const ids = rows
      .filter((r) => wanted.has(identityHash(r.provider, r.externalId)))
      .map((r) => r.id);
    if (ids.length === 0) return;
    await this.prisma.atoAccountIdentity.updateMany({
      where: { id: { in: ids }, organizationId: this.scope.organizationId },
      data: { mailboxRefreshRequestedAt: null },
    });
  }

  async itemByPublicId(integrationId: string, publicId: string): Promise<MailboxItemRow | null> {
    const id = this.check(integrationId);
    const rows = await this.prisma.$queryRaw<ItemRow[]>`
      SELECT public_id, identity_external_id_hash, item_kind, item_hash, provider_item_ref,
             target_domain, traits, enabled, state, source, first_seen_at, last_seen_at,
             removed_at, last_change, emitted_seq, organization_id, integration_id
      FROM ato_provider_mailbox_items
      WHERE public_id = ${publicId} AND integration_id = ${id}
        AND organization_id = ${this.scope.organizationId}`;
    return rows[0] ? this.row(rows[0]) : null;
  }
}

/**
 * `ActionStateStore` over `ato_response_actions.provider_state` (D9.3, §5.2) for one organization:
 * the adapter's pre-state and progress (`providerActionStateSchema` v1, ≤ 2 KiB, ids, booleans and
 * enums only, never an address). Written outside the action's row lock (adapter scratch state);
 * `row_version` is not moved, so the 8.4 store's CAS updates are unaffected. An unreadable stored
 * value reads as `null` (no pre-state: rollback becomes unavailable, never a guess).
 */
export class MysqlActionStateStore implements ActionStateStore {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly organizationId: bigint,
  ) {}

  async load(actionPublicId: string): Promise<ProviderActionState | null> {
    const row = await this.prisma.atoResponseAction.findFirst({
      where: { organizationId: this.organizationId, publicId: actionPublicId },
      select: { organizationId: true, publicId: true, providerState: true },
    });
    if (!row) return null;
    if (row.organizationId !== this.organizationId || row.publicId !== actionPublicId) {
      throw new InconsistentReadError('ato_response_actions');
    }
    if (row.providerState === null) return null;
    const parsed = providerActionStateSchema.safeParse(row.providerState);
    return parsed.success ? parsed.data : null;
  }

  async save(actionPublicId: string, state: ProviderActionState): Promise<void> {
    const valid = validateActionState(state);
    const updated = await this.prisma.atoResponseAction.updateMany({
      where: { organizationId: this.organizationId, publicId: actionPublicId },
      data: { providerState: valid },
    });
    if (updated.count !== 1) throw new Error('provider_state_action_not_found');
  }
}
