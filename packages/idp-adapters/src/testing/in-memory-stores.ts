/**
 * In-memory implementations of the state ports (design note §5.2) for the library tests. WP4
 * implements the same ports over Redis (`RateBudget`) and MySQL (`ato_provider_mailbox_items`,
 * `ato_response_actions.provider_state`); these follow the same semantics.
 */
import { randomUUID } from 'node:crypto';
import { identityHash } from '../core/hash';
import type { ProviderIdentityRef } from '../port/ato-port';
import {
  validateActionState,
  type ActionStateStore,
  type ApiFamily,
  type MailboxItemRow,
  type MailboxItemWrite,
  type MailboxStateStore,
  type ProviderActionState,
  type RateBudget,
} from '../port/state-ports';

const DAY_MS = 86_400_000;

/**
 * Per integration, family and epoch second: at most `limits[family]` takes (D7.5). `exhaust` makes
 * a family answer `exhausted` until `restore`.
 */
export class InMemoryRateBudget implements RateBudget {
  private readonly counters = new Map<string, number>();
  private readonly exhausted = new Set<ApiFamily>();
  takes = 0;

  constructor(
    private readonly limits: Readonly<Record<ApiFamily, number>>,
    private readonly now: () => number = Date.now,
  ) {}

  exhaust(family: ApiFamily): void {
    this.exhausted.add(family);
  }

  restore(family?: ApiFamily): void {
    if (family) this.exhausted.delete(family);
    else this.exhausted.clear();
  }

  take(
    integrationId: string,
    family: ApiFamily,
    _signal?: AbortSignal,
  ): Promise<'ok' | 'exhausted'> {
    this.takes += 1;
    if (this.exhausted.has(family)) return Promise.resolve('exhausted');
    const key = `${integrationId}|${family}|${Math.floor(this.now() / 1000)}`;
    const count = (this.counters.get(key) ?? 0) + 1;
    this.counters.set(key, count);
    return Promise.resolve(count <= this.limits[family] ? 'ok' : 'exhausted');
  }
}

/** Unlimited budget (tests that do not exercise rate limits). */
export class UnlimitedRateBudget implements RateBudget {
  take(): Promise<'ok' | 'exhausted'> {
    return Promise.resolve('ok');
  }
}

interface StoredRow extends MailboxItemRow {
  integrationId: string;
}

/**
 * Mailbox items keyed by (integration, identity hash, kind, item hash) — the unique key of
 * `ato_provider_mailbox_items`. A write with `change: null` only moves `last_seen_at` (the
 * row's `emitted_seq` and `last_change` stay); a non-null change sets both.
 */
export class InMemoryMailboxStateStore implements MailboxStateStore {
  private readonly rows = new Map<string, StoredRow>();
  private readonly priority = new Map<string, { identity: ProviderIdentityRef; at: number }>();
  writes = 0;

  constructor(private readonly now: () => number = Date.now) {}

  private key(integrationId: string, identity: string, kind: string, itemHash: string): string {
    return `${integrationId}|${identity}|${kind}|${itemHash}`;
  }

  load(integrationId: string, identityHashValue: string): Promise<MailboxItemRow[]> {
    const cutoff = this.now() - 30 * DAY_MS;
    return Promise.resolve(
      [...this.rows.values()]
        .filter(
          (row) =>
            row.integrationId === integrationId &&
            row.identityHash === identityHashValue &&
            (row.state === 'present' ||
              (row.removedAt !== null && Date.parse(row.removedAt) >= cutoff)),
        )
        .map((row) => this.copy(row)),
    );
  }

  write(
    integrationId: string,
    identity: ProviderIdentityRef,
    items: MailboxItemWrite[],
    emittedSeq: bigint,
  ): Promise<void> {
    this.writes += 1;
    const hash = identityHash(identity.provider, identity.externalId);
    for (const item of items) {
      const key = this.key(integrationId, hash, item.kind, item.itemHash);
      const existing = this.rows.get(key);
      const base: StoredRow = {
        integrationId,
        publicId: existing?.publicId ?? randomUUID(),
        identityHash: hash,
        kind: item.kind,
        itemHash: item.itemHash,
        providerItemRef: item.providerItemRef,
        targetDomain: item.targetDomain,
        traits: [...item.traits],
        enabled: item.enabled,
        state: item.state,
        source: item.source,
        firstSeenAt: item.firstSeenAt,
        lastSeenAt: item.lastSeenAt,
        removedAt: item.removedAt,
        lastChange: existing?.lastChange ?? 'added',
        emittedSeq: existing?.emittedSeq ?? emittedSeq,
      };
      if (item.change !== null) {
        base.lastChange = item.change;
        base.emittedSeq = emittedSeq;
      }
      this.rows.set(key, base);
    }
    return Promise.resolve();
  }

  /** Marks an identity for a priority refresh (what the api route does, §6 #13). */
  requestRefresh(integrationId: string, identity: ProviderIdentityRef): void {
    const hash = identityHash(identity.provider, identity.externalId);
    this.priority.set(`${integrationId}|${hash}`, { identity, at: this.now() });
  }

  priorityIdentities(integrationId: string, limit: number): Promise<ProviderIdentityRef[]> {
    return Promise.resolve(
      [...this.priority.entries()]
        .filter(([key]) => key.startsWith(`${integrationId}|`))
        .sort((a, b) => a[1].at - b[1].at)
        .slice(0, limit)
        .map(([, value]) => value.identity),
    );
  }

  clearPriority(integrationId: string, identityHashes: string[]): Promise<void> {
    for (const hash of identityHashes) this.priority.delete(`${integrationId}|${hash}`);
    return Promise.resolve();
  }

  pendingPriority(integrationId: string): number {
    return [...this.priority.keys()].filter((key) => key.startsWith(`${integrationId}|`)).length;
  }

  itemByPublicId(integrationId: string, publicId: string): Promise<MailboxItemRow | null> {
    const row = [...this.rows.values()].find(
      (r) => r.integrationId === integrationId && r.publicId === publicId,
    );
    return Promise.resolve(row ? this.copy(row) : null);
  }

  /** Every row of an integration (assertions). */
  all(integrationId: string): MailboxItemRow[] {
    return [...this.rows.values()]
      .filter((row) => row.integrationId === integrationId)
      .map((row) => this.copy(row));
  }

  private copy(row: StoredRow): MailboxItemRow {
    const { integrationId: _integrationId, ...rest } = row;
    return { ...rest, traits: [...rest.traits] };
  }
}

/** `ato_response_actions.provider_state` per action public id (validated, ≤ 2 KiB). */
export class InMemoryActionStateStore implements ActionStateStore {
  private readonly states = new Map<string, ProviderActionState>();

  load(actionPublicId: string): Promise<ProviderActionState | null> {
    const state = this.states.get(actionPublicId);
    return Promise.resolve(state ? structuredClone(state) : null);
  }

  save(actionPublicId: string, state: ProviderActionState): Promise<void> {
    this.states.set(actionPublicId, structuredClone(validateActionState(state)));
    return Promise.resolve();
  }

  /** Simulates a lost state (rollback without pre-state). */
  delete(actionPublicId: string): void {
    this.states.delete(actionPublicId);
  }

  peek(actionPublicId: string): ProviderActionState | null {
    return this.states.get(actionPublicId) ?? null;
  }
}
