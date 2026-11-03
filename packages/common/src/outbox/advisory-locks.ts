import { createMaintenanceClientUrl, PrismaClient } from '@email-gateway/database';

/** The subset of PrismaClient a lock connection needs (a fake implements it in unit tests). */
export interface LockSqlClient {
  $queryRawUnsafe<T = unknown>(query: string, ...values: unknown[]): Promise<T>;
  $disconnect(): Promise<void>;
}

/** MySQL GET_LOCK names are server-wide and at most 64 characters. */
const MAX_LOCK_NAME = 64;

/**
 * MySQL advisory locks (`GET_LOCK(name, 0)`) held on ONE dedicated connection
 * (`connection_limit=1`), so "single active consumer across replicas" (step 2.3 R6, R9) survives the
 * writer pool handing queries to arbitrary connections. A lock is owned by a session: when the
 * connection drops (network, MySQL restart) the server releases it. `ensure()` therefore
 * re-verifies ownership with `IS_USED_LOCK(name) = CONNECTION_ID()` on every call and
 * re-acquires when free; callers run one iteration per successful `ensure()`. A reconnect in
 * the middle of an iteration can let another replica start the same work; everything the
 * holders do is idempotent (processOnce ledger, signal keys), so that window costs no effect.
 */
export class AdvisoryLocks {
  private readonly client: LockSqlClient;
  private readonly held = new Set<string>();

  constructor(databaseUrlOrClient: string | LockSqlClient) {
    this.client =
      typeof databaseUrlOrClient === 'string'
        ? new PrismaClient({ datasourceUrl: createMaintenanceClientUrl(databaseUrlOrClient) })
        : databaseUrlOrClient;
  }

  /** True when this process holds `name` now (acquiring it if nobody does). */
  async ensure(name: string): Promise<boolean> {
    if (name.length === 0 || name.length > MAX_LOCK_NAME) {
      throw new Error(`advisory lock name must be 1-${MAX_LOCK_NAME} characters`);
    }
    const [owned] = await this.client.$queryRawUnsafe<{ mine: bigint | number | null }[]>(
      'SELECT IS_USED_LOCK(?) = CONNECTION_ID() AS mine',
      name,
    );
    if (owned?.mine !== null && owned?.mine !== undefined && Number(owned.mine) === 1) {
      this.held.add(name);
      return true;
    }
    const [row] = await this.client.$queryRawUnsafe<{ acquired: bigint | number | null }[]>(
      'SELECT GET_LOCK(?, 0) AS acquired',
      name,
    );
    const acquired =
      row?.acquired !== null && row?.acquired !== undefined && Number(row.acquired) === 1;
    if (acquired) this.held.add(name);
    else this.held.delete(name);
    return acquired;
  }

  /** True when the last `ensure(name)` of this process acquired or re-verified `name`. */
  isHeld(name: string): boolean {
    return this.held.has(name);
  }

  /**
   * Number of locks this process believes it holds whose name starts with `prefix` (e.g. the
   * shard locks of one outbox consumer). Ownership is re-verified only by `ensure()`.
   */
  heldCount(prefix: string): number {
    let count = 0;
    for (const name of this.held) if (name.startsWith(prefix)) count += 1;
    return count;
  }

  /** Releases `name` if held (best effort; the session end releases it anyway). */
  async release(name: string): Promise<void> {
    if (!this.held.delete(name)) return;
    await this.client.$queryRawUnsafe('SELECT RELEASE_LOCK(?) AS released', name);
  }

  /** Releases every lock and closes the dedicated connection. */
  async close(): Promise<void> {
    try {
      if (this.held.size > 0) {
        this.held.clear();
        await this.client.$queryRawUnsafe('SELECT RELEASE_ALL_LOCKS() AS released');
      }
    } finally {
      await this.client.$disconnect();
    }
  }
}
