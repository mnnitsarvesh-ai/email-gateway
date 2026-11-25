export const DATABASE_OPTIONS = Symbol('DATABASE_OPTIONS');
export const DATABASE_READ_OPTIONS = Symbol('DATABASE_READ_OPTIONS');

/** Read replica settings. Only control-plane services (api) pass these (ADR-0014). */
export interface DatabaseReadOptions {
  /** Reader endpoint. When unset, PrismaReadService serves every read from the writer. */
  url?: string;
  /** Above this replication lag, reads fall back to the writer. */
  maxLagSeconds: number;
  /** How often the replica's lag and thread state are probed. */
  lagCheckIntervalMs: number;
  /**
   * `socket_timeout` of the replica client (step 4.2 §6.2 F2); defaults to the writer's value
   * (`DatabaseModuleOptions.socketTimeoutSeconds`).
   */
  socketTimeoutSeconds?: number;
}

export interface DatabaseModuleOptions {
  /** Writer endpoint. */
  url: string;
  /**
   * `socket_timeout` (seconds) of the writer and replica clients through `databaseClientUrl`
   * (step 4.2 §6.2 F2). Unset: `DATABASE_SOCKET_TIMEOUT_SECONDS` of the process environment,
   * else 0 (none; why 0 is the default: `@email-gateway/database` `client-url.ts`).
   */
  socketTimeoutSeconds?: number;
  /**
   * `connection_limit` (1–500) of the writer client's pool (step AI-4 D14). Unset: the URL's own
   * value, else Prisma's default (`2 × CPUs + 1`). Only services that size their pool pass it.
   */
  connectionLimit?: number;
  /**
   * `pool_timeout` (seconds, 1–600) of the writer client: how long a query waits for a pool
   * connection (`P2024` after it). Unset: the URL's own value, else Prisma's default 10 s.
   */
  poolTimeoutSeconds?: number;
  /** Registers PrismaReadService. Data-plane services must not set this. */
  read?: DatabaseReadOptions;
}
