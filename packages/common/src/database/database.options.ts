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
  /** Registers PrismaReadService. Data-plane services must not set this. */
  read?: DatabaseReadOptions;
}
