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
}

export interface DatabaseModuleOptions {
  /** Writer endpoint. */
  url: string;
  /** Registers PrismaReadService. Data-plane services must not set this. */
  read?: DatabaseReadOptions;
}
