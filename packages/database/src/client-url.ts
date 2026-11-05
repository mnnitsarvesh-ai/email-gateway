/**
 * Shared construction of the database client URLs (writer and replica) of every service (step
 * 4.2 §6.2 F2, docs/plan/steps/10-attachment-scanning.md §12 WP4). One place decides which
 * driver parameters a service's PrismaClient gets, so the writer and the replica clients never
 * drift apart.
 *
 * `socket_timeout` (seconds) is applied only when `DATABASE_SOCKET_TIMEOUT_SECONDS` is above 0.
 * The default is **0 (unset)**: measured with the freeze proxy of
 * `apps/delivery-worker/integration/writer-stall.test.ts`, the Prisma 6.19.3 library engine
 * fails a statement on its socket timeout but neither closes nor discards the connection; the
 * reply that arrives later is read by the next request on that connection (a wrong read). A
 * socket timeout is therefore only safe with a driver that closes the connection (the
 * `@prisma/adapter-mariadb` driver adapter, F3, measured in the same record). Until then a
 * stalled statement waits for the writer, and interactive transactions are sized to outlast the
 * writer's own timeouts (`innodb_lock_wait_timeout`) instead.
 */

export const DATABASE_SOCKET_TIMEOUT_ENV = 'DATABASE_SOCKET_TIMEOUT_SECONDS';
/** Default of `DATABASE_SOCKET_TIMEOUT_SECONDS`: no socket timeout (see the module comment). */
export const DEFAULT_DATABASE_SOCKET_TIMEOUT_SECONDS = 0;
/** Largest accepted socket timeout. */
export const MAX_DATABASE_SOCKET_TIMEOUT_SECONDS = 3600;

export interface DatabaseClientUrlOptions {
  /** `socket_timeout` in seconds; 0 or undefined leaves the URL's own value (normally none). */
  socketTimeoutSeconds?: number;
}

function assertSocketTimeout(value: number, name: string): void {
  if (!Number.isInteger(value) || value < 0 || value > MAX_DATABASE_SOCKET_TIMEOUT_SECONDS) {
    throw new RangeError(
      `${name} must be an integer from 0 to ${MAX_DATABASE_SOCKET_TIMEOUT_SECONDS} (seconds)`,
    );
  }
}

/**
 * The client URL of a writer or replica endpoint with the shared driver parameters. Errors
 * never contain the URL (it carries credentials).
 */
export function databaseClientUrl(url: string, options: DatabaseClientUrlOptions = {}): string {
  const seconds = options.socketTimeoutSeconds ?? DEFAULT_DATABASE_SOCKET_TIMEOUT_SECONDS;
  assertSocketTimeout(seconds, 'socketTimeoutSeconds');
  if (seconds === 0) return url;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new TypeError('The database URL is not a valid URL');
  }
  parsed.searchParams.set('socket_timeout', String(seconds));
  return parsed.toString();
}

/**
 * `DATABASE_SOCKET_TIMEOUT_SECONDS` of an environment (unset or empty → the default 0), for
 * services whose config schema does not carry the key. Invalid values throw, naming the key.
 */
export function socketTimeoutFromEnv(env: Readonly<Record<string, string | undefined>>): number {
  const raw = env[DATABASE_SOCKET_TIMEOUT_ENV]?.trim();
  if (raw === undefined || raw === '') return DEFAULT_DATABASE_SOCKET_TIMEOUT_SECONDS;
  const value = /^[0-9]+$/.test(raw) ? Number(raw) : Number.NaN;
  assertSocketTimeout(value, DATABASE_SOCKET_TIMEOUT_ENV);
  return value;
}

/**
 * The rule of interactive transactions on a client with a socket timeout: the transaction's
 * own timeout must be longer, so a stalled statement fails on its socket (a driver error) and
 * the transaction is never expired by the client while that statement is in flight (§6.2 F2).
 */
export function transactionOutlastsSocket(
  timeoutMs: number,
  socketTimeoutSeconds: number,
): boolean {
  return socketTimeoutSeconds === 0 || timeoutMs > socketTimeoutSeconds * 1000;
}
