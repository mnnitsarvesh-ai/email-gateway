import type { PrismaClient } from '@email-gateway/database';

/**
 * The writer client with default interactive-transaction options. `processOnce` (and the
 * recorder's own transactions) call `$transaction(fn)` without options, i.e. Prisma's 5 s
 * default, which a 1000-recipient approval can exceed on a remote writer. This view of the same
 * client (same pool, no extra connections) applies `timeoutMs` / `maxWait` whenever a caller
 * passes none.
 */
export function withTransactionDefaults(
  prisma: PrismaClient,
  options: { timeoutMs: number; maxWaitMs?: number },
): PrismaClient {
  const defaults = { timeout: options.timeoutMs, maxWait: options.maxWaitMs ?? options.timeoutMs };
  return new Proxy(prisma, {
    get(target, prop, receiver) {
      if (prop === '$transaction') {
        const transaction = (arg: unknown, opts?: object): Promise<unknown> =>
          (
            target.$transaction as (this: PrismaClient, a: unknown, o?: object) => Promise<unknown>
          ).call(target, arg, opts);
        return (arg: unknown, opts?: object) =>
          typeof arg === 'function'
            ? transaction(arg, { ...defaults, ...opts })
            : transaction(arg, opts);
      }
      const value: unknown = Reflect.get(target, prop, receiver);
      return typeof value === 'function'
        ? (value as (...a: unknown[]) => unknown).bind(target)
        : value;
    },
  });
}

/** Prisma unique-constraint violation (P2002). */
export function isUniqueViolation(error: unknown): boolean {
  return (
    typeof error === 'object' && error !== null && (error as { code?: unknown }).code === 'P2002'
  );
}

/** Canonical decimal string of an id from a raw query (bigint, number or string). */
export const idString = (value: bigint | number | string): string => BigInt(value).toString();
