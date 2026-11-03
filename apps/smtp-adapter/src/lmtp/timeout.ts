/** Raised when an awaited dependency call exceeds its budget. */
export class TimeoutError extends Error {
  override readonly name = 'TimeoutError';
}

/**
 * Rejects with `TimeoutError` when `promise` does not settle within `ms`. The underlying
 * operation is not cancelled (Prisma queries cannot be); the caller answers 451 and moves on.
 */
export async function withTimeout<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new TimeoutError(`${what} timed out after ${ms} ms`)), ms);
    timer.unref();
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer);
    // A late rejection of the abandoned operation must not become an unhandled rejection.
    promise.catch(() => undefined);
  }
}
