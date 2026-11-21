import { AsyncLocalStorage } from 'node:async_hooks';

const writerScope = new AsyncLocalStorage<true>();

/**
 * Runs `fn` with every `PrismaReadService.client` read inside it (and its async continuations)
 * on the writer instead of the replica: read-your-writes for a request that must not see replica
 * lag (step AI-2 review: the assistant's precondition reads that guard a confirmed write).
 * Forcing the writer only ever increases consistency; it never changes what a query may see.
 */
export function runReadsOnWriter<T>(fn: () => T): T {
  return writerScope.run(true, fn);
}

/** True inside `runReadsOnWriter`. */
export function readsOnWriter(): boolean {
  return writerScope.getStore() === true;
}
