import { randomUUID } from 'node:crypto';
import type { KeyValueStore } from '../../../kv/key-value-store';
import { CHECK_LOCK_SECONDS, domainKvKeys } from '../domains.constants';

/** A held per-domain check lock (`domains:check:<id>`, D11). */
export interface CheckLock {
  key: string;
  token: string;
}

/**
 * Takes the per-domain check lock shared by the scheduler and manual verification. Returns
 * null when someone else holds it. KV errors propagate (callers fail closed or skip).
 */
export async function acquireCheckLock(
  kv: KeyValueStore,
  domainId: bigint,
): Promise<CheckLock | null> {
  const lock = { key: domainKvKeys.checkLock(domainId), token: randomUUID() };
  return (await kv.setIfAbsent(lock.key, lock.token, CHECK_LOCK_SECONDS)) ? lock : null;
}

/**
 * Releases the lock if it is still ours (it may have expired and been taken by another
 * holder). Best effort: an error leaves the lock to expire on its own.
 */
export async function releaseCheckLock(kv: KeyValueStore, lock: CheckLock): Promise<void> {
  try {
    if ((await kv.get(lock.key)) === lock.token) await kv.del(lock.key);
  } catch {
    // The lock expires after CHECK_LOCK_SECONDS.
  }
}
