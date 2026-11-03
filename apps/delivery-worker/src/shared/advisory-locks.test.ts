import { describe, expect, it } from 'vitest';
import { AdvisoryLocks, type LockSqlClient } from './advisory-locks';

/** A fake MySQL session: locks are owned by a connection id; reconnecting changes the id. */
function fakeSession(holders: Map<string, number>) {
  let connectionId = 1;
  const calls: string[] = [];
  const client: LockSqlClient & { reconnect(): void; calls: string[] } = {
    calls,
    reconnect() {
      for (const [name, owner] of holders) if (owner === connectionId) holders.delete(name);
      connectionId += 100;
    },
    $queryRawUnsafe<T>(query: string, ...values: unknown[]): Promise<T> {
      calls.push(query);
      const name = values[0] as string;
      if (query.includes('IS_USED_LOCK')) {
        const owner = holders.get(name);
        return Promise.resolve([
          { mine: owner === undefined ? null : owner === connectionId ? 1n : 0n },
        ] as T);
      }
      if (query.includes('GET_LOCK')) {
        const owner = holders.get(name);
        if (owner === undefined || owner === connectionId) {
          holders.set(name, connectionId);
          return Promise.resolve([{ acquired: 1n }] as T);
        }
        return Promise.resolve([{ acquired: 0n }] as T);
      }
      if (query.includes('RELEASE_ALL_LOCKS')) {
        for (const [n, owner] of holders) if (owner === connectionId) holders.delete(n);
      } else if (query.includes('RELEASE_LOCK')) {
        if (holders.get(name) === connectionId) holders.delete(name);
      }
      return Promise.resolve([{ released: 1n }] as T);
    },
    $disconnect: () => Promise.resolve(),
  };
  return client;
}

describe('AdvisoryLocks', () => {
  it('acquires once, re-verifies ownership and lets only one holder in', async () => {
    const holders = new Map<string, number>();
    const a = fakeSession(holders);
    const locksA = new AdvisoryLocks(a);
    expect(await locksA.ensure('dw:outbox:x')).toBe(true);
    expect(await locksA.ensure('dw:outbox:x')).toBe(true);
    expect(a.calls.filter((q) => q.includes('GET_LOCK'))).toHaveLength(1);

    const other = new Map(holders);
    other.set('dw:outbox:x', 999); // another session holds it
    const locksB = new AdvisoryLocks(fakeSession(other));
    expect(await locksB.ensure('dw:outbox:x')).toBe(false);
  });

  it('re-acquires after the connection dropped (the server released the lock)', async () => {
    const holders = new Map<string, number>();
    const session = fakeSession(holders);
    const locks = new AdvisoryLocks(session);
    await locks.ensure('dw:postfix-log:out');
    session.reconnect();
    expect(await locks.ensure('dw:postfix-log:out')).toBe(true);
    expect(session.calls.filter((q) => q.includes('GET_LOCK'))).toHaveLength(2);
  });

  it('releases one lock or all of them on close, and validates names', async () => {
    const holders = new Map<string, number>();
    const locks = new AdvisoryLocks(fakeSession(holders));
    await locks.ensure('a');
    await locks.ensure('b');
    await locks.release('a');
    expect(holders.has('a')).toBe(false);
    await locks.close();
    expect(holders.size).toBe(0);
    await expect(locks.ensure('x'.repeat(65))).rejects.toThrow('1-64');
  });
});
