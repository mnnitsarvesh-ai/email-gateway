import { randomBytes, randomUUID } from 'node:crypto';
import { Logger } from '@nestjs/common';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { InMemoryKeyValueStore } from '../../../../test/support/in-memory-key-value-store';
import { SecretBox } from '../../../crypto/secret-box';
import {
  DKIM_KEYS_HASH,
  DKIM_SELECTORS_HASH,
  type PublishedSigningState,
  type SigningPlan,
} from '../domain/dkim-signing-plan';
import { domainKvKeys } from '../domains.constants';
import type { DkimSigningRepository, SignableKey } from '../repositories/dkim-signing.repository';
import { DkimKeyStore, DkimSigningDisabledError } from '../signing/dkim-key-store';
import { DkimSigningPublisher } from './dkim-signing-publisher.service';
import { dkimKeyAad } from './domain-configuration.service';

/** In-memory redis-dkim: the two hashes, applied in plan order. */
class MemoryDkimStore extends DkimKeyStore {
  readonly hashes = {
    [DKIM_SELECTORS_HASH]: new Map<string, string>(),
    [DKIM_KEYS_HASH]: new Map<string, string>(),
  };
  readonly applied: SigningPlan[] = [];
  constructor(readonly configured = true) {
    super();
  }
  readState(): Promise<PublishedSigningState> {
    return Promise.resolve({
      selectors: Object.fromEntries(this.hashes[DKIM_SELECTORS_HASH]),
      keyFields: [...this.hashes[DKIM_KEYS_HASH].keys()],
    });
  }
  apply(plan: SigningPlan): Promise<void> {
    this.applied.push(plan);
    const sel = this.hashes[DKIM_SELECTORS_HASH];
    const keys = this.hashes[DKIM_KEYS_HASH];
    for (const [f, v] of plan.keysToWrite) keys.set(f, v);
    for (const [d, s] of plan.selectorsToWrite) sel.set(d, s);
    for (const d of plan.selectorsToDelete) sel.delete(d);
    for (const f of plan.keysToDelete) keys.delete(f);
    return Promise.resolve();
  }
}

const box = new SecretBox({ DATA_ENCRYPTION_KEY: randomBytes(32).toString('hex') });
const pem = (tag: string) =>
  `-----BEGIN PRIVATE KEY-----\n${tag}${randomBytes(8).toString('hex')}\n-----END PRIVATE KEY-----\n`;

let nextKeyId = 1n;
function signable(domainName: string, selector: string, plaintext: string): SignableKey {
  const domainPublicId = randomUUID();
  return {
    keyId: nextKeyId++,
    domainPublicId,
    domainName,
    selector,
    ciphertext: box.encrypt(plaintext, dkimKeyAad(domainPublicId, selector)),
  };
}

function setup(options: { configured?: boolean; interval?: number } = {}) {
  let keys: SignableKey[] = [];
  const repo = {
    findSignableKeys: () => Promise.resolve(keys),
  } as unknown as DkimSigningRepository;
  const store = new MemoryDkimStore(options.configured ?? true);
  const kv = new InMemoryKeyValueStore();
  const publisher = new DkimSigningPublisher(
    { DKIM_SIGNING_SYNC_ENABLED: true, DKIM_SIGNING_SYNC_INTERVAL_SECONDS: options.interval ?? 30 },
    kv,
    repo,
    box,
    store,
  );
  return {
    publisher,
    store,
    kv,
    setKeys: (list: SignableKey[]) => {
      keys = list;
    },
  };
}

/** Every argument of every Logger call (to prove no PEM is ever logged). */
function captureLogs(): () => string {
  const calls: unknown[] = [];
  for (const level of ['log', 'error', 'warn', 'debug', 'verbose'] as const) {
    vi.spyOn(Logger.prototype, level).mockImplementation((...args: unknown[]) => {
      calls.push(args);
    });
  }
  return () => JSON.stringify(calls);
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('DkimSigningPublisher.reconcile (D12)', () => {
  it('publishes, keeps, rotates, removes and prunes', async () => {
    const logs = captureLogs();
    const { publisher, store, setKeys } = setup();
    const a1 = pem('a1');
    const b1 = pem('b1');
    setKeys([signable('a.test', 'sa1', a1), signable('b.test', 'sb1', b1)]);
    expect(await publisher.reconcile()).toEqual({
      published: 2,
      removed: 0,
      unchanged: 0,
      skipped: 0,
      pruned: 0,
    });
    expect(Object.fromEntries(store.hashes.dkim_selectors)).toEqual({
      'a.test': 'sa1',
      'b.test': 'sb1',
    });
    expect(store.hashes.dkim_keys.get('sa1.a.test')).toBe(a1);

    // Unchanged: no writes at all.
    expect((await publisher.reconcile()).unchanged).toBe(2);
    expect(store.applied.at(-1)!.keysToWrite).toEqual([]);

    // a.test rotates, b.test stops being signable (suspended / outbound disabled).
    const a2 = pem('a2');
    setKeys([signable('a.test', 'sa2', a2)]);
    expect(await publisher.reconcile()).toEqual({
      published: 1,
      removed: 1,
      unchanged: 0,
      skipped: 0,
      pruned: 2,
    });
    expect(Object.fromEntries(store.hashes.dkim_selectors)).toEqual({ 'a.test': 'sa2' });
    expect([...store.hashes.dkim_keys.keys()]).toEqual(['sa2.a.test']);
    expect(store.hashes.dkim_keys.get('sa2.a.test')).toBe(a2);

    for (const secret of [a1, a2, b1]) expect(logs()).not.toContain(secret.split('\n')[1]);
  });

  it('uses the newest active key when a domain has several', async () => {
    const { publisher, store, setKeys } = setup();
    setKeys([signable('a.test', 'old', pem('o')), signable('a.test', 'new', pem('n'))]);
    await publisher.reconcile();
    expect(store.hashes.dkim_selectors.get('a.test')).toBe('new');
    expect([...store.hashes.dkim_keys.keys()]).toEqual(['new.a.test']);
  });

  it('skips a domain whose key cannot be decrypted, logging its public id only', async () => {
    const logs = captureLogs();
    const { publisher, store, setKeys } = setup();
    const good = signable('a.test', 'sa1', pem('a'));
    const published = pem('b');
    setKeys([good, signable('b.test', 'sb1', published)]);
    await publisher.reconcile();

    // b.test's ciphertext is now bound to another AAD (tampered): skipped, left as published.
    const broken = signable('b.test', 'sb1', pem('x'));
    broken.ciphertext = box.encrypt(pem('x'), 'dkim:someone-else:sb1');
    setKeys([good, broken]);
    expect(await publisher.reconcile()).toEqual({
      published: 0,
      removed: 0,
      unchanged: 1,
      skipped: 1,
      pruned: 0,
    });
    expect(store.hashes.dkim_selectors.get('b.test')).toBe('sb1');
    expect(store.hashes.dkim_keys.get('sb1.b.test')).toBe(published);
    const logged = logs();
    expect(logged).toContain(broken.domainPublicId);
    expect(logged).toContain('DKIM signing key could not be decrypted');
    expect(logged).not.toContain('b.test');
    expect(logged).not.toContain('PRIVATE KEY');
  });

  it('throws when no key store is configured', async () => {
    const { publisher } = setup({ configured: false });
    await expect(publisher.reconcile()).rejects.toBeInstanceOf(DkimSigningDisabledError);
  });
});

describe('DkimSigningPublisher scheduling', () => {
  it('runs one reconciliation per tick across replicas (KV lock)', async () => {
    const { publisher, kv, setKeys } = setup({ interval: 30 });
    setKeys([signable('a.test', 's', pem('a'))]);
    expect(await publisher.runOnce()).toMatchObject({ published: 1 });
    expect(await publisher.runOnce()).toBeNull();
    expect(await kv.ttl(domainKvKeys.dkimSyncLock)).toBeLessThanOrEqual(29);
  });

  it('skips the tick when the key-value store is unavailable', async () => {
    captureLogs();
    const { publisher, kv, store } = setup();
    kv.failing = true;
    expect(await publisher.runOnce()).toBeNull();
    expect(store.applied).toHaveLength(0);
  });

  it('schedules an unref’d timer only when configured and enabled, with one warning otherwise', async () => {
    const logs = captureLogs();
    const disabled = setup({ configured: false }).publisher;
    disabled.onApplicationBootstrap();
    expect(disabled.scheduled).toBe(false);
    expect(logs()).toContain('REDIS_DKIM_URL is not set');

    const off = new DkimSigningPublisher(
      { DKIM_SIGNING_SYNC_ENABLED: false, DKIM_SIGNING_SYNC_INTERVAL_SECONDS: 30 },
      new InMemoryKeyValueStore(),
      { findSignableKeys: () => Promise.resolve([]) } as unknown as DkimSigningRepository,
      box,
      new MemoryDkimStore(),
    );
    off.onApplicationBootstrap();
    expect(off.scheduled).toBe(false);

    vi.useFakeTimers();
    const { publisher, store, setKeys } = setup({ interval: 10 });
    setKeys([signable('a.test', 's', pem('a'))]);
    publisher.onApplicationBootstrap();
    expect(publisher.scheduled).toBe(true);
    await vi.advanceTimersByTimeAsync(1_100);
    expect(store.hashes.dkim_selectors.get('a.test')).toBe('s');
    await publisher.onModuleDestroy();
    expect(publisher.scheduled).toBe(false);
  });
});
