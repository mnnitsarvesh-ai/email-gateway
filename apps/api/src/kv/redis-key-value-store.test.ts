import type { RedisService } from '@email-gateway/common';
import { describe, expect, it, vi } from 'vitest';
import { RedisKeyValueStore } from './redis-key-value-store';

function store() {
  const client = {
    get: vi.fn().mockResolvedValue('v'),
    set: vi.fn().mockResolvedValue('OK'),
    incr: vi.fn().mockResolvedValue(1),
    eval: vi.fn().mockResolvedValue(3),
    del: vi.fn().mockResolvedValue(2),
    exists: vi.fn().mockResolvedValue(1),
    ttl: vi.fn().mockResolvedValue(42),
  };
  return { client, kv: new RedisKeyValueStore({ client } as unknown as RedisService) };
}

describe('RedisKeyValueStore', () => {
  it('prefixes every key with eg:', async () => {
    const { client, kv } = store();
    await kv.get('a');
    await kv.set('b', '1', 10);
    await kv.incr('c');
    await kv.del('d', 'e');
    await kv.exists('f');
    await kv.ttl('g');
    expect(client.get).toHaveBeenCalledWith('eg:a');
    expect(client.set).toHaveBeenCalledWith('eg:b', '1', 'EX', 10);
    expect(client.incr).toHaveBeenCalledWith('eg:c');
    expect(client.del).toHaveBeenCalledWith('eg:d', 'eg:e');
    expect(client.exists).toHaveBeenCalledWith('eg:f');
    expect(client.ttl).toHaveBeenCalledWith('eg:g');
  });

  it('setIfAbsent uses SET NX EX and reports whether it set the key', async () => {
    const { client, kv } = store();
    expect(await kv.setIfAbsent('lock', 'x', 60)).toBe(true);
    expect(client.set).toHaveBeenCalledWith('eg:lock', 'x', 'EX', 60, 'NX');
    client.set.mockResolvedValueOnce(null);
    expect(await kv.setIfAbsent('lock', 'x', 60)).toBe(false);
  });

  it('incrWithTtl runs one atomic script', async () => {
    const { client, kv } = store();
    expect(await kv.incrWithTtl('rl:x', 900)).toBe(3);
    expect(client.eval).toHaveBeenCalledWith(expect.stringContaining('INCR'), 1, 'eg:rl:x', 900);
  });

  it('del without keys does not call Redis', async () => {
    const { client, kv } = store();
    expect(await kv.del()).toBe(0);
    expect(client.del).not.toHaveBeenCalled();
  });

  it('rejects invalid TTLs', async () => {
    const { kv } = store();
    await expect(kv.set('a', 'b', 0)).rejects.toThrow();
    await expect(kv.incrWithTtl('a', 1.5)).rejects.toThrow();
  });

  it('propagates Redis errors (callers fail closed)', async () => {
    const { client, kv } = store();
    client.get.mockRejectedValueOnce(new Error('connection lost'));
    await expect(kv.get('a')).rejects.toThrow('connection lost');
  });
});
