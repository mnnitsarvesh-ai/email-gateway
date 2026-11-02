import { Injectable } from '@nestjs/common';
import { RedisService } from '@email-gateway/common';
import { assertTtl, KeyValueStore } from './key-value-store';

/** Every key the api writes lives under this prefix (design §3). */
export const KV_KEY_PREFIX = 'eg:';

/**
 * INCR, then EXPIRE when the counter has no TTL (first increment, or a counter left without one).
 * One script, so the counter can never be created without its expiry.
 */
const INCR_WITH_TTL = `
local value = redis.call('INCR', KEYS[1])
if redis.call('TTL', KEYS[1]) == -1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return value
`;

@Injectable()
export class RedisKeyValueStore extends KeyValueStore {
  constructor(private readonly redis: RedisService) {
    super();
  }

  private k(key: string): string {
    return `${KV_KEY_PREFIX}${key}`;
  }

  get(key: string): Promise<string | null> {
    return this.redis.client.get(this.k(key));
  }

  async set(key: string, value: string, ttlSeconds: number): Promise<void> {
    assertTtl(ttlSeconds);
    await this.redis.client.set(this.k(key), value, 'EX', ttlSeconds);
  }

  async setIfAbsent(key: string, value: string, ttlSeconds: number): Promise<boolean> {
    assertTtl(ttlSeconds);
    return (await this.redis.client.set(this.k(key), value, 'EX', ttlSeconds, 'NX')) === 'OK';
  }

  incr(key: string): Promise<number> {
    return this.redis.client.incr(this.k(key));
  }

  async incrWithTtl(key: string, ttlSeconds: number): Promise<number> {
    assertTtl(ttlSeconds);
    const result = await this.redis.client.eval(INCR_WITH_TTL, 1, this.k(key), ttlSeconds);
    return Number(result);
  }

  del(...keys: string[]): Promise<number> {
    if (keys.length === 0) return Promise.resolve(0);
    return this.redis.client.del(...keys.map((key) => this.k(key)));
  }

  async exists(key: string): Promise<boolean> {
    return (await this.redis.client.exists(this.k(key))) === 1;
  }

  ttl(key: string): Promise<number> {
    return this.redis.client.ttl(this.k(key));
  }
}
