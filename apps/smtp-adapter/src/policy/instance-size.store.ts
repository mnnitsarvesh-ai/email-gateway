import { Injectable } from '@nestjs/common';
import { RedisService } from '@email-gateway/common';
import { LuaScript } from '../rate-limit/lua-script';
import { cacheKeys } from '../tenancy/cache-keys';

/** D4: the per-message size state lives 15 minutes (longer than any SMTP transaction). */
export const INSTANCE_TTL_SECONDS = 15 * 60;

/** Keeps the smaller of the stored and the new limit (KEYS[1], ARGV[1] limit, ARGV[2] TTL). */
const RECORD_MIN = new LuaScript(`
local current = redis.call('GET', KEYS[1])
if (not current) or tonumber(current) > tonumber(ARGV[1]) then
  redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
end
return 1
`);

/**
 * Smallest tenant message-size limit among the recipients of one SMTP transaction (Postfix
 * policy attribute `instance`), recorded at RCPT and checked at END-OF-MESSAGE when the real
 * size is known (step 2.2 D4). Redis errors propagate: the policy tempfails.
 */
@Injectable()
export class InstanceSizeStore {
  constructor(private readonly redis: RedisService) {}

  async recordLimit(instance: string, limitBytes: number): Promise<void> {
    await RECORD_MIN.run(
      this.redis.client,
      [cacheKeys.instance(instance)],
      [limitBytes, INSTANCE_TTL_SECONDS],
    );
  }

  /** The recorded limit, or null when no recipient of this transaction set one. */
  async limit(instance: string): Promise<number | null> {
    const raw = await this.redis.client.get(cacheKeys.instance(instance));
    if (raw === null) return null;
    const value = Number(raw);
    if (!Number.isSafeInteger(value) || value < 0) throw new Error('corrupt instance size state');
    return value;
  }
}
