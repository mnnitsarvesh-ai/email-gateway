import type { Redis } from 'ioredis';
import { createHash } from 'node:crypto';

/**
 * A Redis Lua script run with EVALSHA, falling back to EVAL when the server does not have it
 * cached yet (first call, or after a Redis restart / SCRIPT FLUSH).
 */
export class LuaScript {
  readonly sha: string;

  constructor(readonly source: string) {
    this.sha = createHash('sha1').update(source).digest('hex');
  }

  async run(
    client: Pick<Redis, 'evalsha' | 'eval'>,
    keys: readonly string[],
    args: readonly (string | number)[],
  ): Promise<unknown> {
    const params = [...keys, ...args.map(String)];
    try {
      return await client.evalsha(this.sha, keys.length, ...params);
    } catch (err) {
      if (!(err instanceof Error) || !err.message.includes('NOSCRIPT')) throw err;
      return client.eval(this.source, keys.length, ...params);
    }
  }
}
