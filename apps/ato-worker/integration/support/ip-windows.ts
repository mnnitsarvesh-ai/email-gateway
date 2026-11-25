import Redis from 'ioredis';

/**
 * vitest globalSetup of the ato-worker integration suite: removes, after the run, the
 * platform-wide IP failure windows and campaign flags (`ato:ip:<ip>:*`, `ato:ipflag:<ip>`) of the
 * RFC 5737 documentation ranges the suites use (support/fixtures.ts `ips`, idp-volume).
 *
 * These keys hold no organization id (D8), so the per-organization clean-up of `harness.close()`
 * cannot find them, and a flag lives `ATO_IP_CAMPAIGN_FLAG_HOURS` (24 h). Left behind, a flag
 * turns any later portal login from that address into `ato.ti.attack_source_success` (strong):
 * the portal end-to-end run sends documentation-range `X-Forwarded-For` addresses, so its seeded
 * admins became critical and got automated responses (AI-5 verification round 1). Only the
 * documentation ranges are touched: production traffic never uses them, and the suites use no
 * other routable address.
 */
const DOCUMENTATION_PREFIXES = ['192.0.2.', '198.51.100.', '203.0.113.'] as const;

async function deleteMatching(redis: Redis, pattern: string): Promise<number> {
  let removed = 0;
  let cursor = '0';
  do {
    const [next, keys] = await redis.scan(cursor, 'MATCH', pattern, 'COUNT', 1000);
    cursor = next;
    if (keys.length > 0) removed += await redis.del(...keys);
  } while (cursor !== '0');
  return removed;
}

export async function removeDocumentationIpWindows(url: string): Promise<number> {
  const redis = new Redis(url, { maxRetriesPerRequest: 2, lazyConnect: true });
  try {
    await redis.connect();
    let removed = 0;
    for (const prefix of DOCUMENTATION_PREFIXES) {
      removed += await deleteMatching(redis, `ato:ip:${prefix}*`);
      removed += await deleteMatching(redis, `ato:ipflag:${prefix}*`);
    }
    return removed;
  } finally {
    redis.disconnect();
  }
}

export default function setup(): () => Promise<void> {
  return async () => {
    const url = process.env.REDIS_URL;
    if (!url) return;
    const removed = await removeDocumentationIpWindows(url);
    if (removed > 0) {
      process.stderr.write(
        `[ato-worker integration] removed ${String(removed)} documentation-range IP window/flag keys\n`,
      );
    }
  };
}
