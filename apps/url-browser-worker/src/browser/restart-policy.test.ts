import { describe, expect, it } from 'vitest';
import { chromiumArgs } from './chromium-args';
import { restartReason } from './restart-policy';

const base = { connected: true, jobsSinceLaunch: 0, maxJobs: 50, rssBytes: 100, maxRssBytes: 1000 };

describe('restart policy', () => {
  it('restarts after max jobs, on crash and above the RSS limit', () => {
    expect(restartReason(base)).toBeNull();
    expect(restartReason({ ...base, jobsSinceLaunch: 50 })).toBe('max_jobs');
    expect(restartReason({ ...base, connected: false, jobsSinceLaunch: 50 })).toBe('crash');
    expect(restartReason({ ...base, rssBytes: 1001 })).toBe('rss');
    expect(restartReason({ ...base, rssBytes: null })).toBeNull();
  });
});

describe('chromium flags (U15)', () => {
  it('route everything through the proxy and disable side channels', () => {
    const args = chromiumArgs('url-egress-proxy');
    expect(args).toEqual(
      expect.arrayContaining([
        '--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE url-egress-proxy',
        '--disable-quic',
        '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
        '--disable-background-networking',
        '--disable-component-update',
        '--disable-sync',
        '--no-first-run',
        '--disable-dev-shm-usage',
      ]),
    );
    expect(args.some((a) => a.startsWith('--proxy-bypass'))).toBe(false);
    expect(() => chromiumArgs('evil , MAP * 1.2.3.4')).toThrow();
  });
});
