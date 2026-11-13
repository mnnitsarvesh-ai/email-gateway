import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { GuardedPoster, parseDialMap, RestrictedResolver, SsrfGuard } from '../src';

/**
 * Host-run integration of the webhook POST client (step 6.2 W9) against the TEST-ONLY smtp-test
 * profile: dns-sink (127.0.0.1:${DNS_SINK_HOST_PORT}) is the only resolver; url-test is reached
 * through the dial map after the guard validated 203.0.113.10 (HTTPS with the test-pki CA).
 * Requires `docker compose --profile smtp-test up -d test-pki dns-sink url-test`.
 */

const env = (name: string, fallback?: string): string => {
  const value = process.env[name] ?? fallback;
  if (value === undefined) throw new Error(`${name} is not set (.env, URL protection section)`);
  return value;
};

const repoRoot = resolve(__dirname, '../../..');
const seamEnv = { nodeEnv: 'test', appEnv: 'local' };
const resolver = new RestrictedResolver({
  servers: [env('URL_DNS_SERVERS', `127.0.0.1:${env('DNS_SINK_HOST_PORT', '1053')}`)],
  timeoutMs: 2000,
  tries: 1,
});
const guard = new SsrfGuard({
  allowedPorts: [443],
  testAllowCidrs: ['203.0.113.0/24'],
  ...seamEnv,
});
let ca = '';

const poster = (): GuardedPoster =>
  new GuardedPoster({
    guard,
    resolver,
    connectTimeoutMs: 3000,
    totalTimeoutMs: 8000,
    maxResponseBytes: 4096,
    dialMap: parseDialMap(env('URL_FETCH_TEST_DIAL_MAP'), seamEnv),
    ca,
    env: seamEnv,
  });

const BODY = JSON.stringify({ id: '0193a1b2-0000-8000-8000-000000000001', type: 'webhook.ping' });

beforeAll(async () => {
  try {
    ca = execFileSync('docker', ['compose', 'exec', '-T', 'url-test', 'cat', '/pki/ca/ca.pem'], {
      cwd: repoRoot,
      encoding: 'utf8',
    });
  } catch {
    throw new Error(
      'url-test is not running: docker compose --profile smtp-test up -d test-pki dns-sink url-test',
    );
  }
  const port = Number(env('URL_TEST_HTTP_HOST_PORT', '18080'));
  const health = await fetch(`http://127.0.0.1:${port}/health`).catch(() => null);
  if (!health?.ok) throw new Error('url-test is not reachable on its published port');
});

describe('GuardedPoster against dns-sink and url-test', () => {
  it('POSTs over verified TLS to the validated address', async () => {
    const result = await poster().post({
      url: 'https://clean-site.test/landing',
      headers: { 'EG-Event-Id': '0193a1b2-0000-8000-8000-000000000001' },
      body: BODY,
    });
    expect(result.httpStatus).not.toBeNull();
    expect(['succeeded', 'http_error']).toContain(result.outcome);
    expect(result.blockedReason).toBeNull();
  });

  it('never follows a redirect', async () => {
    const result = await poster().post({
      url: 'https://short-link.test/s/clean',
      headers: {},
      body: BODY,
    });
    expect(result).toMatchObject({ outcome: 'redirect', errorCode: `http_${result.httpStatus}` });
    expect(result.httpStatus).toBeGreaterThanOrEqual(300);
    expect(result.httpStatus).toBeLessThan(400);
  });

  it.each([
    ['private-a.test', 'private'],
    ['loopback-a.test', 'loopback'],
    ['meta-a.test', 'metadata'],
    ['cgnat-a.test', 'cgnat'],
    ['v6-loop.test', 'loopback'],
    ['mixed-a.test', 'private'],
  ])('blocks %s (%s) from real DNS answers', async (host, reason) => {
    const result = await poster().post({ url: `https://${host}/`, headers: {}, body: BODY });
    expect(result).toMatchObject({ outcome: 'blocked', blockedReason: reason });
  });

  it('refuses plain http in this configuration', async () => {
    const result = await poster().post({
      url: 'http://clean-site.test/landing',
      headers: {},
      body: BODY,
    });
    expect(result).toMatchObject({ outcome: 'blocked', blockedReason: 'scheme' });
  });

  it('reports an unknown name as dns_error', async () => {
    const result = await poster().post({
      url: 'https://nothing.invalid-zone.test/',
      headers: {},
      body: BODY,
    });
    expect(result.outcome).toBe('dns_error');
  });
});
