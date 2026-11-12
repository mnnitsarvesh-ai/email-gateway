/**
 * Step 6.1 WP3 e2e (stubbed infrastructure): `GET /threat-intelligence/lookup`
 * (docs/plan/steps/18-rest-api.md §3.3, §8): normalization and matching inputs, the response
 * without analyst data, the audit row, strict queries and invalid values, RBAC, the expensive
 * class and the OpenAPI operation.
 */
// @covers get /api/v1/threat-intelligence/lookup
import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { buildOpenApiDocument } from '../src/http/openapi';
import { createInsightApp, expectCoded, type InsightApp } from './insights-support';

let t: InsightApp;
const sha = (v: string) => createHash('sha256').update(v).digest('hex');
const seen = {
  firstSeenAt: new Date('2026-11-01T00:00:00.000Z'),
  lastSeenAt: new Date('2026-11-10T00:00:00.000Z'),
};
let asked: unknown[][] = [];

beforeAll(async () => {
  t = await createInsightApp();
});
afterAll(async () => {
  await t?.close();
});
beforeEach(() => {
  t.principals.user(['threat_intel:read']);
  t.principals.apiKeyWith(['threat_intel:read']);
  t.doubles.audit.entries.length = 0;
  asked = [];
  t.doubles.threatIntel.indicators = (...args: unknown[]) => {
    asked.push(args);
    return Promise.resolve([]);
  };
  t.doubles.threatIntel.signature = () => Promise.resolve(null);
});

const lookup = async (query: string, auth?: Record<string, string>) =>
  t
    .http()
    .get(`/api/v1/threat-intelligence/lookup?${query}`)
    .set(auth ?? (await t.principals.bearer()));

describe('GET /threat-intelligence/lookup', () => {
  it('normalizes a domain like the engines and returns matches without analyst data', async () => {
    t.doubles.threatIntel.indicators = (...args: unknown[]) => {
      asked.push(args);
      return Promise.resolve([
        {
          valueSha256: sha('example.com'),
          severity: 'high',
          category: 'phishing',
          expiresAt: null,
          ...seen,
        },
      ]);
    };
    const res = await lookup('type=domain&value=Login.EXAMPLE.com.');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      type: 'domain',
      valueSha256: sha('login.example.com'),
      known: true,
      matches: [
        {
          source: 'platform_indicator',
          severity: 'high',
          category: 'phishing',
          firstSeenAt: '2026-11-01T00:00:00.000Z',
          lastSeenAt: '2026-11-10T00:00:00.000Z',
          expiresAt: null,
        },
      ],
    });
    expect(asked[0]![0]).toBe('domain');
    expect(asked[0]![1]).toEqual([sha('login.example.com'), sha('example.com')]);
    expect(t.doubles.audit.entries).toHaveLength(1);
    expect(t.doubles.audit.entries[0]).toMatchObject({
      organizationId: 1n,
      action: 'threat_intel.looked_up',
      metadata: {
        type: 'domain',
        valueSha256: sha('login.example.com'),
        known: true,
        matchCount: 1,
      },
    });
    expect(JSON.stringify(t.doubles.audit.entries[0]!.metadata)).not.toContain('example');
  });

  it('looks up sha256 values in the indicators and the hash catalogue (API keys accepted)', async () => {
    t.doubles.threatIntel.signature = () =>
      Promise.resolve({
        severity: 'critical',
        expiresAt: new Date('2027-01-01T00:00:00.000Z'),
        ...seen,
      });
    const hex = 'EF'.repeat(32);
    const res = await lookup(`type=sha256&value=${hex}`, t.principals.apiKeyHeaders);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      type: 'sha256',
      valueSha256: sha('ef'.repeat(32)),
      known: true,
      matches: [{ source: 'hash_catalog', severity: 'critical', category: null }],
    });
    expect(asked[0]!.slice(0, 2)).toEqual(['file_sha256', [sha('ef'.repeat(32))]]);
  });

  it('answers known=false for url and ip values without matches', async () => {
    const url = await lookup(`type=url&value=${encodeURIComponent('https://Example.com:443/a')}`);
    expect(url.body).toMatchObject({ type: 'url', known: false, matches: [] });
    expect(url.body.valueSha256).toBe(sha('https://example.com/a'));
    const ip = await lookup('type=ip&value=2001:DB8::0:1');
    expect(ip.body).toMatchObject({ type: 'ip', known: false, valueSha256: sha('2001:db8::1') });
  });

  it('refuses unknown parameters, missing or invalid values with 400 validation_failed', async () => {
    for (const query of [
      'type=domain',
      'value=example.com',
      'type=email&value=a@b.c',
      'type=domain&value=example.com&extra=1',
      'type=sha256&value=abc',
      'type=url&value=ftp%3A%2F%2Fexample.com%2F',
      'type=domain&value=co.uk',
      'type=ip&value=999.1.1.1',
      `type=url&value=${'a'.repeat(2049)}`,
    ]) {
      const res = await lookup(query);
      expect(res.status, query).toBe(400);
      expectCoded(res.body, 'validation_failed');
    }
    expect(t.doubles.audit.entries).toEqual([]);
  });

  it('requires threat_intel:read', async () => {
    t.principals.user(['report:read', 'audit:read']);
    t.principals.apiKeyWith(['message:read']);
    expectCoded((await lookup('type=ip&value=192.0.2.1')).body, 'forbidden');
    expect((await lookup('type=ip&value=192.0.2.1', t.principals.apiKeyHeaders)).status).toBe(403);
    expect(
      (await t.http().get('/api/v1/threat-intelligence/lookup?type=ip&value=192.0.2.1')).status,
    ).toBe(401);
  });

  it('is in the expensive rate class (429 with headers)', async () => {
    const limited = await createInsightApp({ API_RATE_EXPENSIVE_PER_MINUTE: '1' });
    try {
      limited.principals.user(['threat_intel:read']);
      const auth = await limited.principals.bearer();
      const ok = await limited
        .http()
        .get('/api/v1/threat-intelligence/lookup?type=ip&value=192.0.2.1')
        .set(auth);
      expect(ok.status).toBe(200);
      const res = await limited
        .http()
        .get('/api/v1/threat-intelligence/lookup?type=ip&value=192.0.2.1')
        .set(auth);
      expect(res.status).toBe(429);
      expect(res.body).toMatchObject({ code: 'rate_limited', scope: 'expensive' });
      expect(res.headers['ratelimit-remaining']).toBe('0');
      expect(res.headers['retry-after']).toBeDefined();
    } finally {
      await limited.close();
    }
  });

  it('is documented with its tag, permission, rate class and example', () => {
    const doc = buildOpenApiDocument(t.app);
    const op = doc.paths['/api/v1/threat-intelligence/lookup']!.get as unknown as Record<
      string,
      unknown
    > & {
      responses: Record<string, { content?: Record<string, { example?: unknown }> }>;
      parameters: Array<{ name: string; required?: boolean }>;
    };
    expect(op.tags).toEqual(['threat-intelligence']);
    expect(op['x-eg-permissions']).toEqual({ mode: 'all', permissions: ['threat_intel:read'] });
    expect(op['x-eg-rate-class']).toBe('expensive');
    expect(op.parameters.map((p) => p.name).sort()).toEqual(['type', 'value']);
    expect(op.responses['200']!.content!['application/json']!.example).toBeDefined();
    expect(op.summary).toEqual(expect.any(String));
  });
});
