/**
 * Step 7.1 P5 e2e (docs/plan/steps/20-admin-portal.md §3.4, ADR-0060), stubbed infrastructure:
 * the trusted client-IP forwarder in the whole api. Every request comes from the same socket
 * address (the "portal", 127.0.0.1, `HTTP_TRUST_PROXY=0`). With the shared token, two forwarded
 * browser addresses get separate per-IP login budgets (20 per minute); without it (or with a
 * wrong one) a forged `X-EG-Client-IP` changes nothing and every request shares the portal's
 * budget. The headers never reach a handler, and the forwarder is not in the OpenAPI document.
 */
import { randomBytes } from 'node:crypto';
import { Controller, Get, Module, Req } from '@nestjs/common';
import type { Request } from 'express';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Public } from '../src/auth-contracts/decorators';
import { clientIp } from '../src/http/client-ip';
import { buildOpenApiDocument } from '../src/http/openapi';
import { AuthenticationService } from '../src/modules/auth/services/authentication.service';
import { createStubbedApiApp, type StubbedApiApp } from './support/api-test-app';

const TOKEN = randomBytes(24).toString('hex');

/** Test-only: what a handler sees of the request (never in production code). */
@Controller({ path: 'forwarder-echo', version: '1' })
class ForwarderEchoController {
  @Get()
  @Public()
  echo(@Req() req: Request): { clientIp: string | null; headers: string[]; raw: string[] } {
    return {
      clientIp: clientIp(req),
      headers: Object.keys(req.headers),
      raw: req.rawHeaders.filter((_, i) => i % 2 === 0).map((h) => h.toLowerCase()),
    };
  }
}

@Module({ controllers: [ForwarderEchoController] })
class ForwarderEchoModule {}

const login = vi.fn();

async function build(env: Record<string, string>): Promise<StubbedApiApp> {
  return createStubbedApiApp(env, {
    imports: [ForwarderEchoModule],
    override: (builder) =>
      builder.overrideProvider(AuthenticationService).useValue({
        login: (...args: unknown[]) => login(...args) as unknown,
      }),
  });
}

const BODY = { email: 'a@example.com', password: 'x' };

describe('trusted forwarder enabled (API_TRUSTED_FORWARDER_TOKEN set)', () => {
  let t: StubbedApiApp;

  beforeAll(async () => {
    t = await build({ API_TRUSTED_FORWARDER_TOKEN: TOKEN });
  });
  afterAll(async () => {
    await t?.close();
  });
  beforeEach(() => {
    t.kv.entries.clear();
    login.mockReset();
    login.mockResolvedValue({ mfaRequired: true, mfaToken: 'egt_y', expiresIn: 300 });
  });

  const viaPortal = (ip: string, token: string | null = TOKEN) => {
    const req = t.http().post('/api/v1/auth/login').set('X-EG-Client-IP', ip);
    return (token === null ? req : req.set('X-EG-Forwarder-Token', token)).send(BODY);
  };

  it('gives two forwarded addresses separate login budgets (20 per minute each)', async () => {
    for (let i = 0; i < 20; i += 1) await viaPortal('203.0.113.10').expect(200);
    const limited = await viaPortal('203.0.113.10').expect(429);
    expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
    // Another browser behind the same portal is not affected.
    for (let i = 0; i < 20; i += 1) await viaPortal('2001:db8::20').expect(200);
    await viaPortal('2001:db8::20').expect(429);
    // The login service saw the browser addresses, never the portal's.
    const ips = new Set(login.mock.calls.map((c) => (c[1] as { ip: string | null }).ip));
    expect([...ips].sort()).toEqual(['2001:db8::20', '203.0.113.10']);
  });

  it('a forged X-EG-Client-IP without or with a wrong token shares the portal budget', async () => {
    for (let i = 0; i < 10; i += 1) await viaPortal(`198.51.100.${i}`, null).expect(200);
    for (let i = 10; i < 20; i += 1) await viaPortal(`198.51.100.${i}`, 'w'.repeat(48)).expect(200);
    // 20 requests, 20 different forged addresses: one budget (the socket address), now used up.
    await viaPortal('198.51.100.99', null).expect(429);
    await t.http().post('/api/v1/auth/login').send(BODY).expect(429);
    const ips = new Set(login.mock.calls.map((c) => (c[1] as { ip: string | null }).ip));
    expect([...ips]).toEqual(['127.0.0.1']);
    // A valid token still gets the browser its own budget.
    await viaPortal('198.51.100.200').expect(200);
  });

  it('normalizes IPv4-mapped addresses and ignores invalid ones', async () => {
    await viaPortal('::ffff:203.0.113.77').expect(200);
    await viaPortal('not-an-ip').expect(200);
    expect(login.mock.calls.map((c) => (c[1] as { ip: string | null }).ip)).toEqual([
      '203.0.113.77',
      '127.0.0.1',
    ]);
  });

  it('never lets the headers reach a handler', async () => {
    for (const token of [TOKEN, 'wrong-token'.padEnd(40, 'x')]) {
      const res = await t
        .http()
        .get('/api/v1/forwarder-echo')
        .set('X-EG-Client-IP', '203.0.113.5')
        .set('X-EG-Forwarder-Token', token)
        .expect(200);
      expect(res.body.headers).not.toContain('x-eg-client-ip');
      expect(res.body.headers).not.toContain('x-eg-forwarder-token');
      expect(res.body.raw).not.toContain('x-eg-client-ip');
      expect(res.body.raw).not.toContain('x-eg-forwarder-token');
      expect(res.body.clientIp).toBe(token === TOKEN ? '203.0.113.5' : '127.0.0.1');
    }
  });

  it('counts outcomes in api_trusted_forwarder_total and is absent from the OpenAPI document', async () => {
    await viaPortal('203.0.113.1').expect(200);
    await viaPortal('203.0.113.1', 'bad').expect(200);
    const metrics = await t.http().get('/metrics').expect(200);
    const lines = metrics.text.split('\n').filter((l) => l.startsWith('api_trusted_forwarder'));
    for (const outcome of ['accepted', 'rejected', 'invalid_ip', 'disabled']) {
      expect(
        lines.some((l) => l.includes(`outcome="${outcome}"`)),
        outcome,
      ).toBe(true);
    }
    expect(lines.join('\n')).not.toContain('203.0.113.1');
    const text = JSON.stringify(buildOpenApiDocument(t.app)).toLowerCase();
    expect(text).not.toContain('x-eg-client-ip');
    expect(text).not.toContain('x-eg-forwarder-token');
  });
});

describe('trusted forwarder disabled (no token)', () => {
  let t: StubbedApiApp;

  beforeAll(async () => {
    t = await build({});
  });
  afterAll(async () => {
    await t?.close();
  });

  it('ignores and strips the headers even with a token-shaped value', async () => {
    const res = await t
      .http()
      .get('/api/v1/forwarder-echo')
      .set('X-EG-Client-IP', '203.0.113.5')
      .set('X-EG-Forwarder-Token', TOKEN)
      .expect(200);
    expect(res.body.clientIp).toBe('127.0.0.1');
    expect(res.body.headers).not.toContain('x-eg-forwarder-token');
    const metrics = await t.http().get('/metrics').expect(200);
    expect(metrics.text).toMatch(
      /^api_trusted_forwarder_total\{[^}]*outcome="disabled"[^}]*\} 1$/m,
    );
  });
});
