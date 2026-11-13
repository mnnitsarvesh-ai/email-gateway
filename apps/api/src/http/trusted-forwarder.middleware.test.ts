import { ExpressAdapter } from '@nestjs/platform-express';
import type { Express, Request, Response } from 'express';
import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';
import { clientIp } from './client-ip';
import {
  CLIENT_IP_HEADER,
  FORWARDER_TOKEN_HEADER,
  normalizeForwardedIp,
  type TrustedForwarderOutcome,
  trustedForwarderMiddleware,
} from './trusted-forwarder.middleware';

const TOKEN = 'f'.repeat(48);

function setup(token: string | undefined) {
  const outcomes: TrustedForwarderOutcome[] = [];
  const warn = vi.fn();
  const middleware = trustedForwarderMiddleware({
    token,
    outcomes: { inc: ({ outcome }) => outcomes.push(outcome) },
    logger: { warn },
  });
  return { middleware, outcomes, warn };
}

/** A fake request whose `ip` is a prototype getter, like Express's. */
function fakeRequest(headers: Record<string, string | string[]>): Request {
  const proto = {
    get ip() {
      return '10.0.0.9';
    },
  };
  const req = Object.create(proto) as Request & { rawHeaders: string[] };
  req.headers = { ...headers, host: 'api' };
  req.rawHeaders = Object.entries(req.headers).flatMap(([k, v]) => [
    k.toUpperCase(),
    Array.isArray(v) ? v.join(', ') : String(v),
  ]);
  return req;
}

function run(token: string | undefined, headers: Record<string, string | string[]>) {
  const t = setup(token);
  const req = fakeRequest(headers);
  const next = vi.fn();
  t.middleware(req, {} as Response, next);
  expect(next).toHaveBeenCalledOnce();
  return { ...t, req };
}

describe('normalizeForwardedIp', () => {
  it('accepts IPv4 and IPv6 literals, unwraps IPv4-mapped IPv6', () => {
    expect(normalizeForwardedIp('203.0.113.7')).toBe('203.0.113.7');
    expect(normalizeForwardedIp(' 2001:db8::1 ')).toBe('2001:db8::1');
    expect(normalizeForwardedIp('::ffff:198.51.100.4')).toBe('198.51.100.4');
    expect(normalizeForwardedIp('::FFFF:198.51.100.4')).toBe('198.51.100.4');
    expect(normalizeForwardedIp('::ffff:c633:6404')).toBe('::ffff:c633:6404');
  });

  it('refuses lists, names, ports, empty and oversized values', () => {
    for (const bad of [
      undefined,
      '',
      'portal',
      '203.0.113.7, 10.0.0.1',
      '203.0.113.7:443',
      '[2001:db8::1]',
      '999.1.1.1',
      `${'1:'.repeat(30)}1`,
    ]) {
      expect(normalizeForwardedIp(bad), String(bad)).toBeNull();
    }
  });
});

describe('trustedForwarderMiddleware', () => {
  it('accepts a valid token and IP: req.ip and clientIp() are the forwarded address', () => {
    const { req, outcomes, warn } = run(TOKEN, {
      [CLIENT_IP_HEADER]: '203.0.113.7',
      [FORWARDER_TOKEN_HEADER]: TOKEN,
    });
    expect(req.ip).toBe('203.0.113.7');
    expect(clientIp(req)).toBe('203.0.113.7');
    expect(outcomes).toEqual(['accepted']);
    expect(warn).not.toHaveBeenCalled();
  });

  it('normalizes an IPv4-mapped forwarded address', () => {
    const { req } = run(TOKEN, {
      [CLIENT_IP_HEADER]: '::ffff:198.51.100.4',
      [FORWARDER_TOKEN_HEADER]: TOKEN,
    });
    expect(req.ip).toBe('198.51.100.4');
  });

  it('rejects a wrong, shorter, longer or missing token: req.ip unchanged, warn without values', () => {
    for (const token of [`${TOKEN.slice(1)}x`, TOKEN.slice(1), `${TOKEN}f`, undefined]) {
      const headers: Record<string, string> = { [CLIENT_IP_HEADER]: '203.0.113.7' };
      if (token !== undefined) headers[FORWARDER_TOKEN_HEADER] = token;
      const { req, outcomes, warn } = run(TOKEN, headers);
      expect(req.ip).toBe('10.0.0.9');
      expect(outcomes).toEqual(['rejected']);
      expect(warn).toHaveBeenCalledOnce();
      expect(JSON.stringify(warn.mock.calls)).not.toContain('203.0.113.7');
      expect(JSON.stringify(warn.mock.calls)).not.toContain(TOKEN.slice(0, 10));
    }
  });

  it('ignores an invalid or missing IP with a valid token', () => {
    const invalid = run(TOKEN, {
      [CLIENT_IP_HEADER]: 'evil.example',
      [FORWARDER_TOKEN_HEADER]: TOKEN,
    });
    expect(invalid.req.ip).toBe('10.0.0.9');
    expect(invalid.outcomes).toEqual(['invalid_ip']);
    expect(invalid.warn).toHaveBeenCalledOnce();
    expect(JSON.stringify(invalid.warn.mock.calls)).not.toContain('evil.example');
    // Repeated headers are joined by Node: a list is not one address.
    const list = run(TOKEN, {
      [CLIENT_IP_HEADER]: ['203.0.113.7', '203.0.113.8'],
      [FORWARDER_TOKEN_HEADER]: TOKEN,
    });
    expect(list.req.ip).toBe('10.0.0.9');
    expect(list.outcomes).toEqual(['invalid_ip']);
    // The portal omits the address when it cannot determine one: not an attack, no warning.
    const missing = run(TOKEN, { [FORWARDER_TOKEN_HEADER]: TOKEN });
    expect(missing.req.ip).toBe('10.0.0.9');
    expect(missing.outcomes).toEqual(['invalid_ip']);
    expect(missing.warn).not.toHaveBeenCalled();
  });

  it('when disabled ignores the headers, counting only requests that carried one', () => {
    const disabled = run(undefined, {
      [CLIENT_IP_HEADER]: '203.0.113.7',
      [FORWARDER_TOKEN_HEADER]: TOKEN,
    });
    expect(disabled.req.ip).toBe('10.0.0.9');
    expect(disabled.outcomes).toEqual(['disabled']);
    expect(run('', { [CLIENT_IP_HEADER]: '203.0.113.7' }).outcomes).toEqual(['disabled']);
    expect(run(undefined, {}).outcomes).toEqual([]);
    expect(run(TOKEN, {}).outcomes).toEqual([]);
  });

  it('always strips both headers from headers and rawHeaders', () => {
    for (const token of [TOKEN, undefined]) {
      for (const sent of [TOKEN, 'wrong']) {
        const { req } = run(token, {
          [CLIENT_IP_HEADER]: '203.0.113.7',
          [FORWARDER_TOKEN_HEADER]: sent,
        });
        expect(req.headers[CLIENT_IP_HEADER]).toBeUndefined();
        expect(req.headers[FORWARDER_TOKEN_HEADER]).toBeUndefined();
        expect(req.headers.host).toBe('api');
        expect(req.rawHeaders.map((h) => h.toLowerCase())).not.toContain(CLIENT_IP_HEADER);
        expect(req.rawHeaders.map((h) => h.toLowerCase())).not.toContain(FORWARDER_TOKEN_HEADER);
        expect(req.rawHeaders.join('|')).not.toContain(sent);
        expect(req.rawHeaders).toEqual(['HOST', 'api']);
      }
    }
  });
});

describe('with the installed Express (req.ip is a prototype getter honouring trust proxy)', () => {
  const app = (token: string | undefined, trustProxy: number) => {
    const t = setup(token);
    // The Express instance of the installed @nestjs/platform-express (the api's Express 5).
    const server = new ExpressAdapter().getInstance<Express>();
    server.set('trust proxy', trustProxy);
    server.use(t.middleware);
    server.get('/ip', (req, res) => {
      res.json({
        ip: req.ip,
        clientIp: clientIp(req),
        headers: Object.keys(req.headers),
        raw: req.rawHeaders.filter((_, i) => i % 2 === 0).map((h) => h.toLowerCase()),
      });
    });
    return { server, ...t };
  };

  it('the instance property shadows the getter; other requests keep the socket address', async () => {
    const { server, outcomes } = app(TOKEN, 0);
    const forwarded = await request(server)
      .get('/ip')
      .set('X-EG-Client-IP', '203.0.113.7')
      .set('X-EG-Forwarder-Token', TOKEN)
      .expect(200);
    expect(forwarded.body.ip).toBe('203.0.113.7');
    expect(forwarded.body.clientIp).toBe('203.0.113.7');
    expect(forwarded.body.headers).not.toContain(CLIENT_IP_HEADER);
    expect(forwarded.body.raw).not.toContain(FORWARDER_TOKEN_HEADER);
    const plain = await request(server).get('/ip').expect(200);
    expect(plain.body.clientIp).toBe('127.0.0.1');
    const forged = await request(server)
      .get('/ip')
      .set('X-EG-Client-IP', '203.0.113.7')
      .set('X-EG-Forwarder-Token', 'not-the-token')
      .expect(200);
    expect(forged.body.clientIp).toBe('127.0.0.1');
    expect(forged.body.headers).not.toContain(FORWARDER_TOKEN_HEADER);
    expect(outcomes).toEqual(['accepted', 'rejected']);
  });

  it('a forged header never beats trust proxy; X-Forwarded-For handling is unchanged', async () => {
    const { server } = app(TOKEN, 1);
    const res = await request(server)
      .get('/ip')
      .set('X-Forwarded-For', '198.51.100.20')
      .set('X-EG-Client-IP', '203.0.113.7')
      .expect(200);
    expect(res.body.clientIp).toBe('198.51.100.20');
  });
});
