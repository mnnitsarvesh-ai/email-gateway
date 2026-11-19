// provider-fake (TEST-ONLY, step 8.2 §10.3/§10.5, docs/plan/steps/25-m365-google-connectors.md):
// the local stand-in for the Microsoft identity platform, Microsoft Graph, the Google OAuth token
// endpoint and the Google Admin SDK. It runs the library's `FakeProviderServer`
// (@email-gateway/provider-integrations `testing`, the same class the in-process suites use), so
// the contract suite `describeProviderClientContract` behaves identically against both. Compose
// profile smtp-test only; never deployed; never contacts the Internet.
//
//   HTTP ${PROVIDER_FAKE_HTTP_PORT:-8480}
//     /m365/login/{tenant}/oauth2/v2.0/token            client credentials (secret or assertion)
//     /m365/login/organizations/v2.0/adminconsent       admin-consent redirect (302 to redirect_uri
//                                                        with tenant, admin_consent, state)
//     /m365/graph/v1.0/organization, /domains/...       Graph reads
//     /google/token                                     JWT bearer (domain-wide delegation)
//     /google/admin/admin/directory/v1/...              Admin SDK customer and domains
//     /_fake/*  (Bearer PROVIDER_FAKE_ADMIN_TOKEN)       runtime state: tenants, apps, consents,
//                                                        customers, service-account PUBLIC keys,
//                                                        delegations, scripted failures, paging,
//                                                        request log; plus (this file):
//       POST /_fake/dns/txt         { name, values: [..] }  TXT record under PROVIDER_FAKE_DNS_ZONE
//       POST /_fake/dns/txt/delete  { name }
//       POST /_fake/reset           also clears the DNS records
//     GET /health                                       liveness
//   DNS ${PROVIDER_FAKE_DNS_PORT:-5300} udp+tcp: TXT of PROVIDER_FAKE_DNS_ZONE (relay-proof.test),
//     reached through dns-sink (forward without cache).
//
// The platform Microsoft app of the local `.env` (PROVIDER_M365_MAILFLOW_APP_CLIENT_ID and
// _CLIENT_SECRET, read from the same keys as the integration-worker) is registered at start, so
// the `platform_app` consent flow works without setup. No secret is ever logged: the request log
// keeps paths, tenant/client ids and status codes only. Zero dependencies beyond the library's
// own (`jose`).
import { timingSafeEqual } from 'node:crypto';
import http from 'node:http';
import { createRequire } from 'node:module';
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { startDns, TxtRegistry } from './dns.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const MAILFLOW_ROLES = ['Organization.Read.All', 'Domain.Read.All'];
const MAX_BODY_BYTES = 262_144;

const log = (message, fields = {}) =>
  process.stdout.write(
    `${JSON.stringify({ time: new Date().toISOString(), message, ...fields })}\n`,
  );

function safeEqual(a, b) {
  const x = Buffer.from(String(a), 'utf8');
  const y = Buffer.from(String(b), 'utf8');
  return x.length === y.length && timingSafeEqual(x, y);
}

async function readJson(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) throw new Error('body too large');
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString('utf8');
  return text ? JSON.parse(text) : {};
}

const send = (res, status, body) => {
  if (body === undefined) {
    res.writeHead(status);
    return res.end();
  }
  const text = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(text);
};

/**
 * Starts the provider-fake. Options default to the environment; returns the bound ports and a
 * `close()` (the contract suite starts it on ephemeral ports when no Compose fake is given).
 */
export async function startProviderFake(env = process.env) {
  const adminToken = env.PROVIDER_FAKE_ADMIN_TOKEN ?? '';
  if (adminToken.length < 16) {
    throw new Error('PROVIDER_FAKE_ADMIN_TOKEN must be set (at least 16 characters)');
  }
  const host = env.PROVIDER_FAKE_HOST ?? '0.0.0.0';
  const httpPort = Number(env.PROVIDER_FAKE_HTTP_PORT ?? 8480);
  const dnsPort = Number(env.PROVIDER_FAKE_DNS_PORT ?? 5300);
  const zone = env.PROVIDER_FAKE_DNS_ZONE ?? 'relay-proof.test';
  const libPath = env.PROVIDER_FAKE_LIB ?? './lib/fake-provider-server.js';
  const require = createRequire(import.meta.url);
  const { FakeProviderServer } = require(isAbsolute(libPath) ? libPath : resolve(here, libPath));

  // The library fake listens on loopback only; this front server adds /health and the DNS admin
  // routes and forwards everything else unchanged (the Host header is kept: the fake derives JWT
  // audiences and paging links from it).
  const inner = new FakeProviderServer({ host: '127.0.0.1', port: 0, adminToken });
  await inner.start();
  const innerUrl = new URL(inner.baseUrl);
  const registry = new TxtRegistry(zone);

  const platformClientId = env.PROVIDER_M365_MAILFLOW_APP_CLIENT_ID?.trim();
  const platformSecret = env.PROVIDER_M365_MAILFLOW_APP_CLIENT_SECRET?.trim();
  const bootstrapPlatformApp = () => {
    if (platformClientId && platformSecret) {
      inner.addMicrosoftApp({
        clientId: platformClientId,
        secret: platformSecret,
        requiredRoles: MAILFLOW_ROLES,
      });
    }
  };
  bootstrapPlatformApp();

  const authorized = (req) => {
    const given = /^Bearer (.+)$/.exec(req.headers.authorization ?? '')?.[1] ?? '';
    return safeEqual(given, adminToken);
  };

  const forward = (req, res) => {
    const upstream = http.request(
      {
        host: innerUrl.hostname,
        port: innerUrl.port,
        method: req.method,
        path: req.url,
        headers: req.headers,
      },
      (response) => {
        res.writeHead(response.statusCode ?? 502, response.headers);
        response.pipe(res);
      },
    );
    upstream.on('error', () => {
      if (!res.headersSent) send(res, 502, { error: 'upstream_unavailable' });
      else res.destroy();
    });
    req.pipe(upstream);
  };

  const server = http.createServer(async (req, res) => {
    const path = new URL(req.url ?? '/', 'http://provider-fake.invalid').pathname;
    try {
      if (req.method === 'GET' && path === '/health') return send(res, 200, { status: 'ok' });
      if (path.startsWith('/_fake/dns/')) {
        if (!authorized(req)) return send(res, 401, { error: 'unauthorized' });
        if (req.method !== 'POST') return send(res, 405, { error: 'method_not_allowed' });
        const body = await readJson(req);
        if (path === '/_fake/dns/txt') {
          registry.set(body.name, body.values);
          log('dns txt registered', { name: String(body.name).toLowerCase() });
          return send(res, 204);
        }
        if (path === '/_fake/dns/txt/delete') {
          registry.delete(body.name);
          return send(res, 204);
        }
        return send(res, 404, { error: 'not_found' });
      }
      if (path === '/_fake/reset' && req.method === 'POST') {
        if (!authorized(req)) return send(res, 401, { error: 'unauthorized' });
        inner.reset();
        registry.clear();
        bootstrapPlatformApp();
        return send(res, 204);
      }
      return forward(req, res);
    } catch {
      if (!res.headersSent) send(res, 400, { error: 'invalid_request' });
      else res.destroy();
    }
  });
  await new Promise((resolveListen) => server.listen(httpPort, host, resolveListen));
  const dns = await startDns(registry, dnsPort, host);
  const ports = { http: server.address().port, dns: dns.port };
  log('provider-fake listening', { ...ports, zone });
  return {
    ports,
    close: async () => {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(() => r()));
      await dns.close();
      await inner.stop();
    },
  };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  startProviderFake().then(
    (fake) => {
      const stop = () => void fake.close().finally(() => process.exit(0));
      process.on('SIGTERM', stop);
      process.on('SIGINT', stop);
    },
    (error) => {
      log('provider-fake failed to start', {
        error: error instanceof Error ? error.message : 'error',
      });
      process.exit(1);
    },
  );
}
