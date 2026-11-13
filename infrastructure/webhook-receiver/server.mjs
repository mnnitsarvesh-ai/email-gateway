// webhook-receiver (TEST-ONLY, step 6.2 §4.5, docs/plan/steps/19-webhooks-notifications.md): the
// local webhook endpoint of the stack suites. Zero dependencies (Node 22), read-only container.
//
//   HTTPS 443  test-pki leaf `webhook-receiver` (${WEBHOOK_RECEIVER_PKI_DIR}/{cert,key}.pem; SANs
//              hooks.receiver.test, hooks2.receiver.test, 203.0.113.20)
//   HTTP  80   the same endpoint without TLS (only for WEBHOOK_ALLOW_HTTP test runs)
//   admin 8080 published on 127.0.0.1:${WEBHOOK_RECEIVER_ADMIN_HOST_PORT:-18091}
//     GET    /health                 liveness
//     PUT    /program/<path>         { responses: [{ status, retryAfter?, delayMs?, body? }], then? }
//                                     answers the next requests of /<path> in order, then `then`
//                                     (default 200)
//     PUT    /secrets/<path>         { secrets: ["whsec_…", …] } verify EG-Signature of /<path>
//     GET    /requests/<path>        the recorded requests of /<path> (oldest first)
//     DELETE /requests               forget every recorded request, program and secret
//
// Every request to 443/80 is recorded per path: method, path, query, headers, the raw body
// (base64), the receive time and `signatureValid` (true/false when secrets are registered for the
// path, else null). The signature is checked with the documented algorithm (ADR-0055, §4.2):
// header `EG-Signature: t=<unix seconds>,v1=<hex>[,v1=<hex>]`, each v1 = hex HMAC-SHA256 keyed
// with the UTF-8 bytes of the whole secret over `<t>.<raw body>`; valid when |now − t| ≤ 300 s and
// any v1 matches any secret (constant-time comparison). Secrets and bodies are never logged.
import { createHmac, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';

const HTTPS_PORT = Number(process.env.WEBHOOK_RECEIVER_HTTPS_PORT ?? 443);
const HTTP_PORT = Number(process.env.WEBHOOK_RECEIVER_HTTP_PORT ?? 80);
const ADMIN_PORT = Number(process.env.WEBHOOK_RECEIVER_ADMIN_PORT ?? 8080);
const PKI_DIR = process.env.WEBHOOK_RECEIVER_PKI_DIR ?? '/pki/webhook-receiver';
const TOLERANCE_SECONDS = 300;
const MAX_BODY_BYTES = 1_048_576;
const MAX_REQUESTS_PER_PATH = 1000;
const MAX_PATHS = 1000;
const MAX_DELAY_MS = 120_000;

/** path → recorded requests */
const requests = new Map();
/** path → { responses: [...], then } */
const programs = new Map();
/** path → [secret, …] */
const secrets = new Map();

const log = (message, fields = {}) =>
  process.stdout.write(
    `${JSON.stringify({ time: new Date().toISOString(), message, ...fields })}\n`,
  );

/** `t=<ts>,v1=<hex>,…` → { timestamp, signatures } or null. */
export function parseSignature(header) {
  if (typeof header !== 'string' || header.length === 0 || header.length > 4096) return null;
  let timestamp = null;
  const signatures = [];
  for (const part of header.split(',')) {
    const eq = part.indexOf('=');
    if (eq <= 0) return null;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key === 't') {
      if (!/^[0-9]{1,12}$/.test(value) || timestamp !== null) return null;
      timestamp = Number(value);
    } else if (key === 'v1') {
      if (!/^[0-9a-f]{64}$/.test(value)) return null;
      signatures.push(value);
    }
  }
  if (timestamp === null || signatures.length === 0) return null;
  return { timestamp, signatures };
}

/** The documented verification (constant time over every v1 × every secret). */
export function signatureValid(header, rawBody, list, nowMs = Date.now()) {
  const parsed = parseSignature(header);
  if (parsed === null) return false;
  if (Math.abs(Math.floor(nowMs / 1000) - parsed.timestamp) > TOLERANCE_SECONDS) return false;
  let ok = false;
  for (const secret of list) {
    const expected = createHmac('sha256', Buffer.from(secret, 'utf8'))
      .update(`${parsed.timestamp}.`)
      .update(rawBody)
      .digest();
    for (const candidate of parsed.signatures) {
      const given = Buffer.from(candidate, 'hex');
      if (given.length === expected.length && timingSafeEqual(given, expected)) ok = true;
    }
  }
  return ok;
}

function readBody(req, limit = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const normalizePath = (value) => {
  const path = `/${String(value ?? '').replace(/^\/+/, '')}`;
  return path.length > 1024 ? path.slice(0, 1024) : path;
};

/** The webhook endpoint (443 and 80). */
async function endpoint(req, res, scheme) {
  let body;
  try {
    body = await readBody(req);
  } catch {
    res.writeHead(413).end();
    return;
  }
  const url = new URL(req.url ?? '/', 'http://receiver');
  const path = url.pathname;
  const list = secrets.get(path);
  const header = req.headers['eg-signature'];
  const record = {
    method: req.method,
    scheme,
    path,
    query: url.search,
    headers: req.headers,
    bodyBase64: body.toString('base64'),
    receivedAt: new Date().toISOString(),
    signatureValid: list === undefined ? null : signatureValid(String(header ?? ''), body, list),
  };
  if (!requests.has(path) && requests.size >= MAX_PATHS)
    requests.delete(requests.keys().next().value);
  const recorded = requests.get(path) ?? [];
  recorded.push(record);
  if (recorded.length > MAX_REQUESTS_PER_PATH) recorded.shift();
  requests.set(path, recorded);

  const program = programs.get(path);
  const next = program?.responses.shift() ?? { status: program?.then ?? 200 };
  const answer = () => {
    if (res.destroyed) return;
    const headers = { 'content-type': 'text/plain; charset=utf-8' };
    if (next.retryAfter !== undefined) headers['retry-after'] = String(next.retryAfter);
    if (next.location !== undefined) headers.location = String(next.location);
    res.writeHead(next.status, headers);
    res.end(next.body ?? (next.status >= 200 && next.status < 300 ? 'ok' : 'error'));
  };
  const delay = Math.min(Math.max(Number(next.delayMs ?? 0), 0), MAX_DELAY_MS);
  if (delay > 0) setTimeout(answer, delay).unref();
  else answer();
}

const json = (res, status, value) => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(value));
};

const validStatus = (s) => Number.isInteger(s) && s >= 100 && s <= 599;

/** The admin API (8080). */
async function admin(req, res) {
  const url = new URL(req.url ?? '/', 'http://admin');
  const route = url.pathname;
  try {
    if (req.method === 'GET' && route === '/health') return json(res, 200, { status: 'ok' });
    if (req.method === 'DELETE' && route === '/requests') {
      requests.clear();
      programs.clear();
      secrets.clear();
      return json(res, 200, { cleared: true });
    }
    if (req.method === 'GET' && route.startsWith('/requests/')) {
      const path = normalizePath(route.slice('/requests/'.length));
      return json(res, 200, { path, requests: requests.get(path) ?? [] });
    }
    if (req.method === 'PUT' && route.startsWith('/program/')) {
      const path = normalizePath(route.slice('/program/'.length));
      const doc = JSON.parse((await readBody(req, 65_536)).toString('utf8'));
      const responses = Array.isArray(doc.responses) ? doc.responses : [];
      if (responses.length > 1000 || !responses.every((r) => validStatus(r?.status))) {
        return json(res, 400, { error: 'responses must be [{ status: 100..599, … }]' });
      }
      const then = doc.then === undefined ? 200 : doc.then;
      if (!validStatus(then)) return json(res, 400, { error: 'then must be a status' });
      programs.set(path, {
        responses: responses.map((r) => ({
          status: r.status,
          ...(r.retryAfter !== undefined ? { retryAfter: String(r.retryAfter) } : {}),
          ...(r.delayMs !== undefined ? { delayMs: Number(r.delayMs) } : {}),
          ...(r.body !== undefined ? { body: String(r.body).slice(0, 65_536) } : {}),
          ...(r.location !== undefined ? { location: String(r.location) } : {}),
        })),
        then,
      });
      return json(res, 200, { path, responses: responses.length, then });
    }
    if (req.method === 'PUT' && route.startsWith('/secrets/')) {
      const path = normalizePath(route.slice('/secrets/'.length));
      const doc = JSON.parse((await readBody(req, 65_536)).toString('utf8'));
      const list = Array.isArray(doc.secrets) ? doc.secrets : [];
      if (
        list.length === 0 ||
        list.length > 8 ||
        !list.every((s) => typeof s === 'string' && s.length > 0 && s.length <= 256)
      ) {
        return json(res, 400, { error: 'secrets must be 1..8 strings' });
      }
      secrets.set(path, list);
      // The count only: a secret is never echoed or logged.
      return json(res, 200, { path, secrets: list.length });
    }
    return json(res, 404, { error: 'not found' });
  } catch {
    return json(res, 400, { error: 'invalid request' });
  }
}

function start() {
  let tlsOptions;
  try {
    tlsOptions = {
      cert: readFileSync(`${PKI_DIR}/cert.pem`),
      key: readFileSync(`${PKI_DIR}/key.pem`),
    };
  } catch {
    log('webhook-receiver: certificate not found; HTTPS disabled', { pkiDir: PKI_DIR });
  }
  if (tlsOptions) {
    https
      .createServer(tlsOptions, (req, res) => void endpoint(req, res, 'https'))
      .listen(HTTPS_PORT, () => log('webhook-receiver https listening', { port: HTTPS_PORT }));
  }
  http
    .createServer((req, res) => void endpoint(req, res, 'http'))
    .listen(HTTP_PORT, () => log('webhook-receiver http listening', { port: HTTP_PORT }));
  http
    .createServer((req, res) => void admin(req, res))
    .listen(ADMIN_PORT, () => log('webhook-receiver admin listening', { port: ADMIN_PORT }));
}

if (process.env.WEBHOOK_RECEIVER_NO_LISTEN !== '1') start();

for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => process.exit(0));
