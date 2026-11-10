// Recording sinkhole of the sandbox detonation network (step 4.6 X5, docs/plan/steps/14-sandbox.md;
// ADR-0039; docs/security/sandbox-threat-model.md §4.5).
//
// LOCAL/CI ONLY (infrastructure/sandbox/compose.exec.yml) — part of the hardened-container test
// harness, which is NOT A VM BOUNDARY. Zero dependencies; mounted read-only into node:22-alpine
// like infrastructure/url-test (no image build). It NEVER forwards anything anywhere.
//
//   detonation address (SINKHOLE_DNS_ADDRESS, default 172.31.253.53):
//     DNS  UDP + TCP 53   every A query → the detonation address; AAAA and other types → empty
//                         NOERROR; records name + type
//     HTTP TCP 80         records host, method, port, SHA-256 of the path and of the User-Agent;
//                         answers 200 with the fixed 2-byte body "ok"; bounded header size + time
//     TLS  TCP 443        reads the ClientHello (≤ 16 KiB), records the SNI, closes
//   control address (SINKHOLE_ADMIN_ADDRESS, default 172.31.252.53), port 3094 — admin only,
//   bearer token SANDBOX_SINKHOLE_ADMIN_TOKEN (constant-time compare):
//     GET /records?ip=<source ip>&since=<epoch ms>   DELETE /records?ip=<source ip>
//     GET /stats (record and source counts)          GET /health (no token)
//
// Records are kept per source IP in a bounded ring (≤ 1 000 per IP, ≤ 50 000 total, TTL 15 min).
// Runners sit only on the detonation network and never see the token; the admin listener is not
// bound there. Recorded values are untrusted: names are validated (ASCII host syntax) before they
// are stored, paths and User-Agents are stored only as hashes.
import { createHash, timingSafeEqual } from 'node:crypto';
import dgram from 'node:dgram';
import http from 'node:http';
import net from 'node:net';
import { pathToFileURL } from 'node:url';

export const LIMITS = Object.freeze({
  perIp: 1_000,
  total: 50_000,
  ttlMs: 15 * 60 * 1000,
  httpHeaderBytes: 8 * 1024,
  httpTimeoutMs: 5_000,
  tlsHelloBytes: 16 * 1024,
  tlsTimeoutMs: 5_000,
  dnsTcpBytes: 4 * 1024,
  dnsTcpTimeoutMs: 5_000,
  maxConnections: 256,
  adminResponseRecords: 1_000,
});

const HOST_PATTERN =
  /^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$/;
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

/** A lower-case ASCII host name (trailing dot removed), or null when it is not one. */
export function normalizeHost(value) {
  if (typeof value !== 'string') return null;
  let host = value.trim().toLowerCase();
  if (host.endsWith('.')) host = host.slice(0, -1);
  return HOST_PATTERN.test(host) ? host : null;
}

// ---------------------------------------------------------------------------------------------
// Record store
// ---------------------------------------------------------------------------------------------

export class RecordStore {
  constructor(limits = LIMITS, now = Date.now) {
    this.limits = limits;
    this.now = now;
    this.byIp = new Map();
    this.total = 0;
    this.dropped = new Map();
  }

  add(ip, record) {
    this.prune();
    const key = canonicalSource(ip);
    if (!key) return;
    let list = this.byIp.get(key);
    if (!list) {
      list = [];
      this.byIp.set(key, list);
    }
    if (list.length >= this.limits.perIp) {
      list.shift();
      this.total -= 1;
      this.dropped.set(key, (this.dropped.get(key) ?? 0) + 1);
    }
    while (this.total >= this.limits.total) this.evictOldest();
    list.push({ ...record, at: this.now() });
    this.total += 1;
  }

  evictOldest() {
    let oldestIp = null;
    let oldestAt = Infinity;
    for (const [ip, list] of this.byIp) {
      if (list.length > 0 && list[0].at < oldestAt) {
        oldestAt = list[0].at;
        oldestIp = ip;
      }
    }
    if (oldestIp === null) {
      this.total = 0;
      return;
    }
    const list = this.byIp.get(oldestIp);
    list.shift();
    this.total -= 1;
    this.dropped.set(oldestIp, (this.dropped.get(oldestIp) ?? 0) + 1);
    if (list.length === 0) this.byIp.delete(oldestIp);
  }

  prune() {
    const cutoff = this.now() - this.limits.ttlMs;
    for (const [ip, list] of this.byIp) {
      let removed = 0;
      while (list.length > 0 && list[0].at < cutoff) {
        list.shift();
        removed += 1;
      }
      this.total -= removed;
      if (list.length === 0) this.byIp.delete(ip);
    }
  }

  get(ip, since = 0) {
    this.prune();
    const key = canonicalSource(ip);
    const list = (key && this.byIp.get(key)) || [];
    return {
      records: list.filter((r) => r.at >= since).slice(0, this.limits.adminResponseRecords),
      dropped: (key && this.dropped.get(key)) || 0,
    };
  }

  clear(ip) {
    const key = canonicalSource(ip);
    if (!key) return 0;
    const list = this.byIp.get(key) ?? [];
    this.byIp.delete(key);
    this.dropped.delete(key);
    this.total -= list.length;
    return list.length;
  }
}

/** Source address as the admin API names it (v4-mapped IPv6 → IPv4). */
export function canonicalSource(ip) {
  if (typeof ip !== 'string') return null;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  const value = mapped ? mapped[1] : ip;
  return net.isIP(value) ? value.toLowerCase() : null;
}

// ---------------------------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------------------------

const DNS_TYPES = { 1: 'A', 28: 'AAAA', 15: 'MX', 16: 'TXT' };

/** Parses the single question of a DNS query (no compression in questions), or null. */
export function parseDnsQuery(message) {
  if (!Buffer.isBuffer(message) || message.length < 12 || message.length > 512) return null;
  const flags = message.readUInt16BE(2);
  if (flags & 0x8000) return null; // a response, not a query
  if (message.readUInt16BE(4) !== 1) return null;
  const labels = [];
  let offset = 12;
  let length = 0;
  for (;;) {
    if (offset >= message.length) return null;
    const size = message[offset];
    if (size === 0) {
      offset += 1;
      break;
    }
    if (size > 63) return null;
    if (offset + 1 + size > message.length) return null;
    labels.push(message.subarray(offset + 1, offset + 1 + size).toString('latin1'));
    length += size + 1;
    if (length > 255) return null;
    offset += 1 + size;
  }
  if (offset + 4 > message.length) return null;
  return {
    id: message.readUInt16BE(0),
    rd: flags & 0x0100,
    rawName: labels.join('.'),
    qtype: message.readUInt16BE(offset),
    qclass: message.readUInt16BE(offset + 2),
    questionEnd: offset + 4,
  };
}

/** The answer to a parsed query: A → `answerAddress`, everything else empty NOERROR. */
export function buildDnsAnswer(message, query, answerAddress) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(query.id, 0);
  const answers = [];
  if (query.qtype === 1 && query.qclass === 1 && net.isIPv4(answerAddress)) {
    const rr = Buffer.alloc(16);
    rr.writeUInt16BE(0xc00c, 0);
    rr.writeUInt16BE(1, 2);
    rr.writeUInt16BE(1, 4);
    rr.writeUInt32BE(30, 6);
    rr.writeUInt16BE(4, 10);
    answerAddress.split('.').forEach((octet, i) => rr.writeUInt8(Number(octet), 12 + i));
    answers.push(rr);
  }
  header.writeUInt16BE(0x8000 | 0x0400 | query.rd | 0x0080, 2); // QR, AA, RD copied, RA
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(answers.length, 6);
  return Buffer.concat([header, message.subarray(12, query.questionEnd), ...answers]);
}

export function dnsRecord(query, transport) {
  const name = normalizeHost(query.rawName);
  if (!name) return null;
  return { kind: 'dns', name, type: DNS_TYPES[query.qtype] ?? 'other', transport };
}

// ---------------------------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------------------------

const METHODS = new Set(['GET', 'POST', 'HEAD', 'PUT']);

/** Parses an HTTP/1.x request head (bounded), or null when it is incomplete / not HTTP. */
export function parseHttpHead(buffer, limit = LIMITS.httpHeaderBytes) {
  const end = buffer.indexOf('\r\n\r\n');
  if (end < 0) return buffer.length > limit ? { error: 'too_large' } : null;
  if (end > limit) return { error: 'too_large' };
  const lines = buffer.subarray(0, end).toString('latin1').split('\r\n');
  const request = /^([A-Z]{1,16}) (\S{1,8192}) HTTP\/1\.[01]$/.exec(lines[0] ?? '');
  if (!request) return { error: 'not_http' };
  const headers = new Map();
  for (const line of lines.slice(1, 101)) {
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    headers.set(line.slice(0, colon).trim().toLowerCase(), line.slice(colon + 1).trim());
  }
  return { method: request[1], target: request[2], headers };
}

export function httpRecord(head, localPort) {
  let host = null;
  let port = localPort;
  const hostHeader = head.headers.get('host');
  if (hostHeader) {
    const match = /^([^:\[\]]+)(?::(\d{1,5}))?$/.exec(hostHeader);
    if (match) {
      host = normalizeHost(match[1]);
      if (match[2] && Number(match[2]) >= 1 && Number(match[2]) <= 65_535) port = Number(match[2]);
    }
  }
  let path = head.target;
  if (/^[a-z]+:\/\//i.test(path)) {
    try {
      const url = new URL(path);
      host ??= normalizeHost(url.hostname);
      path = `${url.pathname}${url.search}`;
    } catch {
      // Keep the raw target.
    }
  }
  const ua = head.headers.get('user-agent');
  return {
    kind: 'http',
    host,
    port,
    method: METHODS.has(head.method) ? head.method : 'OTHER',
    pathSha256: sha256(path),
    userAgentSha256: ua ? sha256(ua) : null,
  };
}

// ---------------------------------------------------------------------------------------------
// TLS ClientHello SNI
// ---------------------------------------------------------------------------------------------

/**
 * The SNI host name of a TLS ClientHello (first record), `null` when the hello has no SNI,
 * `undefined` when more bytes are needed, or `{ error }` when it is not a ClientHello.
 */
export function parseClientHelloSni(buffer, limit = LIMITS.tlsHelloBytes) {
  if (buffer.length < 5) return undefined;
  if (buffer[0] !== 0x16) return { error: 'not_tls' };
  const recordLength = buffer.readUInt16BE(3);
  if (recordLength > limit) return { error: 'too_large' };
  if (buffer.length < 5 + recordLength)
    return buffer.length > limit ? { error: 'too_large' } : undefined;
  const hello = buffer.subarray(5, 5 + recordLength);
  if (hello.length < 4 || hello[0] !== 0x01) return { error: 'not_client_hello' };
  let offset = 4 + 2 + 32; // handshake header, version, random
  const need = (n) => offset + n <= hello.length;
  if (!need(1)) return { error: 'malformed' };
  offset += 1 + hello[offset]; // session id
  if (!need(2)) return { error: 'malformed' };
  offset += 2 + hello.readUInt16BE(offset); // cipher suites
  if (!need(1)) return { error: 'malformed' };
  offset += 1 + hello[offset]; // compression methods
  if (!need(2)) return null; // no extensions
  const extensionsEnd = offset + 2 + hello.readUInt16BE(offset);
  offset += 2;
  if (extensionsEnd > hello.length) return { error: 'malformed' };
  while (offset + 4 <= extensionsEnd) {
    const type = hello.readUInt16BE(offset);
    const size = hello.readUInt16BE(offset + 2);
    offset += 4;
    if (offset + size > extensionsEnd) return { error: 'malformed' };
    if (type === 0x0000) {
      let p = offset + 2; // server name list length
      const listEnd = offset + size;
      while (p + 3 <= listEnd) {
        const nameType = hello[p];
        const nameLength = hello.readUInt16BE(p + 1);
        p += 3;
        if (p + nameLength > listEnd) return { error: 'malformed' };
        if (nameType === 0)
          return normalizeHost(hello.subarray(p, p + nameLength).toString('latin1'));
        p += nameLength;
      }
      return null;
    }
    offset += size;
  }
  return null;
}

// ---------------------------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------------------------

/** Constant-time bearer check (hash both sides so the lengths never leak). */
export function authorized(header, token) {
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
  const given = createHash('sha256').update(header.slice(7)).digest();
  const expected = createHash('sha256').update(token).digest();
  return timingSafeEqual(given, expected);
}

export function adminHandler(store, token) {
  return (req, res) => {
    const send = (status, body) => {
      const json = JSON.stringify(body);
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(json);
    };
    let url;
    try {
      url = new URL(req.url ?? '/', 'http://sinkhole');
    } catch {
      send(400, { error: 'bad_request' });
      return;
    }
    if (url.pathname === '/health' && req.method === 'GET') {
      send(200, { ok: true });
      return;
    }
    if (!authorized(req.headers.authorization, token)) {
      send(401, { error: 'unauthorized' });
      return;
    }
    if (url.pathname === '/stats' && req.method === 'GET') {
      store.prune();
      send(200, { total: store.total, sources: store.byIp.size });
      return;
    }
    if (url.pathname !== '/records') {
      send(404, { error: 'not_found' });
      return;
    }
    const ip = canonicalSource(url.searchParams.get('ip') ?? '');
    if (!ip) {
      send(400, { error: 'ip_required' });
      return;
    }
    if (req.method === 'GET') {
      const since = Number(url.searchParams.get('since') ?? '0');
      send(200, store.get(ip, Number.isFinite(since) ? since : 0));
      return;
    }
    if (req.method === 'DELETE') {
      send(200, { deleted: store.clear(ip) });
      return;
    }
    send(405, { error: 'method_not_allowed' });
  };
}

// ---------------------------------------------------------------------------------------------
// Servers
// ---------------------------------------------------------------------------------------------

function boundedServer(options, onSocket) {
  let open = 0;
  const server = net.createServer((socket) => {
    if (open >= options.maxConnections) {
      socket.destroy();
      return;
    }
    open += 1;
    socket.once('close', () => {
      open -= 1;
    });
    socket.on('error', () => socket.destroy());
    socket.setTimeout(options.timeoutMs, () => socket.destroy());
    onSocket(socket);
  });
  return server;
}

/**
 * Starts the sinkhole. Options: `dnsAddress`, `answerAddress`, `adminAddress`, `token`, ports
 * (`dnsPort` 53, `httpPort` 80, `tlsPort` 443, `adminPort` 3094) and `store`. Returns
 * `{ store, close() }`.
 */
export async function startSinkhole(options) {
  const token = options.token;
  if (typeof token !== 'string' || token.length < 32) {
    throw new Error('SANDBOX_SINKHOLE_ADMIN_TOKEN must be at least 32 characters');
  }
  const store = options.store ?? new RecordStore();
  const answerAddress = options.answerAddress ?? options.dnsAddress;
  const ports = {
    dns: options.dnsPort ?? 53,
    http: options.httpPort ?? 80,
    tls: options.tlsPort ?? 443,
    admin: options.adminPort ?? 3094,
  };

  const udp = dgram.createSocket({ type: net.isIPv6(options.dnsAddress) ? 'udp6' : 'udp4' });
  udp.on('message', (message, rinfo) => {
    const query = parseDnsQuery(message);
    if (!query) return;
    const record = dnsRecord(query, 'udp');
    if (record) store.add(rinfo.address, record);
    udp.send(buildDnsAnswer(message, query, answerAddress), rinfo.port, rinfo.address);
  });
  udp.on('error', () => undefined);

  const dnsTcp = boundedServer(
    { maxConnections: LIMITS.maxConnections, timeoutMs: LIMITS.dnsTcpTimeoutMs },
    (socket) => {
      let buffer = Buffer.alloc(0);
      socket.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        if (buffer.length > LIMITS.dnsTcpBytes) {
          socket.destroy();
          return;
        }
        while (buffer.length >= 2) {
          const size = buffer.readUInt16BE(0);
          if (buffer.length < 2 + size) return;
          const message = buffer.subarray(2, 2 + size);
          buffer = buffer.subarray(2 + size);
          const query = parseDnsQuery(message);
          if (!query) {
            socket.destroy();
            return;
          }
          const record = dnsRecord(query, 'tcp');
          if (record) store.add(socket.remoteAddress, record);
          const answer = buildDnsAnswer(message, query, answerAddress);
          const length = Buffer.alloc(2);
          length.writeUInt16BE(answer.length, 0);
          socket.write(Buffer.concat([length, answer]));
        }
      });
    },
  );

  const httpServer = boundedServer(
    { maxConnections: LIMITS.maxConnections, timeoutMs: LIMITS.httpTimeoutMs },
    (socket) => {
      let buffer = Buffer.alloc(0);
      socket.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        const head = parseHttpHead(buffer);
        if (head === null) return;
        socket.removeAllListeners('data');
        if (head.error) {
          socket.destroy();
          return;
        }
        store.add(socket.remoteAddress, httpRecord(head, socket.localPort));
        socket.end(
          'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok',
        );
      });
    },
  );

  const tlsServer = boundedServer(
    { maxConnections: LIMITS.maxConnections, timeoutMs: LIMITS.tlsTimeoutMs },
    (socket) => {
      let buffer = Buffer.alloc(0);
      socket.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        const sni = parseClientHelloSni(buffer);
        if (sni === undefined && buffer.length <= LIMITS.tlsHelloBytes + 5) return;
        socket.removeAllListeners('data');
        if (sni !== undefined && (sni === null || typeof sni === 'string')) {
          store.add(socket.remoteAddress, { kind: 'tls', sni, port: socket.localPort });
        }
        socket.destroy();
      });
    },
  );

  const admin = http.createServer({ maxHeaderSize: 8 * 1024 }, adminHandler(store, token));
  admin.headersTimeout = 5_000;
  admin.requestTimeout = 10_000;

  const listen = (server, port, address) =>
    new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, address, () => resolve());
    });
  await new Promise((resolve, reject) => {
    udp.once('error', reject);
    udp.bind(ports.dns, options.dnsAddress, () => resolve());
  });
  // DNS over TCP on the same port as UDP (matters when port 0 picks a random one in tests).
  await listen(dnsTcp, udp.address().port, options.dnsAddress);
  await listen(httpServer, ports.http, options.dnsAddress);
  await listen(tlsServer, ports.tls, options.dnsAddress);
  await listen(admin, ports.admin, options.adminAddress);
  const pruneTimer = setInterval(() => store.prune(), 60_000);
  pruneTimer.unref();

  return {
    store,
    ports: {
      dns: udp.address().port,
      http: httpServer.address().port,
      tls: tlsServer.address().port,
      admin: admin.address().port,
    },
    async close() {
      clearInterval(pruneTimer);
      udp.close();
      await Promise.all(
        [dnsTcp, httpServer, tlsServer, admin].map(
          (server) => new Promise((resolve) => server.close(() => resolve())),
        ),
      );
    },
  };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const env = process.env;
  startSinkhole({
    dnsAddress: env.SINKHOLE_DNS_ADDRESS ?? '172.31.253.53',
    answerAddress: env.SINKHOLE_ANSWER_ADDRESS ?? env.SINKHOLE_DNS_ADDRESS ?? '172.31.253.53',
    adminAddress: env.SINKHOLE_ADMIN_ADDRESS ?? '172.31.252.53',
    adminPort: Number(env.SINKHOLE_ADMIN_PORT ?? 3094),
    token: env.SANDBOX_SINKHOLE_ADMIN_TOKEN,
  })
    .then(() => {
      process.stdout.write('sandbox sinkhole listening (LOCAL/CI ONLY; never forwards)\n');
    })
    .catch((error) => {
      process.stderr.write(`sandbox sinkhole failed to start: ${error.message}\n`);
      process.exit(1);
    });
  process.on('SIGTERM', () => process.exit(0));
}
