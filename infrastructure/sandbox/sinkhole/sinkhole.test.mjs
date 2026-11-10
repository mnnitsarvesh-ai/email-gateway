// Unit tests of the recording sinkhole (step 4.6 X5). Run: node --test infrastructure/sandbox/
// (also run by apps/sandbox-controller's unit suite, src/runner/infrastructure-scripts.test.ts).
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import net from 'node:net';
import { describe, it, before, after } from 'node:test';
import tls from 'node:tls';
import {
  authorized,
  buildDnsAnswer,
  canonicalSource,
  normalizeHost,
  parseClientHelloSni,
  parseDnsQuery,
  parseHttpHead,
  RecordStore,
  startSinkhole,
} from './sinkhole.mjs';

const TOKEN = 's'.repeat(48);

function dnsQuery(name, type = 1, id = 0x1234) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const labels = name
    .split('.')
    .map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)]));
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(type, 0);
  tail.writeUInt16BE(1, 2);
  return Buffer.concat([header, ...labels, Buffer.from([0]), tail]);
}

describe('parsers', () => {
  it('DNS question, answers A with the sinkhole address and AAAA/other with empty NOERROR', () => {
    const query = parseDnsQuery(dnsQuery('Metadata.Google.Internal'));
    assert.equal(query.rawName, 'Metadata.Google.Internal');
    assert.equal(query.qtype, 1);
    const answer = buildDnsAnswer(
      dnsQuery('a.test'),
      parseDnsQuery(dnsQuery('a.test')),
      '172.31.253.53',
    );
    assert.equal(answer.readUInt16BE(0), 0x1234);
    assert.equal(answer.readUInt16BE(2) & 0x8000, 0x8000);
    assert.equal(answer.readUInt16BE(2) & 0x000f, 0); // NOERROR
    assert.equal(answer.readUInt16BE(6), 1);
    assert.deepEqual([...answer.subarray(answer.length - 4)], [172, 31, 253, 53]);
    const aaaa = buildDnsAnswer(
      dnsQuery('a.test', 28),
      parseDnsQuery(dnsQuery('a.test', 28)),
      '172.31.253.53',
    );
    assert.equal(aaaa.readUInt16BE(6), 0);
    assert.equal(aaaa.readUInt16BE(2) & 0x000f, 0);
  });

  it('DNS rejects responses, multiple questions, compression, oversized and truncated messages', () => {
    const response = dnsQuery('a.test');
    response.writeUInt16BE(0x8100, 2);
    assert.equal(parseDnsQuery(response), null);
    const two = dnsQuery('a.test');
    two.writeUInt16BE(2, 4);
    assert.equal(parseDnsQuery(two), null);
    const compressed = Buffer.concat([
      dnsQuery('a.test').subarray(0, 12),
      Buffer.from([0xc0, 0x0c, 0, 1, 0, 1]),
    ]);
    assert.equal(parseDnsQuery(compressed), null);
    assert.equal(parseDnsQuery(Buffer.alloc(600)), null);
    assert.equal(parseDnsQuery(dnsQuery('a.test').subarray(0, 15)), null);
    assert.equal(parseDnsQuery(Buffer.alloc(5)), null);
  });

  it('HTTP head: method, target, headers; bounded', () => {
    const head = parseHttpHead(
      Buffer.from(
        'GET /computeMetadata/v1/?x=1 HTTP/1.1\r\nHost: metadata.google.internal\r\nUser-Agent: eg\r\n\r\n',
      ),
    );
    assert.equal(head.method, 'GET');
    assert.equal(head.target, '/computeMetadata/v1/?x=1');
    assert.equal(head.headers.get('host'), 'metadata.google.internal');
    assert.equal(parseHttpHead(Buffer.from('GET / HTTP/1.1\r\nHost: x')), null); // incomplete
    assert.deepEqual(parseHttpHead(Buffer.from('\x16\x03\x01junk\r\n\r\n', 'latin1')), {
      error: 'not_http',
    });
    assert.deepEqual(parseHttpHead(Buffer.alloc(9000, 0x41)), { error: 'too_large' });
  });

  it('TLS ClientHello SNI from a real Node client hello; garbage is rejected', async () => {
    const hello = await new Promise((resolve) => {
      const server = net.createServer((socket) => {
        socket.once('data', (data) => {
          resolve(data);
          socket.destroy();
          server.close();
        });
      });
      server.listen(0, '127.0.0.1', () => {
        const client = tls.connect({
          host: '127.0.0.1',
          port: server.address().port,
          servername: 'c2.example.test',
        });
        client.on('error', () => undefined);
      });
    });
    assert.equal(parseClientHelloSni(hello), 'c2.example.test');
    assert.equal(parseClientHelloSni(hello.subarray(0, 20)), undefined);
    assert.deepEqual(parseClientHelloSni(Buffer.from('GET / HTTP/1.1')), { error: 'not_tls' });
    const corrupt = Buffer.from(hello);
    corrupt[5] = 0x02;
    assert.deepEqual(parseClientHelloSni(corrupt), { error: 'not_client_hello' });
  });

  it('host normalization, source canonicalization, constant-time bearer check', () => {
    assert.equal(normalizeHost('MySQL.'), 'mysql');
    assert.equal(normalizeHost('bad name'), null);
    assert.equal(normalizeHost('x'.repeat(300)), null);
    assert.equal(canonicalSource('::ffff:172.31.253.130'), '172.31.253.130');
    assert.equal(canonicalSource('nope'), null);
    assert.equal(authorized(`Bearer ${TOKEN}`, TOKEN), true);
    assert.equal(authorized(`Bearer ${TOKEN}x`, TOKEN), false);
    assert.equal(authorized('Basic abc', TOKEN), false);
    assert.equal(authorized(undefined, TOKEN), false);
  });
});

describe('RecordStore bounds', () => {
  it('per-IP ring, global cap, TTL, since filter, clear', () => {
    let now = 1_000;
    const store = new RecordStore(
      { perIp: 3, total: 5, ttlMs: 10_000, adminResponseRecords: 100 },
      () => now,
    );
    for (let i = 0; i < 5; i += 1)
      store.add('10.0.0.1', { kind: 'dns', name: `n${i}.test`, type: 'A', transport: 'udp' });
    let view = store.get('10.0.0.1');
    assert.deepEqual(
      view.records.map((r) => r.name),
      ['n2.test', 'n3.test', 'n4.test'],
    );
    assert.equal(view.dropped, 2);
    now = 2_000;
    for (let i = 0; i < 3; i += 1)
      store.add('10.0.0.2', { kind: 'dns', name: `m${i}.test`, type: 'A', transport: 'udp' });
    assert.equal(store.total, 5); // global cap evicted the oldest of 10.0.0.1
    assert.equal(store.get('10.0.0.2', 2_000).records.length, 3);
    assert.equal(store.get('10.0.0.2', 2_001).records.length, 0);
    now = 20_000;
    assert.equal(store.get('10.0.0.1').records.length, 0); // TTL
    assert.equal(store.total, 0);
    store.add('10.0.0.3', { kind: 'tls', sni: null, port: 443 });
    assert.equal(store.clear('10.0.0.3'), 1);
    assert.equal(store.total, 0);
  });
});

describe('servers (loopback, random ports)', () => {
  let sinkhole;
  const admin = (method, path, token = TOKEN) =>
    fetch(`http://127.0.0.1:${sinkhole.ports.admin}${path}`, {
      method,
      headers: token ? { authorization: `Bearer ${token}` } : {},
    });

  before(async () => {
    sinkhole = await startSinkhole({
      dnsAddress: '127.0.0.1',
      answerAddress: '172.31.253.53',
      adminAddress: '127.0.0.1',
      token: TOKEN,
      dnsPort: 0,
      httpPort: 0,
      tlsPort: 0,
      adminPort: 0,
    });
  });
  after(async () => {
    await sinkhole.close();
  });

  it('refuses a short token', async () => {
    await assert.rejects(
      startSinkhole({ dnsAddress: '127.0.0.1', adminAddress: '127.0.0.1', token: 'short' }),
      /32 characters/,
    );
  });

  it('records DNS (UDP + TCP), HTTP and TLS by source IP; admin is token-protected; never forwards', async () => {
    const udp = dgram.createSocket('udp4');
    const answer = await new Promise((resolve) => {
      udp.once('message', resolve);
      udp.send(dnsQuery('mysql'), sinkhole.ports.dns, '127.0.0.1');
    });
    udp.close();
    assert.deepEqual([...answer.subarray(answer.length - 4)], [172, 31, 253, 53]);

    const tcpAnswer = await new Promise((resolve) => {
      const socket = net.connect(sinkhole.ports.dns, '127.0.0.1', () => {
        const q = dnsQuery('host.docker.internal', 28);
        const len = Buffer.alloc(2);
        len.writeUInt16BE(q.length);
        socket.write(Buffer.concat([len, q]));
      });
      socket.once('data', (data) => {
        resolve(data);
        socket.destroy();
      });
    });
    assert.equal(tcpAnswer.readUInt16BE(2 + 6), 0);

    const httpReply = await new Promise((resolve) => {
      const socket = net.connect(sinkhole.ports.http, '127.0.0.1', () =>
        socket.write(
          'POST /exfil?id=1 HTTP/1.1\r\nHost: c2.example.test:8080\r\nUser-Agent: probe\r\n\r\n',
        ),
      );
      let data = '';
      socket.on('data', (c) => (data += c));
      socket.on('end', () => resolve(data));
    });
    assert.match(httpReply, /^HTTP\/1\.1 200 OK/);
    assert.ok(httpReply.endsWith('\r\n\r\nok'));

    await new Promise((resolve) => {
      const client = tls.connect({
        host: '127.0.0.1',
        port: sinkhole.ports.tls,
        servername: 'tls.example.test',
      });
      client.on('error', () => resolve());
      client.on('close', () => resolve());
    });

    assert.equal((await admin('GET', '/records?ip=127.0.0.1', null)).status, 401);
    assert.equal((await admin('GET', '/records?ip=127.0.0.1', 'w'.repeat(48))).status, 401);
    assert.equal((await admin('GET', '/health', null)).status, 200);
    assert.equal((await admin('GET', '/records')).status, 400);
    const body = await (await admin('GET', '/records?ip=127.0.0.1&since=0')).json();
    const kinds = body.records.map((r) => r.kind).sort();
    assert.deepEqual(kinds, ['dns', 'dns', 'http', 'tls']);
    const http = body.records.find((r) => r.kind === 'http');
    assert.equal(http.host, 'c2.example.test');
    assert.equal(http.port, 8080);
    assert.equal(http.method, 'POST');
    assert.match(http.pathSha256, /^[0-9a-f]{64}$/);
    assert.ok(!JSON.stringify(body).includes('exfil'), 'paths are stored as hashes only');
    assert.equal(body.records.find((r) => r.kind === 'tls').sni, 'tls.example.test');
    assert.deepEqual(await (await admin('GET', '/stats')).json(), { total: 4, sources: 1 });
    assert.deepEqual(await (await admin('DELETE', '/records?ip=127.0.0.1')).json(), { deleted: 4 });
    assert.deepEqual(await (await admin('GET', '/stats')).json(), { total: 0, sources: 0 });
  });

  it('drops oversized HTTP heads without recording', async () => {
    await new Promise((resolve) => {
      const socket = net.connect(sinkhole.ports.http, '127.0.0.1', () =>
        socket.write('GET /' + 'a'.repeat(10_000)),
      );
      socket.on('close', resolve);
      socket.on('error', resolve);
    });
    assert.deepEqual(await (await admin('GET', '/stats')).json(), { total: 0, sources: 0 });
  });
});
