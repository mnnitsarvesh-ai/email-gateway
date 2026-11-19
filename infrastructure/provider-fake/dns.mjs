// provider-fake DNS responder (TEST-ONLY, step 8.2 §10.5): a minimal authoritative DNS server for
// the zone `relay-proof.test` (PROVIDER_FAKE_DNS_ZONE). dns-sink forwards the zone here without
// caching, so DKIM public keys that a stack test registers at runtime (admin API
// `POST /_fake/dns/txt`) are visible at once to the smtp-adapter's DKIM proof
// (PROVIDER_RELAY_DNS_SERVERS = dns-sink) and to the integration-worker's DKIM evidence.
//
//   <name> under the zone   TXT  the registered strings (each split into ≤ 255-byte chunks), TTL 0
//   other types / names     NOERROR without data / NXDOMAIN
//   outside the zone        REFUSED
//
// UDP answers larger than the requester's EDNS size (512 without EDNS) are truncated (TC) so the
// resolver retries over TCP. Zero dependencies.
import dgram from 'node:dgram';
import net from 'node:net';

const TYPE_TXT = 16;
const TYPE_OPT = 41;
const CLASS_IN = 1;
const MAX_NAME = 253;

/** A TXT registry: lower-case name → array of strings. */
export class TxtRegistry {
  constructor(zone) {
    this.zone = zone.toLowerCase().replace(/\.$/, '');
    this.records = new Map();
  }

  /** True when `name` is the zone or under it. */
  inZone(name) {
    return name === this.zone || name.endsWith(`.${this.zone}`);
  }

  set(name, values) {
    const key = String(name).toLowerCase().replace(/\.$/, '');
    if (!this.inZone(key) || key.length > MAX_NAME) throw new Error('name outside the zone');
    if (!Array.isArray(values) || values.length === 0 || values.length > 16) {
      throw new Error('values must be 1-16 strings');
    }
    for (const value of values) {
      if (typeof value !== 'string' || value.length === 0 || value.length > 4096) {
        throw new Error('each value must be a 1-4096 character string');
      }
    }
    this.records.set(key, [...values]);
  }

  delete(name) {
    this.records.delete(String(name).toLowerCase().replace(/\.$/, ''));
  }

  clear() {
    this.records.clear();
  }
}

function parseName(message, offset) {
  const labels = [];
  for (;;) {
    if (offset >= message.length) return null;
    const length = message[offset];
    if (length === 0) return { name: labels.join('.').toLowerCase(), end: offset + 1 };
    if (length > 63) return null; // no compression in questions
    labels.push(message.subarray(offset + 1, offset + 1 + length).toString('latin1'));
    offset += 1 + length;
  }
}

function parseQuery(message) {
  if (message.length < 12) return null;
  if (message.readUInt16BE(4) !== 1) return null;
  const question = parseName(message, 12);
  if (!question || question.end + 4 > message.length) return null;
  const type = message.readUInt16BE(question.end);
  const klass = message.readUInt16BE(question.end + 2);
  const questionEnd = question.end + 4;
  // EDNS: an OPT record in the additional section gives the requester's UDP size.
  let udpSize = 512;
  const arcount = message.readUInt16BE(10);
  if (arcount > 0 && questionEnd + 11 <= message.length) {
    const optName = message[questionEnd];
    const optType = message.readUInt16BE(questionEnd + 1);
    if (optName === 0 && optType === TYPE_OPT) {
      udpSize = Math.max(512, Math.min(4096, message.readUInt16BE(questionEnd + 3)));
    }
  }
  return { name: question.name, type, klass, questionEnd, udpSize };
}

function txtRecord(value) {
  const bytes = Buffer.from(value, 'utf8');
  const chunks = [];
  for (let i = 0; i < bytes.length; i += 255) {
    const chunk = bytes.subarray(i, i + 255);
    chunks.push(Buffer.from([chunk.length]), chunk);
  }
  const rdata = Buffer.concat(chunks);
  const rr = Buffer.alloc(12);
  rr.writeUInt16BE(0xc00c, 0); // pointer to the question name
  rr.writeUInt16BE(TYPE_TXT, 2);
  rr.writeUInt16BE(CLASS_IN, 4);
  rr.writeUInt32BE(0, 6); // TTL 0: registrations are visible at once
  rr.writeUInt16BE(rdata.length, 10);
  return Buffer.concat([rr, rdata]);
}

/** The response to one query (Buffer), or null when it cannot be parsed. */
export function answer(message, registry, transport = 'udp') {
  const query = parseQuery(message);
  if (!query) return null;
  const header = Buffer.alloc(12);
  message.copy(header, 0, 0, 2); // id
  const rd = message[2] & 0x01;
  let rcode = 0;
  let answers = [];
  if (!registry.inZone(query.name) || query.klass !== CLASS_IN) {
    rcode = 5; // REFUSED
  } else {
    const values = registry.records.get(query.name);
    if (!values) {
      // NXDOMAIN unless a registered name lives below it (empty non-terminal).
      const below = [...registry.records.keys()].some((k) => k.endsWith(`.${query.name}`));
      rcode = below || query.name === registry.zone ? 0 : 3;
    } else if (query.type === TYPE_TXT || query.type === 255) {
      answers = values.map(txtRecord);
    }
  }
  let flags = 0x8000 | 0x0400 | (rd << 8) | rcode; // QR, AA, RD copied
  const question = message.subarray(12, query.questionEnd);
  let body = Buffer.concat([question, ...answers]);
  if (transport === 'udp' && 12 + body.length > query.udpSize) {
    flags |= 0x0200; // TC: retry over TCP
    answers = [];
    body = Buffer.from(question);
  }
  header.writeUInt16BE(flags, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(answers.length, 6);
  return Buffer.concat([header, body]);
}

/** Starts UDP and TCP listeners; resolves with the bound port. */
export async function startDns(registry, port = 5300, host = '0.0.0.0') {
  const udp = dgram.createSocket('udp4');
  udp.on('message', (message, remote) => {
    const response = answer(message, registry, 'udp');
    if (response) udp.send(response, remote.port, remote.address);
  });
  udp.on('error', () => undefined);
  await new Promise((resolve) => udp.bind(port, host, resolve));
  const bound = udp.address().port;
  const tcp = net.createServer((socket) => {
    let buffer = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > 65_538) return socket.destroy();
      while (buffer.length >= 2) {
        const length = buffer.readUInt16BE(0);
        if (buffer.length < 2 + length) break;
        const response = answer(buffer.subarray(2, 2 + length), registry, 'tcp');
        buffer = buffer.subarray(2 + length);
        if (response) {
          const prefix = Buffer.alloc(2);
          prefix.writeUInt16BE(response.length);
          socket.write(Buffer.concat([prefix, response]));
        }
      }
    });
    socket.on('error', () => undefined);
    socket.setTimeout(10_000, () => socket.destroy());
  });
  await new Promise((resolve) => tcp.listen(bound, host, resolve));
  return {
    port: bound,
    close: async () => {
      udp.close();
      await new Promise((resolve) => tcp.close(() => resolve()));
    },
  };
}
