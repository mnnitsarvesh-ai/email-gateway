// url-test DNS responder (TEST-ONLY, step 4.3 U19): a minimal authoritative DNS server on
// UDP+TCP 5300 for the DNS-rebinding case. dns-sink forwards `rebind.test` here without caching.
//
//   rebind.test  A    203.0.113.10 and 127.0.0.1 ALTERNATELY (one answer per query), TTL 0
//   rebind.test  AAAA no data (NOERROR, empty)
//   anything else     NXDOMAIN
//
// The sequence position is shared with server.mjs: GET /reset (next answer 203.0.113.10) and
// GET /reset?first=private (next answer 127.0.0.1). Zero dependencies; runs standalone too:
//   node infrastructure/url-test/dns.mjs [port]
import dgram from 'node:dgram';
import net from 'node:net';
import { pathToFileURL } from 'node:url';

const REBIND_NAME = 'rebind.test';
const SEQUENCE = ['203.0.113.10', '127.0.0.1'];
let position = 0;

export function resetRebind(first = 'public') {
  position = first === 'private' ? 1 : 0;
}

export function rebindPosition() {
  return position;
}

function parseQuestion(message) {
  if (message.length < 12) return null;
  const qdcount = message.readUInt16BE(4);
  if (qdcount !== 1) return null;
  const labels = [];
  let offset = 12;
  for (;;) {
    if (offset >= message.length) return null;
    const length = message[offset];
    if (length === 0) {
      offset += 1;
      break;
    }
    if (length > 63) return null; // no compression in questions
    labels.push(message.subarray(offset + 1, offset + 1 + length).toString('latin1'));
    offset += 1 + length;
  }
  if (offset + 4 > message.length) return null;
  return {
    name: labels.join('.').toLowerCase(),
    type: message.readUInt16BE(offset),
    klass: message.readUInt16BE(offset + 2),
    questionEnd: offset + 4,
  };
}

/** Builds the response for one query message (Buffer), or null when it cannot be parsed. */
export function answer(message) {
  const question = parseQuestion(message);
  if (!question) return null;
  const header = Buffer.alloc(12);
  message.copy(header, 0, 0, 2); // id
  const rd = message[2] & 0x01;
  let rcode = 0;
  const answers = [];
  if (question.name === REBIND_NAME && question.klass === 1) {
    if (question.type === 1) {
      const address = SEQUENCE[position % SEQUENCE.length];
      position += 1;
      const rr = Buffer.alloc(16);
      rr.writeUInt16BE(0xc00c, 0); // pointer to the question name
      rr.writeUInt16BE(1, 2); // A
      rr.writeUInt16BE(1, 4); // IN
      rr.writeUInt32BE(0, 6); // TTL 0
      rr.writeUInt16BE(4, 10);
      address.split('.').forEach((octet, i) => rr.writeUInt8(Number(octet), 12 + i));
      answers.push(rr);
    }
  } else {
    rcode = 3; // NXDOMAIN
  }
  header.writeUInt16BE(0x8000 | 0x0400 | (rd << 8) | rcode, 2); // QR, AA, RD copied
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(answers.length, 6);
  return Buffer.concat([header, message.subarray(12, question.questionEnd), ...answers]);
}

export function startDns(port = 5300, host = '0.0.0.0') {
  const udp = dgram.createSocket('udp4');
  udp.on('message', (message, remote) => {
    const response = answer(message);
    if (response) udp.send(response, remote.port, remote.address);
  });
  udp.bind(port, host);

  const tcp = net.createServer((socket) => {
    let buffer = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      while (buffer.length >= 2) {
        const length = buffer.readUInt16BE(0);
        if (buffer.length < 2 + length) break;
        const response = answer(buffer.subarray(2, 2 + length));
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
  tcp.listen(port, host);
  return { udp, tcp };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const port = Number(process.argv[2] ?? 5300);
  startDns(port);
  console.log(`url-test dns: udp+tcp ${port}`);
}
