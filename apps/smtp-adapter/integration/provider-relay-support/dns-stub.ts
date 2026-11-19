import { createSocket, type Socket } from 'node:dgram';

export type DnsStubFailure = 'servfail' | 'timeout';

const TYPE_TXT = 16;
const RCODE = { NOERROR: 0, SERVFAIL: 2, NXDOMAIN: 3 } as const;

function readName(packet: Buffer, offset: number): { name: string; next: number } {
  const labels: string[] = [];
  let position = offset;
  for (;;) {
    const length = packet[position];
    if (length === undefined) throw new Error('truncated query');
    if (length === 0) return { name: labels.join('.').toLowerCase(), next: position + 1 };
    if ((length & 0xc0) !== 0) throw new Error('compressed question name');
    labels.push(packet.subarray(position + 1, position + 1 + length).toString('ascii'));
    position += 1 + length;
  }
}

/**
 * A minimal in-process DNS server for the provider relay suites (step 8.2 §10.2): UDP on
 * 127.0.0.1:<random port>, TXT records only, per-name failure injection. Never forwards
 * anything (unknown names are NXDOMAIN), so no test ever reaches the Internet. The smtp-adapter
 * uses it through PROVIDER_RELAY_DNS_SERVERS.
 */
export class DnsStub {
  private readonly txt = new Map<string, string>();
  private readonly failures = new Map<string, DnsStubFailure>();
  readonly queries: string[] = [];

  private constructor(
    private readonly socket: Socket,
    readonly port: number,
  ) {}

  static async start(): Promise<DnsStub> {
    const socket = createSocket('udp4');
    await new Promise<void>((resolve, reject) => {
      socket.once('error', reject);
      socket.bind(0, '127.0.0.1', () => {
        socket.off('error', reject);
        resolve();
      });
    });
    const stub = new DnsStub(socket, socket.address().port);
    socket.on('message', (message, remote) => stub.answer(message, remote.port, remote.address));
    return stub;
  }

  /** `127.0.0.1:<port>`, the PROVIDER_RELAY_DNS_SERVERS form. */
  get address(): string {
    return `127.0.0.1:${this.port}`;
  }

  setTxt(name: string, value: string): void {
    this.txt.set(name.toLowerCase(), value);
  }

  fail(name: string, failure: DnsStubFailure): void {
    this.failures.set(name.toLowerCase(), failure);
  }

  clearFailures(): void {
    this.failures.clear();
  }

  close(): Promise<void> {
    return new Promise((resolve) => this.socket.close(() => resolve()));
  }

  private answer(query: Buffer, port: number, address: string): void {
    let name: string;
    let next: number;
    try {
      ({ name, next } = readName(query, 12));
    } catch {
      return;
    }
    const type = query.readUInt16BE(next);
    this.queries.push(`${name}/${type}`);
    const failure = this.failures.get(name);
    if (failure === 'timeout') return;
    const value = this.txt.get(name);
    const rcode =
      failure === 'servfail'
        ? RCODE.SERVFAIL
        : value === undefined
          ? RCODE.NXDOMAIN
          : RCODE.NOERROR;
    const answers: Buffer[] = [];
    if (rcode === RCODE.NOERROR && type === TYPE_TXT && value !== undefined) {
      const bytes = Buffer.from(value, 'utf8');
      const strings: Buffer[] = [];
      for (let i = 0; i < bytes.length; i += 255) {
        const part = bytes.subarray(i, i + 255);
        strings.push(Buffer.from([part.length]), part);
      }
      const rdata = Buffer.concat(strings);
      const fixed = Buffer.alloc(12);
      fixed.writeUInt16BE(0xc00c, 0); // pointer to the question name
      fixed.writeUInt16BE(TYPE_TXT, 2);
      fixed.writeUInt16BE(1, 4); // IN
      fixed.writeUInt32BE(60, 6);
      fixed.writeUInt16BE(rdata.length, 10);
      answers.push(fixed, rdata);
    }
    const header = Buffer.alloc(12);
    query.copy(header, 0, 0, 2); // id
    header.writeUInt16BE(0x8400 | (query.readUInt16BE(2) & 0x0100) | 0x0080 | rcode, 2);
    header.writeUInt16BE(1, 4);
    header.writeUInt16BE(answers.length / 2, 6);
    const question = query.subarray(12, next + 4);
    this.socket.send(Buffer.concat([header, question, ...answers]), port, address);
  }
}
