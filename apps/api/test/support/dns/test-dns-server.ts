import { createSocket, type Socket as UdpSocket } from 'node:dgram';
import { createServer, type Server, type Socket } from 'node:net';
import * as dnsPacket from 'dns-packet';

/** `timeout` = never answer. */
export type TestDnsFailure = 'servfail' | 'refused' | 'timeout';
export type TestDnsRecordType = 'TXT' | 'MX' | 'CNAME';
/** `doh` marks queries that arrived through a `TestDohServer` backed by this server. */
export type TestDnsTransport = 'udp' | 'tcp' | 'doh';

interface NameRecords {
  TXT?: string[];
  MX?: Array<{ priority: number; exchange: string }>;
  CNAME?: string;
}

const RCODE = { NOERROR: 0, SERVFAIL: 2, NXDOMAIN: 3, REFUSED: 5 } as const;
/** Classic DNS UDP limit without EDNS (RFC 1035 §4.2.1). */
const DEFAULT_UDP_SIZE = 512;
const MAX_CNAME_HOPS = 8;

function canonical(name: string): string {
  return name.trim().toLowerCase().replace(/\.$/, '');
}

/** Splits a TXT value into ≤ 255-byte character-strings (RFC 1035 §3.3.14). */
function chunks(value: string): Buffer[] {
  const bytes = Buffer.from(value, 'utf8');
  if (bytes.length === 0) return [Buffer.alloc(0)];
  const parts: Buffer[] = [];
  for (let offset = 0; offset < bytes.length; offset += 255) {
    parts.push(bytes.subarray(offset, offset + 255));
  }
  return parts;
}

/**
 * In-process authoritative DNS server for tests (ADR-0017 §5): UDP and TCP on 127.0.0.1 with a
 * random port, mutable records and per-name failure injection. It never forwards anything: an
 * unknown name is NXDOMAIN (with an SOA in the authority section); a name that only has records
 * of other types, or that is an ancestor of a configured name (empty non-terminal), is NODATA.
 * UDP answers above the requester's EDNS size (512 without EDNS) are truncated (TC) so resolvers
 * retry over TCP.
 */
export class TestDnsServer {
  private readonly records = new Map<string, NameRecords>();
  private readonly failures = new Map<string, TestDnsFailure>();
  private readonly log: Array<{ name: string; type: string; transport: TestDnsTransport }> = [];
  private readonly tcpSockets = new Set<Socket>();

  private constructor(
    private readonly udp: UdpSocket,
    private readonly tcp: Server,
    readonly port: number,
    private readonly defaultTtl: number,
  ) {}

  /** UDP + TCP on 127.0.0.1:<random port> (the same port for both). */
  static async start(options: { defaultTtl?: number } = {}): Promise<TestDnsServer> {
    // Pick a port free for UDP, then bind TCP to it; retry on the rare TCP clash.
    for (let attempt = 0; attempt < 20; attempt++) {
      const udp = createSocket('udp4');
      await new Promise<void>((resolve, reject) => {
        udp.once('error', reject);
        udp.bind(0, '127.0.0.1', () => {
          udp.off('error', reject);
          resolve();
        });
      });
      const port = udp.address().port;
      const tcp = createServer();
      const listening = await new Promise<boolean>((resolve) => {
        tcp.once('error', () => resolve(false));
        tcp.listen(port, '127.0.0.1', () => resolve(true));
      });
      if (!listening) {
        udp.close();
        continue;
      }
      const server = new TestDnsServer(udp, tcp, port, options.defaultTtl ?? 300);
      server.attach();
      return server;
    }
    throw new Error('TestDnsServer could not bind UDP and TCP on the same port');
  }

  /** `127.0.0.1:<port>`, as `DNS_SERVERS` expects. */
  get address(): string {
    return `127.0.0.1:${this.port}`;
  }

  get queries(): ReadonlyArray<{ name: string; type: string; transport: TestDnsTransport }> {
    return this.log;
  }

  /** Replaces the TXT records of `name`; each value is split into ≤ 255-byte strings. */
  setTxt(name: string, values: string[]): void {
    this.entry(name).TXT = [...values];
  }

  setMx(name: string, records: Array<{ priority: number; exchange: string }>): void {
    this.entry(name).MX = records.map((r) => ({ priority: r.priority, exchange: r.exchange }));
  }

  setCname(name: string, target: string): void {
    this.entry(name).CNAME = canonical(target);
  }

  /** Removes the records of one type, or every record of the name. */
  remove(name: string, type?: TestDnsRecordType): void {
    const key = canonical(name);
    if (!type) {
      this.records.delete(key);
      return;
    }
    const entry = this.records.get(key);
    if (!entry) return;
    delete entry[type];
    if (!entry.TXT && !entry.MX && !entry.CNAME) this.records.delete(key);
  }

  fail(name: string, failure: TestDnsFailure): void {
    this.failures.set(canonical(name), failure);
  }

  clearFailure(name: string): void {
    this.failures.delete(canonical(name));
  }

  /** Drops every record, failure and logged query. */
  reset(): void {
    this.records.clear();
    this.failures.clear();
    this.log.length = 0;
  }

  async close(): Promise<void> {
    for (const socket of this.tcpSockets) socket.destroy();
    await Promise.all([
      new Promise<void>((resolve) => this.udp.close(() => resolve())),
      new Promise<void>((resolve) => this.tcp.close(() => resolve())),
    ]);
  }

  /**
   * Builds the response to a decoded query, or null when the name is configured to time out.
   * Used by the UDP/TCP listeners and by `TestDohServer`.
   */
  respond(query: dnsPacket.Packet, transport: TestDnsTransport): dnsPacket.Packet | null {
    const question = query.questions?.[0];
    const opt = (query.additionals ?? []).find((a): a is dnsPacket.OptAnswer => a.type === 'OPT');
    const response: dnsPacket.Packet = {
      type: 'response',
      id: query.id ?? 0,
      flags:
        dnsPacket.AUTHORITATIVE_ANSWER |
        dnsPacket.RECURSION_AVAILABLE |
        ((query.flags ?? 0) & dnsPacket.RECURSION_DESIRED),
      questions: question ? [question] : [],
      answers: [],
      authorities: [],
      additionals: opt ? [{ type: 'OPT', name: '.', udpPayloadSize: 4096 } as never] : [],
    };
    if (!question) return response;

    const name = canonical(question.name);
    this.log.push({ name, type: question.type, transport });
    const failure = this.failures.get(name);
    if (failure === 'timeout') return null;
    if (failure) {
      response.flags =
        (response.flags ?? 0) | (failure === 'servfail' ? RCODE.SERVFAIL : RCODE.REFUSED);
      return response;
    }

    let current = name;
    for (let hop = 0; hop <= MAX_CNAME_HOPS; hop++) {
      const entry = this.records.get(current);
      if (entry?.CNAME && question.type !== 'CNAME') {
        response.answers!.push({
          type: 'CNAME',
          name: current,
          ttl: this.defaultTtl,
          data: entry.CNAME,
        });
        current = entry.CNAME;
        continue;
      }
      const answers = entry ? this.answersFor(current, question.type, entry) : [];
      if (answers.length > 0) {
        response.answers!.push(...answers);
        return response;
      }
      break;
    }
    if (response.answers!.length > 0 && this.records.has(current)) {
      // CNAME chain ending at a name without records of the asked type: NODATA.
      response.authorities!.push(this.soa(current));
      return response;
    }
    if (this.exists(current)) {
      response.authorities!.push(this.soa(current));
      return response;
    }
    response.flags = (response.flags ?? 0) | RCODE.NXDOMAIN;
    response.authorities!.push(this.soa(current));
    return response;
  }

  private answersFor(name: string, type: string, entry: NameRecords): dnsPacket.Answer[] {
    if (type === 'TXT' && entry.TXT) {
      return entry.TXT.map((value) => ({
        type: 'TXT' as const,
        name,
        ttl: this.defaultTtl,
        data: chunks(value),
      }));
    }
    if (type === 'MX' && entry.MX) {
      return entry.MX.map((mx) => ({
        type: 'MX' as const,
        name,
        ttl: this.defaultTtl,
        data: { preference: mx.priority, exchange: mx.exchange },
      }));
    }
    if (type === 'CNAME' && entry.CNAME) {
      return [{ type: 'CNAME' as const, name, ttl: this.defaultTtl, data: entry.CNAME }];
    }
    return [];
  }

  /** The name has records, or is an ancestor of a name that has (empty non-terminal). */
  private exists(name: string): boolean {
    if (this.records.has(name)) return true;
    for (const key of this.records.keys()) if (key.endsWith(`.${name}`)) return true;
    return false;
  }

  /** SOA of the synthetic zone (the last two labels), MINIMUM = default TTL (RFC 2308). */
  private soa(name: string): dnsPacket.Answer {
    const zone = name.split('.').slice(-2).join('.');
    return {
      type: 'SOA',
      name: zone,
      ttl: this.defaultTtl,
      data: {
        mname: `ns.${zone}`,
        rname: `hostmaster.${zone}`,
        serial: 1,
        refresh: 3600,
        retry: 600,
        expire: 86400,
        minimum: this.defaultTtl,
      },
    };
  }

  private entry(name: string): NameRecords {
    const key = canonical(name);
    let entry = this.records.get(key);
    if (!entry) {
      entry = {};
      this.records.set(key, entry);
    }
    return entry;
  }

  private attach(): void {
    this.udp.on('message', (message, remote) => {
      let query: dnsPacket.Packet;
      try {
        query = dnsPacket.decode(message);
      } catch {
        return;
      }
      const response = this.respond(query, 'udp');
      if (!response) return;
      const opt = (query.additionals ?? []).find((a): a is dnsPacket.OptAnswer => a.type === 'OPT');
      const limit = Math.max(DEFAULT_UDP_SIZE, opt?.udpPayloadSize ?? DEFAULT_UDP_SIZE);
      let encoded = dnsPacket.encode(response);
      if (encoded.length > limit) {
        encoded = dnsPacket.encode({
          ...response,
          flags: (response.flags ?? 0) | dnsPacket.TRUNCATED_RESPONSE,
          answers: [],
          authorities: [],
        });
      }
      this.udp.send(encoded, remote.port, remote.address);
    });

    this.tcp.on('connection', (socket) => {
      this.tcpSockets.add(socket);
      socket.on('close', () => this.tcpSockets.delete(socket));
      socket.on('error', () => socket.destroy());
      let buffered = Buffer.alloc(0);
      socket.on('data', (data) => {
        buffered = Buffer.concat([buffered, data]);
        while (buffered.length >= 2) {
          const length = buffered.readUInt16BE(0);
          if (buffered.length < length + 2) break;
          const frame = buffered.subarray(0, length + 2);
          buffered = buffered.subarray(length + 2);
          let query: dnsPacket.Packet;
          try {
            query = dnsPacket.streamDecode(frame);
          } catch {
            socket.destroy();
            return;
          }
          const response = this.respond(query, 'tcp');
          if (response) socket.write(dnsPacket.streamEncode(response));
        }
      });
    });
  }
}
