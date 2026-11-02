import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import * as dnsPacket from 'dns-packet';
import type { TestDnsServer } from './test-dns-server';

const MEDIA_TYPE = 'application/dns-message';

/**
 * In-process RFC 8484 endpoint (plain HTTP on 127.0.0.1, `GET ?dns=` and `POST`) answering
 * from a `TestDnsServer`'s records and failure injection. Never forwards to real DNS. A name
 * configured to `timeout` leaves the request unanswered until the client gives up.
 */
export class TestDohServer {
  private failures: Array<{ status: number }> = [];
  private readonly sockets = new Set<Socket>();

  private constructor(
    private readonly http: Server,
    private readonly dns: TestDnsServer,
    readonly url: string,
  ) {}

  static async start(dns: TestDnsServer): Promise<TestDohServer> {
    const http = createServer();
    await new Promise<void>((resolve) => http.listen(0, '127.0.0.1', resolve));
    const { port } = http.address() as AddressInfo;
    const server = new TestDohServer(http, dns, `http://127.0.0.1:${port}/dns-query`);
    http.on('connection', (socket) => {
      server.sockets.add(socket);
      socket.on('close', () => server.sockets.delete(socket));
    });
    http.on('request', (req, res) => void server.handle(req, res));
    return server;
  }

  /** Next `count` requests answer with this HTTP status (fault injection). */
  failNext(status: number, count = 1): void {
    for (let i = 0; i < count; i++) this.failures.push({ status });
  }

  async close(): Promise<void> {
    for (const socket of this.sockets) socket.destroy();
    await new Promise<void>((resolve) => this.http.close(() => resolve()));
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    if (url.pathname !== '/dns-query') return this.plain(res, 404, 'not found');
    const failure = this.failures.shift();
    if (failure) return this.plain(res, failure.status, 'injected failure');

    let wire: Buffer;
    if (req.method === 'GET') {
      const param = url.searchParams.get('dns');
      if (!param) return this.plain(res, 400, 'missing dns parameter');
      wire = Buffer.from(param, 'base64url');
    } else if (req.method === 'POST') {
      if ((req.headers['content-type'] ?? '').split(';')[0]!.trim() !== MEDIA_TYPE) {
        return this.plain(res, 415, 'unsupported media type');
      }
      const parts: Buffer[] = [];
      for await (const chunk of req) parts.push(chunk as Buffer);
      wire = Buffer.concat(parts);
    } else {
      return this.plain(res, 405, 'method not allowed');
    }

    let query: dnsPacket.Packet;
    try {
      query = dnsPacket.decode(wire);
    } catch {
      return this.plain(res, 400, 'malformed DNS message');
    }
    const response = this.dns.respond(query, 'doh');
    if (!response) return; // injected timeout: never answer
    const body = dnsPacket.encode(response);
    res.writeHead(200, {
      'content-type': MEDIA_TYPE,
      'content-length': body.length,
      'cache-control': 'max-age=0',
    });
    res.end(body);
  }

  private plain(res: ServerResponse, status: number, message: string): void {
    res.writeHead(status, { 'content-type': 'text/plain' });
    res.end(message);
  }
}
