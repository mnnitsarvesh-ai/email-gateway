import { createServer, type Server, type Socket, connect } from 'node:net';

/**
 * An in-process TCP proxy in front of a broker or database (step 3.2 integration suites):
 * `cut()` destroys every open connection and refuses new ones (a network partition as the client
 * sees it: resets, then connection refused); `restore()` accepts again.
 */
export class TcpProxy {
  private readonly sockets = new Set<Socket>();
  private isCut = false;
  private constructor(
    private readonly server: Server,
    readonly port: number,
  ) {}

  static async start(targetHost: string, targetPort: number): Promise<TcpProxy> {
    const ref: { proxy?: TcpProxy } = {};
    const server = createServer((client) => {
      const proxy = ref.proxy;
      if (!proxy || proxy.isCut) {
        client.destroy();
        return;
      }
      const upstream = connect({ host: targetHost, port: targetPort });
      const track = (socket: Socket) => {
        proxy.sockets.add(socket);
        socket.on('close', () => proxy.sockets.delete(socket));
        socket.on('error', () => {
          client.destroy();
          upstream.destroy();
        });
      };
      track(client);
      track(upstream);
      client.pipe(upstream);
      upstream.pipe(client);
    });
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve());
    });
    const address = server.address();
    if (address === null || typeof address === 'string') throw new Error('proxy has no port');
    ref.proxy = new TcpProxy(server, address.port);
    return ref.proxy;
  }

  /** Open client/upstream sockets (two per proxied connection). */
  get connections(): number {
    return this.sockets.size;
  }

  get cutActive(): boolean {
    return this.isCut;
  }

  cut(): void {
    this.isCut = true;
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
  }

  restore(): void {
    this.isCut = false;
  }

  async close(): Promise<void> {
    this.cut();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }
}
