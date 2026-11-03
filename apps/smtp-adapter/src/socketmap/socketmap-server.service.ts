import { Inject, Injectable, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import {
  type Counter,
  type HealthIndicator,
  type Histogram,
  MetricsService,
} from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import type { BlockList, Socket } from 'node:net';
import { ADAPTER_LOGGER } from '../config';
import { TcpListener } from '../listener/tcp-listener';
import { SOCKETMAP_TEMPFAIL, SOCKETMAP_UNKNOWN_MAP } from '../shared/replies';
import { encodeNetstring, NetstringDecoder } from './netstring';
import { isSocketmapMap, SocketmapLookupService } from './socketmap-lookup.service';

export const SOCKETMAP_SERVER_OPTIONS = Symbol('SOCKETMAP_SERVER_OPTIONS');

export interface SocketmapServerOptions {
  host: string;
  port: number;
  internalNetworks: BlockList;
}

export type SocketmapResult = 'ok' | 'notfound' | 'temp' | 'perm';

/** Postfix keeps socketmap connections open; close them only after a long idle period. */
export const SOCKETMAP_IDLE_TIMEOUT_MS = 330_000;

export function resultLabel(reply: string): SocketmapResult {
  if (reply.startsWith('OK')) return 'ok';
  if (reply.startsWith('NOTFOUND')) return 'notfound';
  if (reply.startsWith('PERM')) return 'perm';
  return 'temp';
}

/**
 * Postfix socketmap server (step 2.2 D11, https://www.postfix.org/socketmap_table.5.html) on
 * SOCKETMAP_PORT. Each request is the netstring `<map> <key>`; each reply the netstring
 * `OK <value>` / `NOTFOUND ` / `TEMP <reason>` / `PERM <reason>`, in request order. A lookup
 * error answers `TEMP Lookup failed` (Postfix defers: fail closed); a malformed or oversized
 * request closes the connection.
 */
@Injectable()
export class SocketmapServerService implements OnModuleInit, OnModuleDestroy, HealthIndicator {
  readonly healthName = 'socketmap-listener';
  private readonly listener: TcpListener;
  private readonly logger: Logger;
  private readonly lookups: Counter<'map' | 'result'>;
  private readonly duration: Histogram<'map'>;

  constructor(
    @Inject(SOCKETMAP_SERVER_OPTIONS) options: SocketmapServerOptions,
    private readonly maps: SocketmapLookupService,
    metrics: MetricsService,
    @Inject(ADAPTER_LOGGER) logger: Logger,
  ) {
    this.logger = logger.child({ component: 'socketmap-server' });
    this.lookups = metrics.counter(
      'smtp_socketmap_lookups_total',
      'Socketmap lookups by map and result',
      ['map', 'result'],
    );
    this.duration = metrics.histogram(
      'smtp_socketmap_lookup_seconds',
      'Socketmap lookup latency',
      ['map'],
      [0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1],
    );
    this.listener = new TcpListener(
      { name: this.healthName, idleTimeoutMs: SOCKETMAP_IDLE_TIMEOUT_MS, ...options },
      this.logger,
      (socket) => this.handle(socket),
    );
  }

  async onModuleInit(): Promise<void> {
    await this.listener.start();
  }

  async onModuleDestroy(): Promise<void> {
    await this.listener.stop();
  }

  checkHealth(): Promise<void> {
    return this.listener.listening
      ? Promise.resolve()
      : Promise.reject(new Error('socketmap listener is not accepting connections'));
  }

  address(): number {
    return this.listener.port();
  }

  /** One request payload → reply text. Never throws. */
  async answer(payload: string): Promise<string> {
    const started = performance.now();
    const space = payload.indexOf(' ');
    const map = space === -1 ? payload : payload.slice(0, space);
    const key = space === -1 ? '' : payload.slice(space + 1);
    const mapLabel = isSocketmapMap(map) ? map : 'unknown';
    let reply: string;
    try {
      reply = space <= 0 ? SOCKETMAP_UNKNOWN_MAP : await this.maps.lookup(map, key);
    } catch (err) {
      this.logger.error({ err, map: mapLabel }, 'socketmap lookup failed; answering TEMP');
      reply = SOCKETMAP_TEMPFAIL;
    }
    this.lookups.inc({ map: mapLabel, result: resultLabel(reply) });
    this.duration.observe({ map: mapLabel }, (performance.now() - started) / 1000);
    return reply;
  }

  private handle(socket: Socket): void {
    const decoder = new NetstringDecoder();
    let queue = Promise.resolve();
    socket.on('data', (chunk: Buffer) => {
      let payloads: Buffer[];
      try {
        payloads = decoder.push(chunk);
      } catch (err) {
        this.logger.warn({ err }, 'malformed socketmap request; closing the connection');
        socket.destroy();
        return;
      }
      for (const payload of payloads) {
        queue = queue.then(async () => {
          const reply = await this.answer(payload.toString('utf8'));
          if (!socket.destroyed && socket.writable) socket.write(encodeNetstring(reply));
        });
      }
    });
  }
}
