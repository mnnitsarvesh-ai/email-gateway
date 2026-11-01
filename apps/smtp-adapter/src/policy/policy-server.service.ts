import { Inject, Injectable, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import { type HealthIndicator } from '@email-gateway/common';
import { createLogger, type Logger } from '@email-gateway/logger';
import { createServer, type Server, type Socket } from 'node:net';
import { PolicyDecisionService } from './policy-decision.service';
import { formatResponse, PolicyRequestParser } from './policy-protocol';

export const POLICY_SERVER_OPTIONS = Symbol('POLICY_SERVER_OPTIONS');

export interface PolicyServerOptions {
  host: string;
  port: number;
  logLevel: string;
}

const TEMPFAIL = 'DEFER_IF_PERMIT 4.3.5 Policy service temporarily unavailable';
const IDLE_TIMEOUT_MS = 60_000;

/** TCP listener Postfix connects to via `check_policy_service inet:smtp-adapter:10040`. */
@Injectable()
export class PolicyServerService implements OnModuleInit, OnModuleDestroy, HealthIndicator {
  readonly healthName = 'policy-listener';
  private readonly server: Server;
  private readonly logger: Logger;

  constructor(
    @Inject(POLICY_SERVER_OPTIONS) private readonly options: PolicyServerOptions,
    private readonly decisions: PolicyDecisionService,
  ) {
    this.logger = createLogger({ service: 'smtp-adapter', level: options.logLevel }).child({
      component: 'policy-server',
    });
    this.server = createServer((socket) => this.handle(socket));
  }

  async onModuleInit(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.options.port, this.options.host, () => resolve());
    });
    this.logger.info({ port: this.address() }, 'policy server listening');
  }

  async onModuleDestroy(): Promise<void> {
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  checkHealth(): Promise<void> {
    return this.server.listening
      ? Promise.resolve()
      : Promise.reject(new Error('policy listener is not accepting connections'));
  }

  /** Bound port (useful when configured with port 0 in tests). */
  address(): number {
    const addr = this.server.address();
    return typeof addr === 'object' && addr ? addr.port : this.options.port;
  }

  private handle(socket: Socket): void {
    const parser = new PolicyRequestParser();
    socket.setEncoding('utf8');
    socket.setTimeout(IDLE_TIMEOUT_MS, () => socket.end());
    // Postfix reuses a connection for many requests; answer them strictly in order.
    let queue = Promise.resolve();

    socket.on('data', (chunk: string) => {
      let requests;
      try {
        requests = parser.push(chunk);
      } catch (err) {
        this.logger.warn({ err }, 'rejecting malformed policy request');
        socket.end(formatResponse(TEMPFAIL));
        return;
      }
      for (const request of requests) {
        queue = queue.then(async () => {
          let action: string;
          try {
            action = await this.decisions.decide(request);
          } catch (err) {
            this.logger.error({ err }, 'policy decision failed; tempfailing');
            action = TEMPFAIL;
          }
          if (!socket.destroyed) socket.write(formatResponse(action));
        });
      }
    });
    socket.on('error', (err) => this.logger.debug({ err }, 'policy client socket error'));
  }
}
