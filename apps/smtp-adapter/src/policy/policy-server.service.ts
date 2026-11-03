import { Inject, Injectable, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import { type HealthIndicator } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import type { BlockList, Socket } from 'node:net';
import { ADAPTER_LOGGER } from '../config';
import { TcpListener } from '../listener/tcp-listener';
import { POLICY_TEMPFAIL } from '../shared/replies';
import { PolicyDecisionService } from './policy-decision.service';
import {
  formatResponse,
  type PolicyRequest,
  PolicyRequestParser,
  postfixAction,
} from './policy-protocol';

export const POLICY_SERVER_OPTIONS = Symbol('POLICY_SERVER_OPTIONS');

export interface PolicyServerOptions {
  host: string;
  port: number;
  /** Peers outside this list are disconnected (SMTP_INTERNAL_CLIENT_NETWORKS, D20). */
  internalNetworks: BlockList;
}

/** Above Postfix's smtpd_policy_service_max_idle (300 s), so Postfix closes idle links first. */
export const POLICY_IDLE_TIMEOUT_MS = 330_000;

/** TCP listener Postfix connects to via `check_policy_service inet:<adapter>:10040`. */
@Injectable()
export class PolicyServerService implements OnModuleInit, OnModuleDestroy, HealthIndicator {
  readonly healthName = 'policy-listener';
  private readonly listener: TcpListener;
  private readonly logger: Logger;

  constructor(
    @Inject(POLICY_SERVER_OPTIONS) options: PolicyServerOptions,
    private readonly decisions: PolicyDecisionService,
    @Inject(ADAPTER_LOGGER) logger: Logger,
  ) {
    this.logger = logger.child({ component: 'policy-server' });
    this.listener = new TcpListener(
      { name: this.healthName, idleTimeoutMs: POLICY_IDLE_TIMEOUT_MS, ...options },
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
      : Promise.reject(new Error('policy listener is not accepting connections'));
  }

  /** Bound port (useful when configured with port 0 in tests). */
  address(): number {
    return this.listener.port();
  }

  private handle(socket: Socket): void {
    const parser = new PolicyRequestParser();
    socket.setEncoding('utf8');
    // Postfix reuses a connection for many requests; answer them strictly in order.
    let queue = Promise.resolve();
    let closed = false;

    socket.on('data', (chunk: string) => {
      if (closed) return;
      let requests: PolicyRequest[];
      try {
        requests = parser.push(chunk);
      } catch (err) {
        closed = true;
        this.logger.warn({ err }, 'rejecting malformed policy request');
        // Answer what is already queued first, then the tempfail, then close.
        queue = queue.then(() => {
          socket.end(formatResponse(POLICY_TEMPFAIL));
        });
        return;
      }
      for (const request of requests) {
        queue = queue.then(async () => {
          let action: string;
          try {
            action = await this.decisions.decide(request);
          } catch (err) {
            this.logger.error({ err }, 'policy decision failed; tempfailing');
            action = POLICY_TEMPFAIL;
          }
          if (!socket.destroyed && socket.writable) {
            socket.write(formatResponse(postfixAction(action)));
          }
        });
      }
    });
  }
}
