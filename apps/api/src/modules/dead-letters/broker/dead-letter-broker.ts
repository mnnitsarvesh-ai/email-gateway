import { Inject, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { AmqpConnection, ConfirmPublisher, DEFAULT_MAX_MESSAGE_BYTES } from '@email-gateway/common';
import { createLogger, type Logger } from '@email-gateway/logger';
import { API_CONFIG } from '../../../api-config.token';
import type { ApiConfig } from '../../../config';
import { DEAD_LETTER_QUEUE, type DeadLetterMessage } from '../domain/dead-letter-replay';

/** Stable `message` of the 503 when no ops broker URL is configured or it cannot be reached. */
export const REPLAY_UNAVAILABLE = 'dead_letter_replay_unavailable';

/** How long a request waits for the ops connection before answering 503. */
const CONNECT_TIMEOUT_MS = 10_000;
const CONFIRM_TIMEOUT_MS = 15_000;

/**
 * One broker session of a request (Q9): a channel on `email.dead-letter` with manual acks, and a
 * confirm publisher for the replayed copies. Everything not acked is returned to the queue when
 * the session closes (explicit `nack(requeue)` by the caller; the broker requeues the rest when
 * the channel closes).
 */
export interface DeadLetterSession {
  /** `basic.get` with `noAck: false`; `null` when the queue is empty. */
  get(): Promise<DeadLetterMessage | null>;
  ack(msg: DeadLetterMessage): void;
  /** `basic.nack` with `requeue: true`. */
  requeue(msg: DeadLetterMessage): void;
  /** Republishes the delivery's bytes (guard first); resolves only when confirmed. */
  republish(
    msg: DeadLetterMessage,
    target: { exchange: string; routingKey: string; headers: Record<string, string | number> },
  ): Promise<void>;
  /** Passive `checkQueue` of the dead-letter queue. */
  stats(): Promise<{ messages: number; consumers: number }>;
  close(): Promise<void>;
}

/** Opens a session per request; implementations never print the URL (it carries credentials). */
export abstract class DeadLetterBroker {
  /** True when an ops URL is configured (otherwise every call answers 503). */
  abstract get configured(): boolean;
  /** Throws `ServiceUnavailableException(REPLAY_UNAVAILABLE)` when the broker is unreachable. */
  abstract open(): Promise<DeadLetterSession>;
}

type Channel = Awaited<ReturnType<AmqpConnection['createChannel']>>;
type RawMessage = Parameters<Channel['ack']>[0];
type RepublishRaw = Parameters<ConfirmPublisher['republish']>[0];

/**
 * The production broker of the replay (Q9, Q10): a lazily created connection per request with
 * the `eg-ops` role user (`RABBITMQ_OPS_URL`: read `email.dead-letter`, write `retry.<work queue>.…` keys to `email.ingestion` / `email.delivery`,
 * no configure rights), closed after the request. Built on the shared `AmqpConnection` and
 * `ConfirmPublisher` of `@email-gateway/common`.
 */
@Injectable()
export class AmqpDeadLetterBroker extends DeadLetterBroker {
  private readonly logger: Logger;

  constructor(@Inject(API_CONFIG) private readonly config: Readonly<ApiConfig>) {
    super();
    // The AMQP client logs tokens only (node index, reply names), never URLs or credentials.
    this.logger = createLogger({
      service: 'api',
      level: config.LOG_LEVEL,
      version: config.SERVICE_VERSION,
    }).child({ component: 'dead-letter-broker' });
  }

  get configured(): boolean {
    return (this.config.RABBITMQ_OPS_URL?.length ?? 0) > 0;
  }

  async open(): Promise<DeadLetterSession> {
    const urls = this.config.RABBITMQ_OPS_URL;
    if (!urls || urls.length === 0) throw new ServiceUnavailableException(REPLAY_UNAVAILABLE);
    const connection = new AmqpConnection({
      urls,
      connectionName: 'api-dead-letter-replay',
      logger: this.logger,
      reconnect: { baseMs: 200, maxMs: 2_000 },
    });
    connection.start();
    let channel: Channel;
    try {
      await connection.waitUntilConnected(CONNECT_TIMEOUT_MS);
      channel = await connection.createChannel();
      // A channel error (e.g. a missing queue) must not crash the process.
      channel.on('error', () => undefined);
    } catch {
      await connection.close();
      throw new ServiceUnavailableException(REPLAY_UNAVAILABLE);
    }
    const publisher = new ConfirmPublisher({
      connection,
      logger: this.logger,
      appId: 'api',
      confirmTimeoutMs: CONFIRM_TIMEOUT_MS,
      maxMessageBytes: DEFAULT_MAX_MESSAGE_BYTES,
    });
    return {
      async get() {
        const msg = await channel.get(DEAD_LETTER_QUEUE, { noAck: false });
        return msg === false ? null : msg;
      },
      ack: (msg) => channel.ack(msg as unknown as RawMessage),
      requeue: (msg) => channel.nack(msg as unknown as RawMessage, false, true),
      republish: (msg, target) => publisher.republish(msg as unknown as RepublishRaw, target),
      async stats() {
        const q = await channel.checkQueue(DEAD_LETTER_QUEUE);
        return { messages: q.messageCount, consumers: q.consumerCount };
      },
      async close() {
        await publisher.close();
        await channel.close().catch(() => undefined);
        await connection.close();
      },
    };
  }
}
