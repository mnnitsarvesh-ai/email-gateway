import {
  type DynamicModule,
  Global,
  Inject,
  Injectable,
  Logger,
  Module,
  type OnModuleDestroy,
  type OnModuleInit,
} from '@nestjs/common';
import {
  deadLetterQueueName,
  EXCHANGES,
  type QueueDefinition,
  queueArguments,
} from '@email-gateway/event-contracts';
import { type ChannelModel, type ConfirmChannel, connect } from 'amqplib';
import type { HealthIndicator } from '../health/health-indicator';

const RABBITMQ_OPTIONS = Symbol('RABBITMQ_OPTIONS');

export interface RabbitMqModuleOptions {
  url: string;
  prefetch: number;
  /** Queues this service consumes; asserted (idempotently) at startup. */
  queues: QueueDefinition[];
  connectionName: string;
}

/**
 * One connection and one confirm channel per process. Publisher confirms and manual acks are
 * mandatory: a message is only considered sent once the broker confirms it, and only removed
 * once the consumer has durably applied it.
 */
@Injectable()
export class RabbitMqService implements OnModuleInit, OnModuleDestroy, HealthIndicator {
  readonly healthName = 'rabbitmq';
  private readonly logger = new Logger(RabbitMqService.name);
  private connection?: ChannelModel;
  private channel?: ConfirmChannel;
  private shuttingDown = false;

  constructor(@Inject(RABBITMQ_OPTIONS) private readonly options: RabbitMqModuleOptions) {}

  async onModuleInit(): Promise<void> {
    this.connection = await connect(this.options.url, {
      clientProperties: { connection_name: this.options.connectionName },
    });
    // Crash-only recovery: an unexpected broker disconnect exits the process so the orchestrator
    // restarts it with fresh connections and topology, rather than leaving a half-alive consumer.
    this.connection.on('error', (err: Error) =>
      this.logger.error(`connection error: ${err.message}`),
    );
    this.connection.on('close', () => {
      if (this.shuttingDown) return;
      this.logger.fatal('RabbitMQ connection closed unexpectedly; exiting for restart');
      process.exit(1);
    });
    this.channel = await this.connection.createConfirmChannel();
    await this.channel.prefetch(this.options.prefetch);
    await this.assertTopology(this.channel);
  }

  async onModuleDestroy(): Promise<void> {
    this.shuttingDown = true;
    await this.channel?.close().catch(() => undefined);
    await this.connection?.close().catch(() => undefined);
  }

  getChannel(): ConfirmChannel {
    if (!this.channel) throw new Error('RabbitMQ channel is not open');
    return this.channel;
  }

  async checkHealth(): Promise<void> {
    if (!this.channel) throw new Error('channel not open');
    // checkExchange is a passive declare: it round-trips to the broker without changing state.
    await this.channel.checkExchange(EXCHANGES.events);
  }

  private async assertTopology(channel: ConfirmChannel): Promise<void> {
    await channel.assertExchange(EXCHANGES.events, 'topic', { durable: true });
    await channel.assertExchange(EXCHANGES.deadLetter, 'direct', { durable: true });
    for (const queue of this.options.queues) {
      const dlq = deadLetterQueueName(queue.name);
      await channel.assertQueue(dlq, { durable: true, arguments: { 'x-queue-type': 'quorum' } });
      await channel.bindQueue(dlq, EXCHANGES.deadLetter, dlq);
      await channel.assertQueue(queue.name, { durable: true, arguments: queueArguments(queue) });
      for (const routingKey of queue.bindings) {
        await channel.bindQueue(queue.name, EXCHANGES.events, routingKey);
      }
    }
  }
}

@Global()
@Module({})
export class RabbitMqModule {
  static forRoot(options: RabbitMqModuleOptions): DynamicModule {
    return {
      module: RabbitMqModule,
      providers: [{ provide: RABBITMQ_OPTIONS, useValue: options }, RabbitMqService],
      exports: [RabbitMqService],
    };
  }
}
