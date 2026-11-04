import {
  type DynamicModule,
  Global,
  Inject,
  Injectable,
  Module,
  type OnApplicationShutdown,
  type OnModuleInit,
} from '@nestjs/common';
import { createLogger, type Logger } from '@email-gateway/logger';
import { MetricsService } from '../metrics/metrics.service';
import { AmqpConnection } from './connection';
import { createMessagingMetrics, type MessagingMetrics } from './metrics';
import { ConfirmPublisher, DEFAULT_MAX_MESSAGE_BYTES } from './publisher';

export const AMQP_MODULE_OPTIONS = Symbol('AMQP_MODULE_OPTIONS');
/** The `MessagingMetrics` of the service (undefined without a `MetricsModule`). */
export const AMQP_MESSAGING_METRICS = Symbol('AMQP_MESSAGING_METRICS');

export interface AmqpModuleOptions {
  /** One or more amqp(s):// URLs of the service's role user (cluster nodes in rotation). */
  urls: string[];
  connectionName: string;
  /** AMQP `appId` of every publish. */
  appId: string;
  /** Default 15 000 ms. */
  confirmTimeoutMs?: number;
  /** Default 131 072 bytes (hard max 262 144). */
  maxMessageBytes?: number;
  /** Objects verified passively for readiness (services never declare). */
  verify?: { exchanges?: string[]; queues?: string[] };
  /** Default: a logger of service `connectionName`. */
  logger?: Logger;
  heartbeatSeconds?: number;
  reconnect?: { baseMs: number; maxMs: number };
}

@Injectable()
class AmqpLifecycle implements OnModuleInit, OnApplicationShutdown {
  constructor(
    @Inject(AmqpConnection) private readonly connection: AmqpConnection,
    @Inject(ConfirmPublisher) private readonly publisher: ConfirmPublisher,
    @Inject(AMQP_MODULE_OPTIONS) private readonly options: AmqpModuleOptions,
  ) {}

  /** Starts connecting in the background; never awaits the broker (readiness reports it). */
  onModuleInit(): void {
    if (this.options.verify) this.connection.requireTopology(this.options.verify);
    this.connection.start();
  }

  /**
   * Runs after every module's `onModuleDestroy`, i.e. after consumers stopped and released
   * their deliveries.
   */
  async onApplicationShutdown(): Promise<void> {
    await this.publisher.close();
    await this.connection.close();
  }
}

/**
 * The AMQP client of a service (step 3.2 Q6): a global `AmqpConnection` (also the `rabbitmq`
 * `HealthIndicator`, list it in `HealthModule.forRoot({ indicators })`) and a `ConfirmPublisher`.
 * Queue consumers are built by the feature modules (`new QueueConsumer(...)`) with these.
 * Replaces the crash-only `RabbitMqModule`: a broker failure never exits the process.
 */
@Global()
@Module({})
export class AmqpModule {
  static forRoot(options: AmqpModuleOptions): DynamicModule {
    return {
      module: AmqpModule,
      providers: [
        { provide: AMQP_MODULE_OPTIONS, useValue: options },
        {
          provide: AMQP_MESSAGING_METRICS,
          useFactory: (metrics?: MetricsService): MessagingMetrics | null =>
            metrics ? createMessagingMetrics(metrics) : null,
          inject: [{ token: MetricsService, optional: true }],
        },
        {
          provide: AmqpConnection,
          useFactory: (metrics: MessagingMetrics | null) =>
            new AmqpConnection({
              urls: options.urls,
              connectionName: options.connectionName,
              logger: options.logger ?? createLogger({ service: options.connectionName }),
              ...(metrics ? { metrics } : {}),
              ...(options.heartbeatSeconds === undefined
                ? {}
                : { heartbeatSeconds: options.heartbeatSeconds }),
              ...(options.reconnect ? { reconnect: options.reconnect } : {}),
            }),
          inject: [AMQP_MESSAGING_METRICS],
        },
        {
          provide: ConfirmPublisher,
          useFactory: (connection: AmqpConnection, metrics: MessagingMetrics | null) =>
            new ConfirmPublisher({
              connection,
              logger: options.logger ?? createLogger({ service: options.connectionName }),
              ...(metrics ? { metrics } : {}),
              appId: options.appId,
              confirmTimeoutMs: options.confirmTimeoutMs ?? 15_000,
              maxMessageBytes: options.maxMessageBytes ?? DEFAULT_MAX_MESSAGE_BYTES,
            }),
          inject: [AmqpConnection, AMQP_MESSAGING_METRICS],
        },
        AmqpLifecycle,
      ],
      exports: [AmqpConnection, ConfirmPublisher, AMQP_MESSAGING_METRICS],
    };
  }
}
