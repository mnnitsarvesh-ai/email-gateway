import {
  type AmqpConnection,
  type ConfirmPublisher,
  type MessagingMetrics,
  QueueConsumer,
} from '@email-gateway/common';
import { EventTypes, type SandboxTaskRequestedV1 } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import { classifyTaskFailure } from './errors';
import type { TaskHandler } from './task-handler';

/**
 * The consumer of `scan.sandbox` (step 4.6 X7): stateless kind, the `@email-gateway/common`
 * consumer with manual acks, prefetch = `SANDBOX_CONCURRENCY`, the topology's hold retry policy
 * (3 attempts, 5 s–60 s, max age 1 h), `TransientTaskError` kept transient. Unknown types,
 * schema and tenant violations are dead-lettered by the consumer's codec / the handler.
 *
 * `pause()` cancels the subscription (in-flight tasks finish; held retries are requeued) while
 * the backend self-test fails at runtime; `resume()` subscribes a fresh consumer when it passes
 * again — never a nack loop against a broken backend.
 */

export const TASK_QUEUE = 'scan.sandbox';
export const CONSUMER_NAME = 'sandbox-controller';

/** What `TaskConsumer` drives: the subset of `QueueConsumer` it uses. */
export interface TaskSubscription {
  start(handler: TaskHandler['handle']): void;
  /** Cancels the subscription and resolves when in-flight deliveries are settled. */
  stop(): Promise<void>;
}

export interface TaskConsumerOptions {
  connection: AmqpConnection;
  publisher: ConfirmPublisher;
  metrics: MessagingMetrics | null;
  handler: TaskHandler;
  prefetch: number;
  /** Longest wait for in-flight tasks on stop (`SANDBOX_TASK_TIMEOUT_MS`). */
  stopTimeoutMs: number;
  logger: Logger;
  /** Builds a subscription (default: a `QueueConsumer` on `scan.sandbox`; tests inject one). */
  createSubscription?: () => TaskSubscription;
}

export class TaskConsumer {
  private consumer: TaskSubscription | null = null;
  private stopping = false;
  private transition: Promise<void> = Promise.resolve();

  constructor(private readonly o: TaskConsumerOptions) {}

  get consuming(): boolean {
    return this.consumer !== null;
  }

  private build(): TaskSubscription {
    if (this.o.createSubscription) return this.o.createSubscription();
    return new QueueConsumer<SandboxTaskRequestedV1>({
      connection: this.o.connection,
      publisher: this.o.publisher,
      queue: TASK_QUEUE,
      consumer: CONSUMER_NAME,
      eventTypes: [EventTypes.SandboxTaskRequested],
      prefetch: this.o.prefetch,
      classify: classifyTaskFailure,
      stopTimeoutMs: this.o.stopTimeoutMs,
      logger: this.o.logger,
      ...(this.o.metrics ? { metrics: this.o.metrics } : {}),
    });
  }

  /** Subscribes (idempotent). */
  resume(): Promise<void> {
    this.transition = this.transition.then(() => {
      if (this.stopping || this.consumer) return;
      this.consumer = this.build();
      this.consumer.start(this.o.handler.handle);
      this.o.logger.info({ queue: TASK_QUEUE }, 'sandbox task consumer started');
    });
    return this.transition;
  }

  /** Cancels the subscription and waits for in-flight tasks (idempotent). */
  pause(): Promise<void> {
    this.transition = this.transition.then(async () => {
      const consumer = this.consumer;
      this.consumer = null;
      if (!consumer) return;
      await consumer.stop();
      this.o.logger.warn({ queue: TASK_QUEUE }, 'sandbox task consumer paused');
    });
    return this.transition;
  }

  async stop(): Promise<void> {
    this.stopping = true;
    await this.pause();
  }
}
