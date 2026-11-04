import { Injectable, Logger } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import {
  type LifecycleLogger,
  type LifecycleSnapshot,
  lockLifecycle,
  type MessageRef,
  type TransitionOutcome,
  type TransitionRequest,
  transitionMessage,
} from '@email-gateway/message-lifecycle';
import { ApiLifecycleMetrics } from '../lifecycle-metrics';

/**
 * The api's door to `@email-gateway/message-lifecycle` (step 3.3 L5, one-door rule): every
 * lifecycle read under lock and every transition of the api goes through these two calls, with
 * the api's metrics and logger. A port so the services can be unit-tested with a fake.
 */
@Injectable()
export class LifecycleGateway {
  private readonly logger = new Logger('MessageLifecycle');
  private readonly lifecycleLogger: LifecycleLogger = {
    warn: (details, message) => this.logger.warn({ message, ...details }),
    debug: (details, message) => this.logger.debug({ message, ...details }),
  };

  constructor(private readonly metrics: ApiLifecycleMetrics) {}

  /** `SELECT … FOR UPDATE` of the message; null for no row or another organization. */
  lock(tx: Prisma.TransactionClient, message: MessageRef): Promise<LifecycleSnapshot | null> {
    return lockLifecycle(tx, message);
  }

  /** One transition in the caller's writer transaction (L5.1). */
  transition(tx: Prisma.TransactionClient, request: TransitionRequest): Promise<TransitionOutcome> {
    return transitionMessage(tx, request, {
      metrics: this.metrics.transitions,
      logger: this.lifecycleLogger,
    });
  }
}
