/**
 * RabbitMQ topology as data. Services assert it idempotently at startup.
 *
 * - One topic exchange for domain events plus a dead-letter exchange.
 * - Quorum queues (replicated, poison-message handling via delivery-limit).
 * - Every work queue dead-letters to `<queue>.dlq` after `deliveryLimit` redeliveries.
 */
export const EXCHANGES = {
  events: 'mail.events',
  deadLetter: 'mail.dlx',
} as const;

export interface QueueDefinition {
  name: string;
  bindings: string[];
  deliveryLimit: number;
}

export const QUEUES = {
  emailProcessing: {
    name: 'email-worker.message-received',
    bindings: ['mail.message.received.v1'],
    deliveryLimit: 5,
  },
  policyEvaluation: {
    name: 'policy-engine.message-scanned',
    bindings: ['mail.message.scanned.v1'],
    deliveryLimit: 5,
  },
  delivery: {
    name: 'delivery-worker.policy-decided',
    bindings: ['mail.policy.decided.v1'],
    deliveryLimit: 10,
  },
  archive: {
    name: 'archive-worker.policy-decided',
    bindings: ['mail.policy.decided.v1'],
    deliveryLimit: 10,
  },
  notification: {
    name: 'notification-worker.events',
    bindings: ['mail.policy.decided.v1'],
    deliveryLimit: 5,
  },
} as const satisfies Record<string, QueueDefinition>;

export function deadLetterQueueName(queue: string): string {
  return `${queue}.dlq`;
}

export function queueArguments(queue: QueueDefinition): Record<string, unknown> {
  return {
    'x-queue-type': 'quorum',
    'x-delivery-limit': queue.deliveryLimit,
    'x-dead-letter-exchange': EXCHANGES.deadLetter,
    'x-dead-letter-routing-key': deadLetterQueueName(queue.name),
    'x-dead-letter-strategy': 'at-least-once',
    'x-overflow': 'reject-publish',
  };
}
