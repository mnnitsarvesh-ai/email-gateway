import type { AmqpConnection } from '@email-gateway/common';
import type { QueueName } from '@email-gateway/event-contracts';
import type { QueueDepthProbe } from './outbox-reconciler';

/** Longest wait for one passive declare. */
export const QUEUE_DEPTH_TIMEOUT_MS = 5_000;

/**
 * `QueueDepthProbe` on the relay's AMQP connection: a passive `queue.declare` (`checkQueue`) on a
 * short-lived channel. `eg-relay` reads no queue, but a passive declare needs no permission
 * (Q10). Rejects while the connection is down or the declare fails or times out.
 */
export class AmqpQueueDepth implements QueueDepthProbe {
  constructor(private readonly connection: Pick<AmqpConnection, 'connected' | 'createChannel'>) {}

  async readyMessages(queue: QueueName): Promise<number> {
    if (!this.connection.connected) throw new Error('broker not connected');
    const channel = await this.connection.createChannel();
    // A failed passive declare closes the channel; the error is the rejection below.
    channel.on('error', () => undefined);
    let timer: NodeJS.Timeout | undefined;
    try {
      const reply = await Promise.race([
        channel.checkQueue(queue),
        new Promise<never>((_, reject) => {
          timer = setTimeout(
            () => reject(new Error('queue depth timed out')),
            QUEUE_DEPTH_TIMEOUT_MS,
          );
          timer.unref?.();
        }),
      ]);
      return reply.messageCount;
    } finally {
      if (timer) clearTimeout(timer);
      await channel.close().catch(() => undefined);
    }
  }
}
