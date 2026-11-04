import type { PrismaClient } from '@email-gateway/database';
import type { ConsumerProgressEntry, ConsumerProgressRecorder } from '../messaging/consumer';

const REASON = /^[a-z0-9_]{1,48}$/;

/**
 * `ConsumerProgressRecorder` on the MySQL writer (table `message_consumer_progress`, step 3.2
 * review round 1): one row per `(consumer, event_id)`, overwritten by every later hop (a replayed
 * dead letter that retries again becomes `retrying`). One `INSERT … ON DUPLICATE KEY UPDATE`
 * (atomic, no read first). `updated_at` is the database clock, like the reconciler's thresholds.
 */
export class PrismaConsumerProgress implements ConsumerProgressRecorder {
  constructor(private readonly prisma: Pick<PrismaClient, '$executeRaw'>) {}

  async record(entry: ConsumerProgressEntry): Promise<void> {
    const reason = entry.reason !== undefined && REASON.test(entry.reason) ? entry.reason : null;
    const attempt = Math.max(0, Math.trunc(entry.attempt));
    const transientRetries = Math.max(0, Math.trunc(entry.transientRetries));
    await this.prisma.$executeRaw`
      INSERT INTO message_consumer_progress
        (consumer, event_id, state, reason, attempt, transient_retries, updated_at)
      VALUES (${entry.consumer}, ${entry.eventId}, ${entry.state}, ${reason}, ${attempt},
              ${transientRetries}, NOW(3)) AS incoming
      ON DUPLICATE KEY UPDATE
        state = incoming.state, reason = incoming.reason, attempt = incoming.attempt,
        transient_retries = incoming.transient_retries, updated_at = incoming.updated_at`;
  }
}
