import type { RowDataPacket } from 'mysql2';
import { createConnection } from 'mysql2/promise';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { composeOk, compose, waitFor } from './support/compose';
import { stack } from './support/env';
import { MessagingScenario } from './support/messaging-scenario';
import {
  containerHealth,
  messagingStackGate,
  record,
  sleep,
  waitForHealthy,
} from './support/messaging-stack';
import { SmtpFixtures } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';

/**
 * MySQL writer outage mid-stream through the live stack (docs/plan/steps/07-rabbitmq.md §10
 * "Database outage", WP5): 300 messages through postfix:25 while `docker compose pause mysql`
 * freezes the writer for 20 s. LMTP ingestion answers 4xx and Postfix retries; the relay marks
 * nothing and backs off; email-worker handlers fail transiently (hold and republish, no attempt
 * consumed, never dead-lettered). After `unpause` every message is parsed, planned and delivered
 * exactly once, no dead letter, every outbox row published; the GTID replica is healthy again.
 */
const N = Number(process.env.MESSAGING_CHAOS_MESSAGES ?? 300);
const PAUSE_MS = Number(process.env.MESSAGING_DB_PAUSE_MS ?? 20_000);
const gate = await messagingStackGate();
const fx = new SmtpFixtures();
const scenario = new MessagingScenario('messaging-db-outage', fx);
let paused = false;

/** `SHOW REPLICA STATUS` of the replica (reader account: REPLICATION CLIENT). */
async function replicaStatus(): Promise<{ io: string; sql: string; lag: number | null }> {
  const conn = await createConnection({ uri: stack.databaseReadUrl(), connectTimeout: 5_000 });
  try {
    const [rows] = await conn.query<RowDataPacket[]>('SHOW REPLICA STATUS');
    const row: Record<string, unknown> = rows[0] ?? {};
    return {
      io: typeof row.Replica_IO_Running === 'string' ? row.Replica_IO_Running : '',
      sql: typeof row.Replica_SQL_Running === 'string' ? row.Replica_SQL_Running : '',
      lag: row.Seconds_Behind_Source === null ? null : Number(row.Seconds_Behind_Source),
    };
  } finally {
    await conn.end();
  }
}

beforeAll(async () => {
  assertStackReady(gate);
  const replica = await replicaStatus();
  expect(replica).toMatchObject({ io: 'Yes', sql: 'Yes' });
  await scenario.setup('mq-dbout');
}, 120_000);

afterAll(async () => {
  if (gate.skip) return;
  if (paused || (await containerHealth('mysql')).startsWith('paused')) {
    await compose(['unpause', 'mysql'], { timeoutMs: 60_000 });
  }
  await scenario.teardown();
}, 300_000);

describe.skipIf(gate.skip)(
  'messaging stack: MySQL writer outage mid-stream',
  { timeout: 1_500_000 },
  () => {
    it(`delivers ${N} messages exactly once across a ${PAUSE_MS / 1000} s writer pause`, async () => {
      await scenario.run({
        n: N,
        chaos: async (progress) => {
          await progress.parsed(Math.floor(N / 4));
          const before = await progress.counts();
          await composeOk(['pause', 'mysql'], { timeoutMs: 60_000 });
          paused = true;
          const pausedAt = Date.now();
          await sleep(PAUSE_MS);
          await composeOk(['unpause', 'mysql'], { timeoutMs: 60_000 });
          paused = false;
          record('messaging-db-outage', {
            paused_s: ((Date.now() - pausedAt) / 1000).toFixed(1),
            parsed_before_pause: before.mimeLedger,
            stored_before_pause: before.messages,
          });
          expect(before.mimeLedger).toBeLessThan(N);
          await waitForHealthy('mysql', 120_000);
        },
      });

      // The GTID replica reconnects to the writer by itself (SOURCE_CONNECT_RETRY).
      const started = Date.now();
      const replica = await waitFor(
        'the replica threads running again with a small lag',
        async () => {
          const status = await replicaStatus();
          return status.io === 'Yes' && status.sql === 'Yes' && (status.lag ?? 99) < 30
            ? status
            : undefined;
        },
        { timeoutMs: 240_000, intervalMs: 2_000 },
      );
      record('messaging-db-outage', {
        replica_io: replica.io,
        replica_sql: replica.sql,
        replica_lag_s: replica.lag,
        replica_recovered_after_s: ((Date.now() - started) / 1000).toFixed(1),
      });
      await waitForHealthy('mysql-replica', 120_000);
    });
  },
);
