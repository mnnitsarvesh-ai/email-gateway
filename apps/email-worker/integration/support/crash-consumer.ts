/**
 * Child process of the consumer-crash tests (step 3.2 §10 "Consumer crash"): the email-worker
 * stage wired with the production factories (`createMimeIngestionService`, `createMimeConsumer`)
 * on the suite's throwaway vhost, consuming `email.received`. At the crash point chosen by the
 * parent it reports over IPC and then hangs; the parent SIGKILLs it there:
 *
 * - `before-finalize`: the parse ran (part objects uploaded, parse row `parsing`), the final
 *   transaction has not started;
 * - `after-commit`: `MimeIngestionService.handle` returned (rows, ledger and outbox committed),
 *   the delivery is not acked yet.
 *
 * Run by `crash.ts` through vite-node; inputs come from the environment, never printed.
 */
import { AmqpConnection, ConfirmPublisher, MetricsService, S3Service } from '@email-gateway/common';
import { s3ConfigSchema } from '@email-gateway/config';
import { PrismaClient } from '@email-gateway/database';
import { createLogger } from '@email-gateway/logger';
import { loadWorkerConfig } from '../../src/config';
import {
  createMimeConsumer,
  createMimeIngestionService,
} from '../../src/mime-ingestion/mime-ingestion.module';
import { MimeMetrics } from '../../src/mime-ingestion/mime-metrics';
import type { MimeStore } from '../../src/mime-ingestion/mime-store';

type CrashPoint = 'before-finalize' | 'after-commit';

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const send = (message: string): void => {
  process.send?.(message);
};
const hang = (): Promise<never> => new Promise<never>(() => undefined);

async function main(): Promise<void> {
  const crashAt = env('IT_CRASH_AT') as CrashPoint;
  const config = loadWorkerConfig(process.env);
  const logger = createLogger({ service: 'email-worker-crash-child', level: 'silent' });
  const prisma = new PrismaClient({ datasourceUrl: env('DATABASE_URL') });
  const s3 = new S3Service(s3ConfigSchema.parse(process.env));
  const metrics = new MimeMetrics(new MetricsService({ service: 'email-worker-crash-child' }));
  const service = createMimeIngestionService({
    config,
    prisma,
    s3,
    metrics,
    logger,
    consumer: env('IT_CONSUMER'),
  });
  if (crashAt === 'before-finalize') {
    // Test-only interception of the final transaction (not production code).
    const store = (service as unknown as { options: { store: MimeStore } }).options.store;
    store.finalize = () => {
      send('crash-point');
      return hang();
    };
  }
  const connection = new AmqpConnection({
    urls: [env('IT_AMQP_URL')],
    connectionName: 'email-worker',
    logger,
    reconnect: { baseMs: 50, maxMs: 500 },
  });
  const publisher = new ConfirmPublisher({
    connection,
    logger,
    appId: 'email-worker',
    confirmTimeoutMs: 15_000,
    maxMessageBytes: 131_072,
  });
  const consumer = createMimeConsumer({
    config,
    connection,
    publisher,
    logger,
    consumer: env('IT_CONSUMER'),
  });
  consumer.start(async (event) => {
    const outcome = await service.handle(event);
    if (crashAt === 'after-commit') {
      send(`crash-point:${outcome}`);
      return hang();
    }
    return outcome;
  });
  connection.start();
  await connection.waitUntilConnected(15_000);
  send('ready');
}

main().catch((error: unknown) => {
  process.stderr.write(`crash child failed: ${(error as Error).name}\n`);
  process.exit(1);
});
