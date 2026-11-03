/**
 * One-shot DKIM signing-key sync (step 2.2 D12, ADR-0020): runs one reconciliation of
 * redis-dkim against MySQL and prints the counts. Used by operators (for example right after a
 * redis-dkim restart) and by tests. Never prints keys, selectors or domain names.
 *
 *   pnpm --filter @email-gateway/api build
 *   pnpm --filter @email-gateway/api dkim:sync
 */
import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../../../app.module';
import { loadApiConfig } from '../../../config';
import { DkimSigningPublisher } from '../services/dkim-signing-publisher.service';
import { DkimSigningDisabledError } from '../signing/dkim-key-store';

async function main(): Promise<number> {
  // No timers: the CLI runs exactly one reconciliation and exits.
  const config = loadApiConfig({
    ...process.env,
    AUTH_BACKGROUND_JOBS_ENABLED: 'false',
    DOMAIN_BACKGROUND_JOBS_ENABLED: 'false',
    DKIM_SIGNING_SYNC_ENABLED: 'false',
  });
  const app = await NestFactory.createApplicationContext(AppModule.forRoot(config), {
    logger: ['error', 'warn'],
  });
  try {
    const counts = await app.get(DkimSigningPublisher).reconcile();
    process.stdout.write(
      `published=${counts.published} removed=${counts.removed} unchanged=${counts.unchanged} ` +
        `skipped=${counts.skipped} pruned=${counts.pruned}\n`,
    );
    return 0;
  } catch (err) {
    if (err instanceof DkimSigningDisabledError) {
      process.stderr.write(`${err.message}\n`);
      return 2;
    }
    throw err;
  } finally {
    await app.close();
  }
}

main().then(
  (code) => process.exit(code),
  (err: unknown) => {
    process.stderr.write(
      `DKIM sync failed: ${err instanceof Error ? err.message : 'unknown error'}\n`,
    );
    process.exit(1);
  },
);
