/**
 * Bootstrap CLI (design D10 "Initial access"): invites the first platform super admin and prints
 * the acceptance link to stdout. Operator-run; the link is never written to a log.
 *
 *   pnpm --filter @email-gateway/api build
 *   pnpm --filter @email-gateway/api auth:bootstrap -- --email ops@example.com [--display-name "Ops"] [--additional]
 */
import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../../../app.module';
import { loadApiConfig } from '../../../config';
import { BootstrapRefusedError, BootstrapAdminService } from '../services/bootstrap-admin.service';
import { BootstrapUsageError, parseBootstrapArgs } from './bootstrap-args';

async function main(argv: readonly string[]): Promise<number> {
  let args;
  try {
    args = parseBootstrapArgs(argv);
  } catch (err) {
    if (err instanceof BootstrapUsageError) {
      process.stderr.write(`${err.message}\n`);
      return 2;
    }
    throw err;
  }

  // Background jobs off: the CLI must not start the hourly purge.
  const config = loadApiConfig({ ...process.env, AUTH_BACKGROUND_JOBS_ENABLED: 'false' });
  const app = await NestFactory.createApplicationContext(AppModule.forRoot(config), {
    logger: ['error', 'warn'],
  });
  try {
    const result = await app.get(BootstrapAdminService).invite(args);
    process.stdout.write(
      [
        result.reused
          ? 'Re-issued the invitation of the existing invited platform user.'
          : 'Invited a new platform super admin.',
        `User: ${result.userPublicId}`,
        `Expires: ${result.expiresAt.toISOString()}`,
        'Open this link to set the password (single use; MFA enrollment follows at first login):',
        result.link,
        '',
      ].join('\n'),
    );
    return 0;
  } catch (err) {
    if (err instanceof BootstrapRefusedError) {
      process.stderr.write(`Refused: ${err.message}\n`);
      return 1;
    }
    throw err;
  } finally {
    await app.close();
  }
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err: unknown) => {
    process.stderr.write(
      `Bootstrap failed: ${err instanceof Error ? err.message : 'unknown error'}\n`,
    );
    process.exit(1);
  },
);
