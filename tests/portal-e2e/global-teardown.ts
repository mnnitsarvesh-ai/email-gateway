/**
 * Global teardown: removes the run's synthetic tenants, the e2e platform user and their MinIO
 * objects (seed/cleanup.ts) and the state file with the generated passwords, so the shared local
 * database looks as before the run (other suites count platform users, e.g. tests/integration
 * seed.test.ts). `E2E_KEEP_DATA=1` keeps everything for debugging.
 */
import { rmSync } from 'node:fs';
import { clean } from './seed/seed';
import { loadEnv } from './support/env';
import { STATE_FILE } from './support/state';

export default async function globalTeardown(): Promise<void> {
  loadEnv();
  if (process.env.E2E_KEEP_DATA === '1') {
    process.stdout.write('portal-e2e teardown: E2E_KEEP_DATA=1, seeded data kept\n');
    return;
  }
  const removed = await clean();
  rmSync(STATE_FILE, { force: true });
  process.stdout.write(
    `portal-e2e teardown: removed ${removed.organizations} organizations, ` +
      `${removed.platformUsers} platform users, ${removed.objects} objects\n`,
  );
}
