/**
 * `pnpm --filter @email-gateway/portal-e2e seed | seed:clean`. Prints counts only (never
 * credentials; they are in the git-ignored .auth/state.json).
 */
import { loadEnv } from '../support/env';
import { clean, seed } from './seed';

async function main(): Promise<void> {
  loadEnv();
  const command = process.argv[2] ?? 'seed';
  if (command === 'clean') {
    const removed = await clean();
    process.stdout.write(`portal-e2e: removed ${JSON.stringify(removed)}\n`);
    return;
  }
  if (command !== 'seed') throw new Error(`unknown command ${command} (seed | clean)`);
  const summary = await seed();
  process.stdout.write(`portal-e2e: seeded ${JSON.stringify(summary)}\n`);
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
