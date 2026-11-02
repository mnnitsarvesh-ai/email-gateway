/**
 * Migration-history preflight. Runs before `prisma migrate deploy` (pnpm db:migrate, Compose
 * db-migrate) so a database that still records a retired migration fails with an explanation
 * instead of Prisma's P3018 on the first CREATE TABLE.
 *
 * Phase 0 shipped `20261101000000_init` (7 tables). Step 1.1 replaced it with
 * `20261101000000_baseline` (the full data model) instead of altering it, because nothing
 * outside local development had applied it. A local schema created in phase 0 must be reset
 * once (docs/runbooks/local-stack.md, "Upgrading from the phase-0 init migration").
 */

/** Migrations that were deleted from the repository and cannot be upgraded in place. */
export const RETIRED_MIGRATIONS: Readonly<Record<string, string>> = Object.freeze({
  '20261101000000_init': 'phase-0 schema, replaced by 20261101000000_baseline in step 1.1',
});

export interface HistoryCheck {
  ok: boolean;
  /** Applied migrations that were retired (fatal). */
  retired: string[];
  /** Applied migrations unknown to this checkout, not retired (warning: newer code ran here). */
  unknown: string[];
  message: string;
}

export const RESET_HINT =
  'This is a local schema created before step 1.1. Reset it once, as the migrator account, ' +
  'with `pnpm db:reset:local` (prisma migrate reset + partitions + seed; refuses to run when ' +
  'APP_ENV is staging/production). It drops and recreates the tables of the gateway schema ' +
  'only, not the Docker volume. See docs/runbooks/local-stack.md.';

export function checkMigrationHistory(
  applied: readonly string[],
  local: readonly string[],
): HistoryCheck {
  const localSet = new Set(local);
  const notLocal = [...new Set(applied)].filter((name) => !localSet.has(name)).sort();
  const retired = notLocal.filter((name) => name in RETIRED_MIGRATIONS);
  const unknown = notLocal.filter((name) => !(name in RETIRED_MIGRATIONS));
  if (retired.length > 0) {
    const details = retired.map((name) => `${name} (${RETIRED_MIGRATIONS[name]})`).join(', ');
    return {
      ok: false,
      retired,
      unknown,
      message: `The database records retired migration(s): ${details}. ${RESET_HINT}`,
    };
  }
  return {
    ok: true,
    retired,
    unknown,
    message:
      unknown.length > 0
        ? `The database records migration(s) this checkout does not have: ${unknown.join(', ')}. ` +
          'A newer release has migrated it; deploy that release instead of this one.'
        : 'migration history is compatible',
  };
}
