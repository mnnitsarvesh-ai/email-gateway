import { baseConfigSchema } from '@email-gateway/config';
import { z } from 'zod';

const mysqlUrl = (key: string) =>
  z.string().startsWith('mysql://', `${key} must be a mysql:// URL`);

/**
 * Config for the database maintenance CLIs that need DDL (partition maintenance, perf
 * harness). MIGRATION_DATABASE_URL may come from MIGRATION_DATABASE_URL_FILE (Kubernetes).
 */
export const maintenanceConfigSchema = baseConfigSchema.extend({
  MIGRATION_DATABASE_URL: mysqlUrl('MIGRATION_DATABASE_URL'),
});

export type MaintenanceConfig = z.infer<typeof maintenanceConfigSchema>;

/** Minimal argv parser: positional command plus `--flag value` and boolean `--flag` options. */
export function parseArgs(
  argv: readonly string[],
  valueFlags: readonly string[],
  booleanFlags: readonly string[],
): { positionals: string[]; values: Record<string, string>; flags: Set<string> } {
  const positionals: string[] = [];
  const values: Record<string, string> = {};
  const flags = new Set<string>();
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === '--') continue;
    if (!arg.startsWith('--')) {
      positionals.push(arg);
      continue;
    }
    const [name, inline] = arg.slice(2).split('=', 2) as [string, string | undefined];
    if (booleanFlags.includes(name)) {
      if (inline !== undefined) throw new Error(`--${name} does not take a value`);
      flags.add(name);
    } else if (valueFlags.includes(name)) {
      const value = inline ?? argv[++i];
      if (value === undefined || value.startsWith('--')) {
        throw new Error(`--${name} requires a value`);
      }
      values[name] = value;
    } else {
      throw new Error(`Unknown option --${name}`);
    }
  }
  return { positionals, values, flags };
}

/** Parses an ISO-8601 instant; throws a readable error otherwise. */
export function parseInstant(value: string, flag: string): Date {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error(`${flag}: invalid ISO date ${value}`);
  return date;
}

/** Parses a YYYY-MM-DD date as 00:00 UTC. */
export function parseDay(value: string, flag: string): Date {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!match) throw new Error(`${flag}: expected YYYY-MM-DD, got ${value}`);
  const [y, m, d] = [Number(match[1]), Number(match[2]), Number(match[3])];
  const date = new Date(Date.UTC(y, m - 1, d));
  if (date.getUTCMonth() !== m - 1 || date.getUTCDate() !== d) {
    throw new Error(`${flag}: invalid date ${value}`);
  }
  return date;
}
