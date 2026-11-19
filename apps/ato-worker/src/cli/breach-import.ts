import { readFile } from 'node:fs/promises';
import { sha256Hex } from '@email-gateway/ato-detection';
import { Prisma, PrismaClient } from '@email-gateway/database';

/**
 * Breach-intelligence importer (step 8.4 D7, ADR-0074): loads an operator-provided file of e-mail
 * addresses (one per line, `#` comments) as platform `threat_indicators` of type `email`
 * (`source = 'feed:<name>'`, `organization_id` NULL, `category = 'other'`), keeping **only**
 * addresses whose domain is an active tenant domain. Prints counts only (never an address) and
 * writes one `audit_logs` row (`threat_intel.breach_imported`, counts only). No third-party breach
 * API is called and no password is ever involved. Rule T4 reads these rows by SHA-256 of the
 * account address.
 *
 *   pnpm --filter @email-gateway/ato-worker breach:import -- --source <name> --file <path>
 *     [--severity low|medium|high|critical] [--expires-days 1..3650]
 */

export const BREACH_SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;
export type BreachSeverity = (typeof BREACH_SEVERITIES)[number];

export interface BreachImportOptions {
  source: string;
  file: string;
  severity: BreachSeverity;
  expiresDays: number;
}

export interface BreachImportCounts {
  read: number;
  invalid: number;
  outsideTenantDomains: number;
  duplicatesInFile: number;
  imported: number;
  updated: number;
}

const SOURCE = /^[a-z0-9][a-z0-9_.-]{0,57}$/;
const ADDRESS =
  /^[^\s@<>"',;]{1,64}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const BATCH = 500;
/** Confidence of an operator-loaded breach list (0–100; T4 is a weak signal regardless). */
const CONFIDENCE = 70;

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

/** Parses `--source <name> --file <path> [--severity s] [--expires-days n]`. */
export function parseBreachImportArgs(argv: readonly string[]): BreachImportOptions {
  const args = argv.filter((a) => a !== '--');
  const values = new Map<string, string>();
  for (let i = 0; i < args.length; i++) {
    const key = args[i]!;
    if (!key.startsWith('--')) throw new UsageError(`unexpected argument at position ${i + 1}`);
    const value = args[i + 1];
    if (value === undefined || value.startsWith('--')) throw new UsageError(`${key} needs a value`);
    if (!['--source', '--file', '--severity', '--expires-days'].includes(key)) {
      throw new UsageError(`unknown option ${key}`);
    }
    values.set(key, value);
    i += 1;
  }
  const source = values.get('--source');
  const file = values.get('--file');
  if (!source || !SOURCE.test(source)) {
    throw new UsageError('--source must be 1-58 characters of a-z, 0-9, _, . and -');
  }
  if (!file) throw new UsageError('--file is required');
  const severity = (values.get('--severity') ?? 'medium') as BreachSeverity;
  if (!BREACH_SEVERITIES.includes(severity)) {
    throw new UsageError('--severity must be low, medium, high or critical');
  }
  const expiresDays = Number(values.get('--expires-days') ?? 365);
  if (!Number.isInteger(expiresDays) || expiresDays < 1 || expiresDays > 3650) {
    throw new UsageError('--expires-days must be an integer 1-3650');
  }
  return { source, file, severity, expiresDays };
}

/** Normalized addresses of a file's text plus the counts of rejected lines. */
export function parseAddresses(text: string): {
  addresses: string[];
  read: number;
  invalid: number;
  duplicates: number;
} {
  const seen = new Set<string>();
  let read = 0;
  let invalid = 0;
  let duplicates = 0;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    read += 1;
    const address = line.toLowerCase();
    if (address.length > 320 || !ADDRESS.test(address)) {
      invalid += 1;
      continue;
    }
    if (seen.has(address)) {
      duplicates += 1;
      continue;
    }
    seen.add(address);
  }
  return { addresses: [...seen], read, invalid, duplicates };
}

/** Lower-cased names of active tenant domains (customer organizations, not deleted). */
export async function activeTenantDomains(prisma: PrismaClient): Promise<Set<string>> {
  const rows = await prisma.$queryRaw<Array<{ name: string | null }>>`
    SELECT LOWER(COALESCE(d.live_name, d.verified_name, d.name)) AS name
    FROM domains d JOIN organizations o ON o.id = d.organization_id
    WHERE d.status = 'active' AND d.deleted_at IS NULL AND o.status = 'active'`;
  return new Set(rows.flatMap((r) => (r.name ? [r.name] : [])));
}

export async function runBreachImport(
  prisma: PrismaClient,
  options: BreachImportOptions,
  now: Date = new Date(),
): Promise<BreachImportCounts> {
  const text = await readFile(options.file, 'utf8');
  const parsed = parseAddresses(text);
  const domains = await activeTenantDomains(prisma);
  const kept = parsed.addresses.filter((a) => domains.has(a.slice(a.lastIndexOf('@') + 1)));
  const source = `feed:${options.source}`;
  const expiresAt = new Date(now.getTime() + options.expiresDays * 86_400_000);
  let imported = 0;
  let updated = 0;
  for (let i = 0; i < kept.length; i += BATCH) {
    const chunk = kept.slice(i, i + BATCH).map((a) => ({ value: a, hash: sha256Hex(a) }));
    const existing = await prisma.threatIndicator.findMany({
      where: {
        orgScope: 0n,
        source,
        indicatorType: 'email',
        valueSha256: { in: chunk.map((c) => c.hash) },
      },
      select: { valueSha256: true },
    });
    const known = new Set(existing.map((e) => e.valueSha256));
    updated += chunk.filter((c) => known.has(c.hash)).length;
    imported += chunk.filter((c) => !known.has(c.hash)).length;
    const rows = chunk.map(
      (c) => Prisma.sql`(NULL, 'email', ${c.value}, ${c.hash}, ${source}, ${options.severity},
        ${CONFIDENCE}, ${now}, ${now}, ${expiresAt}, 'other', ${now}, ${now})`,
    );
    await prisma.$executeRaw`
      INSERT INTO threat_indicators
        (organization_id, indicator_type, value, value_sha256, source, severity, confidence,
         first_seen_at, last_seen_at, expires_at, category, created_at, updated_at)
      VALUES ${Prisma.join(rows)}
      ON DUPLICATE KEY UPDATE
        last_seen_at = VALUES(last_seen_at), expires_at = VALUES(expires_at),
        severity = VALUES(severity), updated_at = VALUES(updated_at)`;
  }
  const counts: BreachImportCounts = {
    read: parsed.read,
    invalid: parsed.invalid,
    outsideTenantDomains: parsed.addresses.length - kept.length,
    duplicatesInFile: parsed.duplicates,
    imported,
    updated,
  };
  await prisma.auditLog.create({
    data: {
      organizationId: null,
      actorType: 'system',
      actorId: null,
      action: 'threat_intel.breach_imported',
      resourceType: 'threat_indicator',
      resourceId: source.slice(0, 64),
      metadata: { ...counts, severity: options.severity, expiresDays: options.expiresDays },
    },
    select: { id: true },
  });
  return counts;
}

async function main(): Promise<void> {
  let options: BreachImportOptions;
  try {
    options = parseBreachImportArgs(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`breach:import: ${(error as Error).message}\n`);
    process.exitCode = 2;
    return;
  }
  const url = process.env.DATABASE_URL;
  if (!url) {
    process.stderr.write('breach:import: DATABASE_URL must be set\n');
    process.exitCode = 2;
    return;
  }
  const prisma = new PrismaClient({ datasourceUrl: url });
  try {
    const counts = await runBreachImport(prisma, options);
    process.stdout.write(`${JSON.stringify({ source: `feed:${options.source}`, ...counts })}\n`);
  } catch (error) {
    const code = (error as { code?: unknown }).code;
    process.stderr.write(
      `breach:import failed (${typeof code === 'string' ? code : (error as Error).name})\n`,
    );
    process.exitCode = 1;
  } finally {
    await prisma.$disconnect();
  }
}

if (require.main === module) void main();
