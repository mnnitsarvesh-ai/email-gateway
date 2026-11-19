import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { baseConfigSchema, databaseConfigSchema, loadConfig } from '@email-gateway/config';
import { PrismaClient } from '@email-gateway/database';
import {
  EgressImportError,
  INTEGRATION_PROVIDERS,
  type IntegrationProvider,
} from '@email-gateway/provider-integrations';
import { importEgressRanges } from '../egress/egress-importer';

export const USAGE = `Usage: node dist/cli/egress-import.js --provider <microsoft_365|google_workspace>
  --file <import.json> --source <url> --published-at <ISO 8601> --operator <name> [--force] [--dry-run]

Imports a provider egress range set (docs/deployment/provider-integrations.md#egress-ranges).
The file is { "schema": "provider-egress-import/1", "provider": "...", "cidrs": ["..."] }.`;

export interface CliArgs {
  provider: IntegrationProvider;
  file: string;
  source: string;
  publishedAt: Date;
  operator: string;
  force: boolean;
  dryRun: boolean;
}

/** Parses the command line; throws EgressImportError with the usage on a missing option. */
export function parseCliArgs(argv: readonly string[]): CliArgs {
  const { values } = parseArgs({
    args: [...argv],
    options: {
      provider: { type: 'string' },
      file: { type: 'string' },
      source: { type: 'string' },
      'published-at': { type: 'string' },
      operator: { type: 'string' },
      force: { type: 'boolean', default: false },
      'dry-run': { type: 'boolean', default: false },
    },
    strict: true,
    allowPositionals: false,
  });
  const provider = values.provider;
  if (!provider || !(INTEGRATION_PROVIDERS as readonly string[]).includes(provider)) {
    throw new EgressImportError(`--provider must be microsoft_365 or google_workspace\n${USAGE}`);
  }
  for (const key of ['file', 'source', 'published-at', 'operator'] as const) {
    if (!values[key]) throw new EgressImportError(`--${key} is required\n${USAGE}`);
  }
  const publishedAt = new Date(values['published-at']!);
  if (Number.isNaN(publishedAt.getTime()) || !/^\d{4}-\d{2}-\d{2}/.test(values['published-at']!)) {
    throw new EgressImportError('--published-at must be an ISO 8601 date');
  }
  return {
    provider: provider as IntegrationProvider,
    file: values.file!,
    source: values.source!,
    publishedAt,
    operator: values.operator!,
    force: values.force === true,
    dryRun: values['dry-run'] === true,
  };
}

/** Runs the import; returns the process exit code (0 ok, 1 refused/invalid, 2 failure). */
export async function main(
  argv: readonly string[],
  env: NodeJS.ProcessEnv = process.env,
  out: (line: string) => void = (line) => process.stdout.write(`${line}\n`),
  err: (line: string) => void = (line) => process.stderr.write(`${line}\n`),
): Promise<number> {
  let args: CliArgs;
  let document: unknown;
  try {
    args = parseCliArgs(argv);
    try {
      document = JSON.parse(readFileSync(args.file, 'utf8')) as unknown;
    } catch {
      throw new EgressImportError('--file is not readable JSON');
    }
  } catch (error) {
    err(error instanceof Error ? error.message : 'invalid arguments');
    return 1;
  }
  // Only the writer is needed: the CLI loads none of the worker's provider keys.
  const config = loadConfig(baseConfigSchema.extend(databaseConfigSchema.shape), env);
  const prisma = new PrismaClient({ datasourceUrl: config.DATABASE_URL });
  try {
    const result = await importEgressRanges(prisma, {
      provider: args.provider,
      document,
      source: args.source,
      publishedAt: args.publishedAt,
      operator: args.operator,
      force: args.force,
      dryRun: args.dryRun,
    });
    out(JSON.stringify(result));
    return 0;
  } catch (error) {
    if (error instanceof EgressImportError) {
      err(`refused: ${error.message}${error.index !== undefined ? ` (entry ${error.index})` : ''}`);
      return 1;
    }
    err(`failed: ${(error as { name?: string })?.name ?? 'error'}`);
    return 2;
  } finally {
    await prisma.$disconnect();
  }
}

if (require.main === module) {
  void main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
