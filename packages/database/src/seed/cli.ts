#!/usr/bin/env node
/**
 * Seed CLI (D7). Uses DATABASE_URL (the DML account).
 *
 *   node dist/seed/cli.js                                      catalog + demo (local/dev/CI)
 *   node dist/seed/cli.js --catalog-only                       catalog only
 *   node dist/seed/cli.js --catalog-only --allow-production    the only form allowed in
 *                                                              staging/production
 */
import { baseConfigSchema, databaseConfigSchema, loadConfig } from '@email-gateway/config';
import { createLogger } from '@email-gateway/logger';
import { PrismaClient } from '@prisma/client';
import { formatId } from '../ids';
import { parseArgs } from '../partitioning/config';
import { decideSeed } from './guard';
import { seedCatalog, seedDemo } from './seed';

const USAGE = 'usage: seed [--catalog-only] [--allow-production]';

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2), [], ['catalog-only', 'allow-production', 'help']);
  if (args.flags.has('help')) {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }
  if (args.positionals.length > 0) {
    process.stderr.write(`${USAGE}\n`);
    return 2;
  }
  const config = loadConfig(baseConfigSchema.extend(databaseConfigSchema.shape));
  const logger = createLogger({
    service: 'db-seed',
    level: config.LOG_LEVEL,
    version: config.SERVICE_VERSION,
  });

  const decision = decideSeed({
    appEnv: config.APP_ENV,
    nodeEnv: config.NODE_ENV,
    catalogOnly: args.flags.has('catalog-only'),
    allowProduction: args.flags.has('allow-production'),
  });
  if (!decision.allowed) {
    logger.error({ appEnv: config.APP_ENV, nodeEnv: config.NODE_ENV }, decision.reason);
    return 1;
  }

  const prisma = new PrismaClient({ datasourceUrl: config.DATABASE_URL });
  try {
    const catalog = await seedCatalog(prisma);
    logger.info(catalog, 'catalog seeded');
    if (decision.demo) {
      const demo = await seedDemo(prisma, { environment: config.APP_ENV });
      logger.info(
        {
          organizationId: formatId(demo.organizationId),
          platformOrganizationId: formatId(demo.platformOrganizationId),
          domainId: formatId(demo.domainId),
          users: demo.userIds.map(formatId),
          policyId: formatId(demo.policyId),
        },
        'demo data seeded',
      );
    }
    return 0;
  } catch (err) {
    logger.error({ err: err instanceof Error ? err.message : String(err) }, 'seed failed');
    return 1;
  } finally {
    await prisma.$disconnect();
  }
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  },
);
