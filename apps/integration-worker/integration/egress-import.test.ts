import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PrismaClient } from '@email-gateway/database';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { main } from '../src/cli/egress-import';
import { requireEnv } from './support/harness';

/**
 * The operator egress-range import CLI (§10.3, D11) on the writer: validation, the
 * 50 % guard and `--force`, a new active version per import, the no-op for identical data and the
 * platform audit row. Platform data: the provider's sets as they were before are restored after.
 */
const url = requireEnv('DATABASE_URL');
const prisma = new PrismaClient({ datasourceUrl: url });
const provider = 'google_workspace';
const dir = mkdtempSync(join(tmpdir(), 'iw-egress-'));
let before: { id: bigint; status: 'active' | 'superseded' }[] = [];
let startedAt: Date;

const file = (name: string, document: unknown) => {
  const path = join(dir, name);
  writeFileSync(path, JSON.stringify(document));
  return path;
};

const run = async (args: string[]) => {
  const out: string[] = [];
  const err: string[] = [];
  const code = await main(
    args,
    { DATABASE_URL: url, APP_ENV: 'ci' },
    (l) => out.push(l),
    (l) => err.push(l),
  );
  return { code, out, err };
};

const args = (path: string, extra: string[] = []) => [
  '--provider',
  provider,
  '--file',
  path,
  '--source',
  'https://support.google.com/a/answer/10026322',
  '--published-at',
  '2026-11-15T00:00:00Z',
  '--operator',
  'it.operator',
  ...extra,
];

beforeAll(async () => {
  startedAt = new Date(Date.now() - 1_000);
  before = await prisma.providerEgressRangeSet.findMany({
    where: { provider },
    select: { id: true, status: true },
  });
});

afterAll(async () => {
  try {
    const keep = before.map((b) => b.id);
    await prisma.providerEgressRangeSet.deleteMany({ where: { provider, id: { notIn: keep } } });
    for (const set of before) {
      await prisma.providerEgressRangeSet.update({
        where: { id: set.id },
        data: { status: set.status },
      });
    }
    await prisma.auditLog.deleteMany({
      where: {
        organizationId: null,
        action: 'integration.egress_ranges_imported',
        createdAt: { gte: startedAt },
      },
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
    await prisma.$disconnect();
  }
});

describe('egress import CLI', () => {
  it('refuses invalid data without writing (private range, wrong provider)', async () => {
    const before = await prisma.providerEgressRangeSet.count({ where: { provider } });
    const privateRange = await run(args(file('private.json', { provider, cidrs: ['10.0.0.0/8'] })));
    expect(privateRange.code).toBe(1);
    expect(privateRange.err.join('\n')).toMatch(/refused: .*globally reachable/);
    const wrongProvider = await run(
      args(file('other.json', { provider: 'microsoft_365', cidrs: ['40.92.0.0/15'] })),
    );
    expect(wrongProvider.code).toBe(1);
    expect(await prisma.providerEgressRangeSet.count({ where: { provider } })).toBe(before);
  });

  it('imports a new active version, supersedes the previous one and audits it', async () => {
    const result = await run(
      args(
        file('v-next.json', {
          schema: 'provider-egress-import/1',
          provider,
          cidrs: ['209.85.128.0/17', '74.125.0.0/16', '2607:f8b0:4000::/36', '74.125.0.0/16'],
        }),
        ['--force'],
      ),
    );
    expect(result.code).toBe(0);
    const summary = JSON.parse(result.out[0]!) as Record<string, unknown>;
    expect(summary).toMatchObject({
      outcome: 'imported',
      provider,
      rangeCount: 3,
      duplicatesRemoved: 1,
    });
    const active = await prisma.providerEgressRangeSet.findMany({
      where: { provider, status: 'active' },
      include: { ranges: true },
    });
    expect(active).toHaveLength(1);
    expect(active[0]!.version).toBe(summary.version);
    expect(active[0]!.importedBy).toBe('it.operator');
    expect(active[0]!.publishedAt?.toISOString()).toBe('2026-11-15T00:00:00.000Z');
    expect(active[0]!.ranges.map((r) => r.cidr).sort()).toEqual(
      ['209.85.128.0/17', '74.125.0.0/16', '2607:f8b0:4000::/36'].sort(),
    );
    const audit = await prisma.auditLog.findFirstOrThrow({
      where: {
        organizationId: null,
        action: 'integration.egress_ranges_imported',
        createdAt: { gte: startedAt },
      },
      orderBy: { id: 'desc' },
    });
    expect(audit).toMatchObject({ actorType: 'system', resourceType: 'provider_connection' });
    expect(audit.metadata).toMatchObject({ provider, operator: 'it.operator', rangeCount: 3 });
  });

  it('is a no-op for identical data', async () => {
    const result = await run(
      args(
        file('same.json', {
          provider,
          cidrs: ['74.125.0.0/16', '209.85.128.0/17', '2607:f8b0:4000::/36'],
        }),
      ),
    );
    expect(result.code).toBe(0);
    expect(JSON.parse(result.out[0]!)).toMatchObject({ outcome: 'unchanged' });
  });

  it('refuses a set that removes more than 50 % of the active ranges unless --force', async () => {
    const path = file('shrink.json', { provider, cidrs: ['74.125.0.0/16'] });
    const refused = await run(args(path));
    expect(refused.code).toBe(1);
    expect(refused.err.join('\n')).toContain('--force');
    const dry = await run(args(path, ['--force', '--dry-run']));
    expect(JSON.parse(dry.out[0]!)).toMatchObject({ outcome: 'dry_run', removed: 2 });
    const forced = await run(args(path, ['--force']));
    expect(forced.code).toBe(0);
    expect(JSON.parse(forced.out[0]!)).toMatchObject({
      outcome: 'imported',
      rangeCount: 1,
      removed: 2,
    });
  });
});
