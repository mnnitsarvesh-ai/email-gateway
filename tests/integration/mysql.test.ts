import { randomUUID } from 'node:crypto';
import { PrismaClient, processOnce } from '@email-gateway/database';
import { createConnection } from 'mysql2/promise';
import { afterAll, describe, expect, it } from 'vitest';
import { stack } from './support/env';

const prisma = new PrismaClient({ datasourceUrl: stack.databaseUrl() });

afterAll(async () => {
  await prisma.$disconnect();
});

describe('MySQL', () => {
  it('runs MySQL 8.4 with UTC and READ-COMMITTED', async () => {
    const [row] = await prisma.$queryRaw<{ version: string; tz: string; iso: string }[]>`
      SELECT VERSION() AS version, @@global.time_zone AS tz, @@transaction_isolation AS iso`;
    expect(row?.version).toMatch(/^8\.4\./);
    expect(row?.tz).toBe('+00:00');
    expect(row?.iso).toBe('READ-COMMITTED');
  });

  it('has every migration applied', async () => {
    const rows = await prisma.$queryRaw<{ migration_name: string; finished_at: Date | null }[]>`
      SELECT migration_name, finished_at FROM _prisma_migrations`;
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.every((r) => r.finished_at !== null)).toBe(true);
  });

  it('gives the runtime account DML but not DDL privileges', async () => {
    const conn = await createConnection(stack.databaseUrl());
    try {
      await expect(
        conn.query('CREATE TABLE should_not_exist (id INT PRIMARY KEY)'),
      ).rejects.toThrow(/denied/i);
    } finally {
      await conn.end();
    }
  });

  it('processOnce applies an event exactly once and rolls back on failure', async () => {
    const consumer = 'integration-test';
    const eventId = randomUUID();
    const slug = `it-${eventId.slice(0, 8)}`;
    const createTenant = () =>
      processOnce(prisma, consumer, eventId, (tx) =>
        tx.tenant.create({ data: { slug, name: 'Integration' } }),
      );

    try {
      expect((await createTenant()).status).toBe('processed');
      expect((await createTenant()).status).toBe('duplicate');
      expect(await prisma.tenant.count({ where: { slug } })).toBe(1);

      const failingId = randomUUID();
      await expect(
        processOnce(prisma, consumer, failingId, () => Promise.reject(new Error('handler failed'))),
      ).rejects.toThrow('handler failed');
      expect(await prisma.processedEvent.count({ where: { consumer, eventId: failingId } })).toBe(
        0,
      );
    } finally {
      await prisma.tenant.deleteMany({ where: { slug } });
      await prisma.processedEvent.deleteMany({ where: { consumer } });
    }
  });
});
