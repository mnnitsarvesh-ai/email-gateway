import { Logger } from '@nestjs/common';
import type { PrismaClient } from '@email-gateway/database';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { DatabaseReadOptions } from './database.options';
import { PrismaReadService, READER_PROBE_TIMEOUT_MS } from './prisma-read.service';
import type { PrismaService } from './prisma.service';

type Row = Record<string, unknown>;

const URL = 'mysql://reader:NeverLogThis@replica:3306/db';
const writer = { healthName: 'mysql' } as unknown as PrismaService;

const row = (overrides: Row = {}): Row => ({
  Replica_IO_Running: 'Yes',
  Replica_SQL_Running: 'Yes',
  Seconds_Behind_Source: 0,
  ...overrides,
});

/** A replica client whose SHOW REPLICA STATUS answer is set per test. */
function fakeReader() {
  const queryRawUnsafe = vi.fn<(sql: string) => Promise<Row[]>>();
  const disconnect = vi.fn(() => Promise.resolve());
  const client = { $queryRawUnsafe: queryRawUnsafe, $disconnect: disconnect };
  return { client: client as unknown as PrismaClient, queryRawUnsafe, disconnect };
}

function build(options: Partial<DatabaseReadOptions> = {}) {
  const reader = fakeReader();
  const factory = vi.fn((_url: string) => reader.client);
  const service = new PrismaReadService(
    writer,
    { url: URL, maxLagSeconds: 10, lagCheckIntervalMs: 5_000, ...options },
    factory,
  );
  return { service, reader, factory };
}

describe('PrismaReadService', () => {
  let warn: ReturnType<typeof vi.spyOn>;
  let info: ReturnType<typeof vi.spyOn>;
  const services: PrismaReadService[] = [];

  beforeEach(() => {
    warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    info = vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
  });

  afterEach(async () => {
    await Promise.all(services.splice(0).map((s) => s.onModuleDestroy()));
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  const init = async (options: Partial<DatabaseReadOptions> = {}, rows: Row[] = [row()]) => {
    const built = build(options);
    built.reader.queryRawUnsafe.mockResolvedValue(rows);
    services.push(built.service);
    await built.service.onModuleInit();
    return built;
  };

  it('uses the reader when both threads run and lag is within the limit', async () => {
    const { service, reader, factory } = await init({}, [row({ Seconds_Behind_Source: 10 })]);
    expect(factory).toHaveBeenCalledWith(URL);
    expect(reader.queryRawUnsafe).toHaveBeenCalledWith('SHOW REPLICA STATUS');
    expect(service.status()).toMatchObject({ mode: 'reader', lagSeconds: 10, maxLagSeconds: 10 });
    expect(service.status().reason).toBeUndefined();
    expect(service.status().checkedAt).toEqual(expect.any(String));
    expect(service.client).toBe(reader.client);
  });

  it.each([
    ['bigint', 3n, 3],
    ['string', '4', 4],
    ['number', 5, 5],
  ])('normalises a %s lag value', async (_type, raw, expected) => {
    const { service } = await init({}, [row({ Seconds_Behind_Source: raw })]);
    expect(service.status()).toMatchObject({ mode: 'reader', lagSeconds: expected });
  });

  it('falls back to the writer when lag exceeds the limit', async () => {
    const { service } = await init({ maxLagSeconds: 10 }, [row({ Seconds_Behind_Source: 11n })]);
    expect(service.status()).toMatchObject({
      mode: 'writer-fallback',
      lagSeconds: 11,
      reason: 'lag 11s > max 10s',
    });
    expect(service.client).toBe(writer);
  });

  it.each([
    ['IO thread', { Replica_IO_Running: 'Connecting' }],
    ['SQL thread', { Replica_SQL_Running: 'No' }],
  ])('falls back to the writer when the %s is stopped', async (_name, overrides) => {
    const { service } = await init({}, [row({ ...overrides, Seconds_Behind_Source: null })]);
    expect(service.status()).toMatchObject({
      mode: 'writer-fallback',
      lagSeconds: null,
      reason: 'replication stopped',
    });
    expect(service.client).toBe(writer);
  });

  /** The shape Prisma's $queryRawUnsafe really returns for SHOW REPLICA STATUS: f0…f59. */
  const positionalRow = (io: string, sql: string, lag: unknown): Row => {
    const r: Row = Object.fromEntries(Array.from({ length: 60 }, (_, i) => [`f${i}`, '']));
    r.f1 = 'mysql';
    r.f10 = io;
    r.f11 = sql;
    r.f32 = lag;
    return r;
  };

  it('reads positional column keys (f10, f11, f32) as Prisma returns them', async () => {
    const { service, reader } = await init({}, [positionalRow('Yes', 'Yes', 2n)]);
    expect(service.status()).toMatchObject({ mode: 'reader', lagSeconds: 2 });
    expect(service.client).toBe(reader.client);
  });

  it.each([
    ['IO thread', positionalRow('Connecting', 'Yes', null), 'replication stopped'],
    ['SQL thread', positionalRow('Yes', 'No', null), 'replication stopped'],
    ['lag', positionalRow('Yes', 'Yes', 30n), 'lag 30s > max 10s'],
  ])('falls back on positional keys when the %s is unhealthy', async (_name, r, reason) => {
    const { service } = await init({}, [r]);
    expect(service.status()).toMatchObject({ mode: 'writer-fallback', reason });
    expect(service.client).toBe(writer);
  });

  it('falls back to the writer when lag is unknown', async () => {
    const { service } = await init({}, [row({ Seconds_Behind_Source: null })]);
    expect(service.status()).toMatchObject({ mode: 'writer-fallback', reason: 'lag unknown' });
  });

  it('falls back to the writer when the server is not a replica', async () => {
    const { service } = await init({}, []);
    expect(service.status()).toMatchObject({ mode: 'writer-fallback', reason: 'not a replica' });
    expect(service.client).toBe(writer);
  });

  it('falls back to the writer when the probe throws, without failing init or leaking the URL', async () => {
    const { service, reader } = build();
    services.push(service);
    reader.queryRawUnsafe.mockRejectedValue(
      new Error(`Invalid \`prisma.$queryRawUnsafe()\` invocation:\n\n\nCan't reach ${URL}`),
    );
    await expect(service.onModuleInit()).resolves.toBeUndefined();
    const status = service.status();
    expect(status.mode).toBe('writer-fallback');
    expect(status.reason).toMatch(/^reader unreachable: Can't reach \[redacted-url\]$/);
    expect(service.client).toBe(writer);
    const logged = JSON.stringify([...warn.mock.calls, ...info.mock.calls]);
    expect(logged).not.toContain('NeverLogThis');
    expect(logged).not.toContain('mysql://');
  });

  it('falls back to the writer when the probe times out', async () => {
    vi.useFakeTimers();
    const { service, reader } = build();
    services.push(service);
    reader.queryRawUnsafe.mockReturnValue(new Promise(() => {}));
    const initDone = service.onModuleInit();
    await vi.advanceTimersByTimeAsync(READER_PROBE_TIMEOUT_MS);
    await initDone;
    expect(service.status()).toMatchObject({
      mode: 'writer-fallback',
      reason: `reader unreachable: probe timed out after ${READER_PROBE_TIMEOUT_MS}ms`,
    });
  });

  it('recovers to the reader and logs once per transition, not per probe', async () => {
    vi.useFakeTimers();
    const { service, reader } = build({ lagCheckIntervalMs: 1_000 });
    services.push(service);
    reader.queryRawUnsafe.mockResolvedValue([row({ Seconds_Behind_Source: 0 })]);

    await service.onModuleInit();
    expect(service.status().mode).toBe('reader');
    expect(info).toHaveBeenCalledTimes(1);

    // Three lagging probes: one warning.
    reader.queryRawUnsafe.mockResolvedValue([row({ Seconds_Behind_Source: 60 })]);
    await vi.advanceTimersByTimeAsync(3_000);
    expect(reader.queryRawUnsafe).toHaveBeenCalledTimes(4);
    expect(service.status().mode).toBe('writer-fallback');
    expect(service.client).toBe(writer);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0]?.[0]).toContain('lag 60s > max 10s');

    // Reason changes inside writer-fallback: still no new warning.
    reader.queryRawUnsafe.mockResolvedValue([row({ Replica_SQL_Running: 'No' })]);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(service.status().reason).toBe('replication stopped');
    expect(warn).toHaveBeenCalledTimes(1);

    // Recovery: one info, then quiet.
    reader.queryRawUnsafe.mockResolvedValue([row({ Seconds_Behind_Source: 1 })]);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(service.status()).toMatchObject({ mode: 'reader', lagSeconds: 1 });
    expect(service.client).toBe(reader.client);
    expect(info).toHaveBeenCalledTimes(2);
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it('stops probing and disconnects the reader on destroy', async () => {
    vi.useFakeTimers();
    const { service, reader } = await init({ lagCheckIntervalMs: 1_000 });
    await service.onModuleDestroy();
    await vi.advanceTimersByTimeAsync(5_000);
    expect(reader.queryRawUnsafe).toHaveBeenCalledTimes(1);
    expect(reader.disconnect).toHaveBeenCalledTimes(1);
  });

  it('checkHealth probes afresh and resolves with details in every mode', async () => {
    const { service, reader } = await init({}, [row({ Seconds_Behind_Source: 2 })]);
    await expect(service.checkHealth()).resolves.toEqual({
      mode: 'reader',
      lagSeconds: 2,
      maxLagSeconds: 10,
    });

    reader.queryRawUnsafe.mockRejectedValue(new Error('connection refused'));
    await expect(service.checkHealth()).resolves.toEqual({
      mode: 'writer-fallback',
      lagSeconds: null,
      maxLagSeconds: 10,
      reason: 'reader unreachable: connection refused',
    });
    expect(reader.queryRawUnsafe).toHaveBeenCalledTimes(3);
  });

  it('shares one probe between concurrent callers', async () => {
    const { service, reader } = await init();
    reader.queryRawUnsafe.mockClear();
    await Promise.all([service.checkHealth(), service.checkHealth(), service.probe()]);
    expect(reader.queryRawUnsafe).toHaveBeenCalledTimes(1);
  });

  it('is writer-only without a reader URL, logging that once', async () => {
    const { service, factory } = build({ url: undefined });
    services.push(service);
    await service.onModuleInit();
    expect(factory).not.toHaveBeenCalled();
    expect(service.client).toBe(writer);
    expect(service.status()).toEqual({ mode: 'writer-only', lagSeconds: null, maxLagSeconds: 10 });
    await expect(service.checkHealth()).resolves.toEqual({
      mode: 'writer-only',
      lagSeconds: null,
      maxLagSeconds: 10,
    });
    expect(info).toHaveBeenCalledTimes(1);
    expect(warn).not.toHaveBeenCalled();
  });
});
