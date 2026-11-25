/* eslint-disable @typescript-eslint/require-await -- the fakes implement async interfaces */
import { ProviderAdapterError } from '@email-gateway/ato-detection';
import { MetricsService } from '@email-gateway/common';
import {
  Prisma,
  type AtoProviderIntegration,
  type AtoProviderStream,
} from '@email-gateway/database';
import { ConnectionAccessError, MICROSOFT_ADAPTER_VERSION } from '@email-gateway/idp-adapters';
import { describe, expect, it } from 'vitest';
import { IdpMetrics } from '../metrics/idp-metrics';
import { IdpProbeLoop } from './probe-loop';
import { IdpStreamRunner } from './stream-runner';
import {
  deferDelayMs,
  IDP_PAGE_TX_ATTEMPTS,
  IDP_WRITE_ATTEMPTS,
  isTransientDbFailure,
  retryDelayMs,
  withTransientRetry,
} from './transient';

// Step AI-4 D14: transient database errors of the IdP loops are retried, then deferred by
// 5–60 s, and never count as provider failures. Fakes only (no database, no provider).

const NOW = new Date('2026-11-24T08:00:00.000Z');
const ORG = 910_001n;

const prismaError = (code: string): Error =>
  new Prisma.PrismaClientKnownRequestError(`synthetic ${code}`, {
    code,
    clientVersion: 'test',
  });

interface Call {
  model: string;
  op: string;
  args: unknown;
}

function integrationRow(over: Partial<AtoProviderIntegration> = {}): AtoProviderIntegration {
  return {
    id: 7n,
    organizationId: ORG,
    provider: 'microsoft_entra',
    status: 'active',
    settings: {},
    directoryDomains: ['example.test'],
    healthCheckedAt: new Date(NOW.getTime() - 60_000),
    healthStatus: 'healthy',
    connectorRef: 'conn_synthetic',
    consecutiveFailures: 0,
    lastErrorCode: null,
    ...over,
  } as unknown as AtoProviderIntegration;
}

function streamRow(over: Partial<AtoProviderStream> = {}): AtoProviderStream {
  return {
    id: 70n,
    organizationId: ORG,
    integrationId: 7n,
    stream: 'sign_ins',
    role: 'primary',
    enabled: true,
    status: 'active',
    cursor: null,
    cursorSeq: 0n,
    backfillFrom: null,
    backfillCompletedAt: new Date(NOW.getTime() - 3_600_000),
    consecutiveFailures: 0,
    lastErrorCode: null,
    watermarkAt: null,
    ...over,
  } as unknown as AtoProviderStream;
}

/** The value of one `ato_idp_transient_db_errors_total` series (0 when absent). */
async function transientCount(
  text: () => Promise<string>,
  loop: string,
  outcome: string,
): Promise<number> {
  const re = new RegExp(
    `^ato_idp_transient_db_errors_total\\{loop="${loop}",outcome="${outcome}"[^}]*\\} (\\d+)$`,
    'm',
  );
  return Number(re.exec(await text())?.[1] ?? 0);
}

function metrics(): { idp: IdpMetrics; text: () => Promise<string> } {
  const service = new MetricsService({ service: `ato-transient-${Math.random()}` });
  return { idp: new IdpMetrics(service), text: () => service.registry.metrics() };
}

const silentLogger = () => {
  const warns: Array<Record<string, unknown>> = [];
  const logger = {
    warn: (fields: Record<string, unknown>) => warns.push(fields),
    debug: () => undefined,
    info: () => undefined,
    error: () => undefined,
  };
  return { logger, warns };
};

/** A stream runner over fakes; `once` is the page transaction (processOnce ledger). */
function streamHarness(options: {
  once?: () => Promise<unknown>;
  ingest?: () => Promise<unknown>;
  orgsGet?: () => Promise<unknown>;
  stream?: Partial<AtoProviderStream>;
}) {
  const calls: Call[] = [];
  const sleeps: number[] = [];
  /** Order of provider-context invalidations and adapter reads (step AI-5 D13). */
  const order: string[] = [];
  let onceCalls = 0;
  const stream = streamRow(options.stream);
  const integration = integrationRow();
  const model = (name: string, impl: Record<string, (args: unknown) => unknown>) =>
    new Proxy(
      {},
      {
        get: (_t, op: string) => async (args: unknown) => {
          calls.push({ model: name, op, args });
          return impl[op]?.(args) ?? { count: 1 };
        },
      },
    );
  const prisma = {
    atoProviderStream: model('stream', {
      findMany: () => [{ ...stream }],
      findFirst: () => ({ consecutiveFailures: 0, lastErrorCode: null }),
    }),
    atoProviderIntegration: model('integration', { findMany: () => [integration] }),
  };
  const tx = {
    $queryRaw: async () => [{ id: stream.id }],
    atoProviderStream: { updateMany: async () => ({ count: 1 }) },
  };
  const m = metrics();
  const { logger, warns } = silentLogger();
  const adapter = {
    kind: 'microsoft_entra',
    version: MICROSOFT_ADAPTER_VERSION,
    ingest: async (...args: unknown[]) => {
      order.push('ingest');
      return options.ingest
        ? options.ingest(...(args as []))
        : { events: [], cursor: 'synthetic-cursor-1', hasMore: false };
    },
  };
  const runner = new IdpStreamRunner({
    db: {
      transaction: async (fn: (t: unknown) => Promise<unknown>) => fn(tx),
      once: async () => {
        onceCalls += 1;
        if (options.once) return options.once();
        return { status: 'processed', result: undefined };
      },
    },
    prisma,
    orgs: {
      get:
        options.orgsGet ??
        (async () => ({
          id: ORG,
          exists: true,
          active: true,
          featureEnabled: true,
          mode: 'enforce',
        })),
    },
    registry: { adapterFor: () => adapter },
    metrics: null,
    idpMetrics: m.idp,
    seen: { mget: async () => [], set: async () => 'OK' },
    providers: {
      invalidate: (organizationId?: bigint) => {
        order.push(`invalidate:${String(organizationId)}`);
      },
    },
    logger,
    now: () => NOW,
    config: {
      claimBatch: 10,
      maxPagesPerPoll: 3,
      maxConsecutiveFailures: 10,
      defaultPollIntervalSeconds: 60,
      historicalSignalAgeHours: 72,
    },
    retrySleep: async (ms: number) => {
      sleeps.push(ms);
    },
  } as unknown as ConstructorParameters<typeof IdpStreamRunner>[0]);
  return {
    runner,
    calls,
    sleeps,
    order,
    warns,
    metricsText: m.text,
    onceCalls: () => onceCalls,
    streamWrites: () =>
      calls.filter((c) => c.model === 'stream' && c.op === 'updateMany') as Array<
        Call & { args: { data: Record<string, unknown> } }
      >,
    integrationWrites: () => calls.filter((c) => c.model === 'integration' && c.op !== 'findMany'),
  };
}

function expectDeferred(h: ReturnType<typeof streamHarness>): void {
  const writes = h.streamWrites();
  expect(writes).toHaveLength(1);
  const data = writes[0]!.args.data;
  // Only the next poll moves: counters, error code and throttling stay as they were.
  expect(Object.keys(data)).toEqual(['nextPollAt']);
  const delay = (data.nextPollAt as Date).getTime() - NOW.getTime();
  expect(delay).toBeGreaterThanOrEqual(5_000);
  expect(delay).toBeLessThanOrEqual(60_000);
  // No integration aggregate, no probe trigger (next_health_at), no worst-stream read.
  expect(h.integrationWrites()).toEqual([]);
  expect(h.calls.some((c) => c.op === 'findFirst')).toBe(false);
}

describe('isTransientDbFailure (D14)', () => {
  it('accepts the transient Prisma and MySQL codes and lock conflicts', () => {
    for (const code of ['P1001', 'P1017', 'P2024', 'P2028', 'P2034']) {
      expect(isTransientDbFailure(prismaError(code))).toBe(true);
    }
    const deadlock = new Prisma.PrismaClientKnownRequestError('raw', {
      code: 'P2010',
      clientVersion: 'test',
      meta: { code: '1213' },
    });
    expect(isTransientDbFailure(deadlock)).toBe(true);
  });

  it('refuses data errors and provider errors', () => {
    expect(isTransientDbFailure(prismaError('P2002'))).toBe(false);
    expect(isTransientDbFailure(new ProviderAdapterError('server_error', true))).toBe(false);
    expect(isTransientDbFailure(new ConnectionAccessError('provider_unavailable'))).toBe(false);
    expect(isTransientDbFailure(new Error('boom'))).toBe(false);
  });

  it('inside an adapter call, counts only database errors (a provider timeout stays a provider failure)', () => {
    const timeout = new DOMException('synthetic', 'TimeoutError');
    expect(isTransientDbFailure(timeout)).toBe(true);
    expect(isTransientDbFailure(timeout, 'adapter')).toBe(false);
    expect(
      isTransientDbFailure(Object.assign(new Error('x'), { code: 'ECONNRESET' }), 'adapter'),
    ).toBe(false);
    expect(isTransientDbFailure(prismaError('P2024'), 'adapter')).toBe(true);
  });

  it('bounds the retry back-off (200 ms × 2^(n−1), ≤ 5 s) and the deferral (5–60 s)', () => {
    expect(retryDelayMs(1, () => 0.999)).toBeLessThanOrEqual(200);
    expect(retryDelayMs(1, () => 0)).toBe(100);
    expect(retryDelayMs(10, () => 0.999)).toBeLessThanOrEqual(5_000);
    for (const k of [1, 2, 3, 4, 5, 10, 100]) {
      for (const r of [0, 0.5, 0.999]) {
        const d = deferDelayMs(k, () => r);
        expect(d).toBeGreaterThanOrEqual(5_000);
        expect(d).toBeLessThanOrEqual(60_000);
      }
    }
    expect(deferDelayMs(20, () => 0.999)).toBeGreaterThan(55_000);
  });

  it('withTransientRetry retries transient errors only, up to the attempt budget', async () => {
    let n = 0;
    const sleeps: number[] = [];
    await expect(
      withTransientRetry(
        async () => {
          n += 1;
          throw prismaError('P2024');
        },
        { attempts: 3, sleep: async (ms) => void sleeps.push(ms) },
      ),
    ).rejects.toMatchObject({ code: 'P2024' });
    expect(n).toBe(3);
    expect(sleeps).toHaveLength(2);
    n = 0;
    await expect(
      withTransientRetry(
        async () => {
          n += 1;
          throw prismaError('P2002');
        },
        { attempts: 3, sleep: async () => undefined },
      ),
    ).rejects.toMatchObject({ code: 'P2002' });
    expect(n).toBe(1);
    n = 0;
    await expect(
      withTransientRetry(
        async () => {
          n += 1;
          if (n < 2) throw prismaError('P1001');
          return 'ok';
        },
        { attempts: 3, sleep: async () => undefined },
      ),
    ).resolves.toBe('ok');
  });
});

describe('IdpStreamRunner: transient database errors (D14)', () => {
  it.each(['P2024', 'P1001', 'P1017'])(
    'retries a page transaction failing with %s, then defers 5–60 s without counting a failure',
    async (code) => {
      const h = streamHarness({
        once: async () => {
          throw prismaError(code);
        },
      });
      await h.runner.runOnce();
      expect(h.onceCalls()).toBe(IDP_PAGE_TX_ATTEMPTS);
      expect(h.sleeps).toHaveLength(IDP_PAGE_TX_ATTEMPTS - 1);
      for (const [i, ms] of h.sleeps.entries()) {
        expect(ms).toBeLessThanOrEqual(Math.min(5_000, 200 * 2 ** i));
      }
      expectDeferred(h);
      expect(await transientCount(h.metricsText, 'stream', 'retried')).toBe(
        IDP_PAGE_TX_ATTEMPTS - 1,
      );
      expect(await transientCount(h.metricsText, 'stream', 'deferred')).toBe(1);
      // Warn logs carry class name and code only.
      const deferredLog = h.warns.find((w) => w.errCode === code);
      expect(deferredLog).toMatchObject({
        errName: 'PrismaClientKnownRequestError',
        errCode: code,
      });
      expect(JSON.stringify(h.warns)).not.toContain('synthetic');
    },
  );

  it('succeeds when the page transaction passes on a retry (no deferral, success recorded)', async () => {
    let n = 0;
    const h = streamHarness({
      once: async () => {
        n += 1;
        if (n === 1) throw prismaError('P2024');
        return { status: 'processed', result: undefined };
      },
    });
    await h.runner.runOnce();
    expect(h.onceCalls()).toBe(2);
    const data = h.streamWrites()[0]!.args.data;
    expect(data).toMatchObject({ consecutiveFailures: 0, lastErrorCode: null });
    expect((data.nextPollAt as Date).getTime() - NOW.getTime()).toBe(300_000); // default binding poll interval
  });

  it('defers a transient error of the organization context read (no lease stall)', async () => {
    const h = streamHarness({
      orgsGet: async () => {
        throw prismaError('P2024');
      },
    });
    await h.runner.runOnce();
    expectDeferred(h);
  });

  it('defers a database error raised by the adapter’s own stores during ingestion', async () => {
    const h = streamHarness({
      ingest: async () => {
        throw prismaError('P1017');
      },
    });
    await h.runner.runOnce();
    expectDeferred(h);
  });

  it('grows the deferral per stream and resets it after a success', async () => {
    let fail = true;
    const h = streamHarness({
      once: async () => {
        if (fail) throw prismaError('P2024');
        return { status: 'processed', result: undefined };
      },
    });
    const delays: number[] = [];
    for (let i = 0; i < 6; i++) {
      await h.runner.runOnce();
      const w = h.streamWrites().at(-1)!;
      delays.push((w.args.data.nextPollAt as Date).getTime() - NOW.getTime());
    }
    expect(delays.every((d) => d >= 5_000 && d <= 60_000)).toBe(true);
    expect(delays[5]!).toBeGreaterThanOrEqual(30_000); // k = 6: d = 60 s, jitter ≥ half
    fail = false;
    await h.runner.runOnce();
    fail = true;
    await h.runner.runOnce();
    const after = h.streamWrites().at(-1)!.args.data.nextPollAt as Date;
    expect(after.getTime() - NOW.getTime()).toBeLessThanOrEqual(5_000); // k = 1 again
  });

  it('keeps today’s back-off for a provider error (failure counted, aggregate updated)', async () => {
    const h = streamHarness({
      stream: { consecutiveFailures: 2 },
      ingest: async () => {
        throw new ProviderAdapterError('server_error', true);
      },
    });
    await h.runner.runOnce();
    const data = h.streamWrites()[0]!.args.data;
    expect(data).toMatchObject({ consecutiveFailures: 3, lastErrorCode: 'server_error' });
    // poll interval (300 s default binding settings) × 2^3, capped at 1 h.
    expect((data.nextPollAt as Date).getTime() - NOW.getTime()).toBe(
      Math.min(3_600_000, 300_000 * 8),
    );
    const integrationWrites = h.integrationWrites() as Array<{ args: { data: unknown } }>;
    // Probe trigger after three failures, then the 8.4 aggregate.
    expect(integrationWrites[0]!.args.data).toEqual({ nextHealthAt: NOW });
    expect(integrationWrites.length).toBeGreaterThanOrEqual(2);
    expect(h.sleeps).toEqual([]);
    expect(await transientCount(h.metricsText, 'stream', 'retried')).toBe(0);
    expect(await transientCount(h.metricsText, 'stream', 'deferred')).toBe(0);
  });

  it('keeps a provider timeout during ingestion a provider failure', async () => {
    const h = streamHarness({
      ingest: async () => {
        throw new DOMException('synthetic', 'TimeoutError');
      },
    });
    await h.runner.runOnce();
    const data = h.streamWrites()[0]!.args.data;
    expect(data).toMatchObject({ consecutiveFailures: 1, lastErrorCode: 'TimeoutError' });
  });

  it('retries the success write and the failure write (bounded)', async () => {
    let writes = 0;
    const h = streamHarness({});
    const original = (h.runner as unknown as { deps: { prisma: { atoProviderStream: unknown } } })
      .deps.prisma.atoProviderStream as Record<string, (a: unknown) => Promise<unknown>>;
    const proxy = new Proxy(original, {
      get: (target, op: string) =>
        op === 'updateMany'
          ? async (args: unknown) => {
              writes += 1;
              if (writes === 1) throw prismaError('P2024');
              return target[op]!(args);
            }
          : target[op],
    });
    (
      h.runner as unknown as { deps: { prisma: { atoProviderStream: unknown } } }
    ).deps.prisma.atoProviderStream = proxy;
    await h.runner.runOnce();
    expect(writes).toBe(2);
    expect(h.streamWrites()[0]!.args.data).toMatchObject({ consecutiveFailures: 0 });
    expect(h.sleeps).toHaveLength(1);
    expect(IDP_WRITE_ATTEMPTS).toBe(3);
  });
});

/** A probe loop over fakes; `storeTx` is the probe's store transaction. */
function probeHarness(options: {
  row?: Partial<AtoProviderIntegration>;
  storeTx?: () => Promise<unknown>;
  connectionsGet?: () => Promise<unknown>;
  failReschedule?: boolean;
}) {
  const calls: Call[] = [];
  const row = integrationRow({ healthCheckedAt: null, ...options.row });
  let transactions = 0;
  const m = metrics();
  const { logger, warns } = silentLogger();
  const loop = new IdpProbeLoop({
    db: {
      transaction: async (fn: (t: unknown) => Promise<unknown>) => {
        transactions += 1;
        if (transactions === 1) {
          return fn({
            $queryRaw: async () => [{ id: row.id }],
            atoProviderIntegration: { updateMany: async () => ({ count: 1 }) },
          });
        }
        if (options.storeTx) return options.storeTx();
        throw new Error('unexpected transaction');
      },
    },
    prisma: {
      atoProviderIntegration: {
        findMany: async () => [row],
        updateMany: async (args: unknown) => {
          calls.push({ model: 'integration', op: 'updateMany', args });
          if (options.failReschedule) throw prismaError('P1001');
          return { count: 1 };
        },
      },
    },
    store: {},
    runtime: {
      connections: {
        get:
          options.connectionsGet ??
          (async () => {
            throw new Error('not used');
          }),
      },
      adapterFor: () => {
        throw new Error('not used');
      },
      forget: () => undefined,
    },
    orgs: {
      get: async () => ({
        id: ORG,
        exists: true,
        active: true,
        featureEnabled: true,
        mode: 'enforce',
      }),
    },
    idpMetrics: m.idp,
    logger,
    now: () => NOW,
    config: { healthIntervalSeconds: 900, lagWarnSeconds: 900 },
    retrySleep: async () => undefined,
  } as unknown as ConstructorParameters<typeof IdpProbeLoop>[0]);
  return { loop, calls, warns, metricsText: m.text };
}

function rescheduledData(h: ReturnType<typeof probeHarness>): Record<string, unknown> {
  const writes = h.calls.filter((c) => c.op === 'updateMany');
  expect(writes.length).toBeGreaterThanOrEqual(1);
  return (writes.at(-1)!.args as { data: Record<string, unknown> }).data;
}

describe('IdpStreamRunner: provider context of the organization (step AI-5 D13)', () => {
  it('drops the organization’s cached provider context before reading the provider', async () => {
    const h = streamHarness({});
    await h.runner.runOnce();
    expect(h.order).toEqual([`invalidate:${ORG}`, 'ingest']);
  });

  it('keeps the cache while the organization’s ATO feature is off (nothing is read)', async () => {
    const h = streamHarness({
      orgsGet: async () => ({
        id: ORG,
        exists: true,
        active: true,
        featureEnabled: false,
        mode: 'enforce',
      }),
    });
    await h.runner.runOnce();
    expect(h.order).toEqual([]);
  });
});

describe('IdpProbeLoop: transient database errors (D14)', () => {
  it('re-schedules a probe that throws P2024 within 60 s, health_status unchanged', async () => {
    const h = probeHarness({
      row: { connectorRef: null }, // observe → disabled → store transaction
      storeTx: async () => {
        throw prismaError('P2024');
      },
    });
    await h.loop.runOnce();
    const data = rescheduledData(h);
    expect(Object.keys(data)).toEqual(['nextHealthAt']);
    const delay = (data.nextHealthAt as Date).getTime() - NOW.getTime();
    expect(delay).toBeGreaterThanOrEqual(5_000);
    expect(delay).toBeLessThanOrEqual(60_000);
    expect(await transientCount(h.metricsText, 'probe', 'deferred')).toBe(1);
  });

  it('defers a transient error while reading the provider connection (not a probe failure)', async () => {
    const h = probeHarness({
      connectionsGet: async () => {
        throw prismaError('P1001');
      },
    });
    await h.loop.runOnce();
    const data = rescheduledData(h);
    expect(data).not.toHaveProperty('lastErrorCode');
    expect(Object.keys(data)).toEqual(['nextHealthAt']);
    expect((data.nextHealthAt as Date).getTime() - NOW.getTime()).toBeLessThanOrEqual(60_000);
  });

  it('re-schedules any other unexpected throw after min(health interval, 300 s)', async () => {
    const h = probeHarness({
      row: { connectorRef: null },
      storeTx: async () => {
        throw new TypeError('synthetic');
      },
    });
    await h.loop.runOnce();
    const data = rescheduledData(h);
    expect((data.nextHealthAt as Date).getTime() - NOW.getTime()).toBe(300_000);
    expect(h.warns.at(-1)).toMatchObject({ errName: 'TypeError' });
    expect(JSON.stringify(h.warns)).not.toContain('synthetic');
  });

  it('lets the Periodic back-off apply when the re-schedule write fails', async () => {
    const h = probeHarness({
      row: { connectorRef: null },
      storeTx: async () => {
        throw prismaError('P2024');
      },
      failReschedule: true,
    });
    await expect(h.loop.runOnce()).rejects.toMatchObject({ code: 'P1001' });
    // The write was retried (bounded) before giving up.
    expect(h.calls.filter((c) => c.op === 'updateMany')).toHaveLength(IDP_WRITE_ATTEMPTS);
  });
});
