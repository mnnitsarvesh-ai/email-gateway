import { Writable } from 'node:stream';
import { Global, Module } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { MetricsModule, MetricsService, RedisService } from '@email-gateway/common';
import { createLogger } from '@email-gateway/logger';
import { describe, expect, it } from 'vitest';
import {
  REPUTATION_EVENTS,
  REPUTATION_TTL_SECONDS,
  ReputationRecorder,
  reputationKey,
} from './reputation';
import { SmtpSharedModule } from './shared.module';

type Command = [string, ...(string | number)[]];

/**
 * An in-memory stand-in for the ioredis client surface the recorder uses (pipeline → hincrby,
 * expire → exec), with switchable failure modes.
 */
class FakeRedis {
  readonly hashes = new Map<string, Map<string, number>>();
  readonly ttls = new Map<string, number>();
  readonly executed: Command[][] = [];
  mode: 'ok' | 'reject' | 'command-error' | 'null' = 'ok';

  pipeline() {
    const commands: Command[] = [];
    const chain = {
      hincrby: (key: string, field: string, by: number) => {
        commands.push(['hincrby', key, field, by]);
        return chain;
      },
      expire: (key: string, seconds: number) => {
        commands.push(['expire', key, seconds]);
        return chain;
      },
      exec: (): Promise<[Error | null, unknown][] | null> => {
        this.executed.push(commands);
        if (this.mode === 'reject') return Promise.reject(new Error('ECONNREFUSED'));
        if (this.mode === 'null') return Promise.resolve(null);
        return Promise.resolve(
          commands.map(([name, key, a, b]): [Error | null, unknown] => {
            if (this.mode === 'command-error' && name === 'hincrby') {
              return [new Error('WRONGTYPE Operation against a key'), null];
            }
            if (name === 'hincrby') {
              const hash = this.hashes.get(String(key)) ?? new Map<string, number>();
              hash.set(String(a), (hash.get(String(a)) ?? 0) + Number(b));
              this.hashes.set(String(key), hash);
              return [null, hash.get(String(a))];
            }
            this.ttls.set(String(key), Number(a));
            return [null, 1];
          }),
        );
      },
    };
    return chain;
  }
}

function setup() {
  const fake = new FakeRedis();
  const redis = { client: fake } as unknown as RedisService;
  const metrics = new MetricsService({ service: 'smtp-adapter' });
  const lines: string[] = [];
  const destination = new Writable({
    write(chunk: Buffer, _enc, cb) {
      lines.push(chunk.toString());
      cb();
    },
  });
  const logger = createLogger({ service: 'smtp-adapter', destination });
  const recorder = new ReputationRecorder(redis, metrics, logger);
  const metricLine = async (pattern: RegExp) =>
    (await metrics.metrics()).split('\n').find((l) => pattern.test(l));
  return { fake, metrics, recorder, lines, metricLine };
}

const now = new Date('2026-11-02T23:59:59.999Z');

describe('reputationKey', () => {
  it('uses the UTC day', () => {
    expect(reputationKey(42n, now)).toBe('rep:42:20261102');
    expect(reputationKey(42n, new Date('2026-01-05T00:00:00Z'))).toBe('rep:42:20260105');
  });
});

describe('ReputationRecorder', () => {
  it('increments the daily hash with a 40-day TTL and the Prometheus counter', async () => {
    const { fake, recorder, metricLine } = setup();
    await recorder.record(42n, 'relayed', 1, now);
    await recorder.record(42n, 'relayed', 2, now);
    await recorder.record(42n, 'bounced_hard', 1, now);

    expect(fake.hashes.get('rep:42:20261102')).toEqual(
      new Map([
        ['relayed', 3],
        ['bounced_hard', 1],
      ]),
    );
    expect(fake.ttls.get('rep:42:20261102')).toBe(REPUTATION_TTL_SECONDS);
    expect(REPUTATION_TTL_SECONDS).toBe(40 * 86_400);
    expect(fake.executed[0]).toEqual([
      ['hincrby', 'rep:42:20261102', 'relayed', 1],
      ['expire', 'rep:42:20261102', REPUTATION_TTL_SECONDS],
    ]);
    expect(await metricLine(/^smtp_tenant_mail_events_total\{.*event="relayed"/)).toBe(
      'smtp_tenant_mail_events_total{organization_id="42",event="relayed",service="smtp-adapter"} 3',
    );
    expect(await metricLine(/^smtp_reputation_errors_total/)).toBe(
      'smtp_reputation_errors_total{service="smtp-adapter"} 0',
    );
  });

  it('defaults to one event now', async () => {
    const { fake, recorder } = setup();
    await recorder.record(7n, 'submitted');
    const [key] = [...fake.hashes.keys()];
    expect(key).toBe(reputationKey(7n, new Date()));
    expect(fake.hashes.get(key!)?.get('submitted')).toBe(1);
  });

  it('accepts every D13 event', async () => {
    const { fake, recorder } = setup();
    expect([...REPUTATION_EVENTS]).toEqual([
      'submitted',
      'relayed',
      'suppressed',
      'rate_limited',
      'bounced_hard',
      'bounced_soft',
      'delayed',
    ]);
    for (const event of REPUTATION_EVENTS) await recorder.record(1n, event, 1, now);
    expect([...fake.hashes.get('rep:1:20261102')!.keys()]).toEqual([...REPUTATION_EVENTS]);
  });

  it.each(['reject', 'command-error', 'null'] as const)(
    'never throws when Redis fails (%s): logs and counts the error',
    async (mode) => {
      const { fake, recorder, lines, metricLine } = setup();
      fake.mode = mode;
      await expect(recorder.record(42n, 'delayed', 1, now)).resolves.toBeUndefined();
      expect(await metricLine(/^smtp_reputation_errors_total/)).toBe(
        'smtp_reputation_errors_total{service="smtp-adapter"} 1',
      );
      expect(lines).toHaveLength(1);
      const entry = JSON.parse(lines[0]!) as Record<string, unknown>;
      expect(entry).toMatchObject({
        level: 'warn',
        component: 'reputation',
        organizationId: '42',
        event: 'delayed',
        message: 'reputation event not recorded',
      });
    },
  );

  it('never throws on invalid input; records nothing for it', async () => {
    const { fake, recorder, metricLine } = setup();
    await expect(recorder.record(42n, 'nonsense' as never, 1, now)).resolves.toBeUndefined();
    await expect(recorder.record(42n, 'relayed', -1, now)).resolves.toBeUndefined();
    await expect(recorder.record(42n, 'relayed', 1.5, now)).resolves.toBeUndefined();
    await expect(recorder.record(0n, 'relayed', 1, now)).resolves.toBeUndefined();
    await expect(recorder.record(42n, 'relayed', 1, new Date(Number.NaN))).resolves.toBeUndefined();
    expect(fake.executed).toHaveLength(0);
    expect(await metricLine(/^smtp_reputation_errors_total/)).toBe(
      'smtp_reputation_errors_total{service="smtp-adapter"} 5',
    );
  });

  it('treats a zero count as a no-op', async () => {
    const { fake, recorder, metricLine } = setup();
    await recorder.record(42n, 'relayed', 0, now);
    expect(fake.executed).toHaveLength(0);
    expect(await metricLine(/^smtp_reputation_errors_total/)).toBe(
      'smtp_reputation_errors_total{service="smtp-adapter"} 0',
    );
  });
});

describe('SmtpSharedModule', () => {
  it('provides ReputationRecorder globally from the global Redis and Metrics modules', async () => {
    const fake = new FakeRedis();
    @Global()
    @Module({
      providers: [{ provide: RedisService, useValue: { client: fake } }],
      exports: [RedisService],
    })
    class FakeRedisModule {}

    const moduleRef = await Test.createTestingModule({
      imports: [
        FakeRedisModule,
        MetricsModule.forRoot({ service: 'smtp-adapter' }),
        SmtpSharedModule,
      ],
    }).compile();
    const recorder = moduleRef.get(ReputationRecorder);
    expect(recorder).toBeInstanceOf(ReputationRecorder);
    await recorder.record(9n, 'suppressed', 1, now);
    expect(fake.hashes.get('rep:9:20261102')?.get('suppressed')).toBe(1);
    const text = await moduleRef.get(MetricsService).metrics();
    expect(text).toContain(
      'smtp_tenant_mail_events_total{organization_id="9",event="suppressed",service="smtp-adapter"} 1',
    );
  });
});
