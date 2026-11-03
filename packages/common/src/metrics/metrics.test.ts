import { Controller, Get, type INestApplication, VersioningType } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { IS_PUBLIC_KEY } from '../auth/public.decorator';
import { MetricsController } from './metrics.controller';
import { MetricsModule } from './metrics.module';
import { MetricsService } from './metrics.service';

const service = (name = 'test-svc') => new MetricsService({ service: name });

describe('MetricsService', () => {
  it('collects default process metrics in a dedicated registry with the service label', async () => {
    const metrics = service();
    const text = await metrics.metrics();
    expect(text).toContain('process_cpu_user_seconds_total');
    expect(text).toContain('nodejs_heap_size_used_bytes');
    expect(text).toMatch(/process_cpu_user_seconds_total\{service="test-svc"\}/);
    expect(metrics.contentType).toMatch(/^text\/plain; version=0\.0\.4/);
  });

  it('keeps registries of two instances independent (no global registry)', async () => {
    const a = service('a');
    const b = service('b');
    a.counter('only_in_a_total', 'A only').inc();
    expect(await a.metrics()).toContain('only_in_a_total{service="a"} 1');
    expect(await b.metrics()).not.toContain('only_in_a_total');
  });

  it('returns the same counter for the same name and labels (get-or-create)', async () => {
    const metrics = service();
    const first = metrics.counter('smtp_test_total', 'Test counter', ['context', 'action']);
    const second = metrics.counter('smtp_test_total', 'Other help text', ['action', 'context']);
    expect(second).toBe(first);
    first.inc({ context: 'inbound', action: 'dunno' });
    second.inc({ context: 'inbound', action: 'dunno' }, 2);
    expect(await metrics.metrics()).toContain(
      'smtp_test_total{context="inbound",action="dunno",service="test-svc"} 3',
    );
  });

  it('creates gauges and histograms, with custom buckets', async () => {
    const metrics = service();
    const gauge = metrics.gauge('smtp_test_gauge', 'Gauge', ['listener']);
    expect(metrics.gauge('smtp_test_gauge', 'Gauge', ['listener'])).toBe(gauge);
    gauge.set({ listener: 'lmtp' }, 4);

    const histogram = metrics.histogram('smtp_test_seconds', 'Histogram', ['context'], [0.01, 0.1]);
    expect(metrics.histogram('smtp_test_seconds', 'Histogram', ['context'])).toBe(histogram);
    histogram.observe({ context: 'inbound' }, 0.05);

    const text = await metrics.metrics();
    expect(text).toContain('smtp_test_gauge{listener="lmtp",service="test-svc"} 4');
    expect(text).toContain(
      'smtp_test_seconds_bucket{le="0.01",service="test-svc",context="inbound"} 0',
    );
    expect(text).toContain(
      'smtp_test_seconds_bucket{le="0.1",service="test-svc",context="inbound"} 1',
    );
    expect(text).toContain('smtp_test_seconds_count{service="test-svc",context="inbound"} 1');
  });

  it('uses prom-client default buckets when none are given', async () => {
    const metrics = service();
    metrics.histogram('smtp_default_seconds', 'Histogram').observe(0.2);
    expect(await metrics.metrics()).toContain(
      'smtp_default_seconds_bucket{le="0.25",service="test-svc"} 1',
    );
  });

  it('refuses the same name with another type or other labels', () => {
    const metrics = service();
    metrics.counter('smtp_conflict_total', 'Conflict', ['a']);
    expect(() => metrics.gauge('smtp_conflict_total', 'Conflict', ['a'])).toThrow(
      'already registered as a counter',
    );
    expect(() => metrics.counter('smtp_conflict_total', 'Conflict', ['b'])).toThrow(
      'already registered with labels [a]',
    );
    expect(() => metrics.counter('smtp_conflict_total', 'Conflict', ['a', 'b'])).toThrow();
  });

  it('validates metric and label names, reserving the service label', () => {
    const metrics = service();
    expect(() => metrics.counter('bad-name', 'x')).toThrow('Invalid metric name');
    expect(() => metrics.counter('ok_total', 'x', ['bad-label'])).toThrow('Invalid label name');
    expect(() => metrics.counter('ok2_total', 'x', ['__reserved'])).toThrow('Invalid label name');
    expect(() => metrics.counter('ok3_total', 'x', ['service'])).toThrow('Invalid label name');
  });

  it('requires a service name', () => {
    expect(() => service(' ')).toThrow('service name');
  });
});

@Controller({ path: 'probe' })
class ProbeController {
  constructor(private readonly metrics: MetricsService) {}

  @Get()
  probe(): string {
    this.metrics.counter('probe_requests_total', 'Probe requests').inc();
    return 'ok';
  }
}

describe('MetricsModule and MetricsController', () => {
  let app: INestApplication | undefined;

  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  it('is global, injects one MetricsService, and serves GET /metrics unversioned', async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [MetricsModule.forRoot({ service: 'smtp-adapter' })],
      controllers: [ProbeController],
    }).compile();
    app = moduleRef.createNestApplication({ logger: false });
    app.enableVersioning({ type: VersioningType.URI, defaultVersion: '1' });
    await app.init();

    await request(app.getHttpServer()).get('/v1/probe').expect(200);
    const res = await request(app.getHttpServer()).get('/metrics').expect(200);
    // Express normalizes the parameter order; Prometheus reads the parameters, not their order.
    expect(res.headers['content-type']).toMatch(/^text\/plain;/);
    expect(res.headers['content-type']).toContain('version=0.0.4');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.text).toContain('probe_requests_total{service="smtp-adapter"} 1');
    expect(res.text).toContain('process_resident_memory_bytes');
    expect(moduleRef.get(MetricsService)).toBe(moduleRef.get(MetricsService, { strict: false }));
  });

  it('marks the controller public (no credentials needed by the API guard)', () => {
    expect(Reflect.getMetadata(IS_PUBLIC_KEY, MetricsController)).toBe(true);
  });
});
