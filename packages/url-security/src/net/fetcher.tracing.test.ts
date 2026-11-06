import { createRequire } from 'node:module';
import http, { type IncomingHttpHeaders } from 'node:http';
import { context, propagation, SpanKind, trace } from '@opentelemetry/api';
import { AsyncLocalStorageContextManager } from '@opentelemetry/context-async-hooks';
import {
  CompositePropagator,
  W3CBaggagePropagator,
  W3CTraceContextPropagator,
} from '@opentelemetry/core';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import {
  InMemorySpanExporter,
  SimpleSpanProcessor,
  TracerProvider,
} from '@opentelemetry/sdk-trace';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { GuardedFetcher, untraced } from './fetcher';
import { dialMap, fakeDns, listen, testGuard, type TestServer } from './net.test-support';

/**
 * Review finding (step 4.3 §12): the email-worker and click-service auto-instrument `http`. The
 * guarded fetcher must still send EXACTLY its header set (U8) to untrusted sites — no
 * `traceparent`/`tracestate`/`baggage` — and no client span may carry the target's path or
 * query. This suite runs the real OpenTelemetry http instrumentation (in its own file, so the
 * patched `http` module never leaks into the other suites).
 */

const exporter = new InMemorySpanExporter();
const provider = new TracerProvider({ spanProcessors: [new SimpleSpanProcessor({ exporter })] });
const instrumentation = new HttpInstrumentation();
const seen: Array<{ url: string; headers: IncomingHttpHeaders }> = [];
let server: TestServer;

const { resolver } = fakeDns({ 'site.test': { v4: ['203.0.113.10'] } });

beforeAll(async () => {
  context.setGlobalContextManager(new AsyncLocalStorageContextManager().enable());
  propagation.setGlobalPropagator(
    new CompositePropagator({
      propagators: [new W3CTraceContextPropagator(), new W3CBaggagePropagator()],
    }),
  );
  trace.setGlobalTracerProvider(provider);
  instrumentation.setTracerProvider(provider);
  instrumentation.enable();
  // The instrumentation patches the module on require; the ESM default import of the fetcher
  // is the same exports object.
  createRequire(__filename)('node:http');
  server = await listen(
    http.createServer((req, res) => {
      seen.push({ url: req.url ?? '', headers: req.headers });
      if (req.url?.startsWith('/hop')) {
        res.writeHead(302, { location: '/reset?token=secret-reset-token' });
        res.end();
        return;
      }
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<p>ok</p>');
    }),
  );
});

afterAll(async () => {
  instrumentation.disable();
  await server.close();
  await provider.shutdown();
  context.disable();
  propagation.disable();
  trace.disable();
});

const fetcher = (): GuardedFetcher =>
  new GuardedFetcher({
    guard: testGuard(),
    resolver,
    userAgent: 'TestScanner/1.0',
    connectTimeoutMs: 1000,
    headerTimeoutMs: 1000,
    totalTimeoutMs: 2500,
    maxHeaderBytes: 16384,
    maxBodyBytes: 16384,
    maxHops: 4,
    dialMap: dialMap({ '203.0.113.10:80': server.port }),
  });

describe('GuardedFetcher under OpenTelemetry auto-instrumentation', () => {
  it('control: an ordinary instrumented request inside a span carries traceparent', async () => {
    seen.length = 0;
    const tracer = provider.getTracer('test');
    await tracer.startActiveSpan('parent', async (span) => {
      await new Promise<void>((resolve, reject) => {
        http
          .get({ host: '127.0.0.1', port: server.port, path: '/control' }, (res) => {
            res.resume();
            res.on('end', resolve);
          })
          .on('error', reject);
      });
      span.end();
    });
    expect(seen[0]?.headers.traceparent).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-0[01]$/);
    expect(exporter.getFinishedSpans().some((s) => s.kind === SpanKind.CLIENT)).toBe(true);
  });

  it('sends exactly the U8 header set inside an active span and records no client span', async () => {
    seen.length = 0;
    exporter.reset();
    const tracer = provider.getTracer('test');
    const result = await tracer.startActiveSpan('scan', async (span) => {
      const r = await fetcher().fetchChain('http://site.test/hop?id=42');
      span.end();
      return r;
    });
    expect(result).toMatchObject({ status: 'completed', finalStatus: 200 });
    expect(seen.map((s) => s.url)).toEqual(['/hop?id=42', '/reset?token=secret-reset-token']);
    for (const { headers } of seen) {
      expect(Object.keys(headers).sort()).toEqual([
        'accept',
        'accept-encoding',
        'connection',
        'host',
        'user-agent',
      ]);
    }
    // The in-process test server's own SERVER spans aside (kind 1), only the caller's span is
    // recorded: nothing of the egress (no http/net/tls CLIENT span, kind 2).
    const spans = exporter.getFinishedSpans().filter((s) => s.kind !== SpanKind.SERVER);
    expect(spans.map((s) => s.name)).toEqual(['scan']);
    expect(JSON.stringify(spans.map((s) => s.attributes))).not.toContain('secret-reset-token');
  });

  it('untraced() suppresses spans for any task (and restores the context afterwards)', async () => {
    exporter.reset();
    const tracer = provider.getTracer('test');
    await untraced(async () => {
      await Promise.resolve();
      // Still suppressed after an await (the context follows the async task).
      tracer.startSpan('inside').end();
    });
    tracer.startSpan('outside').end();
    expect(exporter.getFinishedSpans().map((s) => s.name)).toEqual(['outside']);
  });
});
