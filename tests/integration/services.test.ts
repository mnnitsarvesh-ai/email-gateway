import { describe, expect, it } from 'vitest';
import { composeExec, runningServices } from './support/compose';
import { stack } from './support/env';

// The whole `apps` profile runs as containers (smtp-adapter alone may run on the host for the
// SMTP suites, which says nothing about the other services).
const running = (await runningServices()).has('api');

/**
 * Readiness checks per service (contracts §9). Step 3.2: event-relay is a new deployable
 * (`mysql` writer + `rabbitmq`); email-worker and delivery-worker check RabbitMQ through the
 * client library (connected, not blocked, their exchanges/queues verified passively);
 * policy-engine, archive-worker and notification-worker consume nothing yet and no longer
 * connect to RabbitMQ; the api opens its ops connection per dead-letter request only.
 */
const EXPECTED_CHECKS: Record<string, string[]> = {
  api: ['mysql', 'mysql-reader', 'redis', 's3'],
  // Step 4.1 S1: MIME role (`rabbitmq`) and scan role (`rabbitmq-scanner`, user eg-scanner).
  // Step 4.2 A12: the attachment consumer adds `clamav` (clamd PING) and `attachment-inspector`
  // (ready inspector children). Step 4.3: the URL consumer adds `url-engine` (Redis PING of the
  // URL cache; DNS reachability and egress mode as details). Step 4.4 B4: the BEC consumer adds
  // `bec-engine` (static data, local models and LLM layer loaded; model versions as details).
  // Step 4.5 (WP3): the DLP consumer adds `dlp-engine` (static data and evidence key loaded) and
  // `dlp-extractor` (ready extractor children of the second pool). Step 4.6 (WP3): the sandbox
  // consumers add `sandbox-bucket` (HeadBucket of the restricted sandbox bucket).
  'email-worker': [
    'attachment-inspector',
    'bec-engine',
    'clamav',
    'dlp-engine',
    'dlp-extractor',
    'mysql',
    'rabbitmq',
    'rabbitmq-scanner',
    'redis',
    's3',
    'sandbox-bucket',
    'url-engine',
  ],
  // Step 5.2: the policy-engine consumes email.policy.evaluate (rabbitmq) and writes policy
  // copies (s3); the notification-worker consumes email.notifications (rabbitmq).
  'policy-engine': ['mysql', 'rabbitmq', 'redis', 's3'],
  'delivery-worker': ['mysql', 'rabbitmq', 'redis', 's3'],
  'notification-worker': ['mysql', 'rabbitmq'],
  'archive-worker': ['mysql', 's3'],
  'event-relay': ['mysql', 'rabbitmq'],
};

describe.skipIf(!running)('Application services (compose profile: apps)', () => {
  const nestServices = Object.entries(stack.ports.services).filter(
    ([name]) => name !== 'admin-portal',
  );

  it.each(nestServices)('%s is ready with all dependencies healthy', async (name, port) => {
    const res = await fetch(`http://${stack.host}:${port}/health/ready`);
    const body = (await res.json()) as {
      service: string;
      status: string;
      checks: { name: string; status: string }[];
    };
    expect(res.status, JSON.stringify(body.checks)).toBe(200);
    expect(body.service).toBe(name);
    expect(body.checks.every((c) => c.status === 'ok')).toBe(true);
    const expected = EXPECTED_CHECKS[name];
    if (expected) expect(body.checks.map((c) => c.name).sort()).toEqual([...expected].sort());
    else expect(body.checks.map((c) => c.name)).not.toContain('rabbitmq');
  });

  it('click-service (step 4.3) is ready on its admin port only: mysql (gateway_click) and redis', async () => {
    const admin = `http://${stack.host}:${Number(process.env.CLICK_SERVICE_ADMIN_HOST_PORT ?? 3081)}`;
    const res = await fetch(`${admin}/health/ready`);
    const body = (await res.json()) as { checks: { name: string; status: string }[] };
    expect(res.status, JSON.stringify(body.checks)).toBe(200);
    expect(body.checks.map((c) => c.name).sort()).toEqual(['mysql', 'redis']);
    expect(body.checks.every((c) => c.status === 'ok')).toBe(true);
    // The public port serves the click routes only (no health or metrics there).
    const publicPort = Number(process.env.CLICK_SERVICE_HOST_PORT ?? 3080);
    expect((await fetch(`http://${stack.host}:${publicPort}/health/ready`)).status).toBe(404);
  });

  it('sandbox-controller (step 4.6) is ready with backend disabled: rabbitmq and sandbox-backend, port not published', async () => {
    // Its only network (sandbox-control) is internal: read the probe from inside the container.
    const result = await composeExec(
      'sandbox-controller',
      [
        'node',
        '-e',
        "fetch('http://127.0.0.1:3092/health/ready').then(async r=>process.stdout.write(r.status+' '+await r.text()))",
      ],
      { timeoutMs: 20_000 },
    );
    expect(result.exitCode, result.stderr).toBe(0);
    const [status, ...rest] = result.stdout.split(' ');
    const body = JSON.parse(rest.join(' ')) as {
      checks: { name: string; status: string; details?: Record<string, unknown> }[];
    };
    expect(status).toBe('200');
    expect(body.checks.map((c) => c.name).sort()).toEqual(['rabbitmq', 'sandbox-backend']);
    expect(body.checks.find((c) => c.name === 'sandbox-backend')!.details).toMatchObject({
      backend: 'disabled',
      isolation: 'none',
      executes: false,
    });
  });

  it('event-relay holds every relay shard and reports no outbox lag', async () => {
    const res = await fetch(`http://${stack.host}:${stack.ports.services['event-relay']}/metrics`);
    expect(res.status).toBe(200);
    const text = await res.text();
    const value = (name: string) =>
      text
        .split('\n')
        .filter((l) => l.startsWith(`${name}{`) || l.startsWith(`${name} `))
        .map((l) => Number(l.split(' ').at(-1)));
    const shards = Number(process.env.RELAY_SHARDS ?? 4);
    expect(value('outbox_relay_shards_held').reduce((a, b) => a + b, 0)).toBe(shards);
    expect(value('outbox_relay_lag_seconds')).toHaveLength(shards);
    expect(value('amqp_connection_up')).toEqual([1]);
    expect(value('outbox_poison_rows')).toEqual([0]);
  });

  it('admin portal serves its health endpoint and dashboard', async () => {
    const port = stack.ports.services['admin-portal'];
    expect((await fetch(`http://${stack.host}:${port}/api/health`)).status).toBe(200);
    const page = await fetch(`http://${stack.host}:${port}/`);
    expect(page.status).toBe(200);
    expect(await page.text()).toContain('Operational');
  });

  it('API serves business routes under /api/v1 with correlation ids (ADR-0015)', async () => {
    const base = `http://${stack.host}:${stack.ports.services.api}`;
    const res = await fetch(`${base}/api/v1/meta`, {
      headers: { 'x-correlation-id': 'integration-0001' },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('x-correlation-id')).toBe('integration-0001');
    expect(((await res.json()) as { apiVersion: string }).apiVersion).toBe('v1');
    // The pre-ADR-0015 path is gone; probes stay unprefixed.
    expect((await fetch(`${base}/v1/meta`)).status).toBe(404);
    expect((await fetch(`${base}/api/health/live`)).status).toBe(404);
  });
});
