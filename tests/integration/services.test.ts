import { describe, expect, it } from 'vitest';
import { appsRunning, stack } from './support/env';

const running = await appsRunning();

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
