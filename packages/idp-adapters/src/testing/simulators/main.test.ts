import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { microsoftDirectory, MS_TENANT_ID } from '../datasets/microsoft';
import { ALL_SIMULATORS, runStandalone } from './main';

// Standalone mode (Compose `idp-simulator`, D12): every registered simulator, /health, an admin
// API on its own port and permissive bearer tokens with per-directory permissions.
describe('standalone simulator entry', () => {
  let running: Awaited<ReturnType<typeof runStandalone>>;
  let data: string;
  let admin: string;

  beforeAll(async () => {
    running = await runStandalone({
      IDP_SIM_HOST: '127.0.0.1',
      IDP_SIM_PORT: '0',
      IDP_SIM_ADMIN_PORT: '0',
      IDP_SIM_QUIET: 'true',
    });
    data = `http://127.0.0.1:${running.dataPort}`;
    admin = `http://127.0.0.1:${running.adminPort}`;
  });
  afterAll(async () => {
    await running.stop();
  });

  const post = (path: string, body: unknown) =>
    fetch(`${admin}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  const graph = (path: string) =>
    fetch(`${data}/graph${path}`, { headers: { Authorization: 'Bearer EXAMPLE-stack-token' } });

  it('registers the Microsoft simulators (WP2 adds Google with one line)', () => {
    expect(ALL_SIMULATORS.length).toBeGreaterThanOrEqual(2);
  });

  it('serves /health on both ports', async () => {
    expect((await fetch(`${data}/health`)).status).toBe(200);
    expect(await (await fetch(`${admin}/health`)).json()).toEqual({ status: 'ok' });
  });

  it('loads a dataset, accepts any bearer token and enforces per-directory permissions', async () => {
    expect(
      (
        await post('/admin/dataset', {
          microsoft: { directories: [microsoftDirectory(new Date())] },
        })
      ).status,
    ).toBe(204);
    const users = await graph('/v1.0/users?$top=2');
    expect(users.status).toBe(200);
    expect(((await users.json()) as { value: unknown[] }).value).toHaveLength(2);
    expect((await fetch(`${data}/graph/v1.0/users`)).status).toBe(401);
    expect(
      (
        await post('/admin/permissions', {
          directoryId: MS_TENANT_ID,
          permissions: ['AuditLog.Read.All'],
        })
      ).status,
    ).toBe(204);
    expect((await graph('/v1.0/users')).status).toBe(403);
    await post('/admin/permissions', { directoryId: MS_TENANT_ID, permissions: ['*'] });
  });

  it('scripts failures, licences and exposes the call log; admin routes are not on the data port', async () => {
    expect(
      (
        await post('/admin/inject', {
          simulator: 'graph',
          path: '/v1.0/users',
          status: 429,
          retryAfter: '2',
        })
      ).status,
    ).toBe(204);
    const throttled = await graph('/v1.0/users');
    expect(throttled.status).toBe(429);
    expect(throttled.headers.get('retry-after')).toBe('2');
    expect(
      (
        await post('/admin/license', {
          directoryId: MS_TENANT_ID,
          license: 'entraP1',
          value: false,
        })
      ).status,
    ).toBe(204);
    expect(
      (await post('/admin/license', { directoryId: 'unknown', license: 'entraP1', value: false }))
        .status,
    ).toBe(404);
    expect((await post('/admin/inject', { status: 429 })).status).toBe(400);
    const calls = (await (await fetch(`${admin}/admin/calls`)).json()) as {
      calls: { path: string; status: number }[];
    };
    expect(calls.calls.some((c) => c.path === '/v1.0/users' && c.status === 429)).toBe(true);
    expect((await fetch(`${data}/admin/calls`)).status).toBe(404);
    expect((await post('/admin/reset', {})).status).toBe(204);
  });
});
