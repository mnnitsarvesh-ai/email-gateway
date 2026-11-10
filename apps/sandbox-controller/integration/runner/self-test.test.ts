import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { SinkholeTransport } from '../../src/runner/sinkhole-client';
import { SinkholeClient } from '../../src/runner/sinkhole-client';
import {
  ensureSinkhole,
  makeBackend,
  relayTransport,
  runnerContainers,
  sinkholeContainer,
  sinkholeToken,
  stopSinkhole,
} from './support';

// Self-test of the hardened-container backend against real Docker (step 4.6 X6, §9.3). The probe
// runner must prove its own restrictions and be removed. LOCAL/CI ONLY, NOT A VM BOUNDARY.
describe('hardened-container self-test (real Docker)', () => {
  let transport: SinkholeTransport;
  let admin: SinkholeClient;

  beforeAll(async () => {
    await ensureSinkhole();
    transport = relayTransport(await sinkholeContainer());
    admin = new SinkholeClient({
      adminUrl: 'http://172.31.252.53:3094',
      token: sinkholeToken(),
      transport,
    });
  });

  afterAll(async () => {
    const left = await runnerContainers();
    await stopSinkhole();
    expect(left).toEqual([]);
  }, 180_000);

  it('proves uid≠0, no capabilities, no_new_privs, seccomp, read-only root, sinkhole DNS, no socket, empty env', async () => {
    const backend = makeBackend(transport);
    const result = await backend.selfTest(new AbortController().signal);
    expect(result.details.failures).toBeUndefined();
    expect(result).toMatchObject({ ok: true, code: 'ok' });
    expect(result.details).toMatchObject({
      isolation: 'container-not-vm',
      vmBoundary: false,
      seccomp: true,
      noNewPrivs: true,
      capabilities: 'none',
      rootReadOnly: true,
      dnsSinkhole: true,
      defaultRoute: false,
      dockerSocket: false,
      runnerRemoved: true,
    });
    expect(typeof result.details.apparmor).toBe('boolean');
    expect(result.details.uid).toBe(65532);
    expect(backend.version).toMatch(/^hardened-container\/1\+runner:[0-9a-f]{12}$/);
    expect(await runnerContainers()).toEqual([]);
    expect((await admin.stats()).total).toBe(0);
  });

  it('refuses when the sinkhole token is wrong (admin API is token-protected)', async () => {
    const wrong = new SinkholeClient({
      adminUrl: 'http://172.31.252.53:3094',
      token: 'x'.repeat(40),
      transport,
    });
    await expect(wrong.stats()).rejects.toThrow(/401/);
    expect(await wrong.health()).toBe(true);
  });

  it('reports docker_unreachable for a missing socket', async () => {
    const backend = makeBackend(transport, { socketPath: '/nonexistent/docker.sock' });
    const result = await backend.selfTest(new AbortController().signal);
    expect(result).toMatchObject({ ok: false, code: 'docker_unreachable' });
  });
});
