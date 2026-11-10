import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll } from 'vitest';
import { describeBackendConformance } from '../support/backend-conformance';
import {
  ensureSinkhole,
  makeBackend,
  probe,
  relayTransport,
  runnerContainers,
  sinkholeContainer,
  stopSinkhole,
} from './support';

// The X2 interface conformance suite (WP2's `describeBackendConformance`) against the real
// hardened-container backend and the real Docker daemon (step 4.6 §9.1). LOCAL/CI ONLY, NOT A VM
// BOUNDARY.
beforeAll(async () => {
  await ensureSinkhole();
}, 180_000);

const scratchRoots: string[] = [];

afterAll(async () => {
  for (const dir of scratchRoots) rmSync(dir, { recursive: true, force: true });
  const left = await runnerContainers();
  await stopSinkhole();
  if (left.length > 0) throw new Error(`${left.length} runner container(s) were left behind`);
}, 180_000);

describeBackendConformance({
  label: 'hardened-container (real Docker)',
  create: async () => ({
    backend: makeBackend(relayTransport(await sinkholeContainer())),
    scratchRoot: (() => {
      const dir = mkdtempSync(join(tmpdir(), 'eg-wp4-conformance-'));
      scratchRoots.push(dir);
      return dir;
    })(),
  }),
  sample: { bytes: probe('benign-marker.sh'), detectedType: 'script_shell', profile: 'execute' },
  expect: { name: 'hardened-container', executes: true, selfTestOk: true },
  timeoutMs: 120_000,
});
