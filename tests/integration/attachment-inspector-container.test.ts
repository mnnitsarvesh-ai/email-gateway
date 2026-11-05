import { beforeAll, describe, expect, it } from 'vitest';
import { runInspectorProbe } from './support/inspector-probe';
import { record } from './support/messaging-stack';
import { scanStackGate } from './support/scan-stack';
import { assertStackReady } from './support/smtp-stack';

/**
 * The inspector kill path in the Linux `email-worker` container (docs/plan/steps/
 * 10-attachment-scanning.md A4, §9 "Stack", review round 1): `ATTACHMENT_INSPECTOR_RLIMITS=
 * required` with `prlimit` and the `/proc` sampler, the production path that the host suites
 * (macOS: `ps` sampler, no prlimit) skip. See `support/inspector-probe.ts` for what the probe
 * runs; it builds its own one-child pools from the image's compiled modules and never touches
 * the worker's pool.
 */

const gate = await scanStackGate();

beforeAll(() => {
  assertStackReady(gate);
});

describe.skipIf(gate.skip)(
  'attachment inspector in the container (A4)',
  { timeout: 180_000 },
  () => {
    it('enforces CPU (sampler and prlimit SIGXCPU), memory (/proc RSS), wall clock and crashes under prlimit', async () => {
      const report = await runInspectorProbe();
      expect(report).toMatchObject({ platform: 'linux', nodeEnv: 'production' });
      expect(report.prlimit).toMatch(/\/prlimit$/);

      // The /proc sampler enforces the per-job CPU and RSS limits (the rlimit backstop is 100 s).
      const proc = report.runs.proc;
      expect(proc.rlimitMode).toBe('prlimit');
      expect(proc.samples).toBeGreaterThan(0);
      expect(proc.results).toEqual({
        cpu: { kind: 'limit', code: 'limit.cpu_time' },
        memory: { kind: 'limit', code: 'limit.memory' },
        hang: { kind: 'failure', reason: 'wall' },
        crash: { kind: 'failure', reason: 'crash' },
        // Every kill recycled the child: the pool still inspects.
        inspect: 'pdf',
      });
      expect(proc.kills).toEqual(['cpu', 'memory', 'wall', 'crash']);

      // Without the sampler, only the child's prlimit --cpu backstop can stop the CPU loop.
      const prlimitOnly = report.runs.prlimit_only;
      expect(prlimitOnly).toMatchObject({ rlimitMode: 'prlimit', samples: 0 });
      expect(prlimitOnly.results).toEqual({
        cpu: { kind: 'limit', code: 'limit.cpu_time' },
        inspect: 'pdf',
      });
      expect(prlimitOnly.kills).toEqual(['cpu']);
      record('attachment-inspector-container', {
        prlimit: report.prlimit,
        proc_samples: proc.samples,
        kills: proc.kills.join(','),
      });
    });
  },
);
