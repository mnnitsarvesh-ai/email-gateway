import { composeExec } from './compose';

/**
 * The inspector kill path inside the running `email-worker` container (step 4.2 A4, §9 "Stack";
 * review round 1): the production code path on Linux, `prlimit` plus the `/proc` sampler, which
 * the host suites cannot exercise on macOS.
 *
 * The probe is a short CommonJS script piped to `node -` in the container (`docker compose exec
 * -T email-worker`). It loads the image's own compiled modules (`/app/dist/…/inspector/*.js`), so
 * it tests exactly what the worker runs, and builds separate one-child pools next to the
 * worker's (the worker itself is untouched):
 *
 * - `proc`: `rlimits: 'required'`, the `/proc` sampler (`procSampler`, counted), a CPU rlimit
 *   backstop far above the per-job budget (`maxJobs` 50), so the sampler must enforce the CPU
 *   and memory limits; selftests `cpu`, `memory`, `hang`, `crash`, then a real inspection after
 *   the kills (recycled child).
 * - `prlimit_only`: the sampler disabled (always null) and `maxJobs` 1, so the `prlimit --cpu`
 *   backstop of the child (SIGXCPU) is the only thing that can stop the CPU selftest.
 *
 * Selftests are enabled for the probe's own children only (the pool option; the worker's
 * configuration refuses EG_INSPECTOR_SELFTEST in production). The script prints one JSON line;
 * it never prints content.
 */
const PROBE = String.raw`
const { createRequire } = require('node:module');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const appRequire = createRequire('/app/package.json');
const { InspectorPool, findPrlimit } = appRequire('./dist/scanning/engines/attachment/inspector/pool.js');
const { procSampler } = appRequire('./dist/scanning/engines/attachment/inspector/sampler.js');
const { BUNDLED_RULES_DIR, bundleIdOf } = appRequire('./dist/scanning/engines/attachment/inspector/bundle.js');
const { createLogger } = appRequire('@email-gateway/logger');
const LIMITS = {
  archiveMaxDepth: 3, archiveMaxEntries: 1000, maxEntryBytes: 26214400,
  maxDecompressedBytes: 104857600, maxCompressionRatio: 100, maxEntryFindings: 20,
  yaraTimeoutMs: 5000, cpuSeconds: 2, maxRssMb: 320,
};
const out = { platform: process.platform, nodeEnv: process.env.NODE_ENV, prlimit: findPrlimit(), runs: {} };
async function run(name, sampler, maxJobs, modes) {
  const tmp = mkdtempSync(join(tmpdir(), 'eg-probe-'));
  const kills = [];
  let samples = 0;
  const pool = new InspectorPool({
    size: 1, maxJobs, heapMb: 192, rlimits: 'required', tmpDir: tmp,
    wallTimeoutMs: 6000, cpuSeconds: 2, maxRssMb: 320,
    rulesDir: BUNDLED_RULES_DIR, yaraTimeoutMs: 5000,
    expectedBundleId: bundleIdOf(BUNDLED_RULES_DIR).bundleId,
    selftest: true, nodeEnv: 'production', maxWaiting: 4,
    logger: createLogger({ service: 'inspector-probe', level: 'silent' }),
    onKill: (reason) => kills.push(reason),
    sampler: async (pid) => { if (!sampler) return null; samples += 1; return sampler(pid); },
  });
  await pool.start();
  const results = {};
  try {
    for (const mode of modes) results[mode] = await pool.selftest(mode, AbortSignal.timeout(30000));
    const pdf = Buffer.from('%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n', 'latin1');
    const inspected = await pool.inspect(pdf, LIMITS, AbortSignal.timeout(30000));
    results.inspect = inspected.kind === 'result' ? inspected.result.type.detected : inspected.kind;
  } finally {
    await pool.stop();
    rmSync(tmp, { recursive: true, force: true });
  }
  out.runs[name] = { rlimitMode: pool.rlimitMode, results, kills, samples };
}
(async () => {
  await run('proc', procSampler, 50, ['cpu', 'memory', 'hang', 'crash']);
  await run('prlimit_only', null, 1, ['cpu']);
  process.stdout.write(JSON.stringify(out) + '\n');
})().catch((error) => {
  process.stdout.write(JSON.stringify({ error: String(error && error.code || error && error.message) }) + '\n');
  process.exit(1);
});
`;

export interface ProbeRun {
  rlimitMode: 'prlimit' | 'none';
  results: Record<string, unknown>;
  kills: string[];
  samples: number;
}

export interface ProbeReport {
  platform: string;
  nodeEnv: string | undefined;
  prlimit: string | null;
  runs: { proc: ProbeRun; prlimit_only: ProbeRun };
}

/** Runs the probe in the `email-worker` container; throws with the exit code on a failure. */
export async function runInspectorProbe(): Promise<ProbeReport> {
  const result = await composeExec('email-worker', ['node', '-'], {
    input: PROBE,
    timeoutMs: 120_000,
  });
  const line = result.stdout.trim().split('\n').at(-1) ?? '';
  if (result.exitCode !== 0) {
    throw new Error(`inspector probe exited ${String(result.exitCode)}: ${line}`);
  }
  return JSON.parse(line) as ProbeReport;
}
