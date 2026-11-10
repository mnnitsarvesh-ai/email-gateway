import {
  SANDBOX_FINDING_SEVERITY,
  SANDBOX_OBSERVATION_BOUNDS,
  sandboxFindingSeverityRank,
  type SandboxFinding,
  type SandboxLimit,
  type SandboxObservations,
} from '@email-gateway/security-contracts';
import type {
  BackendObservation,
  BackendSelfTest,
  ReapReport,
  RunContext,
  SandboxBackend,
  SandboxTaskInput,
} from './backend';

/**
 * Static analysis before execution (step 4.6 X3, X4; ADR-0039 decision 4):
 * `withStaticAnalysis(staticAnalyzer, executor | null)` is the backend the factory hands to the
 * controller for `static` (executor `null`) and `hardened-container` (executor = the runner,
 * wired in wave 3). It runs the static analyzer first and merges its findings, indicators and
 * `static_report` with the executor's observation into ONE observation per task, re-applying
 * every bound of the observation schema after the merge.
 */

const B = SANDBOX_OBSERVATION_BOUNDS;
const cap = (value: number): number => Math.min(B.counterMax, Math.max(0, value));

/** Findings by code (counts summed, capped; severity fixed per code), highest severity first. */
export function mergeFindings(...lists: readonly SandboxFinding[][]): SandboxFinding[] {
  const counts = new Map<SandboxFinding['code'], number>();
  for (const list of lists) {
    for (const f of list)
      counts.set(f.code, Math.min(B.findingCountMax, (counts.get(f.code) ?? 0) + f.count));
  }
  return [...counts]
    .map(([code, count]) => ({ code, severity: SANDBOX_FINDING_SEVERITY[code], count }))
    .sort(
      (a, b) =>
        sandboxFindingSeverityRank(b.severity) - sandboxFindingSeverityRank(a.severity) ||
        (a.code < b.code ? -1 : a.code > b.code ? 1 : 0),
    )
    .slice(0, B.findings);
}

/** Adds limits (deduplicated, bounded) and their `limit.<limit>` findings. */
export function withLimits(
  observations: SandboxObservations,
  limits: readonly SandboxLimit[],
): SandboxObservations {
  if (limits.length === 0) return observations;
  const limitsHit = [...new Set([...observations.limitsHit, ...limits])].slice(0, B.limitsHit);
  const added = limits
    .filter((l) => !observations.findings.some((f) => f.code === `limit.${l}`))
    .map((l) => {
      const code = `limit.${l}` as SandboxFinding['code'];
      return { code, severity: SANDBOX_FINDING_SEVERITY[code], count: 1 };
    });
  return { ...observations, limitsHit, findings: mergeFindings(observations.findings, added) };
}

function dedupe<T>(items: readonly T[], key: (item: T) => string, max: number): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const item of items) {
    const k = key(item);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(item);
    if (out.length >= max) break;
  }
  return out;
}

/**
 * Merges two observations (`a` first: static, `b`: executor). Lists are deduplicated and capped,
 * totals summed and kept ≥ the listed entries, processes / files / browser come from `b` (the
 * static analyzer has none).
 */
export function mergeObservations(
  a: SandboxObservations,
  b: SandboxObservations,
): SandboxObservations {
  const dns = dedupe(
    [...a.network.dns, ...b.network.dns],
    (d) => `${d.name}|${d.type}|${d.source}`,
    B.dns,
  );
  const http = dedupe(
    [...a.network.http, ...b.network.http],
    (h) => `${h.host}|${h.port}|${h.method}|${h.pathSha256}`,
    B.http,
  );
  const tls = dedupe([...a.network.tls, ...b.network.tls], (t) => `${t.sni}|${t.port}`, B.tls);
  const connections = dedupe(
    [...a.network.connections, ...b.network.connections],
    (c) => `${c.ip}|${c.port}|${c.protocol}|${c.outcome}`,
    B.connections,
  );
  const processes = [...a.processes, ...b.processes].slice(0, B.processes);
  const dropped = dedupe(
    [...a.files.dropped, ...b.files.dropped],
    (f) => String(f.seq),
    B.droppedFiles,
  );
  return {
    processes,
    processCount: cap(Math.max(a.processCount + b.processCount, processes.length)),
    network: {
      dns,
      http,
      tls,
      connections,
      totals: {
        dns: cap(Math.max(a.network.totals.dns + b.network.totals.dns, dns.length)),
        http: cap(Math.max(a.network.totals.http + b.network.totals.http, http.length)),
        tls: cap(Math.max(a.network.totals.tls + b.network.totals.tls, tls.length)),
        connections: cap(
          Math.max(a.network.totals.connections + b.network.totals.connections, connections.length),
        ),
      },
    },
    files: { dropped, deniedWrites: cap(a.files.deniedWrites + b.files.deniedWrites) },
    findings: mergeFindings(a.findings, b.findings),
    limitsHit: [...new Set([...a.limitsHit, ...b.limitsHit])].slice(0, B.limitsHit),
    browser: b.browser ?? a.browser,
  };
}

/** One combined observation: a failure of either side fails the task (its error code). */
export function mergeBackendObservations(
  staticObs: BackendObservation,
  exec: BackendObservation,
): BackendObservation {
  const failure =
    exec.status === 'failed' ? exec : staticObs.status === 'failed' ? staticObs : null;
  const status = failure ? 'failed' : 'completed';
  return {
    status,
    executed: exec.executed,
    notExecutedReason: null,
    errorCode: failure ? failure.errorCode : null,
    observations: mergeObservations(staticObs.observations, exec.observations),
    artifacts: [...staticObs.artifacts, ...exec.artifacts],
    analyzerVersion: staticObs.analyzerVersion,
    cleanup: {
      runnerRemoved: exec.cleanup.runnerRemoved,
      scratchRemoved: staticObs.cleanup.scratchRemoved && exec.cleanup.scratchRemoved,
    },
  };
}

class StaticFirstBackend implements SandboxBackend {
  readonly name: SandboxBackend['name'];
  readonly isolation: SandboxBackend['isolation'];
  readonly executes: boolean;

  constructor(
    private readonly staticAnalyzer: SandboxBackend,
    private readonly executor: SandboxBackend,
  ) {
    this.name = executor.name;
    this.isolation = executor.isolation;
    this.executes = executor.executes;
  }

  /** Read through: the runner resolves its version (image id) only during its self-test. */
  get version(): string {
    return this.executor.version;
  }

  async selfTest(signal: AbortSignal): Promise<BackendSelfTest> {
    const [s, e] = await Promise.all([
      this.staticAnalyzer.selfTest(signal),
      this.executor.selfTest(signal),
    ]);
    const details = { ...e.details, staticOk: s.ok };
    if (!e.ok) return { ok: false, code: e.code, details };
    if (!s.ok) return { ok: false, code: s.code, details };
    return { ok: true, code: 'ok', details };
  }

  supports(
    task: Pick<SandboxTaskInput, 'profile' | 'sample'>,
  ): ReturnType<SandboxBackend['supports']> {
    // Static analysis runs whenever either side can do something with the sample.
    const s = this.staticAnalyzer.supports(task);
    return s.ok ? s : this.executor.supports(task);
  }

  async run(task: SandboxTaskInput, ctx: RunContext): Promise<BackendObservation> {
    const staticObs = this.staticAnalyzer.supports(task).ok
      ? await this.staticAnalyzer.run(task, ctx)
      : null;
    if (!this.executor.supports(task).ok) {
      // Static result only, never executed (e.g. a type the runner does not execute).
      if (staticObs) return { ...staticObs, executed: false };
      return this.executor.run(task, ctx);
    }
    const exec = await this.executor.run(task, ctx);
    return staticObs ? mergeBackendObservations(staticObs, exec) : exec;
  }

  async reap(active: ReadonlySet<string>, mode: 'startup' | 'periodic'): Promise<ReapReport> {
    const [s, e] = await Promise.all([
      this.staticAnalyzer.reap(active, mode),
      this.executor.reap(active, mode),
    ]);
    return {
      runnersRemoved: s.runnersRemoved + e.runnersRemoved,
      scratchRemoved: s.scratchRemoved + e.scratchRemoved,
      failures: s.failures + e.failures,
    };
  }

  async close(): Promise<void> {
    await Promise.allSettled([this.staticAnalyzer.close(), this.executor.close()]);
  }
}

/**
 * The static-first backend. With `executor === null` it is the static analyzer itself (backend
 * `static`); with an executor it takes the executor's identity (name, isolation, version,
 * `executes`) and runs static analysis first.
 */
export function withStaticAnalysis(
  staticAnalyzer: SandboxBackend,
  executor: SandboxBackend | null,
): SandboxBackend {
  if (staticAnalyzer.name !== 'static')
    throw new Error('withStaticAnalysis needs the static analyzer');
  return executor === null ? staticAnalyzer : new StaticFirstBackend(staticAnalyzer, executor);
}
