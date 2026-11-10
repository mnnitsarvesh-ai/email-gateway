import { randomBytes } from 'node:crypto';
import type { Logger } from '@email-gateway/logger';
import {
  emptySandboxObservations,
  type NotExecutedReason,
  type SandboxLimit,
} from '@email-gateway/security-contracts';
import type {
  BackendObservation,
  BackendSelfTest,
  ReapReport,
  RunContext,
  SandboxBackend,
  SandboxTaskInput,
  TaskLimits,
} from '../backends/backend';
import {
  type AttachOutput,
  type AttachStream,
  DockerApiError,
  type DockerApi,
  DockerClient,
  type NetworkInspect,
} from './docker-client';
import {
  assertHardenedSpec,
  buildRunnerSpec,
  daemonHasAppArmor,
  daemonHasSeccomp,
  ISOLATION_LABEL_VALUE,
  RUNNER_LABELS,
  type RunnerPolicy,
  type RunnerProfile,
  verifyCreated,
} from './hardened-spec';
import { buildObservation } from './observation-builder';
import { browserReportSchema, executeReportSchema, inputErrorReportSchema } from './runner-reports';
import {
  encodeRunnerInput,
  maxOutputBytes,
  type ParsedRunnerOutput,
  parseRunnerOutput,
} from './runner-protocol';
import { judgeSelfTest } from './self-test';
import { SinkholeClient, type SinkholeRecord, type SinkholeTransport } from './sinkhole-client';
import { parseTrace, type TraceSummary } from './trace-parser';

/**
 * The `hardened-container` backend (step 4.6 X3, X6, X8; docs/plan/steps/14-sandbox.md;
 * ADR-0039; docs/security/sandbox-threat-model.md).
 *
 * LOCAL/CI ONLY — NOT A VM BOUNDARY. One disposable, hardened, shared-kernel Docker container per
 * task on the internal `sandbox-detonation` network (DNS = the recording sinkhole). The factory
 * (WP5) builds it only with `APP_ENV ∈ {local, ci}`, outside Kubernetes and with
 * `SANDBOX_ALLOW_NON_VM_EXECUTION=true`, and wraps it with the static analyzer (composite).
 *
 * `run()`: spec → assert → create → `verifyCreated` (mismatch → removed without start,
 * `spec_not_enforced`) → attach → start → inspect (runner IP) → stdin (header + sample, EOF) →
 * outer wall timeout (`wallTimeoutMs + 5 s`) → wait → inspect (OOMKilled, exit) → strict frame
 * parse → sinkhole records of the runner IP and run window (then deleted) → observation → ALWAYS
 * kill + force-remove in `finally` (3 attempts with backoff; a final failure calls
 * `metrics.cleanupFailure('runner')` and logs the container id). Logs carry ids and codes only.
 */

export const HARDENED_CONTAINER_VERSION = 'hardened-container/1';
export const EXECUTE_TYPES: ReadonlySet<string> = new Set(['script_shell', 'script_js']);
export const BROWSER_TYPES: ReadonlySet<string> = new Set(['html', 'svg']);
const OUTER_SLACK_MS = 5_000;
const DEFAULT_GRACE_MS = 30_000;
const ATTACH_DRAIN_MS = 3_000;
const SINKHOLE_WINDOW_SLACK_MS = 2_000;
const DEFAULT_REMOVE_BACKOFF_MS = [250, 1_000, 3_000];
const SELF_TEST_LIMITS: TaskLimits = {
  wallTimeoutMs: 20_000,
  memoryMb: 128,
  cpuMillis: 500,
  pids: 32,
  scratchMb: 8,
  maxArtifacts: 0,
  maxArtifactBytes: 1,
  maxTotalArtifactBytes: 1,
};

export interface HardenedContainerMetrics {
  runnerStarted?(profile: RunnerProfile): void;
  /** A runner could not be removed after every retry (`sandbox_cleanup_failures_total{kind="runner"}`). */
  cleanupFailure?(kind: 'runner'): void;
  /** Runners removed by the reaper (`sandbox_reaped_total{kind="runner",mode}`). */
  reaped?(kind: 'runner', mode: 'startup' | 'periodic', count: number): void;
  limitHit?(limit: SandboxLimit): void;
  sinkholeError?(operation: 'fetch' | 'clear'): void;
}

export interface HardenedContainerBackendOptions {
  /** `SANDBOX_DOCKER_SOCKET` (ignored when `docker` is given). */
  socketPath: string;
  /** `SANDBOX_RUNNER_IMAGE` and `SANDBOX_BROWSER_IMAGE` (the only images a runner may use). */
  images: { runner: string; browser: string };
  /** `SANDBOX_RUNNER_NETWORK`: the internal detonation network. */
  network: string;
  sinkhole: {
    /** `SANDBOX_SINKHOLE_DNS`. */
    dns: string;
    /** `SANDBOX_SINKHOLE_ADMIN_URL`. */
    adminUrl: string;
    /** `SANDBOX_SINKHOLE_ADMIN_TOKEN`. */
    token: string;
    /** Host-run tests only: relays admin requests through the sinkhole container. */
    transport?: SinkholeTransport;
  };
  /** `SANDBOX_CONTROLLER_NAME` (label `eg.sandbox.controller`; the reaper's scope). */
  controllerName: string;
  /** Non-root `uid:gid` of the runner (default `65532:65532`, the images' user). */
  runnerUser?: string;
  logger: Logger;
  metrics?: HardenedContainerMetrics;
  /** Expiry-label grace beyond the wall timeout (default 30 s). */
  graceMs?: number;
  /** Backoff between removal attempts (default 250 ms, 1 s, 3 s → 3 attempts). */
  removeBackoffMs?: readonly number[];
  /** Outer timeout slack beyond the wall timeout (default 5 s, X6; tests shorten it). */
  outerSlackMs?: number;
  /** How long the attach stream may still deliver output after the runner exited (default 3 s). */
  attachDrainMs?: number;
  /** Tests: a fake Docker API. */
  docker?: DockerApi;
  /** Tests: the clock (epoch ms). */
  now?: () => number;
}

/** The task was aborted (task timeout or shutdown); the runner was removed before this throws. */
export class RunAbortedError extends Error {
  constructor() {
    super('sandbox run aborted');
    this.name = 'RunAbortedError';
  }
}

type ContainerOutcome = 'exited' | 'spec_not_enforced' | 'start_failed';

interface ContainerRun {
  outcome: ContainerOutcome;
  output: AttachOutput | null;
  oomKilled: boolean;
  exitCode: number | null;
  outerTimedOut: boolean;
  aborted: boolean;
  runnerIp: string | null;
  sinkhole: SinkholeRecord[] | null;
  runnerRemoved: boolean | null;
  mismatches: string[];
}

const delay = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export class HardenedContainerBackend implements SandboxBackend {
  readonly name = 'hardened-container' as const;
  readonly isolation = 'container' as const;
  readonly executes = true;
  private readonly docker: DockerApi;
  private readonly sinkhole: SinkholeClient;
  private readonly now: () => number;
  private readonly inFlight = new Set<string>();
  private runnerImageId: string | null = null;
  private apparmor: boolean | null = null;
  private closed = false;

  constructor(private readonly options: HardenedContainerBackendOptions) {
    this.docker = options.docker ?? new DockerClient({ socketPath: options.socketPath });
    this.sinkhole = new SinkholeClient({
      adminUrl: options.sinkhole.adminUrl,
      token: options.sinkhole.token,
      ...(options.sinkhole.transport ? { transport: options.sinkhole.transport } : {}),
    });
    this.now = options.now ?? Date.now;
    // Fail fast on a policy the spec would refuse (bad controller name, root user).
    assertHardenedSpec(
      buildRunnerSpec(
        {
          taskId: 'policy-check',
          profile: 'execute',
          limits: SELF_TEST_LIMITS,
          nowMs: this.now(),
          graceMs: 0,
        },
        this.policy(false),
      ),
      this.policy(false),
      'execute',
    );
  }

  /** `hardened-container/1+runner:<12 hex of the runner image id>` once the self-test resolved it. */
  get version(): string {
    const id = this.runnerImageId?.replace(/^sha256:/, '').slice(0, 12) ?? 'unresolved';
    return `${HARDENED_CONTAINER_VERSION}+runner:${id}`;
  }

  supports(
    task: Pick<SandboxTaskInput, 'profile' | 'sample'>,
  ): { ok: true } | { ok: false; reason: NotExecutedReason } {
    if (task.profile === 'execute' && EXECUTE_TYPES.has(task.sample.detectedType))
      return { ok: true };
    if (task.profile === 'browser' && BROWSER_TYPES.has(task.sample.detectedType))
      return { ok: true };
    return { ok: false, reason: 'type_not_supported' };
  }

  async run(task: SandboxTaskInput, ctx: RunContext): Promise<BackendObservation> {
    const support = this.supports(task);
    if (!support.ok) return notExecuted(support.reason);
    if (this.closed) throw new Error('hardened-container backend closed');
    if (ctx.signal.aborted) throw new RunAbortedError();
    const profile = task.profile as 'execute' | 'browser';
    const apparmor = await this.apparmorState(ctx.signal);
    const input = encodeRunnerInput(
      {
        taskId: task.taskId,
        profile,
        detectedType: task.sample.detectedType,
        wallTimeoutMs: task.limits.wallTimeoutMs,
        maxArtifacts: task.limits.maxArtifacts,
        maxArtifactBytes: task.limits.maxArtifactBytes,
        maxTotalArtifactBytes: task.limits.maxTotalArtifactBytes,
      },
      task.sample.bytes,
    );
    const run = await this.runContainer({
      taskId: task.taskId,
      profile,
      limits: task.limits,
      input,
      signal: ctx.signal,
      apparmor,
      logger: ctx.logger,
    });
    if (run.aborted) throw new RunAbortedError();
    const cleanup = { runnerRemoved: run.runnerRemoved, scratchRemoved: false };
    if (run.outcome === 'spec_not_enforced') {
      return failed('spec_not_enforced', cleanup);
    }
    if (run.outcome === 'start_failed') return failed('runner_start_failed', cleanup);

    const output = run.output;
    const parsed: ParsedRunnerOutput | null = output
      ? parseRunnerOutput(output.stdout, task.limits)
      : null;
    const reportSchema = profile === 'execute' ? executeReportSchema : browserReportSchema;
    const report = parsed ? reportSchema.safeParse(parsed.report) : null;
    const inputError = parsed ? inputErrorReportSchema.safeParse(parsed.report) : null;
    const limitReason = run.oomKilled || run.outerTimedOut;
    const noOutput = !parsed || parsed.problem === 'empty' || parsed.problem === 'bad_magic';
    if ((noOutput || inputError?.success) && !limitReason) {
      ctx.logger.warn(
        {
          taskId: task.taskId,
          exitCode: run.exitCode,
          problem: parsed?.problem ?? 'no_output',
          inputError: inputError?.success ? inputError.data.inputError : null,
        },
        'sandbox runner ended without a usable report',
      );
      return failed('runner_crashed', cleanup, `runner-${profile}/1`);
    }
    const outputInvalid =
      !parsed ||
      parsed.problem !== null ||
      !report?.success ||
      output?.stdoutTruncated === true ||
      output?.framingError === true;
    const executeReport = report?.success && report.data.mode === 'execute' ? report.data : null;
    const trace: TraceSummary | null =
      profile === 'execute' && parsed
        ? parseTrace(parsed.trace.toString('utf8'), {
            timedOut: run.outerTimedOut || executeReport?.timedOut === true,
            oomKilled: run.oomKilled,
          })
        : null;
    const built = buildObservation({
      profile,
      limits: task.limits,
      sinkholeIp: this.options.sinkhole.dns,
      output: parsed,
      report: report?.success ? report.data : null,
      outputInvalid,
      trace,
      oomKilled: run.oomKilled,
      exitCode: run.exitCode,
      outerTimedOut: run.outerTimedOut,
      sinkhole: run.sinkhole,
    });
    for (const limit of built.limitsHit) this.options.metrics?.limitHit?.(limit);
    ctx.logger.info(
      {
        taskId: task.taskId,
        profile,
        exitCode: run.exitCode,
        oomKilled: run.oomKilled,
        outerTimedOut: run.outerTimedOut,
        findings: built.observations.findings.length,
        limitsHit: built.limitsHit,
        artifacts: built.artifacts.length,
        runnerRemoved: run.runnerRemoved,
        isolation: ISOLATION_LABEL_VALUE,
      },
      'sandbox runner finished (hardened container, not a VM boundary)',
    );
    return {
      status: 'completed',
      executed: true,
      notExecutedReason: null,
      errorCode: null,
      observations: built.observations,
      artifacts: built.artifacts,
      analyzerVersion: profile === 'execute' ? 'runner-bootstrap/1' : 'sandbox-render/1',
      cleanup,
    };
  }

  async selfTest(signal: AbortSignal): Promise<BackendSelfTest> {
    const base = { isolation: ISOLATION_LABEL_VALUE, vmBoundary: false };
    try {
      await this.docker.ping(signal);
    } catch {
      return { ok: false, code: 'docker_unreachable', details: { ...base } };
    }
    try {
      const version = await this.docker.version(signal);
      const info = await this.docker.info(signal);
      const apparmor = daemonHasAppArmor(info.SecurityOptions);
      const seccomp = daemonHasSeccomp(info.SecurityOptions);
      this.apparmor = apparmor;
      const details: Record<string, string | number | boolean> = {
        ...base,
        dockerVersion: String(version.Version).slice(0, 32),
        apparmor,
        seccomp,
      };
      const image = await this.docker.inspectImage(this.options.images.runner, signal);
      if (!image)
        return {
          ok: false,
          code: 'self_test_failed',
          details: { ...details, reason: 'runner_image_missing' },
        };
      this.runnerImageId = image.Id;
      details.runnerImage = image.Id.replace(/^sha256:/, '').slice(0, 12);
      details.browserImage =
        (await this.docker.inspectImage(this.options.images.browser, signal)) !== null;
      const network = await this.docker.inspectNetwork(this.options.network, signal);
      if (!network || network.Internal !== true) {
        return {
          ok: false,
          code: 'spec_not_enforced',
          details: { ...details, reason: 'network_not_internal' },
        };
      }
      details.gatewayIsolated = detonationGatewayIsolated(network);
      if (!details.gatewayIsolated) {
        return {
          ok: false,
          code: 'spec_not_enforced',
          details: { ...details, reason: 'network_gateway_reachable' },
        };
      }
      if (!seccomp) {
        return {
          ok: false,
          code: 'spec_not_enforced',
          details: { ...details, reason: 'seccomp_unavailable' },
        };
      }
      const run = await this.runContainer({
        taskId: `selftest-${randomBytes(6).toString('hex')}`,
        profile: 'self-test',
        limits: SELF_TEST_LIMITS,
        input: Buffer.alloc(0),
        signal,
        apparmor,
        logger: this.options.logger,
      });
      details.runnerRemoved = run.runnerRemoved === true;
      if (run.outcome === 'spec_not_enforced') {
        return {
          ok: false,
          code: 'spec_not_enforced',
          details: {
            ...details,
            reason: 'verify_created',
            mismatches: run.mismatches.join(',').slice(0, 200),
          },
        };
      }
      if (run.outcome === 'start_failed' || !run.output) {
        return {
          ok: false,
          code: 'self_test_failed',
          details: { ...details, reason: 'probe_not_started' },
        };
      }
      const parsed = parseRunnerOutput(run.output.stdout, SELF_TEST_LIMITS);
      const judgement = judgeSelfTest(parsed.report, {
        sinkholeDns: this.options.sinkhole.dns,
        apparmor,
      });
      const merged = {
        ...details,
        ...judgement.details,
        apparmor: judgement.details.apparmor === true,
        seccomp: seccomp && judgement.details.seccomp === true,
        ...(judgement.failures.length > 0
          ? { failures: judgement.failures.join(',').slice(0, 200) }
          : {}),
      };
      if (!judgement.ok || run.runnerRemoved !== true) {
        return { ok: false, code: 'spec_not_enforced', details: merged };
      }
      return { ok: true, code: 'ok', details: merged };
    } catch (error) {
      this.options.logger.error(
        { errName: error instanceof Error ? error.name : typeof error },
        'sandbox hardened-container self-test failed',
      );
      return { ok: false, code: 'self_test_failed', details: { ...base, reason: 'error' } };
    }
  }

  async reap(active: ReadonlySet<string>, mode: 'startup' | 'periodic'): Promise<ReapReport> {
    const list = await this.docker.listContainers([
      `${RUNNER_LABELS.runner}=1`,
      `${RUNNER_LABELS.controller}=${this.options.controllerName}`,
    ]);
    const nowSeconds = this.now() / 1000;
    let runnersRemoved = 0;
    let failures = 0;
    for (const container of list) {
      const labels = container.Labels ?? {};
      if (
        labels[RUNNER_LABELS.runner] !== '1' ||
        labels[RUNNER_LABELS.controller] !== this.options.controllerName
      )
        continue;
      const task = labels[RUNNER_LABELS.task] ?? '';
      if (active.has(task) || this.inFlight.has(container.Id)) continue;
      if (mode === 'periodic') {
        const expires = Number(labels[RUNNER_LABELS.expires]);
        if (Number.isFinite(expires) && expires > nowSeconds) continue;
      }
      if (await this.removeRunner(container.Id, this.options.logger)) runnersRemoved += 1;
      else failures += 1;
    }
    if (runnersRemoved > 0) {
      this.options.metrics?.reaped?.('runner', mode, runnersRemoved);
      this.options.logger.warn(
        { mode, runnersRemoved, failures },
        'sandbox reaper removed runners',
      );
    }
    return { runnersRemoved, scratchRemoved: 0, failures };
  }

  async close(): Promise<void> {
    this.closed = true;
    const deadline = this.now() + 10_000;
    while (this.inFlight.size > 0 && this.now() < deadline) await delay(100);
  }

  // -------------------------------------------------------------------------------------------

  private policy(apparmor: boolean): RunnerPolicy {
    return {
      images: this.options.images,
      network: this.options.network,
      sinkholeDns: this.options.sinkhole.dns,
      controllerName: this.options.controllerName,
      apparmor,
      ...(this.options.runnerUser ? { user: this.options.runnerUser } : {}),
    };
  }

  private async apparmorState(signal: AbortSignal): Promise<boolean> {
    if (this.apparmor === null) {
      const info = await this.docker.info(signal);
      this.apparmor = daemonHasAppArmor(info.SecurityOptions);
    }
    return this.apparmor;
  }

  private async runContainer(params: {
    taskId: string;
    profile: RunnerProfile;
    limits: TaskLimits;
    input: Buffer;
    signal: AbortSignal;
    apparmor: boolean;
    logger: Logger;
  }): Promise<ContainerRun> {
    const { taskId, profile, limits, signal, logger } = params;
    const policy = this.policy(params.apparmor);
    const spec = buildRunnerSpec(
      {
        taskId,
        profile,
        limits,
        nowMs: this.now(),
        graceMs: this.options.graceMs ?? DEFAULT_GRACE_MS,
      },
      policy,
    );
    const run: ContainerRun = {
      outcome: 'exited',
      output: null,
      oomKilled: false,
      exitCode: null,
      outerTimedOut: false,
      aborted: false,
      runnerIp: null,
      sinkhole: null,
      runnerRemoved: null,
      mismatches: [],
    };
    const name = `eg-sbx-${taskId.slice(0, 40)}-${randomBytes(4).toString('hex')}`;
    let id: string | null = null;
    let attach: AttachStream | null = null;
    let startedAt = this.now();
    try {
      try {
        id = (await this.docker.createContainer(spec, name, signal)).Id;
      } catch (error) {
        if (error instanceof DockerApiError) {
          logger.error({ taskId, status: error.statusCode }, 'sandbox runner create failed');
          run.outcome = 'start_failed';
          return run;
        }
        throw error;
      }
      this.inFlight.add(id);
      const verdict = verifyCreated(await this.docker.inspectContainer(id, signal), {
        policy,
        spec,
      });
      if (!verdict.ok) {
        run.outcome = 'spec_not_enforced';
        run.mismatches = verdict.mismatches;
        logger.error(
          { taskId, containerId: id, mismatches: verdict.mismatches },
          'sandbox runner spec not enforced; removed without start',
        );
        return run;
      }
      attach = await this.docker.attachContainer(id, { maxStdoutBytes: maxOutputBytes(limits) });
      try {
        startedAt = this.now();
        await this.docker.startContainer(id, signal);
      } catch (error) {
        if (error instanceof DockerApiError) {
          logger.error(
            { taskId, containerId: id, status: error.statusCode },
            'sandbox runner start failed',
          );
          run.outcome = 'start_failed';
          return run;
        }
        throw error;
      }
      this.options.metrics?.runnerStarted?.(profile);
      const started = await this.docker.inspectContainer(id, signal);
      const ip = started?.NetworkSettings?.Networks?.[this.options.network]?.IPAddress;
      run.runnerIp = ip && ip.length > 0 ? ip : null;

      await attach.write(params.input).catch(() => undefined);
      attach.endStdin();

      const waitAbort = new AbortController();
      const killing: { promise: Promise<void> | null } = { promise: null };
      const runnerId = id;
      const kill = () => {
        killing.promise ??= this.docker.killContainer(runnerId).catch(() => undefined);
      };
      const outer = setTimeout(
        () => {
          run.outerTimedOut = true;
          kill();
        },
        limits.wallTimeoutMs + (this.options.outerSlackMs ?? OUTER_SLACK_MS),
      );
      const onAbort = () => {
        run.aborted = true;
        kill();
      };
      signal.addEventListener('abort', onAbort, { once: true });
      try {
        const waited = await this.docker.waitContainer(id, waitAbort.signal).catch(() => null);
        run.exitCode = waited?.StatusCode ?? null;
      } finally {
        clearTimeout(outer);
        signal.removeEventListener('abort', onAbort);
        waitAbort.abort();
        if (killing.promise) await killing.promise;
      }
      const stream = attach;
      run.output = await Promise.race([
        stream.collect(),
        delay(this.options.attachDrainMs ?? ATTACH_DRAIN_MS).then(() => {
          stream.destroy();
          return stream.collect();
        }),
      ]);
      const ended = await this.docker.inspectContainer(id).catch(() => null);
      run.oomKilled = ended?.State?.OOMKilled === true;
      if (typeof ended?.State?.ExitCode === 'number') run.exitCode = ended.State.ExitCode;
      if (run.runnerIp && profile !== 'self-test') {
        run.sinkhole = await this.collectSinkhole(run.runnerIp, startedAt, logger, taskId);
      } else if (run.runnerIp) {
        await this.sinkhole
          .clearRecords(run.runnerIp)
          .catch(() => this.options.metrics?.sinkholeError?.('clear'));
      }
      return run;
    } finally {
      attach?.destroy();
      if (id) {
        run.runnerRemoved = await this.removeRunner(id, logger);
        this.inFlight.delete(id);
      }
    }
  }

  private async collectSinkhole(
    ip: string,
    startedAt: number,
    logger: Logger,
    taskId: string,
  ): Promise<SinkholeRecord[] | null> {
    let records: SinkholeRecord[] | null = null;
    try {
      records = (await this.sinkhole.fetchRecords(ip, startedAt - SINKHOLE_WINDOW_SLACK_MS))
        .records;
    } catch {
      this.options.metrics?.sinkholeError?.('fetch');
      logger.warn({ taskId }, 'sandbox sinkhole records unavailable');
    }
    try {
      await this.sinkhole.clearRecords(ip);
    } catch {
      this.options.metrics?.sinkholeError?.('clear');
      logger.warn({ taskId }, 'sandbox sinkhole records not cleared');
    }
    return records;
  }

  /** kill + `DELETE ?force=true&v=true`, retried with backoff; true when the runner is gone. */
  private async removeRunner(id: string, logger: Logger): Promise<boolean> {
    const backoff = this.options.removeBackoffMs ?? DEFAULT_REMOVE_BACKOFF_MS;
    const attempts = Math.max(1, backoff.length);
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      try {
        await this.docker.killContainer(id).catch(() => undefined);
        await this.docker.removeContainer(id);
        return true;
      } catch (error) {
        logger.warn(
          {
            containerId: id,
            attempt: attempt + 1,
            errName: error instanceof Error ? error.name : typeof error,
          },
          'sandbox runner removal failed; retrying',
        );
        if (attempt < attempts - 1) await delay(backoff[attempt] ?? 0);
      }
    }
    this.options.metrics?.cleanupFailure?.('runner');
    logger.error({ containerId: id }, 'sandbox runner could not be removed');
    return false;
  }
}

/**
 * True when the detonation bridge has no address on the Docker host side
 * (`com.docker.network.bridge.gateway_mode_ipv4=isolated` or `inhibit_ipv4`): otherwise runners
 * can open connections to listeners of the Docker host / VM on the bridge gateway (§12 WP4).
 */
export function detonationGatewayIsolated(network: NetworkInspect): boolean {
  const options = network.Options ?? {};
  return (
    options['com.docker.network.bridge.gateway_mode_ipv4'] === 'isolated' ||
    options['com.docker.network.bridge.inhibit_ipv4'] === 'true'
  );
}

function notExecuted(reason: NotExecutedReason): BackendObservation {
  return {
    status: 'not_executed',
    executed: false,
    notExecutedReason: reason,
    errorCode: null,
    observations: emptySandboxObservations(),
    artifacts: [],
    analyzerVersion: null,
    cleanup: { runnerRemoved: null, scratchRemoved: false },
  };
}

function failed(
  errorCode: 'spec_not_enforced' | 'runner_start_failed' | 'runner_crashed',
  cleanup: BackendObservation['cleanup'],
  analyzerVersion: string | null = null,
): BackendObservation {
  return {
    status: 'failed',
    executed: errorCode === 'runner_crashed',
    notExecutedReason: null,
    errorCode,
    observations: emptySandboxObservations(),
    artifacts: [],
    analyzerVersion,
    cleanup,
  };
}
