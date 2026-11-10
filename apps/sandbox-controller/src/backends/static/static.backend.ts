import { randomBytes } from 'node:crypto';
import { mkdir, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Logger } from '@email-gateway/logger';
import {
  emptySandboxObservations,
  isCanonicalIp,
  SANDBOX_FINDING_SEVERITY,
  URL_HOST_PATTERN,
  type SandboxFinding,
  type SandboxLimit,
  type SandboxObservations,
} from '@email-gateway/security-contracts';
import { z } from 'zod';
import type { ScratchArea } from '../../scratch/scratch';
import type {
  BackendObservation,
  BackendSelfTest,
  RawArtifact,
  ReapReport,
  RunContext,
  SandboxBackend,
  SandboxTaskInput,
} from '../backend';
import { ANALYZER_VERSION, STATIC_FINDING_CODES, type AnalysisResult } from './analyzers/analysis';
import { STATIC_SUPPORTED_TYPES } from './analyzers/analyze';
import type { AnalyzerChildRunner, ChildOutcome } from './child-runner';

/**
 * The `static` backend (step 4.6 X3, X4; production-eligible, no execution): the sample is
 * written to `<scratch>/in/sample` (0400, never executable) and analyzed by ONE limited analyzer
 * child (`AnalyzerChildRunner`); its reply is untrusted (a parser exploit could forge it) and is
 * re-validated with a strict bounded schema before it becomes observations and the
 * `static_report` artifact. `executed` is always false.
 */

/** Upper bound of the `static_report` JSON artifact. */
export const STATIC_REPORT_MAX_BYTES = 64 * 1024;

const factValue = z.union([
  z.number().finite(),
  z.boolean(),
  z.string().regex(/^[A-Za-z0-9._+-]{0,32}$/),
]);
const unique = (values: readonly unknown[]) => new Set(values).size === values.length;

/** The analyzer child's reply, re-validated by the parent (strict, bounded). */
export const analysisResultSchema = z.strictObject({
  v: z.literal(1),
  analyzerVersion: z.literal(ANALYZER_VERSION),
  format: z.string().regex(/^[a-z]{2,16}$/),
  supported: z.boolean(),
  findings: z
    .array(
      z.strictObject({
        code: z.enum(STATIC_FINDING_CODES),
        count: z.number().int().min(1).max(1_000_000),
      }),
    )
    .max(STATIC_FINDING_CODES.length)
    .refine((f) => unique(f.map((x) => x.code)), 'Duplicate finding code'),
  facts: z
    .record(z.string().regex(/^[a-z][a-zA-Z0-9_.]{0,47}$/), factValue)
    .refine((facts) => Object.keys(facts).length <= 64, 'Too many facts'),
  hosts: z
    .array(z.string().max(253).regex(URL_HOST_PATTERN))
    .max(50)
    .refine(unique, 'Duplicate host'),
  hostTotal: z.number().int().min(0).max(1_000_000),
  ips: z.array(z.string().max(45).refine(isCanonicalIp)).max(50).refine(unique, 'Duplicate IP'),
  ipTotal: z.number().int().min(0).max(1_000_000),
  tokens: z
    .array(z.string().regex(/^[A-Za-z0-9_.()-]{1,64}$/))
    .max(64)
    .refine(unique, 'Duplicate token'),
});

const SELFTEST_SAMPLE =
  '#!/bin/sh\n# sandbox-controller static self-test (benign)\necho "self-test https://selftest.example.invalid/"\n';

export interface StaticBackendOptions {
  runner: AnalyzerChildRunner;
  scratch: ScratchArea;
  logger: Logger;
}

function findingsOf(analysis: AnalysisResult): SandboxFinding[] {
  return analysis.findings.slice(0, 32).map(({ code, count }) => ({
    code,
    severity: SANDBOX_FINDING_SEVERITY[code],
    count,
  }));
}

/** Observations of a validated analysis: findings and the static network indicators. */
export function observationsOf(
  analysis: AnalysisResult,
  limitsHit: SandboxLimit[] = [],
): SandboxObservations {
  const observations = emptySandboxObservations();
  observations.findings = findingsOf(analysis);
  const names = [...analysis.hosts, ...analysis.ips].slice(0, 50);
  observations.network.dns = names.map((name) => ({
    name,
    type: 'other' as const,
    source: 'static' as const,
  }));
  observations.network.totals.dns = Math.min(
    1_000_000,
    Math.max(names.length, analysis.hostTotal + analysis.ipTotal),
  );
  observations.limitsHit = limitsHit;
  return observations;
}

/** The bounded `static_report` JSON (no sample text: codes, counts, facts, indicators, tokens). */
export function staticReport(
  detectedType: string,
  analysis: AnalysisResult | null,
  limitsHit: SandboxLimit[],
  observations: SandboxObservations,
): RawArtifact {
  const report = {
    v: 1,
    analyzer: ANALYZER_VERSION,
    detectedType,
    format: analysis?.format ?? null,
    supported: analysis?.supported ?? null,
    findings: observations.findings,
    facts: analysis?.facts ?? {},
    indicators: {
      hosts: analysis?.hosts ?? [],
      hostTotal: analysis?.hostTotal ?? 0,
      ips: analysis?.ips ?? [],
      ipTotal: analysis?.ipTotal ?? 0,
    },
    tokens: analysis?.tokens ?? [],
    limitsHit,
  };
  let bytes = Buffer.from(JSON.stringify(report), 'utf8');
  if (bytes.length > STATIC_REPORT_MAX_BYTES) {
    bytes = Buffer.from(
      JSON.stringify({ ...report, facts: {}, tokens: [], truncated: true }),
      'utf8',
    );
  }
  return { kind: 'static_report', contentType: 'application/json', bytes };
}

function failed(errorCode: 'analyzer_crashed' | 'analyzer_timeout'): BackendObservation {
  return {
    status: 'failed',
    executed: false,
    notExecutedReason: null,
    errorCode,
    observations: emptySandboxObservations(),
    artifacts: [],
    analyzerVersion: ANALYZER_VERSION,
    cleanup: { runnerRemoved: null, scratchRemoved: false },
  };
}

export class StaticBackend implements SandboxBackend {
  readonly name = 'static' as const;
  readonly isolation = 'process' as const;
  readonly version = ANALYZER_VERSION;
  readonly executes = false;

  constructor(private readonly options: StaticBackendOptions) {}

  supports(
    task: Pick<SandboxTaskInput, 'profile' | 'sample'>,
  ): { ok: true } | { ok: false; reason: 'type_not_supported' } {
    return STATIC_SUPPORTED_TYPES.includes(task.sample.detectedType)
      ? { ok: true }
      : { ok: false, reason: 'type_not_supported' };
  }

  /** Writes the sample (0400) and runs one analyzer child on it. */
  private async analyze(
    scratchDir: string,
    bytes: Buffer,
    detectedType: string,
    signal: AbortSignal,
  ): Promise<ChildOutcome> {
    const inDir = join(scratchDir, 'in');
    const outDir = join(scratchDir, 'out');
    await mkdir(inDir, { mode: 0o700 });
    await mkdir(outDir, { mode: 0o700 });
    const samplePath = join(inDir, 'sample');
    await writeFile(samplePath, bytes, { mode: 0o400, flag: 'wx' });
    return this.options.runner.run(
      scratchDir,
      { op: 'analyze', samplePath: await realpath(samplePath), detectedType },
      signal,
    );
  }

  async run(task: SandboxTaskInput, ctx: RunContext): Promise<BackendObservation> {
    const outcome = await this.analyze(
      ctx.scratchDir,
      task.sample.bytes,
      task.sample.detectedType,
      ctx.signal,
    );
    return this.observe(task.sample.detectedType, outcome, ctx);
  }

  private observe(
    detectedType: string,
    outcome: ChildOutcome,
    ctx: RunContext,
  ): BackendObservation {
    switch (outcome.kind) {
      case 'aborted':
        throw ctx.signal.reason instanceof Error
          ? ctx.signal.reason
          : new DOMException('aborted', 'AbortError');
      case 'timeout':
        ctx.logger.warn(
          { outcome: 'analyzer_timeout' },
          'static analyzer killed at its wall timeout',
        );
        return failed('analyzer_timeout');
      case 'crashed':
      case 'error':
      case 'probe':
        ctx.logger.warn(
          {
            outcome: 'analyzer_crashed',
            reason: outcome.kind === 'crashed' ? outcome.reason : outcome.kind,
          },
          'static analyzer failed',
        );
        return failed('analyzer_crashed');
      case 'resources': {
        // The file is hostile to parsers: a finding, not a failure of the controller.
        ctx.logger.warn(
          { outcome: 'analyzer_resources', reason: outcome.reason },
          'static analyzer killed at a resource limit',
        );
        const limitsHit: SandboxLimit[] = ['analyzer_resources'];
        const observations = emptySandboxObservations();
        observations.findings = [
          {
            code: 'limit.analyzer_resources',
            severity: SANDBOX_FINDING_SEVERITY['limit.analyzer_resources'],
            count: 1,
          },
        ];
        observations.limitsHit = limitsHit;
        return {
          status: 'completed',
          executed: false,
          notExecutedReason: null,
          errorCode: null,
          observations,
          artifacts: [staticReport(detectedType, null, limitsHit, observations)],
          analyzerVersion: ANALYZER_VERSION,
          cleanup: { runnerRemoved: null, scratchRemoved: false },
        };
      }
      case 'result': {
        const parsed = analysisResultSchema.safeParse(outcome.analysis);
        if (!parsed.success) {
          ctx.logger.warn(
            { outcome: 'analyzer_output_invalid' },
            'static analyzer reply failed validation',
          );
          return failed('analyzer_crashed');
        }
        const observations = observationsOf(parsed.data);
        return {
          status: 'completed',
          executed: false,
          notExecutedReason: null,
          errorCode: null,
          observations,
          artifacts: [staticReport(detectedType, parsed.data, [], observations)],
          analyzerVersion: ANALYZER_VERSION,
          cleanup: { runnerRemoved: null, scratchRemoved: false },
        };
      }
    }
  }

  /**
   * Self-test (X3): scratch writable, a child spawns under the permission model, completes the
   * handshake and analyzes a built-in benign sample with the expected result.
   */
  async selfTest(signal: AbortSignal): Promise<BackendSelfTest> {
    const details = {
      execution: false,
      analyzerVersion: ANALYZER_VERSION,
      permissionModel: true,
      rlimit: this.options.runner.rlimitMode,
    };
    let dir: string | undefined;
    try {
      dir = await this.options.scratch.createSelfTest(randomBytes(8).toString('hex'));
      const outcome = await this.analyze(
        dir,
        Buffer.from(SELFTEST_SAMPLE, 'utf8'),
        'script_shell',
        signal,
      );
      if (outcome.kind !== 'result')
        return {
          ok: false,
          code: 'self_test_failed',
          details: { ...details, outcome: outcome.kind },
        };
      const parsed = analysisResultSchema.safeParse(outcome.analysis);
      const ok =
        parsed.success &&
        parsed.data.format === 'script' &&
        parsed.data.hosts.includes('selftest.example.invalid') &&
        parsed.data.findings.every((f) => f.code === 'static.embedded_urls');
      return ok
        ? { ok: true, code: 'ok', details }
        : {
            ok: false,
            code: 'self_test_failed',
            details: { ...details, outcome: 'unexpected_result' },
          };
    } catch {
      return {
        ok: false,
        code: 'self_test_failed',
        details: { ...details, outcome: 'scratch_or_spawn' },
      };
    } finally {
      if (dir) await this.options.scratch.remove(dir).catch(() => false);
    }
  }

  /** Children are killed and awaited per task; nothing of this backend outlives a task. */
  reap(): Promise<ReapReport> {
    return Promise.resolve({ runnersRemoved: 0, scratchRemoved: 0, failures: 0 });
  }

  get activeChildren(): number {
    return this.options.runner.active;
  }

  async close(): Promise<void> {
    await this.options.runner.close();
  }
}
