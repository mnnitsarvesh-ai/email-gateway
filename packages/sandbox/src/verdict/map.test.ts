import {
  SANDBOX_ERROR_CODES,
  SANDBOX_FINDING_CODES,
  SANDBOX_FINDING_SEVERITY,
  SANDBOX_ISOLATION_CLASSES,
  SANDBOX_LIMITS,
  SANDBOX_NOT_EXECUTED_REASONS,
  SANDBOX_REASON_CODES,
  SANDBOX_SKIP_REASONS,
  type SandboxFindingCode,
  type SandboxIsolationClass,
  type SandboxLimit,
  type SandboxVerdict,
} from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import {
  aggregateSubmissions,
  DEFAULT_MIN_RUNTIME_MS,
  mapAnalysis,
  orderReasonCodes,
  SANDBOX_MAP_VERSION,
  SandboxMapError,
  type SandboxResultForMap,
  type SandboxSubmissionOutcome,
  submissionSkipCodes,
} from './map';

const result = (overrides: Partial<SandboxResultForMap> = {}): SandboxResultForMap => ({
  kind: 'result',
  status: 'completed',
  executed: false,
  isolation: 'process',
  notExecutedReason: null,
  errorCode: null,
  durationMs: 1_000,
  findings: [],
  limitsHit: [],
  ...overrides,
});
const f = (...codes: SandboxFindingCode[]) => codes.map((code) => ({ code }));
const vm = (overrides: Partial<SandboxResultForMap> = {}) =>
  result({ executed: true, isolation: 'vm', durationMs: DEFAULT_MIN_RUNTIME_MS, ...overrides });

describe('sandbox-map/1 rules (X14)', () => {
  it('F1: failed → error with sandbox.error and sandbox.error.<code>', () => {
    for (const code of SANDBOX_ERROR_CODES) {
      const r = mapAnalysis(result({ status: 'failed', errorCode: code }));
      expect(r).toMatchObject({ verdict: 'error', rule: 'F1', mapVersion: 'sandbox-map/1' });
      expect(r.reasonCodes).toEqual(['sandbox.error', `sandbox.error.${code}`].sort());
    }
    expect(() => mapAnalysis(result({ status: 'failed' }))).toThrow(SandboxMapError);
    expect(() => mapAnalysis(result({ status: 'failed', errorCode: 'bogus' as never }))).toThrow(
      SandboxMapError,
    );
  });

  it('F2: expired → timeout with sandbox.timeout', () => {
    expect(mapAnalysis({ kind: 'expired' })).toEqual({
      verdict: 'timeout',
      reasonCodes: ['sandbox.timeout'],
      rule: 'F2',
      rules: ['F2'],
      mapVersion: SANDBOX_MAP_VERSION,
    });
  });

  it('N1: not_executed → unknown, never clean, for every reason and backend', () => {
    for (const reason of SANDBOX_NOT_EXECUTED_REASONS) {
      for (const isolation of SANDBOX_ISOLATION_CLASSES) {
        const r = mapAnalysis(
          result({ status: 'not_executed', notExecutedReason: reason, isolation }),
        );
        expect(r.verdict).toBe('unknown');
        expect(r.rule).toBe('N1');
        expect(r.reasonCodes).toEqual(['sandbox.not_executed', `sandbox.not_executed.${reason}`]);
      }
    }
    expect(() => mapAnalysis(result({ status: 'not_executed' }))).toThrow(SandboxMapError);
    expect(() =>
      mapAnalysis(
        result({ status: 'not_executed', notExecutedReason: 'backend_disabled', executed: true }),
      ),
    ).toThrow(SandboxMapError);
  });

  it('M1: a critical or high finding → malicious (EICAR, metadata access, auto-exec shell macro)', () => {
    for (const code of [
      'static.eicar_test',
      'behaviour.metadata_access',
      'static.office_auto_exec_shell',
    ] as const) {
      const r = mapAnalysis(result({ findings: f(code) }));
      expect(r.verdict, code).toBe('malicious');
      expect(r.rule).toBe('M1');
      expect(r.reasonCodes).toContain(`sandbox.${code}`);
    }
    // U1 also fired: its code explains that it was a static-only run.
    expect(mapAnalysis(result({ findings: f('static.eicar_test') })).reasonCodes).toEqual([
      'sandbox.static_only',
      'sandbox.static.eicar_test',
    ]);
    // Every high/critical code is malicious on its own.
    for (const code of SANDBOX_FINDING_CODES) {
      const severity = SANDBOX_FINDING_SEVERITY[code];
      if (severity === 'high' || severity === 'critical') {
        expect(mapAnalysis(result({ findings: f(code) })).verdict, code).toBe('malicious');
      }
    }
  });

  it('S1: a medium finding or a raising limit → suspicious; wall_timeout/output_truncated/artifact_cap never raise', () => {
    expect(mapAnalysis(result({ findings: f('static.script_obfuscation') }))).toMatchObject({
      verdict: 'suspicious',
      rule: 'S1',
      rules: ['S1', 'U1'],
    });
    for (const limit of ['memory', 'pids', 'cpu', 'scratch_full', 'analyzer_resources'] as const) {
      const r = mapAnalysis(result({ limitsHit: [limit] }));
      expect(r.verdict, limit).toBe('suspicious');
      expect(r.reasonCodes).toContain(`sandbox.limit.${limit}`);
    }
    for (const limit of ['wall_timeout', 'output_truncated', 'artifact_cap'] as const) {
      const r = mapAnalysis(result({ limitsHit: [limit] }));
      expect(r.verdict, limit).toBe('unknown');
      expect(r.reasonCodes).toContain(`sandbox.limit.${limit}`);
      expect(r.rule).toBe('U1');
    }
    // The same limit as a finding and as a hit yields one code.
    const r = mapAnalysis(result({ findings: f('limit.memory'), limitsHit: ['memory'] }));
    expect(r.reasonCodes.filter((c) => c === 'sandbox.limit.memory')).toHaveLength(1);
    // M1 wins over S1 (first match), both contribute codes.
    const both = mapAnalysis(
      result({ findings: f('static.pe_packed', 'static.pe_injection_imports') }),
    );
    expect(both).toMatchObject({ verdict: 'malicious', rules: ['M1', 'S1', 'U1'] });
    expect(both.reasonCodes).toEqual([
      'sandbox.static_only',
      'sandbox.static.pe_injection_imports',
      'sandbox.static.pe_packed',
    ]);
  });

  it('low and info findings are kept as codes but never raise the verdict', () => {
    const lowInfo = SANDBOX_FINDING_CODES.filter((c) =>
      ['low', 'info'].includes(SANDBOX_FINDING_SEVERITY[c]),
    );
    for (const code of lowInfo) {
      const r = mapAnalysis(result({ findings: f(code) }));
      expect(r.verdict, code).toBe('unknown');
      expect(r.reasonCodes).toContain(`sandbox.${code}`);
    }
    // sandbox.no_findings only when no finding is ≥ low (info is not a finding for that purpose).
    expect(mapAnalysis(result({ findings: f('static.embedded_urls') })).reasonCodes).toEqual([
      'sandbox.no_findings',
      'sandbox.static_only',
      'sandbox.static.embedded_urls',
    ]);
    expect(mapAnalysis(result({ findings: f('static.high_entropy') })).reasonCodes).not.toContain(
      'sandbox.no_findings',
    );
  });

  it('U1: a completed static-only run is unknown, never clean, whatever the isolation', () => {
    for (const isolation of SANDBOX_ISOLATION_CLASSES) {
      const r = mapAnalysis(result({ isolation, durationMs: 10 * DEFAULT_MIN_RUNTIME_MS }));
      expect(r).toMatchObject({ verdict: 'unknown', rule: 'U1' });
      expect(r.reasonCodes).toEqual(['sandbox.no_findings', 'sandbox.static_only']);
    }
  });

  it('U2: an executed run without VM isolation is unknown (container is not a VM boundary)', () => {
    for (const isolation of ['none', 'process', 'container'] as const) {
      const r = mapAnalysis(
        result({ executed: true, isolation, durationMs: 10 * DEFAULT_MIN_RUNTIME_MS }),
      );
      expect(r).toMatchObject({ verdict: 'unknown', rule: 'U2' });
      expect(r.reasonCodes).toEqual(['sandbox.no_findings', 'sandbox.not_vm_isolated']);
    }
    expect(
      mapAnalysis(
        result({ executed: true, isolation: 'container', findings: f('behaviour.dns_queries') }),
      ).reasonCodes,
    ).toEqual(['sandbox.no_findings', 'sandbox.not_vm_isolated', 'sandbox.behaviour.dns_queries']);
  });

  it('U3: a VM run shorter than minRuntimeMs, with evasion, or with lost evidence is unknown', () => {
    expect(mapAnalysis(vm({ durationMs: DEFAULT_MIN_RUNTIME_MS - 1 }))).toMatchObject({
      verdict: 'unknown',
      rule: 'U3',
      reasonCodes: ['sandbox.incomplete_run'],
    });
    expect(mapAnalysis(vm({ findings: f('evasion.long_sleep') })).reasonCodes).toEqual([
      'sandbox.evasion_suspected',
      'sandbox.evasion.long_sleep',
    ]);
    expect(
      mapAnalysis(vm({ durationMs: 10, findings: f('evasion.environment_checks') })).reasonCodes,
    ).toEqual([
      'sandbox.evasion_suspected',
      'sandbox.incomplete_run',
      'sandbox.evasion.environment_checks',
    ]);
    for (const limit of ['output_truncated', 'artifact_cap'] as const) {
      expect(mapAnalysis(vm({ limitsHit: [limit] })).verdict, limit).toBe('unknown');
    }
    // Only low findings on a complete VM run: unknown (U3), the low code kept.
    expect(mapAnalysis(vm({ findings: f('behaviour.http_requests') }))).toMatchObject({
      verdict: 'unknown',
      rule: 'U3',
      reasonCodes: ['sandbox.behaviour.http_requests'],
    });
    expect(mapAnalysis(vm({ durationMs: 999 }), { minRuntimeMs: 1000 }).verdict).toBe('unknown');
    expect(() => mapAnalysis(vm(), { minRuntimeMs: -1 })).toThrow(SandboxMapError);
  });

  it('C1: clean only for a complete VM-isolated executed run without findings ≥ low (boundary at minRuntimeMs)', () => {
    expect(mapAnalysis(vm())).toEqual({
      verdict: 'clean',
      reasonCodes: ['sandbox.no_findings'],
      rule: 'C1',
      rules: ['C1'],
      mapVersion: 'sandbox-map/1',
    });
    expect(
      mapAnalysis(vm({ findings: f('behaviour.process_spawn', 'behaviour.dns_queries') })).verdict,
    ).toBe('clean');
    expect(mapAnalysis(vm({ limitsHit: ['wall_timeout'] })).verdict).toBe('clean');
    expect(mapAnalysis(vm({ durationMs: 1000 }), { minRuntimeMs: 1000 }).verdict).toBe('clean');
  });

  it('never yields clean outside C1 (exhaustive over status × executed × isolation × finding)', () => {
    const findingSets: SandboxFindingCode[][] = [[], ...SANDBOX_FINDING_CODES.map((c) => [c])];
    for (const status of ['completed', 'not_executed', 'failed'] as const) {
      for (const executed of [false, true]) {
        if (status === 'not_executed' && executed) continue;
        for (const isolation of SANDBOX_ISOLATION_CLASSES) {
          for (const findings of findingSets) {
            for (const durationMs of [0, DEFAULT_MIN_RUNTIME_MS]) {
              const r = mapAnalysis(
                result({
                  status,
                  executed,
                  isolation,
                  durationMs,
                  findings: f(...findings),
                  notExecutedReason: status === 'not_executed' ? 'backend_disabled' : null,
                  errorCode: status === 'failed' ? 'internal' : null,
                }),
              );
              if (r.verdict === 'clean') {
                expect({ status, executed, isolation, durationMs }).toEqual({
                  status: 'completed',
                  executed: true,
                  isolation: 'vm',
                  durationMs: DEFAULT_MIN_RUNTIME_MS,
                });
                expect(findings.every((c) => SANDBOX_FINDING_SEVERITY[c] === 'info')).toBe(true);
              }
              expect(r.reasonCodes.length).toBeLessThanOrEqual(16);
              for (const code of r.reasonCodes) expect(SANDBOX_REASON_CODES, code).toContain(code);
            }
          }
        }
      }
    }
  });

  it('orders codes: analysis-level first, then severity, then name; at most 16', () => {
    const many = SANDBOX_FINDING_CODES.slice(0, 32);
    const r = mapAnalysis(result({ findings: f(...many) }));
    expect(r.reasonCodes).toHaveLength(16);
    expect(r.reasonCodes[0]).toBe('sandbox.static_only');
    expect(r.reasonCodes[1]).toBe('sandbox.static.eicar_test'); // the only critical code
    const severities = r.reasonCodes
      .slice(1)
      .map((c) => SANDBOX_FINDING_SEVERITY[c.slice('sandbox.'.length) as SandboxFindingCode]);
    const rank = ['info', 'low', 'medium', 'high', 'critical'];
    const ranks = severities.map((s) => rank.indexOf(s));
    expect([...ranks].sort((a, b) => b - a)).toEqual(ranks);
    expect(
      orderReasonCodes(['sandbox.static.pe_packed', 'sandbox.static.elf_packed', 'sandbox.error']),
    ).toEqual(['sandbox.error', 'sandbox.static.elf_packed', 'sandbox.static.pe_packed']);
    expect(orderReasonCodes(['b.x', 'a.x', 'sandbox.timeout', 'sandbox.timeout'])).toEqual([
      'sandbox.timeout',
      'a.x',
      'b.x',
    ]);
  });

  it('refuses unknown finding codes and limits (results are validated first)', () => {
    expect(() => mapAnalysis(result({ findings: [{ code: 'static.made_up' }] }))).toThrow(
      SandboxMapError,
    );
    expect(() => mapAnalysis(result({ limitsHit: ['disk'] }))).toThrow(SandboxMapError);
  });
});

describe('per submission and per round', () => {
  const done = (
    verdict: SandboxVerdict,
    reasonCodes: string[],
    isolation: SandboxIsolationClass | null = 'process',
    executed = false,
  ): SandboxSubmissionOutcome => ({
    status: 'completed',
    verdict,
    reasonCodes,
    executed,
    isolation,
  });
  const skipped = (reason: (typeof SANDBOX_SKIP_REASONS)[number]): SandboxSubmissionOutcome => ({
    status: 'skipped',
    skipReason: reason,
  });

  it('maps each skip reason to its code', () => {
    for (const reason of SANDBOX_SKIP_REASONS) {
      expect(submissionSkipCodes(reason)).toEqual([`sandbox.${reason}`]);
      expect(SANDBOX_REASON_CODES).toContain(`sandbox.${reason}`);
    }
    expect(() => submissionSkipCodes('bogus' as never)).toThrow(SandboxMapError);
  });

  it('aggregates malicious > suspicious > error > timeout > unknown > clean, in every order', () => {
    const items: SandboxSubmissionOutcome[] = [
      done('unknown', ['sandbox.static_only', 'sandbox.no_findings']),
      {
        status: 'failed',
        verdict: 'error',
        reasonCodes: ['sandbox.error', 'sandbox.error.internal'],
        executed: false,
        isolation: 'process',
      },
      done('suspicious', ['sandbox.static_only', 'sandbox.static.pe_packed'], 'container', true),
      {
        status: 'expired',
        verdict: 'timeout',
        reasonCodes: ['sandbox.timeout'],
        executed: false,
        isolation: null,
      },
      skipped('type_excluded'),
    ];
    const permutations = (list: SandboxSubmissionOutcome[]): SandboxSubmissionOutcome[][] =>
      list.length <= 1
        ? [list]
        : list.flatMap((item, i) =>
            permutations([...list.slice(0, i), ...list.slice(i + 1)]).map((rest) => [
              item,
              ...rest,
            ]),
          );
    const results = permutations(items).map((p) => {
      const a = aggregateSubmissions(p);
      expect(p[a.mostSevereIndex!]).toMatchObject({ verdict: 'suspicious' });
      return JSON.stringify({ ...a, mostSevereIndex: null });
    });
    expect(new Set(results).size).toBe(1);
    const a = aggregateSubmissions(items);
    expect(a.outcome).toBe('suspicious');
    expect(a.reasonCodes.slice(0, 2)).toEqual(['sandbox.static_only', 'sandbox.static.pe_packed']);
    expect(a.reasonCodes).toEqual(
      expect.arrayContaining(['sandbox.error', 'sandbox.timeout', 'sandbox.no_findings']),
    );
    expect(a.reasonCodes).not.toContain('sandbox.type_excluded');
    expect(a.evidence).toEqual({
      submissions: 5,
      executed: 1,
      isolation: ['process', 'container'],
    });

    const ladder: SandboxVerdict[] = [
      'clean',
      'unknown',
      'timeout',
      'error',
      'suspicious',
      'malicious',
    ];
    for (let i = 1; i < ladder.length; i += 1) {
      const pair = [done(ladder[i - 1]!, []), done(ladder[i]!, [])];
      expect(aggregateSubmissions(pair).outcome).toBe(ladder[i]);
      expect(aggregateSubmissions([...pair].reverse()).outcome).toBe(ladder[i]);
    }
  });

  it('is skipped (with the skip codes) only when every submission was skipped', () => {
    const a = aggregateSubmissions([
      skipped('tenant_disabled'),
      skipped('size_excluded'),
      skipped('tenant_disabled'),
    ]);
    expect(a).toEqual({
      outcome: 'skipped',
      reasonCodes: ['sandbox.size_excluded', 'sandbox.tenant_disabled'],
      mostSevereIndex: null,
      evidence: { submissions: 3, executed: 0, isolation: [] },
    });
    expect(aggregateSubmissions([skipped('tenant_disabled'), done('unknown', [])]).outcome).toBe(
      'unknown',
    );
    expect(() => aggregateSubmissions([])).toThrow(SandboxMapError);
  });

  it('caps the round codes at 16', () => {
    const codes = SANDBOX_FINDING_CODES.slice(0, 20).map((c) => `sandbox.${c}`);
    const a = aggregateSubmissions([
      done('malicious', codes.slice(0, 10)),
      done('malicious', codes.slice(10)),
    ]);
    expect(a.reasonCodes).toHaveLength(16);
  });

  it('only ever produces limits and isolation classes of the contracts', () => {
    const limits: SandboxLimit[] = [...SANDBOX_LIMITS];
    expect(mapAnalysis(result({ limitsHit: limits })).reasonCodes.length).toBeLessThanOrEqual(16);
  });
});
