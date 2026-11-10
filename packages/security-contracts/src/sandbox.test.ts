import { describe, expect, it } from 'vitest';
import {
  ARTIFACT_CONTENT_TYPES,
  ARTIFACT_KIND_CONTENT_TYPE,
  ARTIFACT_KINDS,
  buildSandboxReportView,
  emptySandboxObservations,
  FILE_TYPE_IDS,
  isCanonicalIp,
  isSandboxFindingCode,
  isSandboxReasonCode,
  REASON_CODE_MAX_LENGTH,
  REASON_CODE_PATTERN,
  resolveSandboxSettings,
  SANDBOX_ANALYSIS_STATUSES,
  SANDBOX_BACKEND_ISOLATION,
  SANDBOX_BACKENDS,
  SANDBOX_DEFAULT_FILE_TYPES,
  SANDBOX_ERROR_CODES,
  SANDBOX_FINDING_CODES,
  SANDBOX_FINDING_SEVERITY,
  SANDBOX_ISOLATION_CLASSES,
  SANDBOX_LIMITS,
  SANDBOX_MAPPING_VERSION,
  SANDBOX_NOT_EXECUTED_REASONS,
  SANDBOX_OBSERVATION_BOUNDS,
  SANDBOX_PLATFORM_DEFAULTS,
  SANDBOX_PLATFORM_ENV_KEYS,
  SANDBOX_PROFILES,
  SANDBOX_REASON_CODES,
  SANDBOX_SKIP_REASONS,
  SANDBOX_SUBMISSION_STATUSES,
  SANDBOX_TASK_LIMIT_BOUNDS,
  SANDBOX_VERDICTS,
  type SandboxObservations,
  sandboxFindingSeverityRank,
  sandboxObservationsSchema,
  sandboxPlatformSettingsFromEnv,
  sandboxPlatformSettingsSchema,
  sandboxReasonCodesSchema,
  sandboxReportViewSchema,
  sandboxSettingsBounds,
  sandboxSettingsVersion,
  sandboxTaskLimitsSchema,
  sandboxTenantSettingsSchema,
  sandboxVerdictRank,
} from './index';

const hex = (c: string) => c.repeat(64);

/** A maximal, valid observation (every list at its bound). */
function maximalObservations(): SandboxObservations {
  const b = SANDBOX_OBSERVATION_BOUNDS;
  return {
    processes: Array.from({ length: b.processes }, (_, i) => ({
      seq: i,
      parentSeq: i === 0 ? null : i - 1,
      image: i % 2 === 0 ? 'sh' : 'node',
      argvSha256: hex('a'),
      exitCode: i % 3 === 0 ? null : 0,
      killedBy: i === 5 ? ('timeout' as const) : null,
    })),
    processCount: 1000,
    network: {
      dns: Array.from({ length: b.dns }, (_, i) => ({
        name: `host-${i}.example.test`,
        type: 'A' as const,
        source: 'sinkhole' as const,
      })),
      http: Array.from({ length: b.http }, (_, i) => ({
        host: `h${i}.example.test`,
        port: 80,
        method: 'GET' as const,
        pathSha256: hex('b'),
        userAgentSha256: null,
      })),
      tls: Array.from({ length: b.tls }, (_, i) => ({ sni: `t${i}.example.test`, port: 443 })),
      connections: Array.from({ length: b.connections }, (_, i) => ({
        ip: `10.0.0.${i + 1}`,
        port: 5432,
        protocol: 'tcp' as const,
        outcome: 'unreachable' as const,
      })),
      totals: { dns: 999, http: 999, tls: 999, connections: 999 },
    },
    files: {
      dropped: Array.from({ length: b.droppedFiles }, (_, i) => ({
        seq: i,
        sha256: hex('c'),
        sizeBytes: 10,
        typeHint: 'pe_executable' as const,
      })),
      deniedWrites: 3,
    },
    findings: SANDBOX_FINDING_CODES.slice(0, b.findings).map((code) => ({
      code,
      severity: SANDBOX_FINDING_SEVERITY[code],
      count: 1_000_000,
    })),
    limitsHit: [...SANDBOX_LIMITS],
    browser: {
      navigations: 1,
      requests: 2,
      downloadsAttempted: 1,
      dialogs: 0,
      passwordFields: 1,
      forms: 1,
    },
  };
}

describe('sandbox vocabularies (§4)', () => {
  it('lists exactly the design values (equal to the Prisma enums where one exists)', () => {
    expect(SANDBOX_MAPPING_VERSION).toBe('sandbox-map/1');
    expect([...SANDBOX_VERDICTS]).toEqual([
      'clean',
      'suspicious',
      'malicious',
      'unknown',
      'error',
      'timeout',
    ]);
    expect([...SANDBOX_BACKENDS]).toEqual(['disabled', 'static', 'hardened-container', 'vm']);
    expect([...SANDBOX_ISOLATION_CLASSES]).toEqual(['none', 'process', 'container', 'vm']);
    expect(SANDBOX_BACKEND_ISOLATION).toEqual({
      disabled: 'none',
      static: 'process',
      'hardened-container': 'container',
      vm: 'vm',
    });
    expect([...SANDBOX_PROFILES]).toEqual(['static', 'execute', 'browser']);
    expect([...SANDBOX_NOT_EXECUTED_REASONS]).toEqual([
      'backend_disabled',
      'type_not_supported',
      'profile_not_supported',
      'size_exceeded',
      'deadline_passed',
    ]);
    expect(SANDBOX_ERROR_CODES).toHaveLength(10);
    expect(SANDBOX_ERROR_CODES).toContain('spec_not_enforced');
    expect([...SANDBOX_SKIP_REASONS]).toEqual([
      'feature_disabled',
      'tenant_disabled',
      'type_excluded',
      'size_excluded',
      'part_unavailable',
      'part_integrity',
    ]);
    expect([...SANDBOX_ANALYSIS_STATUSES]).toEqual([
      'pending',
      'dispatched',
      'completed',
      'not_executed',
      'failed',
      'expired',
    ]);
    expect(SANDBOX_SUBMISSION_STATUSES.at(-1)).toBe('skipped');
    expect([...ARTIFACT_KINDS]).toEqual([
      'screenshot',
      'process_log',
      'network_log',
      'static_report',
      'dropped_file',
    ]);
    for (const kind of ARTIFACT_KINDS) {
      expect(ARTIFACT_CONTENT_TYPES).toContain(ARTIFACT_KIND_CONTENT_TYPE[kind]);
    }
    expect(ARTIFACT_KIND_CONTENT_TYPE.screenshot).toBe('image/png');
  });

  it('orders verdicts for the round aggregation: malicious > suspicious > error > timeout > unknown > clean', () => {
    const ordered = [...SANDBOX_VERDICTS].sort(
      (a, b) => sandboxVerdictRank(b) - sandboxVerdictRank(a),
    );
    expect(ordered).toEqual(['malicious', 'suspicious', 'error', 'timeout', 'unknown', 'clean']);
  });

  it('fixes the design severities of the behaviour, browser, limit and evasion findings', () => {
    expect(SANDBOX_FINDING_SEVERITY).toMatchObject({
      'behaviour.process_spawn': 'info',
      'behaviour.shell_spawn': 'medium',
      'behaviour.many_processes': 'medium',
      'behaviour.metadata_access': 'critical',
      'behaviour.internal_network_access': 'high',
      'behaviour.direct_ip_connect': 'medium',
      'behaviour.dns_queries': 'info',
      'behaviour.http_requests': 'low',
      'behaviour.network_beacon': 'medium',
      'behaviour.dropped_files': 'low',
      'behaviour.dropped_executable': 'high',
      'behaviour.write_outside_scratch': 'medium',
      'behaviour.privilege_escalation_attempt': 'high',
      'behaviour.persistence_attempt': 'medium',
      'browser.download_attempt': 'high',
      'browser.password_form': 'medium',
      'browser.cross_origin_form': 'medium',
      'browser.js_redirect': 'low',
      'browser.dialogs': 'low',
      'limit.memory': 'medium',
      'limit.pids': 'medium',
      'limit.cpu': 'low',
      'limit.scratch_full': 'medium',
      'limit.wall_timeout': 'info',
      'limit.analyzer_resources': 'medium',
      'limit.output_truncated': 'info',
      'limit.artifact_cap': 'info',
      'evasion.long_sleep': 'low',
      'evasion.environment_checks': 'low',
      // X14 examples of M1.
      'static.eicar_test': 'critical',
      'static.office_auto_exec_shell': 'high',
    });
    // Every X4 static code is present.
    for (const code of [
      'static.pe_injection_imports',
      'static.pe_downloader_imports',
      'static.pe_packed',
      'static.pe_anti_debug',
      'static.pe_overlay',
      'static.elf_packed',
      'static.office_macro',
      'static.office_auto_exec',
      'static.office_macro_shell',
      'static.office_ole_object',
      'static.office_external_template',
      'static.office_dde',
      'static.pdf_javascript',
      'static.pdf_open_action_js',
      'static.pdf_launch',
      'static.pdf_embedded_file',
      'static.pdf_obfuscated_names',
      'static.html_smuggling',
      'static.html_password_form',
      'static.html_external_form',
      'static.html_meta_refresh_external',
      'static.html_obfuscated_script',
      'static.script_encoded_powershell',
      'static.script_download_cradle',
      'static.script_lolbin',
      'static.script_shell_exec',
      'static.script_obfuscation',
      'static.lnk_present',
      'static.lnk_command',
      'static.embedded_urls',
      'static.embedded_ips',
      'static.high_entropy',
    ]) {
      expect(isSandboxFindingCode(code), code).toBe(true);
    }
    for (const limit of SANDBOX_LIMITS) expect(isSandboxFindingCode(`limit.${limit}`)).toBe(true);
    expect(isSandboxFindingCode('static.unknown')).toBe(false);
    expect(isSandboxFindingCode('toString')).toBe(false);
    expect(sandboxFindingSeverityRank('critical')).toBeGreaterThan(
      sandboxFindingSeverityRank('high'),
    );
    expect(sandboxFindingSeverityRank('info')).toBe(0);
  });

  it('defines every reason code sandbox-map/1 can emit: unique, dotted, ≤ 64 characters', () => {
    expect(new Set(SANDBOX_REASON_CODES).size).toBe(SANDBOX_REASON_CODES.length);
    for (const code of SANDBOX_REASON_CODES) {
      expect(code, code).toMatch(REASON_CODE_PATTERN);
      expect(code.length, code).toBeLessThanOrEqual(REASON_CODE_MAX_LENGTH);
      expect(code.startsWith('sandbox.'), code).toBe(true);
    }
    const expected = [
      'sandbox.timeout',
      'sandbox.no_findings',
      'sandbox.static_only',
      'sandbox.not_vm_isolated',
      'sandbox.incomplete_run',
      'sandbox.evasion_suspected',
      'sandbox.not_executed',
      'sandbox.error',
      ...SANDBOX_NOT_EXECUTED_REASONS.map((r) => `sandbox.not_executed.${r}`),
      ...SANDBOX_ERROR_CODES.map((c) => `sandbox.error.${c}`),
      ...SANDBOX_FINDING_CODES.map((c) => `sandbox.${c}`),
      ...SANDBOX_LIMITS.map((l) => `sandbox.limit.${l}`),
      ...SANDBOX_SKIP_REASONS.map((r) => `sandbox.${r}`),
    ];
    expect([...SANDBOX_REASON_CODES].sort()).toEqual([...new Set(expected)].sort());
    expect(isSandboxReasonCode('sandbox.not_executed.backend_disabled')).toBe(true);
    expect(isSandboxReasonCode('sandbox.static.eicar_test')).toBe(true);
    expect(isSandboxReasonCode('sandbox.tenant_disabled')).toBe(true);
    expect(isSandboxReasonCode('sandbox.clean')).toBe(false);
    expect(sandboxReasonCodesSchema.safeParse(['sandbox.timeout']).success).toBe(true);
    expect(sandboxReasonCodesSchema.safeParse(['sandbox.timeout', 'sandbox.timeout']).success).toBe(
      false,
    );
    expect(sandboxReasonCodesSchema.safeParse(['sandbox.bogus']).success).toBe(false);
    expect(sandboxReasonCodesSchema.safeParse(SANDBOX_REASON_CODES.slice(0, 17)).success).toBe(
      false,
    );
  });
});

describe('task limits', () => {
  const valid = {
    wallTimeoutMs: 60_000,
    memoryMb: 512,
    cpuMillis: 1000,
    pids: 128,
    scratchMb: 64,
    maxArtifacts: 16,
    maxArtifactBytes: 2_097_152,
    maxTotalArtifactBytes: 8_388_608,
  };
  it('accepts the §5 defaults and every bound, refuses outside and unknown keys', () => {
    expect(sandboxTaskLimitsSchema.safeParse(valid).success).toBe(true);
    for (const [key, bounds] of Object.entries(SANDBOX_TASK_LIMIT_BOUNDS)) {
      expect(sandboxTaskLimitsSchema.safeParse({ ...valid, [key]: bounds.min }).success, key).toBe(
        true,
      );
      expect(sandboxTaskLimitsSchema.safeParse({ ...valid, [key]: bounds.max }).success, key).toBe(
        true,
      );
      expect(
        sandboxTaskLimitsSchema.safeParse({ ...valid, [key]: bounds.min - 1 }).success,
        key,
      ).toBe(false);
      expect(
        sandboxTaskLimitsSchema.safeParse({ ...valid, [key]: bounds.max + 1 }).success,
        key,
      ).toBe(false);
      expect(sandboxTaskLimitsSchema.safeParse({ ...valid, [key]: 1.5 }).success, key).toBe(false);
    }
    expect(sandboxTaskLimitsSchema.safeParse({ ...valid, extra: 1 }).success).toBe(false);
  });
});

describe('observations schema', () => {
  it('accepts an empty and a maximal observation', () => {
    expect(sandboxObservationsSchema.parse(emptySandboxObservations())).toEqual(
      emptySandboxObservations(),
    );
    expect(sandboxObservationsSchema.safeParse(maximalObservations()).success).toBe(true);
  });

  it('refuses lists above their bound', () => {
    const o = maximalObservations();
    const over = (mutate: (x: SandboxObservations) => void) => {
      const copy = structuredClone(o);
      mutate(copy);
      return sandboxObservationsSchema.safeParse(copy).success;
    };
    expect(
      over((x) =>
        x.processes.push({
          seq: 0,
          parentSeq: null,
          image: 'x',
          argvSha256: null,
          exitCode: null,
          killedBy: null,
        }),
      ),
    ).toBe(false);
    expect(over((x) => x.network.dns.push({ name: 'z.test', type: 'A', source: 'static' }))).toBe(
      false,
    );
    expect(over((x) => x.network.tls.push({ sni: 'z.test', port: 443 }))).toBe(false);
    expect(
      over((x) =>
        x.network.connections.push({
          ip: '10.1.1.1',
          port: 1,
          protocol: 'udp',
          outcome: 'timeout',
        }),
      ),
    ).toBe(false);
    expect(
      over((x) =>
        x.files.dropped.push({ seq: 99, sha256: hex('d'), sizeBytes: 1, typeHint: 'text' }),
      ),
    ).toBe(false);
  });

  it('refuses content-like or malformed values', () => {
    const base = emptySandboxObservations();
    const parse = (value: unknown) => sandboxObservationsSchema.safeParse(value).success;
    // A path, an argument or a space is not an image basename.
    for (const image of ['/bin/sh', 'sh -c', '', 'a'.repeat(65), 'ä']) {
      expect(
        parse({
          ...base,
          processCount: 1,
          processes: [
            { seq: 0, parentSeq: null, image, argvSha256: null, exitCode: 0, killedBy: null },
          ],
        }),
        image,
      ).toBe(false);
    }
    // A URL is not a host.
    expect(
      parse({
        ...base,
        network: {
          ...base.network,
          dns: [{ name: 'http://x.test/p', type: 'A', source: 'sinkhole' }],
          totals: { ...base.network.totals, dns: 1 },
        },
      }),
    ).toBe(false);
    // Non-canonical IPs.
    for (const ip of ['010.0.0.1', '::FFFF:1.2.3.4', '[::1]', 'fe80::1%eth0', '1.2.3', 'host']) {
      expect(
        parse({
          ...base,
          network: {
            ...base.network,
            connections: [{ ip, port: 80, protocol: 'tcp', outcome: 'refused' }],
            totals: { ...base.network.totals, connections: 1 },
          },
        }),
        ip,
      ).toBe(false);
    }
    // Unknown finding code, wrong severity, duplicate code, unknown limit, extra key.
    const finding = (code: string, severity: string) => ({
      ...base,
      findings: [{ code, severity, count: 1 }],
    });
    expect(parse(finding('static.eicar_test', 'critical'))).toBe(true);
    expect(parse(finding('static.eicar_test', 'low'))).toBe(false);
    expect(parse(finding('static.made_up', 'low'))).toBe(false);
    expect(
      parse({
        ...base,
        findings: [
          { code: 'static.pe_packed', severity: 'medium', count: 1 },
          { code: 'static.pe_packed', severity: 'medium', count: 2 },
        ],
      }),
    ).toBe(false);
    expect(parse({ ...base, limitsHit: ['disk'] })).toBe(false);
    expect(parse({ ...base, limitsHit: ['memory', 'memory'] })).toBe(false);
    expect(parse({ ...base, filename: 'invoice.exe' })).toBe(false);
    // Totals below the listed entries; processCount below the processes.
    expect(
      parse({
        ...base,
        network: {
          ...base.network,
          tls: [{ sni: 'x.test', port: 443 }],
        },
      }),
    ).toBe(false);
    expect(
      parse({
        ...base,
        processes: [
          { seq: 0, parentSeq: null, image: 'sh', argvSha256: null, exitCode: 0, killedBy: null },
        ],
      }),
    ).toBe(false);
  });

  it('recognizes canonical IP literals', () => {
    for (const ip of [
      '1.2.3.4',
      '0.0.0.0',
      '255.255.255.255',
      '::1',
      'fd00:ec2::254',
      '2001:db8::1',
    ]) {
      expect(isCanonicalIp(ip), ip).toBe(true);
    }
    for (const ip of [
      '256.1.1.1',
      '01.2.3.4',
      '2001:DB8::1',
      '2001:0db8::1',
      '::ffff:1.2.3.4',
      '',
    ]) {
      expect(isCanonicalIp(ip), ip).toBe(false);
    }
  });
});

describe('report view', () => {
  it('builds a bounded, deduplicated view ordered by severity', () => {
    const o = maximalObservations();
    const view = buildSandboxReportView(o);
    expect(sandboxReportViewSchema.safeParse(view).success).toBe(true);
    expect(view.v).toBe(1);
    expect(view.findings[0]?.severity).toBe('critical');
    const ranks = view.findings.map((f) => sandboxFindingSeverityRank(f.severity));
    expect([...ranks].sort((a, b) => b - a)).toEqual(ranks);
    expect(view.processes.images).toEqual(['sh', 'node']);
    expect(view.processes.count).toBe(1000);
    expect(view.indicators.dns).toHaveLength(50);
    expect(view.indicators.ips).toHaveLength(50);
    expect(view.droppedFiles[0]).toEqual({
      sha256: hex('c'),
      sizeBytes: 10,
      typeHint: 'pe_executable',
    });
    expect(view.limitsHit).toEqual([...SANDBOX_LIMITS]);
    expect(JSON.stringify(view)).not.toContain('pathSha256');
  });

  it('builds the view of an empty observation and refuses content', () => {
    const view = buildSandboxReportView(emptySandboxObservations());
    expect(view.findings).toEqual([]);
    expect(view.browser).toBeNull();
    expect(sandboxReportViewSchema.safeParse({ ...view, url: 'http://x' }).success).toBe(false);
    expect(
      sandboxReportViewSchema.safeParse({
        ...view,
        indicators: { ...view.indicators, dns: ['a.test', 'a.test'] },
      }).success,
    ).toBe(false);
  });
});

describe('sandbox settings (X17)', () => {
  const platform = SANDBOX_PLATFORM_DEFAULTS;

  it('has the §5 defaults and env keys', () => {
    expect(sandboxPlatformSettingsSchema.parse(platform)).toEqual(platform);
    expect(platform).toEqual({
      tenantDefaultEnabled: false,
      fileTypes: [...SANDBOX_DEFAULT_FILE_TYPES],
      maxSampleBytes: 26_214_400,
      browserAnalysis: true,
    });
    expect(SANDBOX_DEFAULT_FILE_TYPES).toHaveLength(19);
    for (const t of SANDBOX_DEFAULT_FILE_TYPES) expect(FILE_TYPE_IDS).toContain(t);
    expect(Object.values(SANDBOX_PLATFORM_ENV_KEYS)).toEqual([
      'SANDBOX_TENANT_DEFAULT_ENABLED',
      'SANDBOX_FILE_TYPES',
      'SANDBOX_MAX_SAMPLE_BYTES',
      'SANDBOX_BROWSER_ANALYSIS',
    ]);
  });

  it('reads the platform settings from the environment and refuses invalid values', () => {
    expect(sandboxPlatformSettingsFromEnv({})).toEqual(platform);
    expect(
      sandboxPlatformSettingsFromEnv({
        SANDBOX_TENANT_DEFAULT_ENABLED: 'true',
        SANDBOX_FILE_TYPES: ' pdf , html ',
        SANDBOX_MAX_SAMPLE_BYTES: '67108864',
        SANDBOX_BROWSER_ANALYSIS: 'false',
        SANDBOX_ENABLED: 'ignored',
      }),
    ).toEqual({
      tenantDefaultEnabled: true,
      fileTypes: ['pdf', 'html'],
      maxSampleBytes: 67_108_864,
      browserAnalysis: false,
    });
    expect(() =>
      sandboxPlatformSettingsFromEnv({ SANDBOX_MAX_SAMPLE_BYTES: '67108865' }),
    ).toThrow();
    expect(() => sandboxPlatformSettingsFromEnv({ SANDBOX_MAX_SAMPLE_BYTES: '0' })).toThrow();
    expect(() => sandboxPlatformSettingsFromEnv({ SANDBOX_FILE_TYPES: 'pdf,docx' })).toThrow();
    expect(() => sandboxPlatformSettingsFromEnv({ SANDBOX_FILE_TYPES: 'pdf,pdf' })).toThrow();
    expect(() => sandboxPlatformSettingsFromEnv({ SANDBOX_FILE_TYPES: ',' })).toThrow();
    expect(() => sandboxPlatformSettingsFromEnv({ SANDBOX_BROWSER_ANALYSIS: 'yes' })).toThrow();
    expect(() => sandboxPlatformSettingsFromEnv({ SANDBOX_TENANT_DEFAULT_ENABLED: '1' })).toThrow();
  });

  it('resolves no override to the platform settings (opt-in default false)', () => {
    for (const override of [null, undefined]) {
      expect(resolveSandboxSettings(platform, override)).toEqual({
        ok: true,
        overridden: false,
        settings: {
          enabled: false,
          fileTypes: [...SANDBOX_DEFAULT_FILE_TYPES],
          maxSampleBytes: 26_214_400,
          browserAnalysis: true,
        },
      });
    }
    expect(resolveSandboxSettings(platform, {})).toMatchObject({ ok: true, overridden: false });
  });

  it('applies a valid override within the bounds', () => {
    expect(
      resolveSandboxSettings(platform, {
        enabled: true,
        fileTypes: ['pdf', 'script_js'],
        maxSampleBytes: 1,
        browserAnalysis: false,
      }),
    ).toEqual({
      ok: true,
      overridden: true,
      settings: {
        enabled: true,
        fileTypes: ['pdf', 'script_js'],
        maxSampleBytes: 1,
        browserAnalysis: false,
      },
    });
    expect(
      resolveSandboxSettings(platform, { maxSampleBytes: platform.maxSampleBytes }),
    ).toMatchObject({ ok: true });
  });

  it('refuses out-of-bounds, invalid and unknown settings', () => {
    const violations = (override: unknown) => {
      const r = resolveSandboxSettings(platform, override);
      return r.ok ? [] : r.violations.map((v) => `${v.path}:${v.code}`);
    };
    expect(violations({ fileTypes: ['pdf', 'zip'] })).toEqual(['fileTypes:out_of_bounds']);
    expect(violations({ fileTypes: [] })).toEqual(['fileTypes:invalid']);
    expect(violations({ fileTypes: ['pdf', 'pdf'] })).toEqual(['fileTypes:invalid']);
    expect(violations({ maxSampleBytes: 0 })).toEqual(['maxSampleBytes:out_of_bounds']);
    expect(violations({ maxSampleBytes: platform.maxSampleBytes + 1 })).toEqual([
      'maxSampleBytes:out_of_bounds',
    ]);
    expect(violations({ maxSampleBytes: 1.5 })).toEqual(['maxSampleBytes:invalid']);
    expect(violations({ enabled: 'yes' })).toEqual(['enabled:invalid']);
    expect(violations({ backend: 'hardened-container' })).toEqual(['backend:unknown_key']);
    expect(violations('x')).toEqual(['settings:invalid']);
    const noBrowser = { ...platform, browserAnalysis: false };
    const r = resolveSandboxSettings(noBrowser, { browserAnalysis: true });
    expect(r.ok ? [] : r.violations.map((v) => `${v.path}:${v.code}`)).toEqual([
      'browserAnalysis:out_of_bounds',
    ]);
    expect(resolveSandboxSettings(noBrowser, { browserAnalysis: false }).ok).toBe(true);
    expect(sandboxTenantSettingsSchema.safeParse({ limits: {} }).success).toBe(false);
  });

  it('returns the bounds and a settings version like the other engines', () => {
    expect(sandboxSettingsBounds(platform)).toEqual({
      enabled: [false, true],
      fileTypes: [...SANDBOX_DEFAULT_FILE_TYPES],
      maxSampleBytes: { min: 1, max: 26_214_400 },
      browserAnalysis: [false, true],
    });
    expect(sandboxSettingsBounds({ ...platform, browserAnalysis: false }).browserAnalysis).toEqual([
      false,
    ]);
    const v = sandboxSettingsVersion(platform, null);
    expect(v).toMatch(/^sandbox-map\/1;p=[0-9a-f]{12};t=none$/);
    expect(sandboxSettingsVersion(platform, 7)).toMatch(/;t=7$/);
    expect(sandboxSettingsVersion({ ...platform, maxSampleBytes: 1 }, null)).not.toBe(v);
    expect(v.length).toBeLessThanOrEqual(96);
  });
});
