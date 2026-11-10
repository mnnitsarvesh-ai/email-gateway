import { sandboxObservationsSchema } from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import type { TaskLimits } from '../backends/backend';
import {
  buildObservation,
  type BuildInput,
  isInternalName,
  isMetadataIp,
  isMetadataName,
  isPrivateIp,
  typeHintFromHead,
} from './observation-builder';
import type { BrowserReport, ExecuteReport } from './runner-reports';
import type { ParsedRunnerOutput } from './runner-protocol';
import { parseTrace } from './trace-parser';

const SHA = 'a'.repeat(64);
const limits: TaskLimits = {
  wallTimeoutMs: 10_000,
  memoryMb: 256,
  cpuMillis: 1_000,
  pids: 64,
  scratchMb: 16,
  maxArtifacts: 4,
  maxArtifactBytes: 1_000,
  maxTotalArtifactBytes: 2_000,
};
const stats = (over: Partial<ExecuteReport['cgroup']['before']> = {}) => ({
  cpuUsageUsec: 0,
  nrThrottled: 0,
  throttledUsec: 0,
  oomKill: 0,
  cpuMax: '100000 100000',
  pidsMax: '64',
  memoryMax: '268435456',
  ...over,
});
const executeReport = (over: Partial<ExecuteReport> = {}): ExecuteReport => ({
  v: 1,
  mode: 'execute',
  inputError: null,
  spawnError: null,
  exit: { code: 0, signal: null },
  timedOut: false,
  innerTimeoutMs: 8_000,
  durationMs: 100,
  stdoutBytes: 0,
  stderrBytes: 0,
  traceBytes: 0,
  traceTruncated: false,
  scratchFull: false,
  files: [],
  filesTotal: 0,
  filesOmitted: 0,
  cgroup: { before: stats(), after: stats({ cpuUsageUsec: 50_000 }) },
  ...over,
});
const output = (over: Partial<ParsedRunnerOutput> = {}): ParsedRunnerOutput => ({
  report: {},
  trace: Buffer.from('1 00:00:00.000001 execve("/bin/sh", ["sh"], 0x1 /* 1 var */) = 0\n'),
  stdout: Buffer.from('RESULT x\n'),
  stderr: Buffer.alloc(0),
  files: [],
  screenshot: null,
  complete: true,
  problem: null,
  artifactCapHit: false,
  ...over,
});
const input = (over: Partial<BuildInput> = {}): BuildInput => ({
  profile: 'execute',
  limits,
  sinkholeIp: '172.31.253.53',
  output: output(),
  report: executeReport(),
  outputInvalid: false,
  trace: parseTrace('1 00:00:00.000001 execve("/bin/sh", ["sh"], 0x1 /* 1 var */) = 0', {
    timedOut: false,
    oomKilled: false,
  }),
  oomKilled: false,
  exitCode: 0,
  outerTimedOut: false,
  sinkhole: [],
  ...over,
});
const codes = (r: ReturnType<typeof buildObservation>) =>
  r.observations.findings.map((f) => f.code);

describe('buildObservation', () => {
  it('a quiet run: one process, a process log, no findings', () => {
    const result = buildObservation(input());
    expect(sandboxObservationsSchema.safeParse(result.observations).success).toBe(true);
    expect(result.observations.processCount).toBe(1);
    expect(result.observations.findings).toEqual([]);
    expect(result.limitsHit).toEqual([]);
    expect(result.artifacts.map((a) => [a.kind, a.contentType])).toEqual([
      ['process_log', 'text/plain'],
    ]);
    const log = result.artifacts[0]!.bytes.toString();
    expect(log).toContain('NOT A VM BOUNDARY');
    expect(log).toContain('RESULT x');
  });

  it('network: metadata, internal names/IPs, direct IPs, dns/http/tls from the sinkhole, beacons', () => {
    const trace = parseTrace(
      [
        '1 00:00:00.000001 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("169.254.169.254")}, 16) = -1 ENETUNREACH (x)',
        '1 00:00:00.000002 connect(3, {sa_family=AF_INET, sin_port=htons(3306), sin_addr=inet_addr("172.18.0.5")}, 16) = -1 ENETUNREACH (x)',
        '1 00:00:00.000003 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = -1 ENETUNREACH (x)',
        '1 00:00:00.000004 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("172.31.253.53")}, 16) = 0',
      ].join('\n'),
      { timedOut: false, oomKilled: false },
    );
    const http = (host: string | null) => ({
      kind: 'http' as const,
      at: 1,
      host,
      port: 80,
      method: 'GET' as const,
      pathSha256: SHA,
      userAgentSha256: null,
    });
    const result = buildObservation(
      input({
        trace,
        sinkhole: [
          { kind: 'dns', at: 1, name: 'metadata.google.internal', type: 'A', transport: 'udp' },
          { kind: 'dns', at: 1, name: 'mysql', type: 'A', transport: 'udp' },
          { kind: 'dns', at: 1, name: 'mysql', type: 'A', transport: 'udp' },
          { kind: 'dns', at: 1, name: 'example.test', type: 'AAAA', transport: 'udp' },
          http('beacon.example.test'),
          http('beacon.example.test'),
          http('beacon.example.test'),
          http(null),
          { kind: 'tls', at: 1, sni: 'c2.example.test', port: 443 },
          { kind: 'tls', at: 1, sni: null, port: 443 },
        ],
      }),
    );
    const o = result.observations;
    expect(o.network.connections).toEqual([
      { ip: '169.254.169.254', port: 80, protocol: 'tcp', outcome: 'unreachable' },
      { ip: '172.18.0.5', port: 3306, protocol: 'tcp', outcome: 'unreachable' },
      { ip: '93.184.216.34', port: 443, protocol: 'tcp', outcome: 'unreachable' },
      { ip: '172.31.253.53', port: 80, protocol: 'tcp', outcome: 'sinkhole' },
    ]);
    expect(o.network.dns).toEqual([
      { name: 'metadata.google.internal', type: 'A', source: 'sinkhole' },
      { name: 'mysql', type: 'A', source: 'sinkhole' },
      { name: 'example.test', type: 'AAAA', source: 'sinkhole' },
    ]);
    expect(o.network.totals).toEqual({ dns: 4, http: 4, tls: 2, connections: 4 });
    expect(o.network.http.map((h) => h.host)).toEqual(['beacon.example.test', '172.31.253.53']);
    expect(o.network.tls).toEqual([{ sni: 'c2.example.test', port: 443 }]);
    const byCode = Object.fromEntries(o.findings.map((f) => [f.code, f]));
    expect(byCode['behaviour.metadata_access']).toMatchObject({ severity: 'critical', count: 2 });
    expect(byCode['behaviour.internal_network_access']).toMatchObject({
      severity: 'high',
      count: 2,
    });
    expect(byCode['behaviour.direct_ip_connect']).toMatchObject({ severity: 'medium', count: 1 });
    expect(byCode['behaviour.dns_queries']).toMatchObject({ severity: 'info', count: 4 });
    expect(byCode['behaviour.http_requests']).toMatchObject({ severity: 'low', count: 4 });
    expect(byCode['behaviour.network_beacon']).toMatchObject({ severity: 'medium', count: 1 });
  });

  it('limits: memory, pids, cpu, scratch, wall timeout (+ long sleep), output, artifacts — each also a finding', () => {
    const trace = parseTrace(
      '1 00:00:00.000001 clone(child_stack=NULL, flags=SIGCHLD) = -1 EAGAIN (x)',
      {
        timedOut: true,
        oomKilled: true,
      },
    );
    const result = buildObservation(
      input({
        trace,
        oomKilled: true,
        outputInvalid: true,
        report: executeReport({
          timedOut: true,
          scratchFull: true,
          filesOmitted: 1,
          cgroup: { before: stats(), after: stats({ nrThrottled: 5, cpuUsageUsec: 1_000 }) },
        }),
      }),
    );
    expect(result.limitsHit.sort()).toEqual(
      [
        'artifact_cap',
        'cpu',
        'memory',
        'output_truncated',
        'pids',
        'scratch_full',
        'wall_timeout',
      ].sort(),
    );
    expect(codes(result)).toEqual(
      expect.arrayContaining([
        'limit.memory',
        'limit.pids',
        'limit.cpu',
        'limit.scratch_full',
        'limit.wall_timeout',
        'limit.output_truncated',
        'limit.artifact_cap',
        'evasion.long_sleep',
      ]),
    );
  });

  it('a busy run that times out is not a long sleep', () => {
    const result = buildObservation(
      input({
        outerTimedOut: true,
        report: executeReport({
          timedOut: true,
          cgroup: { before: stats(), after: stats({ cpuUsageUsec: 7_000_000 }) },
        }),
      }),
    );
    expect(codes(result)).toContain('limit.wall_timeout');
    expect(codes(result)).not.toContain('evasion.long_sleep');
  });

  it('dropped files: hashes, type hints, executables, artifacts bounded by the caps', () => {
    const files = [
      {
        seq: 0,
        pathSha256: SHA,
        size: 5,
        sha256: SHA,
        head: Buffer.from('hello').toString('base64'),
        executable: false,
      },
      {
        seq: 1,
        pathSha256: SHA,
        size: 10,
        sha256: SHA,
        head: Buffer.from('#!/bin/sh\n').toString('base64'),
        executable: true,
      },
      {
        seq: 2,
        pathSha256: SHA,
        size: 4,
        sha256: SHA,
        head: Buffer.from([0x7f, 0x45, 0x4c, 0x46]).toString('base64'),
        executable: false,
      },
    ];
    const result = buildObservation(
      input({
        report: executeReport({ files, filesTotal: 3 }),
        output: output({
          files: [
            { seq: 0, bytes: Buffer.from('hello') },
            { seq: 1, bytes: Buffer.alloc(900, 1) },
            { seq: 2, bytes: Buffer.alloc(900, 2) },
            { seq: 9, bytes: Buffer.from('unlisted') },
          ],
        }),
      }),
    );
    expect(result.observations.files.dropped.map((d) => d.typeHint)).toEqual([
      'text',
      'script_shell',
      'elf',
    ]);
    expect(codes(result)).toEqual(
      expect.arrayContaining(['behaviour.dropped_files', 'behaviour.dropped_executable']),
    );
    expect(
      result.observations.findings.find((f) => f.code === 'behaviour.dropped_executable')?.count,
    ).toBe(2);
    // process log + 2 files fit the 2 000-byte total; the third file and the unlisted one do not.
    expect(result.artifacts.map((a) => a.kind)).toEqual([
      'process_log',
      'dropped_file',
      'dropped_file',
    ]);
    expect(result.limitsHit).toEqual(expect.arrayContaining(['artifact_cap', 'output_truncated']));
  });

  it('browser: counters, findings, screenshot artifact (PNG signature checked), request hosts merged', () => {
    const report: BrowserReport = {
      v: 1,
      mode: 'browser',
      error: null,
      durationMs: 1,
      navigations: 2,
      requests: 5,
      requestList: [
        { host: '169.254.169.254', port: 80, method: 'GET', pathSha256: SHA, scheme: 'http' },
        { host: 'mysql', port: 3306, method: 'GET', pathSha256: SHA, scheme: 'http' },
        { host: 'Bad Host', port: 80, method: 'GET', pathSha256: SHA, scheme: 'http' },
      ],
      downloadsAttempted: 1,
      dialogs: 1,
      passwordFields: 1,
      forms: 1,
      crossOriginForms: 1,
      jsRedirects: 1,
      screenshot: true,
      chromiumVersion: '140',
    };
    const png = Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
      Buffer.alloc(10),
    ]);
    const result = buildObservation(
      input({
        profile: 'browser',
        report,
        trace: null,
        output: output({ trace: Buffer.alloc(0), stdout: Buffer.alloc(0), screenshot: png }),
        sinkhole: [{ kind: 'dns', at: 1, name: 'mysql', type: 'A', transport: 'udp' }],
      }),
    );
    expect(result.observations.browser).toEqual({
      navigations: 2,
      requests: 5,
      downloadsAttempted: 1,
      dialogs: 1,
      passwordFields: 1,
      forms: 1,
    });
    expect(result.artifacts.map((a) => a.kind)).toEqual(['screenshot']);
    expect(result.observations.network.http.map((h) => h.host)).toEqual([
      '169.254.169.254',
      'mysql',
    ]);
    expect(codes(result)).toEqual(
      expect.arrayContaining([
        'browser.download_attempt',
        'browser.password_form',
        'browser.cross_origin_form',
        'browser.js_redirect',
        'browser.dialogs',
        'behaviour.metadata_access',
        'behaviour.internal_network_access',
      ]),
    );
    const notPng = buildObservation(
      input({
        profile: 'browser',
        report,
        trace: null,
        output: output({ screenshot: Buffer.from('GIF89a') }),
      }),
    );
    expect(notPng.artifacts.some((a) => a.kind === 'screenshot')).toBe(false);
    expect(notPng.limitsHit).toContain('output_truncated');
  });

  it('no report at all (killed runner): limits only, schema-valid', () => {
    const result = buildObservation(
      input({ report: null, output: null, trace: null, oomKilled: true, outputInvalid: true }),
    );
    expect(result.limitsHit.sort()).toEqual(['memory', 'output_truncated']);
    expect(result.artifacts).toEqual([]);
    expect(sandboxObservationsSchema.safeParse(result.observations).success).toBe(true);
  });

  it('maxArtifacts = 0 keeps no artifact', () => {
    const result = buildObservation(input({ limits: { ...limits, maxArtifacts: 0 } }));
    expect(result.artifacts).toEqual([]);
    expect(result.limitsHit).toContain('artifact_cap');
  });
});

describe('classifiers', () => {
  it('metadata, private, internal names, type hints', () => {
    expect(isMetadataIp('169.254.169.254')).toBe(true);
    expect(isMetadataIp('169.254.1.1')).toBe(true);
    expect(isMetadataIp('fd00:ec2::254')).toBe(true);
    expect(isMetadataIp('10.0.0.1')).toBe(false);
    for (const ip of [
      '10.0.0.1',
      '172.16.0.1',
      '172.31.255.1',
      '192.168.65.254',
      '100.64.0.1',
      '127.0.0.1',
      'fd12::1',
      'fe80::1',
      '::1',
    ]) {
      expect(isPrivateIp(ip), ip).toBe(true);
    }
    for (const ip of ['8.8.8.8', '172.32.0.1', '203.0.113.10', '2001:db8::1'])
      expect(isPrivateIp(ip), ip).toBe(false);
    expect(isMetadataName('METADATA.google.internal.')).toBe(true);
    for (const name of [
      'mysql',
      'host.docker.internal',
      'gateway.docker.internal',
      'printer.local',
      'redis.svc',
    ]) {
      expect(isInternalName(name), name).toBe(true);
    }
    expect(isInternalName('example.com')).toBe(false);
    expect(typeHintFromHead(Buffer.from('MZ\x90\x00', 'latin1'))).toBe('pe_executable');
    expect(typeHintFromHead(Buffer.from('%PDF-1.7'))).toBe('pdf');
    expect(typeHintFromHead(Buffer.from([0x50, 0x4b, 0x03, 0x04]))).toBe('zip');
    expect(typeHintFromHead(Buffer.from('<!DOCTYPE html>'))).toBe('html');
    expect(typeHintFromHead(Buffer.from('<svg xmlns'))).toBe('svg');
    expect(typeHintFromHead(Buffer.from([0, 1, 2, 3]))).toBe('unknown');
  });
});
