import {
  ARTIFACT_KIND_CONTENT_TYPE,
  type FileTypeId,
  SANDBOX_FINDING_SEVERITY,
  SANDBOX_OBSERVATION_BOUNDS,
  type SandboxFinding,
  type SandboxFindingCode,
  type SandboxLimit,
  type SandboxObservations,
  sandboxObservationsSchema,
  URL_HOST_PATTERN,
} from '@email-gateway/security-contracts';
import type { RawArtifact, TaskLimits } from '../backends/backend';
import type { BrowserReport, ExecuteReport } from './runner-reports';
import type { ParsedRunnerOutput } from './runner-protocol';
import type { SinkholeRecord } from './sinkhole-client';
import type { TraceConnection, TraceSummary } from './trace-parser';

/**
 * Builds the `BackendObservation.observations` and artifacts of one hardened-container run from
 * the runner's (untrusted, already parsed) output, the controller-side facts (inspect: OOM, exit;
 * the outer timeout) and the sinkhole's records (step 4.6 X6). Pure.
 *
 * Findings use the codes and fixed severities of `@email-gateway/security-contracts`
 * (`behaviour.*`, `browser.*`, `limit.*`, `evasion.*`); every limit hit is both a `limitsHit`
 * entry and the finding `limit.<limit>` (§12 WP1 deviation 2a). Cloud metadata targets map to
 * `behaviour.metadata_access`, private / internal targets to `behaviour.internal_network_access`.
 * A connect() that completed (only possible to a peer on the detonation network, i.e. the
 * sinkhole) is reported with outcome `sinkhole` (the contract has no `connected`).
 */

export const PROCESS_LOG_MAX_BYTES = 256 * 1024;
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const METADATA_NAMES = new Set([
  'metadata.google.internal',
  'metadata',
  'metadata.goog',
  'instance-data',
  'instance-data.ec2.internal',
  'metadata.azure.com',
  'metadata.tencentyun.com',
  'metadata.platformequinix.com',
]);
const METADATA_IPS = new Set([
  '169.254.169.254',
  'fd00:ec2::254',
  '169.254.170.2',
  '100.100.100.200',
]);
const INTERNAL_SUFFIXES = [
  '.internal',
  '.local',
  '.localhost',
  '.localdomain',
  '.lan',
  '.home.arpa',
  '.svc',
  '.cluster.local',
];
const MANY_PROCESSES = 20;
const BEACON_REPEATS = 3;
const LONG_SLEEP_CPU_FRACTION = 0.1;

export interface BuildInput {
  profile: 'execute' | 'browser';
  limits: TaskLimits;
  /** `SANDBOX_SINKHOLE_DNS`: the sinkhole's detonation address. */
  sinkholeIp: string;
  output: ParsedRunnerOutput | null;
  /** The validated report (null when missing or invalid). */
  report: ExecuteReport | BrowserReport | null;
  /** Output was malformed, cut by the cap or the report failed its schema. */
  outputInvalid: boolean;
  trace: TraceSummary | null;
  oomKilled: boolean;
  exitCode: number | null;
  outerTimedOut: boolean;
  sinkhole: SinkholeRecord[] | null;
}

export interface BuildResult {
  observations: SandboxObservations;
  artifacts: RawArtifact[];
  limitsHit: SandboxLimit[];
}

const isHost = (value: string): boolean => value.length <= 253 && URL_HOST_PATTERN.test(value);
const stripDot = (name: string) => (name.endsWith('.') ? name.slice(0, -1) : name);

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null;
    n = n * 256 + octet;
  }
  return n;
}
const inCidr = (ip: number, base: string, bits: number): boolean => {
  const b = ipv4ToInt(base)!;
  const size = 2 ** (32 - bits);
  return ip >= b && ip < b + size;
};

/** Cloud metadata address (link-local 169.254/16 included). */
export function isMetadataIp(ip: string): boolean {
  if (METADATA_IPS.has(ip)) return true;
  const n = ipv4ToInt(ip);
  return n !== null && inCidr(n, '169.254.0.0', 16);
}

/** RFC 1918, CGNAT, loopback, unique-local and link-local IPv6. */
export function isPrivateIp(ip: string): boolean {
  const n = ipv4ToInt(ip);
  if (n !== null) {
    return (
      inCidr(n, '10.0.0.0', 8) ||
      inCidr(n, '172.16.0.0', 12) ||
      inCidr(n, '192.168.0.0', 16) ||
      inCidr(n, '100.64.0.0', 10) ||
      inCidr(n, '127.0.0.0', 8) ||
      inCidr(n, '0.0.0.0', 8)
    );
  }
  const lower = ip.toLowerCase();
  return lower === '::1' || /^f[cd][0-9a-f]{0,2}:/.test(lower) || /^fe[89ab][0-9a-f]?:/.test(lower);
}

export function isMetadataName(name: string): boolean {
  return METADATA_NAMES.has(stripDot(name.toLowerCase()));
}

/** Single-label names, internal suffixes and Docker Desktop's host names. */
export function isInternalName(name: string): boolean {
  const n = stripDot(name.toLowerCase());
  if (!n.includes('.')) return true;
  return INTERNAL_SUFFIXES.some((suffix) => n.endsWith(suffix));
}

/** A type hint from the first bytes of a dropped file (the vocabulary of `FILE_TYPE_IDS`). */
export function typeHintFromHead(head: Buffer): FileTypeId {
  const starts = (bytes: number[] | string) =>
    typeof bytes === 'string'
      ? head.subarray(0, bytes.length).toString('latin1') === bytes
      : bytes.every((b, i) => head[i] === b);
  if (starts([0x7f, 0x45, 0x4c, 0x46])) return 'elf';
  if (starts('MZ')) return 'pe_executable';
  if (starts('%PDF')) return 'pdf';
  if (starts([0x50, 0x4b, 0x03, 0x04])) return 'zip';
  if (starts([0x1f, 0x8b])) return 'gzip';
  if (starts([...PNG_SIGNATURE])) return 'png';
  if (starts([0xff, 0xd8, 0xff])) return 'jpeg';
  if (starts('GIF8')) return 'gif';
  if (starts('#!')) return 'script_shell';
  const text = head.toString('latin1').trimStart().toLowerCase();
  if (text.startsWith('<!doctype html') || text.startsWith('<html')) return 'html';
  if (text.startsWith('<svg') || text.startsWith('<?xml'))
    return text.startsWith('<svg') ? 'svg' : 'xml';
  if (
    head.length > 0 &&
    head.every((b) => b === 0x09 || b === 0x0a || b === 0x0d || (b >= 0x20 && b < 0x7f))
  ) {
    return 'text';
  }
  return 'unknown';
}

const isExecutableHead = (head: Buffer): boolean =>
  head.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) ||
  head.subarray(0, 2).toString('latin1') === 'MZ' ||
  head.subarray(0, 2).toString('latin1') === '#!';

const toContractOutcome = (
  connection: TraceConnection,
): SandboxObservations['network']['connections'][number]['outcome'] =>
  connection.outcome === 'connected' ? 'sinkhole' : connection.outcome;

export function buildObservation(input: BuildInput): BuildResult {
  const counterMax = SANDBOX_OBSERVATION_BOUNDS.counterMax;
  const clamp = (n: number) => Math.max(0, Math.min(counterMax, Math.floor(n)));
  const findings = new Map<SandboxFindingCode, number>();
  const addFinding = (code: SandboxFindingCode, count = 1) => {
    if (count <= 0) return;
    findings.set(
      code,
      Math.min(SANDBOX_OBSERVATION_BOUNDS.findingCountMax, (findings.get(code) ?? 0) + count),
    );
  };
  const limits = new Set<SandboxLimit>();
  const execute =
    input.profile === 'execute' && input.report?.mode === 'execute' ? input.report : null;
  const browser =
    input.profile === 'browser' && input.report?.mode === 'browser' ? input.report : null;
  const trace = input.trace;

  // --- limits -------------------------------------------------------------------------------
  const before = execute?.cgroup.before;
  const after = execute?.cgroup.after;
  if (input.oomKilled || (after?.oomKill ?? 0) > (before?.oomKill ?? 0)) limits.add('memory');
  if ((trace?.pidsLimitHits ?? 0) > 0) limits.add('pids');
  if ((after?.nrThrottled ?? 0) > (before?.nrThrottled ?? 0)) limits.add('cpu');
  if (execute?.scratchFull) limits.add('scratch_full');
  const timedOut = input.outerTimedOut || execute?.timedOut === true;
  if (timedOut) limits.add('wall_timeout');
  if (input.outputInvalid || execute?.traceTruncated || trace?.truncated)
    limits.add('output_truncated');
  if (input.output?.artifactCapHit || (execute?.filesOmitted ?? 0) > 0) limits.add('artifact_cap');

  // --- processes ------------------------------------------------------------------------------
  const processes = (trace?.processes ?? []).map((p) => ({ ...p }));
  const processCount = clamp(Math.max(trace?.processCount ?? 0, processes.length));
  if (processCount > 1) addFinding('behaviour.process_spawn', processCount - 1);
  if ((trace?.shellSpawns ?? 0) > 0) addFinding('behaviour.shell_spawn', trace!.shellSpawns);
  if (processCount > MANY_PROCESSES) addFinding('behaviour.many_processes', processCount);
  if ((trace?.privilegeAttempts ?? 0) > 0) {
    addFinding('behaviour.privilege_escalation_attempt', trace!.privilegeAttempts);
  }
  if ((trace?.persistenceAttempts ?? 0) > 0)
    addFinding('behaviour.persistence_attempt', trace!.persistenceAttempts);
  if ((trace?.environmentChecks ?? 0) > 0)
    addFinding('evasion.environment_checks', trace!.environmentChecks);
  const deniedWrites = clamp(trace?.deniedWrites ?? 0);
  if (deniedWrites > 0) addFinding('behaviour.write_outside_scratch', deniedWrites);
  if (timedOut && execute && after?.cpuUsageUsec != null && before?.cpuUsageUsec != null) {
    const used = after.cpuUsageUsec - before.cpuUsageUsec;
    if (used < execute.innerTimeoutMs * 1000 * LONG_SLEEP_CPU_FRACTION)
      addFinding('evasion.long_sleep');
  }

  // --- network --------------------------------------------------------------------------------
  const records = input.sinkhole ?? [];
  const dnsRecords = records.filter(
    (r): r is Extract<SinkholeRecord, { kind: 'dns' }> => r.kind === 'dns',
  );
  const httpRecords = records.filter(
    (r): r is Extract<SinkholeRecord, { kind: 'http' }> => r.kind === 'http',
  );
  const tlsRecords = records.filter(
    (r): r is Extract<SinkholeRecord, { kind: 'tls' }> => r.kind === 'tls',
  );

  const dns: SandboxObservations['network']['dns'] = [];
  const dnsSeen = new Set<string>();
  for (const r of dnsRecords) {
    const name = stripDot(r.name);
    const key = `${name}|${r.type}`;
    if (!isHost(name) || dnsSeen.has(key) || dns.length >= SANDBOX_OBSERVATION_BOUNDS.dns) continue;
    dnsSeen.add(key);
    dns.push({ name, type: r.type, source: 'sinkhole' });
  }

  const http: SandboxObservations['network']['http'] = [];
  const httpSeen = new Set<string>();
  const beaconCounts = new Map<string, number>();
  const pushHttp = (entry: SandboxObservations['network']['http'][number]) => {
    const key = `${entry.host}|${entry.port}|${entry.method}|${entry.pathSha256}`;
    beaconCounts.set(
      `${entry.host}|${entry.pathSha256}`,
      (beaconCounts.get(`${entry.host}|${entry.pathSha256}`) ?? 0) + 1,
    );
    if (httpSeen.has(key) || http.length >= SANDBOX_OBSERVATION_BOUNDS.http) return;
    httpSeen.add(key);
    http.push(entry);
  };
  for (const r of httpRecords) {
    const host = r.host ? stripDot(r.host) : input.sinkholeIp;
    if (!isHost(host)) continue;
    pushHttp({
      host,
      port: r.port,
      method: r.method,
      pathSha256: r.pathSha256,
      userAgentSha256: r.userAgentSha256,
    });
  }
  let browserOnlyRequests = 0;
  for (const r of browser?.requestList ?? []) {
    if (r.scheme !== 'http' && r.scheme !== 'https') continue;
    const host = stripDot(r.host.toLowerCase());
    if (!isHost(host)) continue;
    const key = `${host}|${r.port}|${r.method}|${r.pathSha256}`;
    if (httpSeen.has(key)) continue;
    browserOnlyRequests += 1;
    if (http.length < SANDBOX_OBSERVATION_BOUNDS.http) {
      httpSeen.add(key);
      http.push({
        host,
        port: r.port,
        method: r.method,
        pathSha256: r.pathSha256,
        userAgentSha256: null,
      });
    }
  }

  const tls: SandboxObservations['network']['tls'] = [];
  const tlsSeen = new Set<string>();
  for (const r of tlsRecords) {
    if (!r.sni) continue;
    const sni = stripDot(r.sni);
    const key = `${sni}|${r.port}`;
    if (!isHost(sni) || tlsSeen.has(key) || tls.length >= SANDBOX_OBSERVATION_BOUNDS.tls) continue;
    tlsSeen.add(key);
    tls.push({ sni, port: r.port });
  }

  const connections = (trace?.connections ?? []).map((c) => ({
    ip: c.ip,
    port: c.port,
    protocol: c.protocol,
    outcome: toContractOutcome(c),
  }));

  // Targets: metadata first, then internal, then direct public IPs.
  let metadata = 0;
  let internal = 0;
  let directIp = 0;
  for (const c of trace?.connections ?? []) {
    if (c.ip === input.sinkholeIp) continue;
    if (isMetadataIp(c.ip)) metadata += 1;
    else if (isPrivateIp(c.ip)) internal += 1;
    else directIp += 1;
  }
  const names = [
    ...dnsRecords.map((r) => r.name),
    ...httpRecords.flatMap((r) => (r.host ? [r.host] : [])),
    ...tlsRecords.flatMap((r) => (r.sni ? [r.sni] : [])),
    ...(browser?.requestList ?? []).map((r) => r.host),
  ];
  for (const name of new Set(names.map((n) => stripDot(n.toLowerCase())))) {
    if (isMetadataName(name) || isMetadataIp(name)) metadata += 1;
    else if (
      isInternalName(name) ||
      (isHost(name) && isPrivateIp(name) && name !== input.sinkholeIp)
    )
      internal += 1;
  }
  addFinding('behaviour.metadata_access', metadata);
  addFinding('behaviour.internal_network_access', internal);
  addFinding('behaviour.direct_ip_connect', directIp);
  addFinding('behaviour.dns_queries', dnsRecords.length);
  addFinding('behaviour.http_requests', httpRecords.length + browserOnlyRequests);
  const beacons = [...beaconCounts.values()].filter((n) => n >= BEACON_REPEATS).length;
  addFinding('behaviour.network_beacon', beacons);

  // --- files ----------------------------------------------------------------------------------
  const dropped: SandboxObservations['files']['dropped'] = [];
  let executables = 0;
  for (const f of execute?.files ?? []) {
    const head = Buffer.from(f.head, 'base64');
    if (f.executable || isExecutableHead(head)) executables += 1;
    dropped.push({
      seq: f.seq,
      sha256: f.sha256,
      sizeBytes: f.size,
      typeHint: typeHintFromHead(head),
    });
  }
  addFinding('behaviour.dropped_files', execute ? Math.max(execute.filesTotal, dropped.length) : 0);
  addFinding('behaviour.dropped_executable', executables);

  // --- browser --------------------------------------------------------------------------------
  let browserCounters: SandboxObservations['browser'] = null;
  if (input.profile === 'browser') {
    browserCounters = {
      navigations: clamp(browser?.navigations ?? 0),
      requests: clamp(browser?.requests ?? 0),
      downloadsAttempted: clamp(browser?.downloadsAttempted ?? 0),
      dialogs: clamp(browser?.dialogs ?? 0),
      passwordFields: clamp(browser?.passwordFields ?? 0),
      forms: clamp(browser?.forms ?? 0),
    };
    if (browser) {
      addFinding('browser.download_attempt', browser.downloadsAttempted);
      addFinding('browser.password_form', browser.passwordFields);
      addFinding('browser.cross_origin_form', browser.crossOriginForms);
      addFinding('browser.js_redirect', browser.jsRedirects);
      addFinding('browser.dialogs', browser.dialogs);
    }
  }

  // --- artifacts ------------------------------------------------------------------------------
  const artifacts: RawArtifact[] = [];
  let artifactBytes = 0;
  const pushArtifact = (kind: RawArtifact['kind'], bytes: Buffer) => {
    if (
      artifacts.length >= input.limits.maxArtifacts ||
      bytes.length > input.limits.maxArtifactBytes ||
      artifactBytes + bytes.length > input.limits.maxTotalArtifactBytes ||
      bytes.length === 0
    ) {
      if (bytes.length > 0) limits.add('artifact_cap');
      return;
    }
    artifacts.push({ kind, contentType: ARTIFACT_KIND_CONTENT_TYPE[kind], bytes });
    artifactBytes += bytes.length;
  };
  const screenshot = input.output?.screenshot;
  if (screenshot) {
    if (screenshot.subarray(0, 8).equals(PNG_SIGNATURE)) pushArtifact('screenshot', screenshot);
    else limits.add('output_truncated');
  }
  if (
    input.output &&
    (input.output.trace.length > 0 ||
      input.output.stdout.length > 0 ||
      input.output.stderr.length > 0)
  ) {
    pushArtifact(
      'process_log',
      processLog(input, Math.min(PROCESS_LOG_MAX_BYTES, input.limits.maxArtifactBytes)),
    );
  }
  const listedSeqs = new Set(dropped.map((d) => d.seq));
  for (const file of input.output?.files ?? []) {
    if (!listedSeqs.has(file.seq)) {
      limits.add('output_truncated');
      continue;
    }
    pushArtifact('dropped_file', file.bytes);
  }

  // --- limits as findings -----------------------------------------------------------------------
  const limitsHit = [...limits].slice(0, SANDBOX_OBSERVATION_BOUNDS.limitsHit);
  for (const limit of limitsHit) addFinding(`limit.${limit}` as SandboxFindingCode);

  const findingList: SandboxFinding[] = [...findings.entries()]
    .slice(0, SANDBOX_OBSERVATION_BOUNDS.findings)
    .map(([code, count]) => ({ code, severity: SANDBOX_FINDING_SEVERITY[code], count }));

  const observations: SandboxObservations = {
    processes,
    processCount,
    network: {
      dns,
      http,
      tls,
      connections,
      totals: {
        dns: clamp(Math.max(dnsRecords.length, dns.length)),
        http: clamp(Math.max(httpRecords.length + browserOnlyRequests, http.length)),
        tls: clamp(Math.max(tlsRecords.length, tls.length)),
        connections: clamp(Math.max(trace?.connectionAttempts ?? 0, connections.length)),
      },
    },
    files: { dropped, deniedWrites },
    findings: findingList,
    limitsHit,
    browser: browserCounters,
  };
  return { observations: sandboxObservationsSchema.parse(observations), artifacts, limitsHit };
}

/** The `process_log` artifact: header, sample stdout/stderr excerpts and the trace excerpt (bounded). */
function processLog(input: BuildInput, cap: number): Buffer {
  const out = input.output!;
  const header = Buffer.from(
    [
      '# eg sandbox process log (hardened-container runner: LOCAL/CI ONLY, NOT A VM BOUNDARY)',
      '# untrusted runner output: evidence only',
      `# profile=${input.profile} exit=${input.exitCode ?? 'none'} oom=${input.oomKilled} outer_timeout=${input.outerTimedOut}`,
      `--- stdout (${out.stdout.length} bytes kept) ---`,
      '',
    ].join('\n'),
    'utf8',
  );
  const parts = [
    header,
    out.stdout,
    Buffer.from(`\n--- stderr (${out.stderr.length} bytes kept) ---\n`, 'utf8'),
    out.stderr,
    Buffer.from(`\n--- trace (${out.trace.length} bytes kept) ---\n`, 'utf8'),
    out.trace,
  ];
  const all = Buffer.concat(parts);
  return all.length > cap ? all.subarray(0, cap) : all;
}
