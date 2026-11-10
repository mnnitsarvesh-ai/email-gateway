import { isIP } from 'node:net';
import { z } from 'zod';
import { FILE_TYPE_IDS, type FileTypeId, fileTypeIdSchema } from './file-types';
import { type SettingsViolation, settingsVersion } from './settings';
import { URL_HOST_PATTERN } from './url';
import { REASON_CODE_MAX_LENGTH, REASON_CODE_PATTERN } from './verdicts';

/**
 * Sandbox contracts (step 4.6, docs/plan/steps/14-sandbox.md §4, X2, X10, X12, X14, X17;
 * ADR-0039, ADR-0040; docs/security/sandbox-threat-model.md): the vocabularies of the isolation
 * backends and of the asynchronous `sandbox` engine (verdicts, backends, isolation classes,
 * profiles, not-executed reasons, error codes, skip reasons, finding codes with their fixed
 * severities, the reason codes of `sandbox-map/1`), the artifact kinds and content types, the
 * strict observation schema a backend returns (the shape of `mail.sandbox.task_completed.v1`
 * `observations`), the bounded stored report view, and the platform/tenant settings with their
 * pure resolver.
 *
 * Execution of unknown files is disabled by default and refused in production (§2.0 invariant
 * 1); `clean` exists only as rule C1 of `sandbox-map/1` (isolation `vm`), unreachable in 4.6
 * (invariant 2). Everything here is metadata: codes, counts, hashes, sizes, types, host names and
 * IPs of observed indicators. Never sample or artifact bytes, never file names or paths
 * (invariant 5).
 */

/** Version of the verdict map (`@email-gateway/sandbox` `SANDBOX_MAP_VERSION`); settings prefix. */
export const SANDBOX_MAPPING_VERSION = 'sandbox-map/1';

const unique = (values: readonly unknown[]) => new Set(values).size === values.length;

// ---------------------------------------------------------------------------------------------
// Vocabularies (§4)
// ---------------------------------------------------------------------------------------------

/**
 * Verdict of an analysis and of the round-level `sandbox` final (X14). Equal to the Prisma enum
 * `SandboxVerdict`. `error` and `timeout` are failures, never a classification; `clean` only from
 * rule C1 (a complete VM-isolated run).
 */
export const SANDBOX_VERDICTS = [
  'clean',
  'suspicious',
  'malicious',
  'unknown',
  'error',
  'timeout',
] as const;
export type SandboxVerdict = (typeof SANDBOX_VERDICTS)[number];
export const sandboxVerdictSchema = z.enum(SANDBOX_VERDICTS);

const SANDBOX_VERDICT_RANK: Readonly<Record<SandboxVerdict, number>> = Object.freeze({
  clean: 0,
  unknown: 1,
  timeout: 2,
  error: 3,
  suspicious: 4,
  malicious: 5,
});

/** Aggregation order of `aggregateSubmissions` (X14): malicious > suspicious > error > timeout > unknown > clean. */
export const sandboxVerdictRank = (verdict: SandboxVerdict): number =>
  SANDBOX_VERDICT_RANK[verdict];

/** The isolation backends (X2, X3). `hardened-container` is local/CI only; `vm` refuses in 4.6. */
export const SANDBOX_BACKENDS = ['disabled', 'static', 'hardened-container', 'vm'] as const;
export type SandboxBackendName = (typeof SANDBOX_BACKENDS)[number];
export const sandboxBackendSchema = z.enum(SANDBOX_BACKENDS);

/**
 * What isolates the sample (X2): nothing runs (`none`), an isolated analyzer process
 * (`process`), a hardened shared-kernel container (`container` — NOT a VM boundary), a VM-class
 * runtime (`vm`).
 */
export const SANDBOX_ISOLATION_CLASSES = ['none', 'process', 'container', 'vm'] as const;
export type SandboxIsolationClass = (typeof SANDBOX_ISOLATION_CLASSES)[number];
export const sandboxIsolationClassSchema = z.enum(SANDBOX_ISOLATION_CLASSES);

/** The isolation class of each backend (X3). */
export const SANDBOX_BACKEND_ISOLATION: Readonly<
  Record<SandboxBackendName, SandboxIsolationClass>
> = Object.freeze({
  disabled: 'none',
  static: 'process',
  'hardened-container': 'container',
  vm: 'vm',
});

/** Analysis profiles (X13; Prisma `SandboxProfile`). */
export const SANDBOX_PROFILES = ['static', 'execute', 'browser'] as const;
export type SandboxProfile = (typeof SANDBOX_PROFILES)[number];
export const sandboxProfileSchema = z.enum(SANDBOX_PROFILES);

/** Status of a task result (`mail.sandbox.task_completed.v1` `status`, X2 `BackendObservation`). */
export const SANDBOX_TASK_STATUSES = ['completed', 'not_executed', 'failed'] as const;
export type SandboxTaskStatus = (typeof SANDBOX_TASK_STATUSES)[number];

/** Status of an analysis row (Prisma `SandboxAnalysisStatus`, X13, X16). */
export const SANDBOX_ANALYSIS_STATUSES = [
  'pending',
  'dispatched',
  'completed',
  'not_executed',
  'failed',
  'expired',
] as const;
export type SandboxAnalysisStatus = (typeof SANDBOX_ANALYSIS_STATUSES)[number];

/** Status of a submission row (Prisma `SandboxSubmissionStatus`; 4.6 appends `skipped`). */
export const SANDBOX_SUBMISSION_STATUSES = [
  'pending',
  'submitted',
  'completed',
  'failed',
  'expired',
  'skipped',
] as const;
export type SandboxSubmissionStatus = (typeof SANDBOX_SUBMISSION_STATUSES)[number];

/** Why a backend did not run a sample (X2, X3, X7). Never `clean`: rule N1 → `unknown`. */
export const SANDBOX_NOT_EXECUTED_REASONS = [
  'backend_disabled',
  'type_not_supported',
  'profile_not_supported',
  'size_exceeded',
  'deadline_passed',
] as const;
export type NotExecutedReason = (typeof SANDBOX_NOT_EXECUTED_REASONS)[number];
export const notExecutedReasonSchema = z.enum(SANDBOX_NOT_EXECUTED_REASONS);

/** Controller / infrastructure failures of a task (X7). Rule F1 → `error`. */
export const SANDBOX_ERROR_CODES = [
  'sample_unavailable',
  'sample_integrity',
  'storage_unavailable',
  'runner_start_failed',
  'runner_crashed',
  'analyzer_crashed',
  'analyzer_timeout',
  'backend_not_ready',
  'spec_not_enforced',
  'internal',
] as const;
export type SandboxErrorCode = (typeof SANDBOX_ERROR_CODES)[number];
export const sandboxErrorCodeSchema = z.enum(SANDBOX_ERROR_CODES);

/** Why a submission was skipped (X13 step 3, step 6): no analysis, no verdict. */
export const SANDBOX_SKIP_REASONS = [
  'feature_disabled',
  'tenant_disabled',
  'type_excluded',
  'size_excluded',
  'part_unavailable',
  'part_integrity',
] as const;
export type SandboxSkipReason = (typeof SANDBOX_SKIP_REASONS)[number];
export const sandboxSkipReasonSchema = z.enum(SANDBOX_SKIP_REASONS);

/** Severities of findings (fixed per code in `SANDBOX_FINDING_SEVERITY`; tenants cannot change them). */
export const SANDBOX_FINDING_SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type SandboxFindingSeverity = (typeof SANDBOX_FINDING_SEVERITIES)[number];
export const sandboxFindingSeveritySchema = z.enum(SANDBOX_FINDING_SEVERITIES);
export const sandboxFindingSeverityRank = (severity: SandboxFindingSeverity): number =>
  SANDBOX_FINDING_SEVERITIES.indexOf(severity);

/** Resource limits a run can hit (X6, X19); `limit.<limit>` findings and `limitsHit` entries. */
export const SANDBOX_LIMITS = [
  'memory',
  'pids',
  'cpu',
  'scratch_full',
  'wall_timeout',
  'analyzer_resources',
  'output_truncated',
  'artifact_cap',
] as const;
export type SandboxLimit = (typeof SANDBOX_LIMITS)[number];
export const sandboxLimitSchema = z.enum(SANDBOX_LIMITS);

/** Limits that never raise the verdict (rule S1 exceptions, X14). */
export const SANDBOX_NON_RAISING_LIMITS: readonly SandboxLimit[] = Object.freeze([
  'wall_timeout',
  'output_truncated',
  'artifact_cap',
]);

/**
 * Every finding code with its fixed severity (§4, X4, X14). `static.*` from the static analyzers
 * (X4), `behaviour.*` from an executing runner (X6), `browser.*` from the browser profile,
 * `limit.*` resource limits, `evasion.*` sandbox-evasion hints.
 *
 * `static.office_auto_exec_shell` is the combined finding the OLE/OOXML analyzer emits when an
 * auto-exec macro entry point and a shell/download call occur in the same VBA project (X14's
 * example "office_auto_exec with office_macro_shell" → malicious); severities are fixed per code,
 * so the combination is its own code.
 */
export const SANDBOX_FINDING_SEVERITY = Object.freeze({
  // X4 static: pe
  'static.pe_injection_imports': 'high',
  'static.pe_downloader_imports': 'medium',
  'static.pe_packed': 'medium',
  'static.pe_anti_debug': 'low',
  'static.pe_overlay': 'low',
  // elf
  'static.elf_packed': 'medium',
  // ole / ooxml
  'static.office_macro': 'low',
  'static.office_auto_exec': 'medium',
  'static.office_macro_shell': 'medium',
  'static.office_auto_exec_shell': 'high',
  'static.office_ole_object': 'low',
  'static.office_external_template': 'high',
  'static.office_dde': 'high',
  // pdf
  'static.pdf_javascript': 'medium',
  'static.pdf_open_action_js': 'high',
  'static.pdf_launch': 'high',
  'static.pdf_embedded_file': 'low',
  'static.pdf_obfuscated_names': 'medium',
  // html / svg
  'static.html_smuggling': 'high',
  'static.html_password_form': 'medium',
  'static.html_external_form': 'medium',
  'static.html_meta_refresh_external': 'low',
  'static.html_obfuscated_script': 'medium',
  // script
  'static.script_encoded_powershell': 'high',
  'static.script_download_cradle': 'high',
  'static.script_lolbin': 'high',
  'static.script_shell_exec': 'medium',
  'static.script_obfuscation': 'medium',
  // lnk
  'static.lnk_present': 'low',
  'static.lnk_command': 'high',
  // generic
  'static.eicar_test': 'critical',
  'static.embedded_urls': 'info',
  'static.embedded_ips': 'info',
  'static.high_entropy': 'low',
  // behaviour (X6)
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
  // browser
  'browser.download_attempt': 'high',
  'browser.password_form': 'medium',
  'browser.cross_origin_form': 'medium',
  'browser.js_redirect': 'low',
  'browser.dialogs': 'low',
  // limit
  'limit.memory': 'medium',
  'limit.pids': 'medium',
  'limit.cpu': 'low',
  'limit.scratch_full': 'medium',
  'limit.wall_timeout': 'info',
  'limit.analyzer_resources': 'medium',
  'limit.output_truncated': 'info',
  'limit.artifact_cap': 'info',
  // evasion
  'evasion.long_sleep': 'low',
  'evasion.environment_checks': 'low',
} as const satisfies Record<string, SandboxFindingSeverity>);

export type SandboxFindingCode = keyof typeof SANDBOX_FINDING_SEVERITY;
/** Every finding code (`SANDBOX_FINDING_SEVERITY` order). */
export const SANDBOX_FINDING_CODES = Object.freeze(
  Object.keys(SANDBOX_FINDING_SEVERITY),
) as readonly SandboxFindingCode[] as readonly [SandboxFindingCode, ...SandboxFindingCode[]];
export const sandboxFindingCodeSchema = z.enum(SANDBOX_FINDING_CODES);

export const isSandboxFindingCode = (value: string): value is SandboxFindingCode =>
  Object.prototype.hasOwnProperty.call(SANDBOX_FINDING_SEVERITY, value);

/** The fixed severity of a finding code. */
export const sandboxFindingSeverity = (code: SandboxFindingCode): SandboxFindingSeverity =>
  SANDBOX_FINDING_SEVERITY[code];

/** Analysis-level codes of `sandbox-map/1` (X14) other than findings, limits, reasons and errors. */
export const SANDBOX_OUTCOME_CODES = [
  'sandbox.timeout',
  'sandbox.no_findings',
  'sandbox.static_only',
  'sandbox.not_vm_isolated',
  'sandbox.incomplete_run',
  'sandbox.evasion_suspected',
  'sandbox.not_executed',
  'sandbox.error',
] as const;

/** `sandbox.<reason>` per skip reason (X14 per-submission codes). */
export const sandboxSkipCode = (reason: SandboxSkipReason): string => `sandbox.${reason}`;
/** `sandbox.not_executed.<reason>`. */
export const sandboxNotExecutedCode = (reason: NotExecutedReason): string =>
  `sandbox.not_executed.${reason}`;
/** `sandbox.error.<code>`. */
export const sandboxErrorCode = (code: SandboxErrorCode): string => `sandbox.error.${code}`;
/** `sandbox.<finding code>`. */
export const sandboxFindingReasonCode = (code: SandboxFindingCode): string => `sandbox.${code}`;
/** `sandbox.limit.<limit>` (equal to the reason code of the finding `limit.<limit>`). */
export const sandboxLimitCode = (limit: SandboxLimit): string => `sandbox.limit.${limit}`;

/**
 * Every reason code `sandbox-map/1` can emit (X14), also the metric label set: one per finding
 * code, per limit, per not-executed reason and per error code, the analysis-level codes and the
 * per-submission skip codes. Each matches `REASON_CODE_PATTERN` and is ≤ 64 characters (tested).
 */
export const SANDBOX_REASON_CODES: readonly string[] = Object.freeze([
  ...new Set<string>([
    ...SANDBOX_OUTCOME_CODES,
    ...SANDBOX_NOT_EXECUTED_REASONS.map(sandboxNotExecutedCode),
    ...SANDBOX_ERROR_CODES.map(sandboxErrorCode),
    ...SANDBOX_FINDING_CODES.map(sandboxFindingReasonCode),
    ...SANDBOX_LIMITS.map(sandboxLimitCode),
    ...SANDBOX_SKIP_REASONS.map(sandboxSkipCode),
  ]),
]);
const SANDBOX_REASON_CODE_SET: ReadonlySet<string> = new Set(SANDBOX_REASON_CODES);
export const isSandboxReasonCode = (value: string): boolean => SANDBOX_REASON_CODE_SET.has(value);
export const sandboxReasonCodeSchema = z
  .string()
  .max(REASON_CODE_MAX_LENGTH)
  .regex(REASON_CODE_PATTERN)
  .refine(isSandboxReasonCode, { message: 'Unknown sandbox reason code' });
/** At most this many reason codes per analysis, submission or final (X14). */
export const SANDBOX_MAX_REASON_CODES = 16;
export const sandboxReasonCodesSchema = z
  .array(sandboxReasonCodeSchema)
  .max(SANDBOX_MAX_REASON_CODES)
  .refine(unique, { message: 'Duplicate reason code' });

// ---------------------------------------------------------------------------------------------
// Artifacts (X12)
// ---------------------------------------------------------------------------------------------

/** Artifact kinds (Prisma `SandboxArtifactKind`). */
export const ARTIFACT_KINDS = [
  'screenshot',
  'process_log',
  'network_log',
  'static_report',
  'dropped_file',
] as const;
export type ArtifactKind = (typeof ARTIFACT_KINDS)[number];
export const artifactKindSchema = z.enum(ARTIFACT_KINDS);

export const ARTIFACT_CONTENT_TYPES = [
  'image/png',
  'text/plain',
  'application/json',
  'application/octet-stream',
] as const;
export type ArtifactContentType = (typeof ARTIFACT_CONTENT_TYPES)[number];
export const artifactContentTypeSchema = z.enum(ARTIFACT_CONTENT_TYPES);

/** The content type of each kind (X12; a screenshot's PNG signature is checked by the sealer). */
export const ARTIFACT_KIND_CONTENT_TYPE: Readonly<Record<ArtifactKind, ArtifactContentType>> =
  Object.freeze({
    screenshot: 'image/png',
    process_log: 'text/plain',
    network_log: 'text/plain',
    static_report: 'application/json',
    dropped_file: 'application/octet-stream',
  });

/** Envelope formats (`@email-gateway/sandbox`). */
export const SANDBOX_SAMPLE_ALGORITHM = 'sandbox-sample/1';
export const SANDBOX_ARTIFACT_ALGORITHM = 'sandbox-artifact/1';

/** Hard ceilings (X12, §4): the configured caps may only be lower. */
export const SANDBOX_MAX_ARTIFACTS_CEILING = 16;
export const SANDBOX_MAX_ARTIFACT_BYTES_CEILING = 8_388_608;
export const SANDBOX_MAX_TOTAL_ARTIFACT_BYTES_CEILING = 33_554_432;
/** Largest sample the platform accepts (64 MiB, X17). */
export const SANDBOX_MAX_SAMPLE_BYTES_CEILING = 67_108_864;

// ---------------------------------------------------------------------------------------------
// Task limits (X2 `TaskLimits`; mail.sandbox.task_requested.v1 `limits`)
// ---------------------------------------------------------------------------------------------

/** Bounds of every task limit (§4); the controller clamps further to its `SANDBOX_MAX_*`. */
export const SANDBOX_TASK_LIMIT_BOUNDS = Object.freeze({
  wallTimeoutMs: Object.freeze({ min: 5_000, max: 600_000 }),
  memoryMb: Object.freeze({ min: 64, max: 4_096 }),
  cpuMillis: Object.freeze({ min: 100, max: 4_000 }),
  pids: Object.freeze({ min: 16, max: 1_024 }),
  scratchMb: Object.freeze({ min: 8, max: 1_024 }),
  maxArtifacts: Object.freeze({ min: 0, max: SANDBOX_MAX_ARTIFACTS_CEILING }),
  maxArtifactBytes: Object.freeze({ min: 1, max: SANDBOX_MAX_ARTIFACT_BYTES_CEILING }),
  maxTotalArtifactBytes: Object.freeze({ min: 1, max: SANDBOX_MAX_TOTAL_ARTIFACT_BYTES_CEILING }),
});
const boundedInt = (bounds: { min: number; max: number }) =>
  z.number().int().min(bounds.min).max(bounds.max);

export const sandboxTaskLimitsSchema = z.strictObject({
  wallTimeoutMs: boundedInt(SANDBOX_TASK_LIMIT_BOUNDS.wallTimeoutMs),
  memoryMb: boundedInt(SANDBOX_TASK_LIMIT_BOUNDS.memoryMb),
  cpuMillis: boundedInt(SANDBOX_TASK_LIMIT_BOUNDS.cpuMillis),
  pids: boundedInt(SANDBOX_TASK_LIMIT_BOUNDS.pids),
  scratchMb: boundedInt(SANDBOX_TASK_LIMIT_BOUNDS.scratchMb),
  maxArtifacts: boundedInt(SANDBOX_TASK_LIMIT_BOUNDS.maxArtifacts),
  maxArtifactBytes: boundedInt(SANDBOX_TASK_LIMIT_BOUNDS.maxArtifactBytes),
  maxTotalArtifactBytes: boundedInt(SANDBOX_TASK_LIMIT_BOUNDS.maxTotalArtifactBytes),
});
export type SandboxTaskLimits = z.infer<typeof sandboxTaskLimitsSchema>;

// ---------------------------------------------------------------------------------------------
// Observations (X2 `BackendObservation.observations` = task_completed.v1 `observations`, §4)
// ---------------------------------------------------------------------------------------------

/** List bounds of the observations (§4). */
export const SANDBOX_OBSERVATION_BOUNDS = Object.freeze({
  processes: 32,
  processSeqMax: 63,
  dns: 50,
  http: 50,
  tls: 50,
  connections: 50,
  droppedFiles: 32,
  findings: 32,
  limitsHit: 8,
  findingCountMax: 1_000_000,
  counterMax: 1_000_000,
});

/** A process image basename (`execve`), never a path or argument (§4). */
export const SANDBOX_PROCESS_IMAGE_PATTERN = /^[A-Za-z0-9._+-]{1,64}$/;
const sha256Hex = z.string().regex(/^[0-9a-f]{64}$/, 'Expected a lower-case hex SHA-256');
const hostSchema = z.string().max(253).regex(URL_HOST_PATTERN, 'Expected an ASCII host');
const portSchema = z.number().int().min(1).max(65_535);
const counter = z.number().int().min(0).max(SANDBOX_OBSERVATION_BOUNDS.counterMax);

/**
 * A canonical IP literal: dotted-quad IPv4 without leading zeros, or IPv6 in the WHATWG
 * serialization (lower case, compressed, no brackets, no zone).
 */
export function isCanonicalIp(value: string): boolean {
  const family = isIP(value);
  if (family === 4) {
    return value.split('.').every((octet) => octet === String(Number(octet)));
  }
  if (family === 6) {
    if (value.includes('%')) return false;
    try {
      return new URL(`http://[${value}]/`).hostname === `[${value}]`;
    } catch {
      return false;
    }
  }
  return false;
}
const canonicalIpSchema = z
  .string()
  .max(45)
  .refine(isCanonicalIp, { message: 'Expected a canonical IP literal' });

export const DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'other'] as const;
export const HTTP_METHODS = ['GET', 'POST', 'HEAD', 'PUT', 'OTHER'] as const;
export const CONNECTION_OUTCOMES = ['refused', 'unreachable', 'sinkhole', 'timeout'] as const;
export const PROCESS_KILLED_BY = ['timeout', 'memory', 'pids'] as const;

const browserCountersSchema = z.strictObject({
  navigations: counter,
  requests: counter,
  downloadsAttempted: counter,
  dialogs: counter,
  passwordFields: counter,
  forms: counter,
});

const findingSchema = z
  .strictObject({
    code: sandboxFindingCodeSchema,
    severity: sandboxFindingSeveritySchema,
    count: z.number().int().min(1).max(SANDBOX_OBSERVATION_BOUNDS.findingCountMax),
  })
  .superRefine((finding, ctx) => {
    if (SANDBOX_FINDING_SEVERITY[finding.code] !== finding.severity) {
      ctx.addIssue({
        code: 'custom',
        path: ['severity'],
        message: `The severity of ${finding.code} is ${SANDBOX_FINDING_SEVERITY[finding.code]}`,
      });
    }
  });
export type SandboxFinding = z.infer<typeof findingSchema>;
export const sandboxFindingSchema = findingSchema;

const droppedFileSchema = z.strictObject({
  seq: z.number().int().min(0).max(65_535),
  sha256: sha256Hex,
  sizeBytes: z.number().int().nonnegative(),
  typeHint: fileTypeIdSchema,
});

/**
 * What a backend observed (§4): processes (basenames, argv hashes, exit/kill), network indicators
 * (DNS names, HTTP hosts with path/User-Agent hashes, TLS SNI, connection attempts by canonical
 * IP), dropped files (hashes, sizes, type hints), findings (codes with their fixed severities),
 * limits hit and browser counters. Strict and bounded; finding codes and limits are the
 * security-contracts enums (the event schema accepts any dotted code of the same shape; the
 * results consumer re-validates with this schema).
 */
export const sandboxObservationsSchema = z
  .strictObject({
    processes: z
      .array(
        z.strictObject({
          seq: z.number().int().min(0).max(SANDBOX_OBSERVATION_BOUNDS.processSeqMax),
          parentSeq: z
            .number()
            .int()
            .min(0)
            .max(SANDBOX_OBSERVATION_BOUNDS.processSeqMax)
            .nullable(),
          image: z.string().regex(SANDBOX_PROCESS_IMAGE_PATTERN, 'Expected an image basename'),
          argvSha256: sha256Hex.nullable(),
          exitCode: z.number().int().min(-2_147_483_648).max(2_147_483_647).nullable(),
          killedBy: z.enum(PROCESS_KILLED_BY).nullable(),
        }),
      )
      .max(SANDBOX_OBSERVATION_BOUNDS.processes),
    processCount: counter,
    network: z.strictObject({
      dns: z
        .array(
          z.strictObject({
            name: hostSchema,
            type: z.enum(DNS_RECORD_TYPES),
            source: z.enum(['sinkhole', 'static']),
          }),
        )
        .max(SANDBOX_OBSERVATION_BOUNDS.dns),
      http: z
        .array(
          z.strictObject({
            host: hostSchema,
            port: portSchema,
            method: z.enum(HTTP_METHODS),
            pathSha256: sha256Hex,
            userAgentSha256: sha256Hex.nullable(),
          }),
        )
        .max(SANDBOX_OBSERVATION_BOUNDS.http),
      tls: z
        .array(z.strictObject({ sni: hostSchema, port: portSchema }))
        .max(SANDBOX_OBSERVATION_BOUNDS.tls),
      connections: z
        .array(
          z.strictObject({
            ip: canonicalIpSchema,
            port: portSchema,
            protocol: z.enum(['tcp', 'udp']),
            outcome: z.enum(CONNECTION_OUTCOMES),
          }),
        )
        .max(SANDBOX_OBSERVATION_BOUNDS.connections),
      totals: z.strictObject({ dns: counter, http: counter, tls: counter, connections: counter }),
    }),
    files: z.strictObject({
      dropped: z.array(droppedFileSchema).max(SANDBOX_OBSERVATION_BOUNDS.droppedFiles),
      deniedWrites: counter,
    }),
    findings: z.array(findingSchema).max(SANDBOX_OBSERVATION_BOUNDS.findings),
    limitsHit: z.array(sandboxLimitSchema).max(SANDBOX_OBSERVATION_BOUNDS.limitsHit),
    browser: browserCountersSchema.nullable(),
  })
  .superRefine((o, ctx) => {
    const issue = (path: (string | number)[], message: string) =>
      ctx.addIssue({ code: 'custom', path, message });
    if (!unique(o.findings.map((f) => f.code))) issue(['findings'], 'Duplicate finding code');
    if (!unique(o.limitsHit)) issue(['limitsHit'], 'Duplicate limit');
    if (!unique(o.processes.map((p) => p.seq))) issue(['processes'], 'Duplicate process seq');
    if (!unique(o.files.dropped.map((f) => f.seq))) issue(['files', 'dropped'], 'Duplicate seq');
    if (o.processCount < o.processes.length) {
      issue(['processCount'], 'processCount is below the listed processes');
    }
    const totals = o.network.totals;
    for (const key of ['dns', 'http', 'tls', 'connections'] as const) {
      if (totals[key] < o.network[key].length) {
        issue(['network', 'totals', key], `totals.${key} is below the listed entries`);
      }
    }
  });
export type SandboxObservations = z.infer<typeof sandboxObservationsSchema>;

/** Observations of a run that observed nothing (disabled backend, not executed). */
export function emptySandboxObservations(): SandboxObservations {
  return {
    processes: [],
    processCount: 0,
    network: {
      dns: [],
      http: [],
      tls: [],
      connections: [],
      totals: { dns: 0, http: 0, tls: 0, connections: 0 },
    },
    files: { dropped: [], deniedWrites: 0 },
    findings: [],
    limitsHit: [],
    browser: null,
  };
}

// ---------------------------------------------------------------------------------------------
// Stored report view (`sandbox_analyses.report`, §3; read API X18)
// ---------------------------------------------------------------------------------------------

export const SANDBOX_REPORT_BOUNDS = Object.freeze({
  findings: 32,
  hosts: 50,
  ips: 50,
  images: 32,
  droppedFiles: 32,
  limitsHit: 8,
});

const uniqueStrings = (schema: z.ZodString, max: number) =>
  z.array(schema).max(max).refine(unique, { message: 'Duplicate value' });

/**
 * The bounded view stored in `sandbox_analyses.report` (§3) and shown by the scans read API
 * (X18): findings, indicator host names / IPs (deduplicated), process count and image
 * basenames, dropped files (hash, size, type hint), denied writes, network totals, limits and
 * browser counters. No content, no paths, no URLs.
 */
export const sandboxReportViewSchema = z.strictObject({
  v: z.literal(1),
  findings: z.array(findingSchema).max(SANDBOX_REPORT_BOUNDS.findings),
  indicators: z.strictObject({
    dns: uniqueStrings(hostSchema, SANDBOX_REPORT_BOUNDS.hosts),
    httpHosts: uniqueStrings(hostSchema, SANDBOX_REPORT_BOUNDS.hosts),
    tlsSni: uniqueStrings(hostSchema, SANDBOX_REPORT_BOUNDS.hosts),
    ips: z
      .array(canonicalIpSchema)
      .max(SANDBOX_REPORT_BOUNDS.ips)
      .refine(unique, { message: 'Duplicate value' }),
  }),
  networkTotals: z.strictObject({
    dns: counter,
    http: counter,
    tls: counter,
    connections: counter,
  }),
  processes: z.strictObject({
    count: counter,
    images: uniqueStrings(
      z.string().regex(SANDBOX_PROCESS_IMAGE_PATTERN),
      SANDBOX_REPORT_BOUNDS.images,
    ),
  }),
  droppedFiles: z
    .array(droppedFileSchema.omit({ seq: true }))
    .max(SANDBOX_REPORT_BOUNDS.droppedFiles),
  deniedWrites: counter,
  limitsHit: z.array(sandboxLimitSchema).max(SANDBOX_REPORT_BOUNDS.limitsHit),
  browser: browserCountersSchema.nullable(),
});
export type SandboxReportView = z.infer<typeof sandboxReportViewSchema>;

const firstUnique = <T>(values: readonly T[], max: number): T[] =>
  [...new Set(values)].slice(0, max);

/**
 * The stored view of validated observations (pure): findings ordered by severity (highest first)
 * then code, indicators deduplicated in first-seen order and capped.
 */
export function buildSandboxReportView(observations: SandboxObservations): SandboxReportView {
  const findings = [...observations.findings].sort(
    (a, b) =>
      sandboxFindingSeverityRank(b.severity) - sandboxFindingSeverityRank(a.severity) ||
      (a.code < b.code ? -1 : a.code > b.code ? 1 : 0),
  );
  return sandboxReportViewSchema.parse({
    v: 1,
    findings: findings.slice(0, SANDBOX_REPORT_BOUNDS.findings),
    indicators: {
      dns: firstUnique(
        observations.network.dns.map((d) => d.name),
        SANDBOX_REPORT_BOUNDS.hosts,
      ),
      httpHosts: firstUnique(
        observations.network.http.map((h) => h.host),
        SANDBOX_REPORT_BOUNDS.hosts,
      ),
      tlsSni: firstUnique(
        observations.network.tls.map((t) => t.sni),
        SANDBOX_REPORT_BOUNDS.hosts,
      ),
      ips: firstUnique(
        observations.network.connections.map((c) => c.ip),
        SANDBOX_REPORT_BOUNDS.ips,
      ),
    },
    networkTotals: { ...observations.network.totals },
    processes: {
      count: observations.processCount,
      images: firstUnique(
        observations.processes.map((p) => p.image),
        SANDBOX_REPORT_BOUNDS.images,
      ),
    },
    droppedFiles: observations.files.dropped
      .slice(0, SANDBOX_REPORT_BOUNDS.droppedFiles)
      .map(({ sha256, sizeBytes, typeHint }) => ({ sha256, sizeBytes, typeHint })),
    deniedWrites: observations.files.deniedWrites,
    limitsHit: [...observations.limitsHit],
    browser: observations.browser === null ? null : { ...observations.browser },
  });
}

// ---------------------------------------------------------------------------------------------
// Settings (X17; platform defaults with bounded tenant overrides, the 4.1 S8 pattern)
// ---------------------------------------------------------------------------------------------

/** The default platform file types (§5 `SANDBOX_FILE_TYPES`). */
export const SANDBOX_DEFAULT_FILE_TYPES = [
  'pdf',
  'ooxml_word',
  'ooxml_excel',
  'ooxml_powerpoint',
  'ooxml_macro',
  'ole_office',
  'rtf',
  'pe_executable',
  'msi',
  'elf',
  'lnk',
  'script_js',
  'script_vbs',
  'script_ps1',
  'script_batch',
  'script_shell',
  'hta',
  'html',
  'svg',
] as const satisfies readonly FileTypeId[];

const fileTypesSchema = z
  .array(fileTypeIdSchema)
  .min(1)
  .max(FILE_TYPE_IDS.length)
  .refine(unique, { message: 'Duplicate file type' });

/**
 * Platform sandbox settings (X17; env `SANDBOX_TENANT_DEFAULT_ENABLED`, `SANDBOX_FILE_TYPES`,
 * `SANDBOX_MAX_SAMPLE_BYTES`, `SANDBOX_BROWSER_ANALYSIS`, read by the api and the email-worker).
 * The backend, limits and timeouts are platform-only configuration of the services, not settings.
 */
export const sandboxPlatformSettingsSchema = z.strictObject({
  tenantDefaultEnabled: z.boolean(),
  fileTypes: fileTypesSchema,
  maxSampleBytes: z.number().int().min(1).max(SANDBOX_MAX_SAMPLE_BYTES_CEILING),
  browserAnalysis: z.boolean(),
});
export type SandboxPlatformSettings = z.infer<typeof sandboxPlatformSettingsSchema>;

/** Platform defaults (`.env.example`, §5). */
export const SANDBOX_PLATFORM_DEFAULTS: Readonly<SandboxPlatformSettings> = Object.freeze({
  tenantDefaultEnabled: false,
  fileTypes: [...SANDBOX_DEFAULT_FILE_TYPES],
  maxSampleBytes: 26_214_400,
  browserAnalysis: true,
});

/** Environment keys of the platform settings (both the api and the email-worker read them). */
export const SANDBOX_PLATFORM_ENV_KEYS = Object.freeze({
  tenantDefaultEnabled: 'SANDBOX_TENANT_DEFAULT_ENABLED',
  fileTypes: 'SANDBOX_FILE_TYPES',
  maxSampleBytes: 'SANDBOX_MAX_SAMPLE_BYTES',
  browserAnalysis: 'SANDBOX_BROWSER_ANALYSIS',
} as const satisfies Record<keyof SandboxPlatformSettings, string>);

const parseBoolean = (value: string): boolean | string =>
  value === 'true' ? true : value === 'false' ? false : value;

/**
 * Reads the platform settings from environment variables (unset or empty → default) and
 * validates them. Throws a `ZodError` naming the setting on invalid input. Booleans are exactly
 * `true` or `false`; the file types are a comma-separated list of `FILE_TYPE_IDS`.
 */
export function sandboxPlatformSettingsFromEnv(
  env: Readonly<Record<string, string | undefined>>,
): SandboxPlatformSettings {
  const read = (key: keyof SandboxPlatformSettings): string | undefined => {
    const value = env[SANDBOX_PLATFORM_ENV_KEYS[key]];
    return value === undefined || value.trim() === '' ? undefined : value.trim();
  };
  const tenantDefault = read('tenantDefaultEnabled');
  const browser = read('browserAnalysis');
  const types = read('fileTypes');
  const max = read('maxSampleBytes');
  return sandboxPlatformSettingsSchema.parse({
    tenantDefaultEnabled:
      tenantDefault === undefined
        ? SANDBOX_PLATFORM_DEFAULTS.tenantDefaultEnabled
        : parseBoolean(tenantDefault),
    fileTypes:
      types === undefined
        ? [...SANDBOX_PLATFORM_DEFAULTS.fileTypes]
        : types
            .split(',')
            .map((t) => t.trim())
            .filter((t) => t.length > 0),
    maxSampleBytes: max === undefined ? SANDBOX_PLATFORM_DEFAULTS.maxSampleBytes : Number(max),
    browserAnalysis:
      browser === undefined ? SANDBOX_PLATFORM_DEFAULTS.browserAnalysis : parseBoolean(browser),
  });
}

/**
 * A tenant override (`scan_engine_settings.settings` of engine `sandbox`, X17): strict, every key
 * optional. `enabled: true` additionally needs the plan feature `attachment_sandbox` (the api
 * answers `409 feature_not_enabled`; the worker re-checks at use); bounds that depend on the
 * platform are checked by `resolveSandboxSettings`.
 */
export const sandboxTenantSettingsSchema = z.strictObject({
  enabled: z.boolean().optional(),
  fileTypes: fileTypesSchema.optional(),
  maxSampleBytes: z.number().int().optional(),
  browserAnalysis: z.boolean().optional(),
});
export type SandboxTenantSettings = z.infer<typeof sandboxTenantSettingsSchema>;

/** The settings the sandbox engine uses for one tenant (X13 step 3). */
export interface SandboxEffectiveSettings {
  enabled: boolean;
  fileTypes: FileTypeId[];
  maxSampleBytes: number;
  browserAnalysis: boolean;
}

export type SandboxSettingsResolution =
  | { ok: true; settings: SandboxEffectiveSettings; overridden: boolean }
  | { ok: false; violations: SettingsViolation[] };

/** The bounds a tenant override must respect (the settings API returns them). */
export interface SandboxSettingsBounds {
  enabled: readonly boolean[];
  fileTypes: readonly FileTypeId[];
  maxSampleBytes: { min: number; max: number };
  browserAnalysis: readonly boolean[];
}

/** The values a tenant may choose given the platform settings. */
export function sandboxSettingsBounds(platform: SandboxPlatformSettings): SandboxSettingsBounds {
  return {
    enabled: [false, true],
    fileTypes: [...platform.fileTypes],
    maxSampleBytes: { min: 1, max: platform.maxSampleBytes },
    browserAnalysis: platform.browserAnalysis ? [false, true] : [false],
  };
}

const sandboxPlatformEffective = (platform: SandboxPlatformSettings): SandboxEffectiveSettings => ({
  enabled: platform.tenantDefaultEnabled,
  fileTypes: [...platform.fileTypes],
  maxSampleBytes: platform.maxSampleBytes,
  browserAnalysis: platform.browserAnalysis,
});

/**
 * Merges a tenant override (raw JSON from `scan_engine_settings.settings`, or null/undefined for
 * none) into the platform settings (X17). Pure; mirrors `resolveDlpSettings`. Bounds: `fileTypes`
 * a non-empty subset of the platform list; `maxSampleBytes` within [1, platform maximum];
 * `browserAnalysis` may be `true` only when the platform allows it; unknown keys refused. The
 * plan-feature gate of `enabled` is the caller's (api 409, worker skip `feature_disabled`).
 */
export function resolveSandboxSettings(
  platform: SandboxPlatformSettings,
  override: unknown,
): SandboxSettingsResolution {
  if (override === null || override === undefined) {
    return { ok: true, settings: sandboxPlatformEffective(platform), overridden: false };
  }
  const parsed = sandboxTenantSettingsSchema.safeParse(override);
  if (!parsed.success) {
    return {
      ok: false,
      violations: parsed.error.issues.flatMap((issue): SettingsViolation[] => {
        const base = issue.path.map(String);
        if (issue.code === 'unrecognized_keys') {
          return issue.keys.map((key) => ({
            path: [...base, key].join('.'),
            code: 'unknown_key',
            message: `Unknown setting: ${[...base, key].join('.')}`,
          }));
        }
        return [
          {
            path: base.length > 0 ? base.join('.') : 'settings',
            code: 'invalid',
            message: issue.message,
          },
        ];
      }),
    };
  }
  const tenant = parsed.data;
  const base = sandboxPlatformEffective(platform);
  const violations: SettingsViolation[] = [];
  if (tenant.fileTypes !== undefined) {
    const outside = tenant.fileTypes.filter((t) => !platform.fileTypes.includes(t));
    if (outside.length > 0) {
      violations.push({
        path: 'fileTypes',
        code: 'out_of_bounds',
        message: `fileTypes must be a subset of the platform list (not allowed: ${outside.join(', ')})`,
      });
    }
  }
  if (
    tenant.maxSampleBytes !== undefined &&
    (tenant.maxSampleBytes < 1 || tenant.maxSampleBytes > platform.maxSampleBytes)
  ) {
    violations.push({
      path: 'maxSampleBytes',
      code: 'out_of_bounds',
      message: `maxSampleBytes must be within [1, ${platform.maxSampleBytes}]`,
    });
  }
  if (tenant.browserAnalysis === true && !platform.browserAnalysis) {
    violations.push({
      path: 'browserAnalysis',
      code: 'out_of_bounds',
      message: 'browserAnalysis may not exceed the platform setting (disabled)',
    });
  }
  if (violations.length > 0) return { ok: false, violations };
  return {
    ok: true,
    overridden: Object.values(tenant).some((value) => value !== undefined),
    settings: {
      enabled: tenant.enabled ?? base.enabled,
      fileTypes: tenant.fileTypes ? [...tenant.fileTypes] : base.fileTypes,
      maxSampleBytes: tenant.maxSampleBytes ?? base.maxSampleBytes,
      browserAnalysis: tenant.browserAnalysis ?? base.browserAnalysis,
    },
  };
}

/**
 * `settings_version` of the sandbox engine (stored on the submission at dispatch, copied to the
 * final row; X14): `sandbox-map/1;p=<12 hex of the platform settings>;t=<row version | none>`.
 */
export function sandboxSettingsVersion(
  platform: SandboxPlatformSettings,
  rowVersion: number | null,
): string {
  return settingsVersion(SANDBOX_MAPPING_VERSION, platform, rowVersion);
}
