import { z } from 'zod';

/**
 * Strict schemas of the JSON reports runners write (step 4.6 X6): `bootstrap.mjs` (execute,
 * self-test) and the url-browser-worker's `sandbox-render/render-main.ts` (browser). Reports are
 * UNTRUSTED: a report that does not match is treated as no report (`limit.output_truncated`).
 */

const token = (max: number) =>
  z
    .string()
    .max(max)
    .regex(/^[A-Za-z0-9_.:-]*$/);
const count = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const sha = z.string().regex(/^[0-9a-f]{64}$/);

const cgroupStatsSchema = z.strictObject({
  cpuUsageUsec: count.nullable(),
  nrThrottled: count.nullable(),
  throttledUsec: count.nullable(),
  oomKill: count.nullable(),
  cpuMax: z.string().max(64).nullable(),
  pidsMax: z.string().max(32).nullable(),
  memoryMax: z.string().max(32).nullable(),
});
export type CgroupStats = z.infer<typeof cgroupStatsSchema>;

export const executeReportSchema = z.strictObject({
  v: z.literal(1),
  mode: z.literal('execute'),
  inputError: z.null(),
  spawnError: token(32).nullable(),
  exit: z.strictObject({
    code: z.number().int().min(-255).max(255).nullable(),
    signal: token(16).nullable(),
  }),
  timedOut: z.boolean(),
  innerTimeoutMs: count,
  durationMs: count,
  stdoutBytes: count,
  stderrBytes: count,
  traceBytes: count,
  traceTruncated: z.boolean(),
  scratchFull: z.boolean(),
  files: z
    .array(
      z.strictObject({
        seq: z.number().int().min(0).max(63),
        pathSha256: sha,
        size: count,
        sha256: sha,
        head: z
          .string()
          .max(32)
          .regex(/^[A-Za-z0-9+/]*={0,2}$/),
        executable: z.boolean(),
      }),
    )
    .max(32),
  filesTotal: count,
  filesOmitted: count,
  cgroup: z.strictObject({ before: cgroupStatsSchema, after: cgroupStatsSchema }),
});
export type ExecuteReport = z.infer<typeof executeReportSchema>;

/** A runner that could not even start the sample (bad input, internal error). */
export const inputErrorReportSchema = z.strictObject({
  v: z.literal(1),
  mode: z.enum(['execute', 'error', 'browser']),
  inputError: token(64),
});

export const browserReportSchema = z.strictObject({
  v: z.literal(1),
  mode: z.literal('browser'),
  error: token(64).nullable(),
  durationMs: count,
  navigations: count,
  requests: count,
  requestList: z
    .array(
      z.strictObject({
        host: z.string().max(253),
        port: z.number().int().min(1).max(65_535),
        method: z.enum(['GET', 'POST', 'HEAD', 'PUT', 'OTHER']),
        pathSha256: sha,
        scheme: z.enum(['http', 'https', 'ws', 'wss', 'other']),
      }),
    )
    .max(50),
  downloadsAttempted: count,
  dialogs: count,
  passwordFields: count,
  forms: count,
  crossOriginForms: count,
  jsRedirects: count,
  screenshot: z.boolean(),
  chromiumVersion: z.string().max(64).nullable(),
});
export type BrowserReport = z.infer<typeof browserReportSchema>;

export const selfTestReportSchema = z.strictObject({
  v: z.literal(1),
  mode: z.literal('self-test'),
  uid: z.number().int(),
  gid: z.number().int(),
  capEff: z.string().max(32).nullable(),
  capPrm: z.string().max(32).nullable(),
  capBnd: z.string().max(32).nullable(),
  noNewPrivs: z.string().max(8).nullable(),
  seccomp: z.string().max(8).nullable(),
  rootWrite: z.union([z.literal(true), token(32)]),
  etcWrite: z.union([z.literal(true), token(32)]),
  scratchWrite: z.union([z.literal(true), token(32)]),
  routes: z
    .array(
      z.strictObject({
        iface: z.string().max(16),
        destination: z.string().max(15),
        gateway: z.string().max(15),
        mask: z.string().max(15),
      }),
    )
    .max(16),
  resolver: z.strictObject({
    nameservers: z.array(z.string().max(64)).max(8),
    extServers: z.array(z.string().max(64)).max(8),
  }),
  dnsAnswer: z.string().max(64).nullable(),
  dockerSocket: z.boolean(),
  envKeys: z.array(z.string().max(64)).max(32),
  apparmor: z.string().max(64).nullable(),
  cgroup: cgroupStatsSchema,
});
export type SelfTestReport = z.infer<typeof selfTestReportSchema>;
