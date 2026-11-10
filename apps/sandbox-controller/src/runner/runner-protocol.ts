/**
 * The controller ⇄ runner protocol (step 4.6 X6; docs/plan/steps/14-sandbox.md). Both sides are
 * bounded; everything the runner writes is UNTRUSTED (the sample runs with the runner's uid and
 * can tamper with it) and is parsed strictly here — malformed or over-cap output is never a crash
 * of the controller, it becomes `limit.output_truncated` evidence.
 *
 *   stdin   u32be headerLength | header JSON | sample bytes   (then the controller closes stdin)
 *   stdout  "EGSB" 0x01 | frame* | 0xff 00 00 00 00
 *           frame = u8 type | u32be length | payload
 *           0x01 report JSON (exactly one)   0x02 file: u16be metaLength | meta JSON {seq} | bytes
 *           0x03 strace text                 0x04 sample stdout   0x05 sample stderr
 *           0x06 screenshot PNG
 *
 * Writers: `infrastructure/sandbox/runner/bootstrap.mjs` (execute, self-test) and
 * `apps/url-browser-worker/src/sandbox-render/render-main.ts` (browser).
 */

export const PROTOCOL_VERSION = 1;
export const OUTPUT_MAGIC = Buffer.from('EGSB\u0001', 'latin1');
export const FRAME_TYPES = Object.freeze({
  report: 0x01,
  file: 0x02,
  trace: 0x03,
  stdout: 0x04,
  stderr: 0x05,
  screenshot: 0x06,
  end: 0xff,
});
export const MAX_HEADER_BYTES = 64 * 1024;

/** Caps of the parts of one runner output. */
export const OUTPUT_CAPS = Object.freeze({
  report: 256 * 1024,
  trace: 2 * 1024 * 1024,
  stdout: 64 * 1024,
  stderr: 64 * 1024,
  fileMeta: 256,
});

export interface RunnerInputHeader {
  v: 1;
  taskId: string;
  profile: 'execute' | 'browser';
  detectedType: string;
  wallTimeoutMs: number;
  maxArtifacts: number;
  maxArtifactBytes: number;
  maxTotalArtifactBytes: number;
  sampleSize: number;
}

/** Encodes the stdin of a runner: length-prefixed header JSON followed by the sample bytes. */
export function encodeRunnerInput(
  header: Omit<RunnerInputHeader, 'v' | 'sampleSize'>,
  sample: Buffer,
): Buffer {
  const full: RunnerInputHeader = { v: PROTOCOL_VERSION, ...header, sampleSize: sample.length };
  const json = Buffer.from(JSON.stringify(full), 'utf8');
  if (json.length > MAX_HEADER_BYTES) throw new Error('runner header too large');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(json.length, 0);
  return Buffer.concat([length, json, sample]);
}

export interface OutputLimits {
  maxArtifacts: number;
  maxArtifactBytes: number;
  maxTotalArtifactBytes: number;
}

/** The most stdout bytes the controller keeps for one runner (everything beyond is truncation). */
export function maxOutputBytes(limits: OutputLimits): number {
  return (
    OUTPUT_MAGIC.length +
    5 * 6 +
    OUTPUT_CAPS.report +
    OUTPUT_CAPS.trace +
    OUTPUT_CAPS.stdout +
    OUTPUT_CAPS.stderr +
    limits.maxTotalArtifactBytes +
    limits.maxArtifacts * (5 + 2 + OUTPUT_CAPS.fileMeta) +
    5
  );
}

export interface ParsedFile {
  seq: number;
  bytes: Buffer;
}

export interface ParsedRunnerOutput {
  /** The report JSON (unvalidated: the caller applies its strict schema), or null. */
  report: unknown;
  trace: Buffer;
  stdout: Buffer;
  stderr: Buffer;
  files: ParsedFile[];
  screenshot: Buffer | null;
  /** The end frame was seen and nothing followed it. */
  complete: boolean;
  /** Why the output is unusable or incomplete (first problem), or null. */
  problem: OutputProblem | null;
  /** Artifacts beyond `maxArtifacts` / byte caps were dropped. */
  artifactCapHit: boolean;
}

export type OutputProblem =
  | 'empty'
  | 'bad_magic'
  | 'truncated'
  | 'unknown_frame'
  | 'oversized_frame'
  | 'duplicate_report'
  | 'bad_report_json'
  | 'bad_file_meta'
  | 'missing_report'
  | 'trailing_data';

/**
 * Parses a runner's stdout (pure, bounded). Never throws: problems are reported in `problem`;
 * whatever was valid before the problem is kept (the report only when it parsed). Output cut by
 * the controller's own stdout cap ends without the end frame and reports `truncated`.
 */
export function parseRunnerOutput(data: Buffer, limits: OutputLimits): ParsedRunnerOutput {
  const out: ParsedRunnerOutput = {
    report: null,
    trace: Buffer.alloc(0),
    stdout: Buffer.alloc(0),
    stderr: Buffer.alloc(0),
    files: [],
    screenshot: null,
    complete: false,
    problem: null,
    artifactCapHit: false,
  };
  const setProblem = (problem: OutputProblem) => {
    out.problem ??= problem;
  };
  if (data.length === 0) {
    setProblem('empty');
    return out;
  }
  if (
    data.length < OUTPUT_MAGIC.length ||
    !data.subarray(0, OUTPUT_MAGIC.length).equals(OUTPUT_MAGIC)
  ) {
    setProblem('bad_magic');
    return out;
  }
  let offset = OUTPUT_MAGIC.length;
  let reportSeen = false;
  let artifactCount = 0;
  let artifactBytes = 0;
  const seqs = new Set<number>();
  const artifactFits = (size: number) =>
    artifactCount < limits.maxArtifacts &&
    size <= limits.maxArtifactBytes &&
    artifactBytes + size <= limits.maxTotalArtifactBytes;

  while (offset < data.length) {
    if (data.length - offset < 5) {
      setProblem('truncated');
      break;
    }
    const type = data.readUInt8(offset);
    const length = data.readUInt32BE(offset + 1);
    const start = offset + 5;
    if (type === FRAME_TYPES.end) {
      if (length !== 0) {
        setProblem('oversized_frame');
        break;
      }
      out.complete = true;
      if (start !== data.length) setProblem('trailing_data');
      break;
    }
    const cap = frameCap(type, limits);
    if (cap === null) {
      setProblem('unknown_frame');
      break;
    }
    if (length > cap) {
      setProblem('oversized_frame');
      break;
    }
    if (data.length - start < length) {
      setProblem('truncated');
      break;
    }
    const payload = data.subarray(start, start + length);
    offset = start + length;
    switch (type) {
      case FRAME_TYPES.report: {
        if (reportSeen) {
          setProblem('duplicate_report');
          break;
        }
        reportSeen = true;
        try {
          out.report = JSON.parse(payload.toString('utf8')) as unknown;
        } catch {
          setProblem('bad_report_json');
        }
        break;
      }
      case FRAME_TYPES.trace:
        out.trace = Buffer.from(payload);
        break;
      case FRAME_TYPES.stdout:
        out.stdout = Buffer.from(payload);
        break;
      case FRAME_TYPES.stderr:
        out.stderr = Buffer.from(payload);
        break;
      case FRAME_TYPES.file: {
        const file = parseFilePayload(payload);
        if (!file || seqs.has(file.seq)) {
          setProblem('bad_file_meta');
          break;
        }
        seqs.add(file.seq);
        if (!artifactFits(file.bytes.length)) {
          out.artifactCapHit = true;
          break;
        }
        artifactCount += 1;
        artifactBytes += file.bytes.length;
        out.files.push(file);
        break;
      }
      case FRAME_TYPES.screenshot: {
        if (out.screenshot || !artifactFits(payload.length)) {
          out.artifactCapHit = true;
          break;
        }
        artifactCount += 1;
        artifactBytes += payload.length;
        out.screenshot = Buffer.from(payload);
        break;
      }
    }
    if (out.problem) break;
  }
  if (!out.complete) setProblem('truncated');
  if (!reportSeen) setProblem('missing_report');
  return out;
}

function frameCap(type: number, limits: OutputLimits): number | null {
  switch (type) {
    case FRAME_TYPES.report:
      return OUTPUT_CAPS.report;
    case FRAME_TYPES.trace:
      return OUTPUT_CAPS.trace;
    case FRAME_TYPES.stdout:
      return OUTPUT_CAPS.stdout;
    case FRAME_TYPES.stderr:
      return OUTPUT_CAPS.stderr;
    case FRAME_TYPES.file:
      return 2 + OUTPUT_CAPS.fileMeta + limits.maxArtifactBytes;
    case FRAME_TYPES.screenshot:
      return limits.maxArtifactBytes;
    default:
      return null;
  }
}

function parseFilePayload(payload: Buffer): ParsedFile | null {
  if (payload.length < 2) return null;
  const metaLength = payload.readUInt16BE(0);
  if (metaLength === 0 || metaLength > OUTPUT_CAPS.fileMeta || payload.length < 2 + metaLength) {
    return null;
  }
  let meta: unknown;
  try {
    meta = JSON.parse(payload.subarray(2, 2 + metaLength).toString('utf8'));
  } catch {
    return null;
  }
  if (typeof meta !== 'object' || meta === null || Array.isArray(meta)) return null;
  const keys = Object.keys(meta);
  const seq = (meta as { seq?: unknown }).seq;
  if (
    keys.length !== 1 ||
    typeof seq !== 'number' ||
    !Number.isInteger(seq) ||
    seq < 0 ||
    seq > 63
  ) {
    return null;
  }
  return { seq, bytes: Buffer.from(payload.subarray(2 + metaLength)) };
}

/** Encodes runner output (used by the unit tests and mirrored by the in-image writers). */
export function encodeRunnerOutput(
  frames: Array<{ type: number; payload: Buffer }>,
  options: { end?: boolean } = {},
): Buffer {
  const parts: Buffer[] = [OUTPUT_MAGIC];
  for (const f of frames) {
    const head = Buffer.alloc(5);
    head.writeUInt8(f.type, 0);
    head.writeUInt32BE(f.payload.length, 1);
    parts.push(head, f.payload);
  }
  if (options.end !== false) parts.push(Buffer.from([FRAME_TYPES.end, 0, 0, 0, 0]));
  return Buffer.concat(parts);
}

/** A `file` frame payload: u16be meta length | {"seq":n} | bytes. */
export function filePayload(seq: number, bytes: Buffer): Buffer {
  const meta = Buffer.from(JSON.stringify({ seq }), 'utf8');
  const length = Buffer.alloc(2);
  length.writeUInt16BE(meta.length, 0);
  return Buffer.concat([length, meta, bytes]);
}
