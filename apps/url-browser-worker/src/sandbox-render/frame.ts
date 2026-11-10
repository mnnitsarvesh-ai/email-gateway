/**
 * Framing of the sandbox runner protocol (step 4.6 X6), browser side. Mirrors
 * `apps/sandbox-controller/src/runner/runner-protocol.ts` (the authoritative description) and
 * `infrastructure/sandbox/runner/bootstrap.mjs`; apps never import each other, so the few lines
 * are repeated here and pinned by unit tests on both sides.
 *
 *   stdin   u32be headerLength | header JSON | sample bytes   (then EOF)
 *   stdout  "EGSB" 0x01 | frame* | 0xff 00 00 00 00 ; frame = u8 type | u32be length | payload
 *           0x01 report JSON, 0x06 screenshot PNG
 */

export const OUTPUT_MAGIC = Buffer.from('EGSB\u0001', 'latin1');
export const FRAME = Object.freeze({ report: 0x01, screenshot: 0x06, end: 0xff });
export const MAX_HEADER_BYTES = 64 * 1024;
export const MAX_SAMPLE_BYTES = 64 * 1024 * 1024;
export const BROWSER_TYPES = Object.freeze(['html', 'svg']);

export interface RenderHeader {
  v: 1;
  taskId: string;
  profile: 'browser';
  detectedType: 'html' | 'svg';
  wallTimeoutMs: number;
  maxArtifacts: number;
  maxArtifactBytes: number;
  maxTotalArtifactBytes: number;
  sampleSize: number;
}

export class RenderInputError extends Error {
  constructor(readonly code: string) {
    super(`render input invalid: ${code}`);
    this.name = 'RenderInputError';
  }
}

const isInt = (value: unknown, min: number, max: number): value is number =>
  typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max;

/** Parses the runner input (bounded, strict); throws `RenderInputError`. */
export function parseRenderInput(buffer: Buffer): { header: RenderHeader; sample: Buffer } {
  if (buffer.length < 4) throw new RenderInputError('input_truncated');
  const headerLength = buffer.readUInt32BE(0);
  if (headerLength < 2 || headerLength > MAX_HEADER_BYTES)
    throw new RenderInputError('header_length');
  if (buffer.length < 4 + headerLength) throw new RenderInputError('input_truncated');
  let raw: unknown;
  try {
    raw = JSON.parse(buffer.subarray(4, 4 + headerLength).toString('utf8'));
  } catch {
    throw new RenderInputError('header_json');
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new RenderInputError('header_json');
  }
  const h = raw as Record<string, unknown>;
  if (h.v !== 1) throw new RenderInputError('header_version');
  if (h.profile !== 'browser') throw new RenderInputError('header_profile');
  if (typeof h.detectedType !== 'string' || !BROWSER_TYPES.includes(h.detectedType)) {
    throw new RenderInputError('type_not_supported');
  }
  if (typeof h.taskId !== 'string' || !/^[A-Za-z0-9-]{1,64}$/.test(h.taskId)) {
    throw new RenderInputError('header_task');
  }
  if (!isInt(h.wallTimeoutMs, 1_000, 600_000)) throw new RenderInputError('header_wall');
  if (!isInt(h.maxArtifacts, 0, 16)) throw new RenderInputError('header_artifacts');
  if (!isInt(h.maxArtifactBytes, 1, 8_388_608)) throw new RenderInputError('header_artifact_bytes');
  if (!isInt(h.maxTotalArtifactBytes, 1, 33_554_432))
    throw new RenderInputError('header_total_bytes');
  if (!isInt(h.sampleSize, 0, MAX_SAMPLE_BYTES)) throw new RenderInputError('header_sample_size');
  const sample = buffer.subarray(4 + headerLength);
  if (sample.length !== h.sampleSize) throw new RenderInputError('sample_size_mismatch');
  return { header: h as unknown as RenderHeader, sample };
}

export function frame(type: number, payload: Buffer): Buffer {
  const head = Buffer.alloc(5);
  head.writeUInt8(type, 0);
  head.writeUInt32BE(payload.length, 1);
  return Buffer.concat([head, payload]);
}

/** The complete stdout of a render: magic, report, optional screenshot, end frame. */
export function encodeRenderOutput(report: object, screenshot: Buffer | null): Buffer {
  const parts = [OUTPUT_MAGIC, frame(FRAME.report, Buffer.from(JSON.stringify(report), 'utf8'))];
  if (screenshot) parts.push(frame(FRAME.screenshot, screenshot));
  parts.push(frame(FRAME.end, Buffer.alloc(0)));
  return Buffer.concat(parts);
}
