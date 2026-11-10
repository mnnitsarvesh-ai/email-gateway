import { describe, expect, it } from 'vitest';
import {
  encodeRenderOutput,
  FRAME,
  OUTPUT_MAGIC,
  parseRenderInput,
  RenderInputError,
} from './frame';

const header = (over: Record<string, unknown> = {}) => ({
  v: 1,
  taskId: '0190c3a2-7b1e-7cc1-8f00-000000000001',
  profile: 'browser',
  detectedType: 'html',
  wallTimeoutMs: 20_000,
  maxArtifacts: 2,
  maxArtifactBytes: 1_000_000,
  maxTotalArtifactBytes: 2_000_000,
  sampleSize: 6,
  ...over,
});
const encode = (h: object, sample: Buffer) => {
  const json = Buffer.from(JSON.stringify(h));
  const len = Buffer.alloc(4);
  len.writeUInt32BE(json.length);
  return Buffer.concat([len, json, sample]);
};

describe('parseRenderInput (the sandbox runner protocol, browser side)', () => {
  it('accepts the controller encoding', () => {
    const { header: h, sample } = parseRenderInput(encode(header(), Buffer.from('<html>')));
    expect(h.detectedType).toBe('html');
    expect(sample.toString()).toBe('<html>');
  });

  it.each([
    ['truncated', Buffer.from([0, 0, 1]), 'input_truncated'],
    ['header too large', Buffer.from([0, 9, 0, 0]), 'header_length'],
    ['not JSON', Buffer.concat([Buffer.from([0, 0, 0, 2]), Buffer.from('{x')]), 'header_json'],
    ['array header', encode([], Buffer.alloc(0)), 'header_json'],
    ['wrong version', encode(header({ v: 2 }), Buffer.from('<html>')), 'header_version'],
    [
      'execute profile',
      encode(header({ profile: 'execute' }), Buffer.from('<html>')),
      'header_profile',
    ],
    [
      'script type',
      encode(header({ detectedType: 'script_js' }), Buffer.from('<html>')),
      'type_not_supported',
    ],
    ['bad task id', encode(header({ taskId: '../x' }), Buffer.from('<html>')), 'header_task'],
    ['wall', encode(header({ wallTimeoutMs: 10 }), Buffer.from('<html>')), 'header_wall'],
    ['artifacts', encode(header({ maxArtifacts: 17 }), Buffer.from('<html>')), 'header_artifacts'],
    [
      'artifact bytes',
      encode(header({ maxArtifactBytes: 0 }), Buffer.from('<html>')),
      'header_artifact_bytes',
    ],
    [
      'total bytes',
      encode(header({ maxTotalArtifactBytes: 1e9 }), Buffer.from('<html>')),
      'header_total_bytes',
    ],
    [
      'size mismatch',
      encode(header({ sampleSize: 7 }), Buffer.from('<html>')),
      'sample_size_mismatch',
    ],
  ])('%s → %s', (_name, input, code) => {
    expect(() => parseRenderInput(input)).toThrow(RenderInputError);
    try {
      parseRenderInput(input);
    } catch (error) {
      expect((error as RenderInputError).code).toBe(code);
    }
  });
});

describe('encodeRenderOutput', () => {
  it('magic, report frame, optional screenshot frame, end frame', () => {
    const out = encodeRenderOutput({ v: 1 }, Buffer.from([1, 2, 3]));
    expect(out.subarray(0, 5).equals(OUTPUT_MAGIC)).toBe(true);
    expect(out[5]).toBe(FRAME.report);
    const reportLength = out.readUInt32BE(6);
    expect(JSON.parse(out.subarray(10, 10 + reportLength).toString())).toEqual({ v: 1 });
    const next = 10 + reportLength;
    expect(out[next]).toBe(FRAME.screenshot);
    expect(out.readUInt32BE(next + 1)).toBe(3);
    expect([...out.subarray(-5)]).toEqual([FRAME.end, 0, 0, 0, 0]);
    expect(encodeRenderOutput({}, null).includes(Buffer.from([FRAME.screenshot, 0, 0, 0, 3]))).toBe(
      false,
    );
  });
});
