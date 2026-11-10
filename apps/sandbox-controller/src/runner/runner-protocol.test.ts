import { describe, expect, it } from 'vitest';
import {
  encodeRunnerInput,
  encodeRunnerOutput,
  filePayload,
  FRAME_TYPES,
  MAX_HEADER_BYTES,
  maxOutputBytes,
  OUTPUT_CAPS,
  OUTPUT_MAGIC,
  parseRunnerOutput,
} from './runner-protocol';

const limits = { maxArtifacts: 3, maxArtifactBytes: 1024, maxTotalArtifactBytes: 2048 };
const report = Buffer.from(JSON.stringify({ v: 1, mode: 'execute' }));

describe('encodeRunnerInput', () => {
  it('writes u32be length, header JSON with v and sampleSize, then the sample', () => {
    const sample = Buffer.from('echo hi\n');
    const input = encodeRunnerInput(
      {
        taskId: 't-1',
        profile: 'execute',
        detectedType: 'script_shell',
        wallTimeoutMs: 10_000,
        maxArtifacts: 2,
        maxArtifactBytes: 10,
        maxTotalArtifactBytes: 20,
      },
      sample,
    );
    const length = input.readUInt32BE(0);
    const header = JSON.parse(input.subarray(4, 4 + length).toString()) as Record<string, unknown>;
    expect(header).toEqual({
      v: 1,
      taskId: 't-1',
      profile: 'execute',
      detectedType: 'script_shell',
      wallTimeoutMs: 10_000,
      maxArtifacts: 2,
      maxArtifactBytes: 10,
      maxTotalArtifactBytes: 20,
      sampleSize: sample.length,
    });
    expect(input.subarray(4 + length).equals(sample)).toBe(true);
  });

  it('refuses an oversized header', () => {
    expect(() =>
      encodeRunnerInput(
        {
          taskId: 'x'.repeat(MAX_HEADER_BYTES),
          profile: 'execute',
          detectedType: 'script_shell',
          wallTimeoutMs: 1,
          maxArtifacts: 0,
          maxArtifactBytes: 1,
          maxTotalArtifactBytes: 1,
        },
        Buffer.alloc(0),
      ),
    ).toThrow(/too large/);
  });
});

describe('parseRunnerOutput', () => {
  it('parses report, trace, streams, files and the screenshot', () => {
    const out = encodeRunnerOutput([
      { type: FRAME_TYPES.report, payload: report },
      { type: FRAME_TYPES.trace, payload: Buffer.from('1 00:00:00.0 execve("/bin/sh") = 0\n') },
      { type: FRAME_TYPES.stdout, payload: Buffer.from('RESULT x\n') },
      { type: FRAME_TYPES.stderr, payload: Buffer.from('warn\n') },
      { type: FRAME_TYPES.file, payload: filePayload(0, Buffer.from('dropped')) },
      { type: FRAME_TYPES.screenshot, payload: Buffer.from([0x89, 0x50, 0x4e, 0x47]) },
    ]);
    const parsed = parseRunnerOutput(out, limits);
    expect(parsed.problem).toBeNull();
    expect(parsed.complete).toBe(true);
    expect(parsed.report).toEqual({ v: 1, mode: 'execute' });
    expect(parsed.trace.toString()).toContain('execve');
    expect(parsed.stdout.toString()).toBe('RESULT x\n');
    expect(parsed.stderr.toString()).toBe('warn\n');
    expect(parsed.files).toEqual([{ seq: 0, bytes: Buffer.from('dropped') }]);
    expect(parsed.screenshot?.length).toBe(4);
    expect(parsed.artifactCapHit).toBe(false);
  });

  it.each([
    ['empty', Buffer.alloc(0), 'empty'],
    ['bad magic', Buffer.from('HELLO world'), 'bad_magic'],
    ['short magic', Buffer.from('EG'), 'bad_magic'],
    [
      'missing end frame',
      encodeRunnerOutput([{ type: FRAME_TYPES.report, payload: report }], { end: false }),
      'truncated',
    ],
    ['truncated header', Buffer.concat([OUTPUT_MAGIC, Buffer.from([1, 0, 0])]), 'truncated'],
    [
      'truncated payload',
      Buffer.concat([OUTPUT_MAGIC, Buffer.from([1, 0, 0, 0, 50]), Buffer.from('{}')]),
      'truncated',
    ],
    [
      'unknown frame type',
      encodeRunnerOutput([{ type: 0x42, payload: Buffer.from('x') }]),
      'unknown_frame',
    ],
    [
      'duplicate report',
      encodeRunnerOutput([
        { type: FRAME_TYPES.report, payload: report },
        { type: FRAME_TYPES.report, payload: report },
      ]),
      'duplicate_report',
    ],
    [
      'report not JSON',
      encodeRunnerOutput([{ type: FRAME_TYPES.report, payload: Buffer.from('{nope') }]),
      'bad_report_json',
    ],
    [
      'no report',
      encodeRunnerOutput([{ type: FRAME_TYPES.trace, payload: Buffer.from('x') }]),
      'missing_report',
    ],
    [
      'trailing data',
      Buffer.concat([
        encodeRunnerOutput([{ type: FRAME_TYPES.report, payload: report }]),
        Buffer.from('junk'),
      ]),
      'trailing_data',
    ],
    [
      'end frame with a length',
      Buffer.concat([OUTPUT_MAGIC, Buffer.from([0xff, 0, 0, 0, 1, 0])]),
      'oversized_frame',
    ],
    [
      'oversized report',
      encodeRunnerOutput([
        { type: FRAME_TYPES.report, payload: Buffer.alloc(OUTPUT_CAPS.report + 1, 0x20) },
      ]),
      'oversized_frame',
    ],
    [
      'oversized stdout',
      encodeRunnerOutput([
        { type: FRAME_TYPES.report, payload: report },
        { type: FRAME_TYPES.stdout, payload: Buffer.alloc(OUTPUT_CAPS.stdout + 1) },
      ]),
      'oversized_frame',
    ],
    [
      'oversized file',
      encodeRunnerOutput([
        { type: FRAME_TYPES.report, payload: report },
        { type: FRAME_TYPES.file, payload: filePayload(0, Buffer.alloc(2000)) },
      ]),
      'oversized_frame',
    ],
    [
      'file meta not JSON',
      encodeRunnerOutput([
        { type: FRAME_TYPES.report, payload: report },
        { type: FRAME_TYPES.file, payload: Buffer.from([0, 3, 0x7b, 0x7b, 0x7b]) },
      ]),
      'bad_file_meta',
    ],
    [
      'file meta extra key',
      encodeRunnerOutput([
        { type: FRAME_TYPES.report, payload: report },
        {
          type: FRAME_TYPES.file,
          payload: (() => {
            const m = Buffer.from('{"seq":1,"name":"a"}');
            const l = Buffer.alloc(2);
            l.writeUInt16BE(m.length);
            return Buffer.concat([l, m]);
          })(),
        },
      ]),
      'bad_file_meta',
    ],
    [
      'file seq out of range',
      encodeRunnerOutput([
        { type: FRAME_TYPES.report, payload: report },
        { type: FRAME_TYPES.file, payload: filePayload(64, Buffer.from('x')) },
      ]),
      'bad_file_meta',
    ],
    [
      'duplicate file seq',
      encodeRunnerOutput([
        { type: FRAME_TYPES.report, payload: report },
        { type: FRAME_TYPES.file, payload: filePayload(1, Buffer.from('x')) },
        { type: FRAME_TYPES.file, payload: filePayload(1, Buffer.from('y')) },
      ]),
      'bad_file_meta',
    ],
  ])('%s → %s (never throws)', (_name, data, problem) => {
    const parsed = parseRunnerOutput(data, limits);
    expect(parsed.problem).toBe(problem);
  });

  it('keeps the report parsed before a later problem', () => {
    const out = Buffer.concat([
      encodeRunnerOutput([{ type: FRAME_TYPES.report, payload: report }], { end: false }),
      Buffer.from([0x42, 0, 0, 0, 0]),
    ]);
    const parsed = parseRunnerOutput(out, limits);
    expect(parsed.problem).toBe('unknown_frame');
    expect(parsed.report).toEqual({ v: 1, mode: 'execute' });
  });

  it('drops artifacts beyond the count and total caps (artifact_cap)', () => {
    const files = [0, 1, 2, 3].map((seq) => ({
      type: FRAME_TYPES.file,
      payload: filePayload(seq, Buffer.alloc(700, seq)),
    }));
    const parsed = parseRunnerOutput(
      encodeRunnerOutput([{ type: FRAME_TYPES.report, payload: report }, ...files]),
      limits,
    );
    expect(parsed.problem).toBeNull();
    expect(parsed.files.map((f) => f.seq)).toEqual([0, 1]); // 3 × 700 > 2048
    expect(parsed.artifactCapHit).toBe(true);
  });

  it('a second screenshot is dropped', () => {
    const png = { type: FRAME_TYPES.screenshot, payload: Buffer.alloc(10) };
    const parsed = parseRunnerOutput(
      encodeRunnerOutput([{ type: FRAME_TYPES.report, payload: report }, png, png]),
      limits,
    );
    expect(parsed.screenshot?.length).toBe(10);
    expect(parsed.artifactCapHit).toBe(true);
  });

  it('maxOutputBytes covers every cap', () => {
    expect(maxOutputBytes(limits)).toBeGreaterThan(
      OUTPUT_CAPS.report +
        OUTPUT_CAPS.trace +
        OUTPUT_CAPS.stdout +
        OUTPUT_CAPS.stderr +
        limits.maxTotalArtifactBytes,
    );
  });

  it('random garbage never throws', () => {
    for (let i = 0; i < 200; i += 1) {
      const junk = Buffer.concat([
        OUTPUT_MAGIC,
        Buffer.from(Array.from({ length: i * 3 }, (_, j) => (j * 37 + i) & 255)),
      ]);
      expect(() => parseRunnerOutput(junk, limits)).not.toThrow();
    }
  });
});
