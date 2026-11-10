// Unit tests of the runner bootstrap's pure parts (step 4.6 X6). Run: node --test infrastructure/sandbox/
// (also run by apps/sandbox-controller's unit suite). The bootstrap itself only ever runs inside
// the hardened runner container (LOCAL/CI ONLY, NOT A VM BOUNDARY); importing it here does not
// execute anything.
import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { FRAME, fileFrame, frame, interpreterFor, listDropped, parseInput } from './bootstrap.mjs';

const header = (over = {}) => ({
  v: 1,
  taskId: 't-1',
  profile: 'execute',
  detectedType: 'script_shell',
  wallTimeoutMs: 10_000,
  maxArtifacts: 4,
  maxArtifactBytes: 1024,
  maxTotalArtifactBytes: 4096,
  sampleSize: 3,
  ...over,
});
const encode = (h, sample) => {
  const json = Buffer.from(JSON.stringify(h));
  const len = Buffer.alloc(4);
  len.writeUInt32BE(json.length);
  return Buffer.concat([len, json, sample]);
};

describe('parseInput', () => {
  it('accepts the controller encoding', () => {
    const { header: h, sample } = parseInput(encode(header(), Buffer.from('id\n')));
    assert.equal(h.detectedType, 'script_shell');
    assert.equal(sample.toString(), 'id\n');
  });

  for (const [name, input, code] of [
    ['truncated length', Buffer.from([0, 0]), 'input_truncated'],
    ['zero header', Buffer.from([0, 0, 0, 0]), 'header_length'],
    ['huge header', Buffer.from([0, 2, 0, 0]), 'header_length'],
    ['wrong version', encode(header({ v: 2 }), Buffer.from('abc')), 'header_version'],
    [
      'wall too long',
      encode(header({ wallTimeoutMs: 999_999 }), Buffer.from('abc')),
      'header_wall',
    ],
    [
      'artifact count',
      encode(header({ maxArtifacts: 99 }), Buffer.from('abc')),
      'header_artifacts',
    ],
    [
      'bad type token',
      encode(header({ detectedType: '../sh' }), Buffer.from('abc')),
      'header_type',
    ],
    [
      'size mismatch',
      encode(header({ sampleSize: 4 }), Buffer.from('abc')),
      'sample_size_mismatch',
    ],
  ]) {
    it(`refuses ${name}`, () => {
      assert.throws(() => parseInput(input), new RegExp(code));
    });
  }

  it('only the two script interpreters', () => {
    assert.deepEqual(interpreterFor('script_shell'), ['/bin/sh', '/scratch/in/sample']);
    assert.deepEqual(interpreterFor('script_js'), ['/usr/local/bin/node', '/scratch/in/sample']);
    assert.equal(interpreterFor('pe_executable'), null);
    assert.equal(interpreterFor('html'), null);
  });
});

describe('framing', () => {
  it('frame and file frame layout', () => {
    const f = frame(FRAME.report, Buffer.from('{}'));
    assert.deepEqual([...f], [1, 0, 0, 0, 2, 0x7b, 0x7d]);
    const file = fileFrame({ seq: 3 }, Buffer.from('xy'));
    assert.equal(file[0], FRAME.file);
    const payload = file.subarray(5);
    const metaLength = payload.readUInt16BE(0);
    assert.deepEqual(JSON.parse(payload.subarray(2, 2 + metaLength).toString()), { seq: 3 });
    assert.equal(payload.subarray(2 + metaLength).toString(), 'xy');
  });
});

describe('listDropped', () => {
  it('lists regular files (not the sample, not symlinks), bounded, with the exec bit', () => {
    const root = mkdtempSync(join(tmpdir(), 'eg-bootstrap-'));
    try {
      mkdirSync(join(root, 'in'));
      mkdirSync(join(root, 'work/deep'), { recursive: true });
      writeFileSync(join(root, 'in/sample'), 'sample');
      writeFileSync(join(root, 'work/a.txt'), 'a');
      writeFileSync(join(root, 'work/deep/run.sh'), '#!/bin/sh\n');
      chmodSync(join(root, 'work/deep/run.sh'), 0o755);
      symlinkSync('/etc/passwd', join(root, 'work/link'));
      const result = listDropped(root, new Set([join(root, 'in/sample')]));
      assert.equal(result.total, 2);
      assert.deepEqual(
        result.files.map((f) => [f.path.slice(root.length), f.size, f.executable]),
        [
          ['/work/a.txt', 1, false],
          ['/work/deep/run.sh', 10, true],
        ],
      );
      for (let i = 0; i < 40; i += 1)
        writeFileSync(join(root, `work/f${String(i).padStart(2, '0')}`), 'x');
      const many = listDropped(root, new Set());
      assert.equal(many.files.length, 32);
      assert.equal(many.total, 43);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
