import { createHash, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { SandboxKeyError } from '../keys';
import { SandboxEnvelopeError } from './errors';
import { openSample, SANDBOX_SAMPLE_MAGIC, sampleAad, sealSample } from './sample';

const TASK = '01890a5d-ac96-774b-bcce-b302099a8070';
const OTHER_TASK = '01890a5d-ac96-774b-bcce-b302099a8071';
const KEY = 'a1'.repeat(32);
const PREVIOUS = 'b2'.repeat(32);
const plaintext = Buffer.from('#!/bin/sh\necho synthetic benign sample\n');
const sha256 = createHash('sha256').update(plaintext).digest('hex');
const ids = { taskId: TASK, sha256 };

const failure = (fn: () => unknown): string => {
  try {
    fn();
  } catch (error) {
    if (error instanceof SandboxEnvelopeError) return error.reason;
    if (error instanceof SandboxKeyError) return `key:${error.keyName}`;
    throw error;
  }
  return 'opened';
};

describe('sandbox-sample/1', () => {
  it('round-trips, with the documented layout and metadata', () => {
    const sealed = sealSample({ current: KEY }, plaintext, ids);
    expect(sealed.object.subarray(0, 7)).toEqual(SANDBOX_SAMPLE_MAGIC);
    expect(sealed.object.subarray(0, 7).toString('ascii')).toBe('EGSBXS1');
    const headerLength = sealed.object.readUInt16BE(7);
    const header = JSON.parse(sealed.object.subarray(9, 9 + headerLength).toString('utf8'));
    expect(Object.keys(header).sort()).toEqual(['kid', 'v', 'wrappedKey']);
    expect(header).toMatchObject({ v: 1, kid: 'k1' });
    expect(header.wrappedKey).toMatch(
      /^v1\.k1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/,
    );
    // IV (12) + tag (16) + ciphertext (same length as the plaintext).
    expect(sealed.object.length).toBe(9 + headerLength + 12 + 16 + plaintext.length);
    expect(sealed).toMatchObject({
      keyId: 'k1',
      algorithm: 'sandbox-sample/1',
      size: sealed.object.length,
    });
    expect(sealed.objectSha256).toBe(createHash('sha256').update(sealed.object).digest('hex'));
    // The plaintext never appears in the object.
    expect(sealed.object.includes(plaintext.subarray(0, 16))).toBe(false);
    expect(openSample({ current: KEY }, sealed.object, ids)).toEqual({
      plaintext,
      usedPreviousKey: false,
    });
    // Buffer keys work like hex keys; a fresh data key and IV per seal.
    expect(openSample({ current: Buffer.from(KEY, 'hex') }, sealed.object, ids).plaintext).toEqual(
      plaintext,
    );
    expect(sealSample({ current: KEY }, plaintext, ids).object.equals(sealed.object)).toBe(false);
  });

  it('round-trips an empty and a large sample', () => {
    for (const body of [Buffer.alloc(0), randomBytes(1_048_576)]) {
      const s = { taskId: TASK, sha256: createHash('sha256').update(body).digest('hex') };
      const opened = openSample({ current: KEY }, sealSample({ current: KEY }, body, s).object, s);
      expect(opened.plaintext.equals(body)).toBe(true);
    }
  });

  it('opens with the previous key during a rotation, and only then', () => {
    const sealed = sealSample({ current: PREVIOUS }, plaintext, ids);
    expect(openSample({ current: KEY, previous: PREVIOUS }, sealed.object, ids)).toEqual({
      plaintext,
      usedPreviousKey: true,
    });
    expect(failure(() => openSample({ current: KEY }, sealed.object, ids))).toBe('unauthentic');
    expect(failure(() => openSample({ current: KEY, previous: '' }, sealed.object, ids))).toBe(
      'unauthentic',
    );
    expect(failure(() => openSample({ current: KEY, previous: KEY }, sealed.object, ids))).toBe(
      'key:SANDBOX_SAMPLE_KEY_PREVIOUS',
    );
  });

  it('refuses the wrong key, the wrong task id and the wrong hash (AAD binding)', () => {
    const sealed = sealSample({ current: KEY }, plaintext, ids);
    expect(failure(() => openSample({ current: PREVIOUS }, sealed.object, ids))).toBe(
      'unauthentic',
    );
    expect(
      failure(() => openSample({ current: KEY }, sealed.object, { ...ids, taskId: OTHER_TASK })),
    ).toBe('unauthentic');
    expect(
      failure(() =>
        openSample({ current: KEY }, sealed.object, { ...ids, sha256: 'f'.repeat(64) }),
      ),
    ).toBe('unauthentic');
  });

  it('refuses tampering with every region of the object', () => {
    const sealed = sealSample({ current: KEY }, plaintext, ids).object;
    const headerLength = sealed.readUInt16BE(7);
    const bodyStart = 9 + headerLength;
    const flip = (offset: number) => {
      const copy = Buffer.from(sealed);
      copy[offset] = copy[offset]! ^ 0x01;
      return failure(() => openSample({ current: KEY }, copy, ids));
    };
    expect(flip(0)).toBe('malformed'); // magic
    expect(flip(7)).toBe('malformed'); // header length
    // Header: a changed wrapped-key character is unauthentic or malformed, never opened.
    const header = sealed.subarray(9, bodyStart).toString('utf8');
    const ctIndex = 9 + header.lastIndexOf('.') + 2;
    expect(['unauthentic', 'malformed']).toContain(flip(ctIndex));
    expect(flip(bodyStart)).toBe('unauthentic'); // IV
    expect(flip(bodyStart + 12)).toBe('unauthentic'); // tag
    expect(flip(sealed.length - 1)).toBe('unauthentic'); // ciphertext
    expect(
      failure(() => openSample({ current: KEY }, sealed.subarray(0, sealed.length - 1), ids)),
    ).toBe('unauthentic');
    expect(
      failure(() => openSample({ current: KEY }, Buffer.concat([sealed, Buffer.from([0])]), ids)),
    ).toBe('unauthentic');
    expect(
      failure(() => openSample({ current: KEY }, sealed.subarray(0, bodyStart + 10), ids)),
    ).toBe('malformed');
    expect(failure(() => openSample({ current: KEY }, Buffer.alloc(0), ids))).toBe('malformed');
  });

  it('refuses malformed headers', () => {
    const forge = (header: unknown) => {
      const json = Buffer.from(JSON.stringify(header), 'utf8');
      const len = Buffer.alloc(2);
      len.writeUInt16BE(json.length);
      return Buffer.concat([SANDBOX_SAMPLE_MAGIC, len, json, Buffer.alloc(28)]);
    };
    const good =
      'v1.k1.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    for (const header of [
      { v: 2, kid: 'k1', wrappedKey: good },
      { v: 1, kid: 'k2', wrappedKey: good },
      { v: 1, kid: 'k1', wrappedKey: good, extra: 1 },
      { v: 1, kid: 'k1' },
      { v: 1, kid: 'k1', wrappedKey: 'v1.k1.a.b' },
      { v: 1, kid: 'k1', wrappedKey: good.replace('v1', 'v2') },
      [1, 2],
      null,
    ]) {
      expect(
        failure(() => openSample({ current: KEY }, forge(header), ids)),
        JSON.stringify(header),
      ).toBe('malformed');
    }
    // A header that is not JSON, and an oversized header length.
    const notJson = Buffer.concat([
      SANDBOX_SAMPLE_MAGIC,
      Buffer.from([0, 3]),
      Buffer.from('{x}'),
      Buffer.alloc(28),
    ]);
    expect(failure(() => openSample({ current: KEY }, notJson, ids))).toBe('malformed');
    const huge = Buffer.concat([
      SANDBOX_SAMPLE_MAGIC,
      Buffer.from([0xff, 0xff]),
      Buffer.alloc(70_000),
    ]);
    expect(failure(() => openSample({ current: KEY }, huge, ids))).toBe('malformed');
  });

  it('refuses to seal a plaintext whose hash differs from the expected hash (staging integrity)', () => {
    expect(failure(() => sealSample({ current: KEY }, Buffer.from('other'), ids))).toBe(
      'integrity',
    );
  });

  it('validates keys and ids without revealing values', () => {
    for (const bad of ['', 'zz'.repeat(32), 'a1'.repeat(31), Buffer.alloc(16)]) {
      let message = '';
      try {
        sealSample({ current: bad }, plaintext, ids);
      } catch (error) {
        expect(error).toBeInstanceOf(SandboxKeyError);
        message = (error as Error).message;
      }
      expect(message).toBe('SANDBOX_SAMPLE_KEY must be 32 bytes (64 hex characters)');
    }
    expect(failure(() => sampleAad({ taskId: 'x', sha256 }))).toBe('malformed');
    expect(failure(() => sampleAad({ taskId: TASK, sha256: 'A'.repeat(64) }))).toBe('malformed');
    expect(sampleAad(ids)).toBe(`eg-sandbox-sample/v1\0${TASK}\0${sha256}`);
    const error = new SandboxEnvelopeError('unauthentic');
    expect(error.message).not.toContain(KEY);
  });
});
