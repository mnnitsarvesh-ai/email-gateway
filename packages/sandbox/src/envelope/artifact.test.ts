import { createHash, createPublicKey, generateKeyPairSync, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  artifactKeyId,
  generateArtifactKeyPair,
  parseArtifactPrivateKey,
  parseArtifactPublicKey,
} from '../keys';
import {
  ARTIFACT_WRAPPED_KEY_PATTERN,
  artifactAad,
  openArtifact,
  SANDBOX_ARTIFACT_MAGIC,
  sealArtifact,
} from './artifact';
import { SandboxEnvelopeError } from './errors';

const TASK = '01890a5d-ac96-774b-bcce-b302099a8070';
const ids = { taskId: TASK, seq: 0, kind: 'static_report' as const };
const pair = generateArtifactKeyPair();
const publicKey = parseArtifactPublicKey(pair.publicKey);
const privateKey = parseArtifactPrivateKey(pair.privateKey);
const report = Buffer.from(JSON.stringify({ v: 1, findings: ['static.script_download_cradle'] }));

const failure = (fn: () => unknown): string => {
  try {
    fn();
  } catch (error) {
    if (error instanceof SandboxEnvelopeError) return error.reason;
    throw error;
  }
  return 'opened';
};

describe('sandbox-artifact/1', () => {
  it('round-trips with a generated X25519 pair; the documented layout and wrapped-key format', () => {
    const sealed = sealArtifact(publicKey, report, ids);
    expect(sealed.object.subarray(0, 7).toString('ascii')).toBe('EGSBXA1');
    expect(sealed.object.length).toBe(7 + 12 + 16 + report.length);
    expect(sealed.wrappedKey).toMatch(ARTIFACT_WRAPPED_KEY_PATTERN);
    expect(sealed.wrappedKey.length).toBeLessThanOrEqual(256);
    const [version, kid, eph, iv, tag, ct] = sealed.wrappedKey.split('.');
    expect(version).toBe('x1');
    expect(kid).toBe(artifactKeyId(publicKey));
    expect(kid).toMatch(/^[0-9a-f]{8}$/);
    expect(Buffer.from(eph!, 'base64url')).toHaveLength(32);
    expect(Buffer.from(iv!, 'base64url')).toHaveLength(12);
    expect(Buffer.from(tag!, 'base64url')).toHaveLength(16);
    expect(Buffer.from(ct!, 'base64url')).toHaveLength(32);
    expect(sealed).toMatchObject({
      keyId: kid,
      algorithm: 'sandbox-artifact/1',
      sizeBytes: report.length,
      plainSha256: createHash('sha256').update(report).digest('hex'),
      objectSha256: createHash('sha256').update(sealed.object).digest('hex'),
    });
    expect(openArtifact(privateKey, sealed.object, sealed.wrappedKey, ids)).toEqual(report);
    // A fresh ephemeral key per artifact.
    expect(sealArtifact(publicKey, report, ids).wrappedKey.split('.')[2]).not.toBe(eph);
  });

  it('round-trips every kind, an empty and a 2 MiB artifact', () => {
    const kinds = [
      'screenshot',
      'process_log',
      'network_log',
      'static_report',
      'dropped_file',
    ] as const;
    kinds.forEach((kind, seq) => {
      const body = seq === 0 ? Buffer.alloc(0) : randomBytes(seq === 4 ? 2_097_152 : 100);
      const a = { taskId: TASK, seq, kind };
      const s = sealArtifact(publicKey, body, a);
      expect(openArtifact(privateKey, s.object, s.wrappedKey, a).equals(body)).toBe(true);
    });
  });

  it('is asymmetric: the controller side (public key only) cannot open what it sealed', () => {
    const sealed = sealArtifact(publicKey, report, ids);
    // The public key is no private key; another pair's private key does not open it either.
    expect(failure(() => openArtifact(publicKey, sealed.object, sealed.wrappedKey, ids))).toBe(
      'malformed',
    );
    const other = parseArtifactPrivateKey(generateArtifactKeyPair().privateKey);
    expect(failure(() => openArtifact(other, sealed.object, sealed.wrappedKey, ids))).toBe(
      'unauthentic',
    );
    // Even with the kid rewritten to the other pair's id, the ECDH result differs.
    const otherKid = artifactKeyId(createPublicKey(other));
    const relabelled = sealed.wrappedKey.replace(/^x1\.[0-9a-f]{8}\./, `x1.${otherKid}.`);
    expect(failure(() => openArtifact(other, sealed.object, relabelled, ids))).toBe('unauthentic');
  });

  it('binds the task id, seq and kind (AAD)', () => {
    const sealed = sealArtifact(publicKey, report, ids);
    const open = (a: { taskId: string; seq: number; kind: 'static_report' | 'screenshot' }) =>
      failure(() => openArtifact(privateKey, sealed.object, sealed.wrappedKey, a));
    expect(open({ ...ids, taskId: '01890a5d-ac96-774b-bcce-b302099a8071' })).toBe('unauthentic');
    expect(open({ ...ids, seq: 1 })).toBe('unauthentic');
    expect(open({ ...ids, kind: 'screenshot' })).toBe('unauthentic');
    expect(artifactAad(ids)).toBe(`eg-sandbox-artifact/v1\0${TASK}\x000\0static_report`);
    expect(failure(() => artifactAad({ ...ids, seq: 16 }))).toBe('malformed');
    expect(failure(() => artifactAad({ ...ids, kind: 'memory_dump' as never }))).toBe('malformed');
    expect(failure(() => artifactAad({ ...ids, taskId: 'not-a-task' }))).toBe('malformed');
  });

  it('refuses tampering with the object and the wrapped key', () => {
    const sealed = sealArtifact(publicKey, report, ids);
    const flip = (offset: number) => {
      const copy = Buffer.from(sealed.object);
      copy[offset] = copy[offset]! ^ 0x80;
      return failure(() => openArtifact(privateKey, copy, sealed.wrappedKey, ids));
    };
    expect(flip(0)).toBe('malformed');
    expect(flip(7)).toBe('unauthentic'); // IV
    expect(flip(19)).toBe('unauthentic'); // tag
    expect(flip(sealed.object.length - 1)).toBe('unauthentic'); // ciphertext
    expect(
      failure(() =>
        openArtifact(privateKey, sealed.object.subarray(0, 20), sealed.wrappedKey, ids),
      ),
    ).toBe('malformed');
    const parts = sealed.wrappedKey.split('.');
    const mutate = (index: number) => {
      const copy = [...parts];
      const bytes = Buffer.from(copy[index]!, 'base64url');
      bytes[0] = bytes[0]! ^ 0x01;
      copy[index] = bytes.toString('base64url');
      return failure(() => openArtifact(privateKey, sealed.object, copy.join('.'), ids));
    };
    for (const index of [2, 3, 4, 5]) expect(mutate(index), String(index)).toBe('unauthentic');
    for (const bad of [
      'v1.k1.a.b.c.d',
      `x1.${parts[1]}.a.b.c`,
      `x1.${parts[1]}.AAAA.${parts[3]}.${parts[4]}.${parts[5]}`,
      `${sealed.wrappedKey}.extra`,
      `x1.${'a'.repeat(250)}`,
      '',
    ]) {
      expect(['malformed', 'unauthentic']).toContain(
        failure(() => openArtifact(privateKey, sealed.object, bad, ids)),
      );
      expect(failure(() => openArtifact(privateKey, sealed.object, bad, ids))).not.toBe('opened');
    }
  });

  it('refuses a non-X25519 key', () => {
    const ed = generateKeyPairSync('ed25519');
    expect(failure(() => sealArtifact(ed.publicKey, report, ids))).toBe('malformed');
    const sealed = sealArtifact(publicKey, report, ids);
    expect(failure(() => openArtifact(ed.privateKey, sealed.object, sealed.wrappedKey, ids))).toBe(
      'malformed',
    );
    expect(SANDBOX_ARTIFACT_MAGIC.toString('ascii')).toBe('EGSBXA1');
  });
});
