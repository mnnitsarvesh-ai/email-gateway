import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { emlObjectKey, ingestKey, objectRef, type QueueFileRef } from './ingestion-keys';

const ref: QueueFileRef = {
  mtaId: 'mx.gateway.local',
  queueId: '4ZbK3B2xyzQ',
  direction: 'inbound',
};
const sha = (s: string) => createHash('sha256').update(s).digest('hex');

describe('ingest key (D7)', () => {
  const rcpts = ['Bob@a.test', 'alice@a.test'];

  it('is v2: + hex SHA-256 of mtaId|queueId|direction|contentSha256|recipientSet and fits VARCHAR(128)', () => {
    const content = sha('message');
    const key = ingestKey(ref, content, rcpts);
    const recipientSet = sha('alice@a.test\nbob@a.test');
    expect(key).toBe(
      `v2:${sha(`mx.gateway.local|4ZbK3B2xyzQ|inbound|${content}|${recipientSet}`)}`,
    );
    expect(key).toHaveLength(67);
    expect(ingestKey(ref, content, rcpts)).toBe(key);
  });

  it('changes with each component', () => {
    const content = sha('message');
    const base = ingestKey(ref, content, rcpts);
    expect(ingestKey({ ...ref, mtaId: 'mx2.gateway.local' }, content, rcpts)).not.toBe(base);
    expect(ingestKey({ ...ref, queueId: 'OTHER' }, content, rcpts)).not.toBe(base);
    expect(ingestKey({ ...ref, direction: 'outbound' }, content, rcpts)).not.toBe(base);
    expect(ingestKey(ref, sha('other'), rcpts)).not.toBe(base);
  });

  it('covers the recipient set: order, case and repeats do not matter, membership does', () => {
    const content = sha('message');
    const base = ingestKey(ref, content, rcpts);
    // A redelivery after a lost 250 (same recipients) is a duplicate …
    expect(ingestKey(ref, content, ['ALICE@a.test', 'bob@A.TEST', 'alice@a.test'])).toBe(base);
    // … a retry of only some recipients is not (it must be stored, never answered 250 and lost).
    expect(ingestKey(ref, content, ['Bob@a.test'])).not.toBe(base);
    expect(ingestKey(ref, content, ['alice@a.test'])).not.toBe(base);
    expect(ingestKey(ref, content, [...rcpts, 'carol@a.test'])).not.toBe(base);
  });
});

describe('S3 key (D8)', () => {
  it('is org/{org}/eml/{yyyy}/{mm}/{dd}/{objectRef}.eml with the UTC date', () => {
    const at = new Date('2026-11-02T23:59:59.999-05:00'); // 2026-11-03 UTC
    const refHex = sha(`mx.gateway.local|4ZbK3B2xyzQ|inbound|42`).slice(0, 32);
    expect(objectRef(ref, 42n)).toBe(refHex);
    expect(emlObjectKey(ref, 42n, at)).toBe(`org/42/eml/2026/11/03/${refHex}.eml`);
  });

  it('is deterministic per queue file and organization, and disjoint per organization', () => {
    const at = new Date('2026-01-05T00:00:00Z');
    expect(emlObjectKey(ref, 1n, at)).toBe(emlObjectKey(ref, 1n, at));
    expect(emlObjectKey(ref, 1n, at)).not.toBe(emlObjectKey(ref, 2n, at));
    expect(emlObjectKey(ref, 2n, at).startsWith('org/2/eml/2026/01/05/')).toBe(true);
    expect(emlObjectKey({ ...ref, direction: 'outbound' }, 1n, at)).not.toBe(
      emlObjectKey(ref, 1n, at),
    );
  });
});
