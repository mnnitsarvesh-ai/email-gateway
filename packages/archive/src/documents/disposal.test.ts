import { describe, expect, it } from 'vitest';
import {
  disposalObjectsOf,
  disposalReplicaStatusOf,
  readDisposalObjects,
  readDisposalReplicaStatus,
  recordVersions,
} from './disposal';

const ids = {
  organizationId: 42n,
  receivedAt: new Date('2026-11-16T10:15:00.000Z'),
  messagePublicId: '0f0e0d0c-0b0a-4908-8706-050403020100',
};
const captureId = '11111111-2222-4333-8444-555555555555';
const prefix = 'org/42/archive/2026/11/16/0f0e0d0c-0b0a-4908-8706-050403020100/';
const ref = (name: string, versionId: string | null = `v-${name}`) => ({
  key: `${prefix}${captureId}/${name}`,
  versionId,
  sha256: 'a'.repeat(64),
  bytes: 10,
});
/** `email_archives.objects` (`archive-record-objects`), as the api's record row carries it. */
const recordObjects = {
  captureId,
  eml: ref('eml.bin'),
  journal: ref('journal.bin'),
  scans: [{ ...ref('scan-r0-v0.bin'), round: 0, revision: 0 }],
};

describe('disposal objects (one builder for every disposal writer)', () => {
  it('builds the prefix and the exact versions from a record', () => {
    const built = disposalObjectsOf({ ...ids, objects: recordObjects });
    expect(built).toEqual({
      captureId,
      prefix,
      versions: [
        { key: `${prefix}${captureId}/eml.bin`, versionId: 'v-eml.bin' },
        { key: `${prefix}${captureId}/journal.bin`, versionId: 'v-journal.bin' },
        { key: `${prefix}${captureId}/scan-r0-v0.bin`, versionId: 'v-scan-r0-v0.bin' },
      ],
    });
    // A JSON string (raw query) reads the same.
    expect(disposalObjectsOf({ ...ids, objects: JSON.stringify(recordObjects) })).toEqual(built);
  });

  it('drops versions of another organization and tolerates a malformed objects column', () => {
    const foreign = {
      ...recordObjects,
      eml: { ...ref('eml.bin'), key: 'org/7/archive/x/eml.bin' },
    };
    expect(
      recordVersions({ organizationId: 42n, objects: foreign }).map((v) => v.key),
    ).not.toContain('org/7/archive/x/eml.bin');
    expect(disposalObjectsOf({ ...ids, objects: { nope: true } })).toEqual({
      captureId: null,
      prefix,
      versions: [],
    });
  });

  it('reads the disposal shape, converts the legacy record shape, and falls back to the prefix', () => {
    const built = disposalObjectsOf({ ...ids, objects: recordObjects });
    expect(readDisposalObjects(built, ids)).toEqual({ objects: built, shape: 'disposal' });
    expect(readDisposalObjects(JSON.stringify(built), ids).shape).toBe('disposal');
    // Rows written by the api before the shared builder stored the record's own objects.
    expect(readDisposalObjects(recordObjects, ids)).toEqual({ objects: built, shape: 'record' });
    for (const bad of [null, undefined, '{', { versions: 'x' }]) {
      expect(readDisposalObjects(bad, ids)).toEqual({
        objects: { captureId: null, prefix, versions: [] },
        shape: 'fallback',
      });
    }
    // A prefix that does not belong to the record is never trusted.
    expect(
      readDisposalObjects({ ...built, prefix: 'org/7/archive/2026/11/16/x/' }, ids).objects.prefix,
    ).toBe(prefix);
  });

  it('replica status: targets at the decision, nothing pending; malformed reads as empty', () => {
    expect(disposalReplicaStatusOf(['replica-a'])).toEqual({ targets: ['replica-a'], pending: [] });
    expect(readDisposalReplicaStatus('{"targets":["r"],"pending":[]}')).toEqual({
      targets: ['r'],
      pending: [],
    });
    expect(readDisposalReplicaStatus({ targets: 1 })).toEqual({ targets: [], pending: [] });
  });
});
