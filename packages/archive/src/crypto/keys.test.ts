import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ArchiveCryptoError, ArchiveKeyConfigError } from './errors';
import {
  deriveObjectKey,
  exportKeyAad,
  generateDataKey,
  keyVersionOfWrapped,
  objectKeyInfo,
  recordKeyAad,
  tenantKeyAad,
  unwrapExportKey,
  unwrapRecordKey,
  unwrapTenantKey,
  wrapExportKey,
  wrapRecordKey,
  wrapTenantKey,
} from './keys';
import { LocalRootKeyProvider, parseArchiveRootKeys } from './root-keys';

const hex = () => randomBytes(32).toString('hex');
const ORG = '42';
const MSG = '0190a5d0-0000-7000-8000-0000000000aa';
const CAP = '0190a5d0-0000-7000-8000-0000000000bb';
const EXP = '0190a5d0-0000-7000-8000-0000000000cc';
const WRAPPED = /^v1\.[a-z0-9]+\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/;

async function reason(p: Promise<unknown> | (() => unknown)): Promise<string> {
  try {
    if (typeof p === 'function') p();
    else await p;
  } catch (error) {
    if (error instanceof ArchiveCryptoError) return error.reason;
    throw error;
  }
  return 'opened';
}

describe('root key configuration', () => {
  it('parses the current key with the default id r1', () => {
    const keys = parseArchiveRootKeys({ ARCHIVE_ROOT_KEY: hex() });
    expect(keys.current.id).toBe('r1');
    expect(keys.current.key).toHaveLength(32);
    expect(keys.previous).toBeNull();
  });

  it.each([
    [{ ARCHIVE_ROOT_KEY: 'abc' }, 'ARCHIVE_ROOT_KEY'],
    [{ ARCHIVE_ROOT_KEY: hex(), ARCHIVE_ROOT_KEY_ID: 'R1' }, 'ARCHIVE_ROOT_KEY_ID'],
    [{ ARCHIVE_ROOT_KEY: hex(), ARCHIVE_ROOT_KEY_ID: '1r' }, 'ARCHIVE_ROOT_KEY_ID'],
    [{ ARCHIVE_ROOT_KEY: hex(), ARCHIVE_ROOT_KEY_ID: 'a'.repeat(17) }, 'ARCHIVE_ROOT_KEY_ID'],
    [{ ARCHIVE_ROOT_KEY: hex(), ARCHIVE_ROOT_KEY_PREVIOUS: hex() }, 'ARCHIVE_ROOT_KEY_PREVIOUS_ID'],
    [{ ARCHIVE_ROOT_KEY: hex(), ARCHIVE_ROOT_KEY_PREVIOUS_ID: 'r0' }, 'ARCHIVE_ROOT_KEY_PREVIOUS'],
    [
      {
        ARCHIVE_ROOT_KEY: hex(),
        ARCHIVE_ROOT_KEY_PREVIOUS: 'xyz',
        ARCHIVE_ROOT_KEY_PREVIOUS_ID: 'r0',
      },
      'ARCHIVE_ROOT_KEY_PREVIOUS',
    ],
    [
      {
        ARCHIVE_ROOT_KEY: hex(),
        ARCHIVE_ROOT_KEY_PREVIOUS: hex(),
        ARCHIVE_ROOT_KEY_PREVIOUS_ID: 'r1',
      },
      'ARCHIVE_ROOT_KEY_PREVIOUS_ID',
    ],
  ])('refuses %#, naming %s and never the value', (config, keyName) => {
    try {
      parseArchiveRootKeys(config);
      expect.fail('expected ArchiveKeyConfigError');
    } catch (error) {
      expect(error).toBeInstanceOf(ArchiveKeyConfigError);
      expect((error as ArchiveKeyConfigError).keyName).toBe(keyName);
      for (const v of Object.values(config)) {
        if (typeof v === 'string' && v.length >= 32)
          expect((error as Error).message).not.toContain(v);
      }
    }
  });

  it('refuses a previous key equal to the current key', () => {
    const k = hex();
    expect(() =>
      parseArchiveRootKeys({
        ARCHIVE_ROOT_KEY: k,
        ARCHIVE_ROOT_KEY_PREVIOUS: k.toUpperCase(),
        ARCHIVE_ROOT_KEY_PREVIOUS_ID: 'r0',
      }),
    ).toThrow(/ARCHIVE_ROOT_KEY_PREVIOUS must be different/);
  });
});

describe('tenant keys under the root key', () => {
  it('round-trips in the SecretBox format with the root key id', async () => {
    const provider = LocalRootKeyProvider.fromConfig({
      ARCHIVE_ROOT_KEY: hex(),
      ARCHIVE_ROOT_KEY_ID: 'r2',
    });
    const tenantKey = generateDataKey();
    const wrapped = await wrapTenantKey(provider, { organizationId: 42n, version: 1 }, tenantKey);
    expect(wrapped).toMatch(WRAPPED);
    expect(wrapped.split('.')[1]).toBe('r2');
    const out = await unwrapTenantKey(provider, wrapped, { organizationId: '42', version: 1 });
    expect(out.key.equals(tenantKey)).toBe(true);
    expect(out).toMatchObject({ rootKeyId: 'r2', usedPreviousKey: false });
    // A fresh IV every time.
    expect(await wrapTenantKey(provider, { organizationId: 42, version: 1 }, tenantKey)).not.toBe(
      wrapped,
    );
  });

  it('binds organization and version (AAD)', async () => {
    const provider = LocalRootKeyProvider.fromConfig({ ARCHIVE_ROOT_KEY: hex() });
    const wrapped = await wrapTenantKey(
      provider,
      { organizationId: 42, version: 1 },
      generateDataKey(),
    );
    expect(
      await reason(unwrapTenantKey(provider, wrapped, { organizationId: 43, version: 1 })),
    ).toBe('unauthentic');
    expect(
      await reason(unwrapTenantKey(provider, wrapped, { organizationId: 42, version: 2 })),
    ).toBe('unauthentic');
    expect(tenantKeyAad({ organizationId: 42, version: 3 })).toBe(
      'eg-archive-tenant-key/v1\x0042\x003',
    );
  });

  it('unwraps with the previous root key during a rotation and flags it', async () => {
    const oldKey = hex();
    const before = LocalRootKeyProvider.fromConfig({
      ARCHIVE_ROOT_KEY: oldKey,
      ARCHIVE_ROOT_KEY_ID: 'r1',
    });
    const tenantKey = generateDataKey();
    const wrapped = await wrapTenantKey(before, { organizationId: 7, version: 1 }, tenantKey);
    const after = LocalRootKeyProvider.fromConfig({
      ARCHIVE_ROOT_KEY: hex(),
      ARCHIVE_ROOT_KEY_ID: 'r2',
      ARCHIVE_ROOT_KEY_PREVIOUS: oldKey,
      ARCHIVE_ROOT_KEY_PREVIOUS_ID: 'r1',
    });
    expect(after.previousKeyId).toBe('r1');
    const out = await unwrapTenantKey(after, wrapped, { organizationId: 7, version: 1 });
    expect(out.key.equals(tenantKey)).toBe(true);
    expect(out).toMatchObject({ rootKeyId: 'r1', usedPreviousKey: true });
    const rewrapped = await wrapTenantKey(after, { organizationId: 7, version: 1 }, out.key);
    expect(rewrapped.split('.')[1]).toBe('r2');
    // Without the previous key the old value no longer opens.
    const removed = LocalRootKeyProvider.fromConfig({
      ARCHIVE_ROOT_KEY: hex(),
      ARCHIVE_ROOT_KEY_ID: 'r2',
    });
    expect(await reason(unwrapTenantKey(removed, wrapped, { organizationId: 7, version: 1 }))).toBe(
      'unauthentic',
    );
  });

  it('refuses malformed wrapped values and non-32-byte keys', async () => {
    const provider = LocalRootKeyProvider.fromConfig({ ARCHIVE_ROOT_KEY: hex() });
    const ids = { organizationId: 1, version: 1 };
    for (const bad of [
      '',
      'v1.r1.a.b',
      'v2.r1.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA.AAAA',
      'v1.R1.x.y.z',
      'x'.repeat(600),
    ]) {
      expect(await reason(unwrapTenantKey(provider, bad, ids))).toBe('malformed');
    }
    expect(await reason(wrapTenantKey(provider, ids, Buffer.alloc(16)))).toBe('malformed');
    expect(
      await reason(wrapTenantKey(provider, { organizationId: -1, version: 1 }, generateDataKey())),
    ).toBe('malformed');
    expect(
      await reason(wrapTenantKey(provider, { organizationId: 1, version: 0 }, generateDataKey())),
    ).toBe('malformed');
  });

  it('error messages carry no detail', async () => {
    const provider = LocalRootKeyProvider.fromConfig({ ARCHIVE_ROOT_KEY: hex() });
    try {
      await unwrapTenantKey(provider, 'v1.r1.AAAA.BBBB.CCCC', { organizationId: 1, version: 1 });
    } catch (error) {
      expect((error as Error).message).toBe('Archive crypto operation failed (malformed)');
    }
  });
});

describe('record and export DEKs under the tenant key', () => {
  const tenantKey = generateDataKey();
  const ids = { organizationId: ORG, messagePublicId: MSG, captureId: CAP, keyVersion: 3 };

  it('round-trips a record DEK in v1.k<version> format', () => {
    const dek = generateDataKey();
    const wrapped = wrapRecordKey(tenantKey, ids, dek);
    expect(wrapped).toMatch(/^v1\.k3\./);
    expect(wrapped).toMatch(WRAPPED);
    expect(wrapped.length).toBeLessThanOrEqual(255);
    expect(keyVersionOfWrapped(wrapped)).toBe(3);
    expect(unwrapRecordKey(tenantKey, wrapped, ids).equals(dek)).toBe(true);
    expect(recordKeyAad(ids)).toBe(`eg-archive-dek/v1\x00${ORG}\x00${MSG}\x00${CAP}\x003`);
  });

  it('binds organization, message, capture and key version', async () => {
    const wrapped = wrapRecordKey(tenantKey, ids, generateDataKey());
    const other = '0190a5d0-0000-7000-8000-0000000000dd';
    expect(
      await reason(() => unwrapRecordKey(tenantKey, wrapped, { ...ids, organizationId: '43' })),
    ).toBe('unauthentic');
    expect(
      await reason(() => unwrapRecordKey(tenantKey, wrapped, { ...ids, messagePublicId: other })),
    ).toBe('unauthentic');
    expect(
      await reason(() => unwrapRecordKey(tenantKey, wrapped, { ...ids, captureId: other })),
    ).toBe('unauthentic');
    expect(await reason(() => unwrapRecordKey(tenantKey, wrapped, { ...ids, keyVersion: 4 }))).toBe(
      'unauthentic',
    );
    expect(await reason(() => unwrapRecordKey(generateDataKey(), wrapped, ids))).toBe(
      'unauthentic',
    );
    expect(
      await reason(() => unwrapRecordKey(tenantKey, wrapped, { ...ids, captureId: 'nope' })),
    ).toBe('malformed');
  });

  it('round-trips an export DEK and does not confuse it with a record DEK', async () => {
    const eids = { organizationId: ORG, exportPublicId: EXP, keyVersion: 1 };
    const dek = generateDataKey();
    const wrapped = wrapExportKey(tenantKey, eids, dek);
    expect(unwrapExportKey(tenantKey, wrapped, eids).equals(dek)).toBe(true);
    expect(exportKeyAad(eids)).toBe(`eg-archive-export-dek/v1\x00${ORG}\x00${EXP}\x001`);
    expect(
      await reason(() =>
        unwrapRecordKey(tenantKey, wrapped, {
          organizationId: ORG,
          messagePublicId: EXP,
          captureId: EXP,
          keyVersion: 1,
        }),
      ),
    ).toBe('unauthentic');
  });

  it('detects tampering with each part', async () => {
    const wrapped = wrapRecordKey(tenantKey, ids, generateDataKey());
    const parts = wrapped.split('.');
    for (const index of [2, 3, 4]) {
      const copy = [...parts];
      const bytes = Buffer.from(copy[index]!, 'base64url');
      bytes[0] = bytes[0]! ^ 1;
      copy[index] = bytes.toString('base64url');
      expect(await reason(() => unwrapRecordKey(tenantKey, copy.join('.'), ids))).toBe(
        'unauthentic',
      );
    }
    expect(
      await reason(() => keyVersionOfWrapped('v1.r1.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA.AAAA')),
    ).toBe('malformed');
  });
});

describe('HKDF object keys', () => {
  const dek = generateDataKey();
  const salt = randomBytes(32);
  const ctx = { kind: 'eml' as const, organizationId: ORG, subjectId: MSG };

  it('is deterministic for the same inputs and differs per kind, salt, organization and subject', () => {
    const k = deriveObjectKey(dek, salt, ctx);
    expect(k).toHaveLength(32);
    expect(deriveObjectKey(dek, salt, ctx).equals(k)).toBe(true);
    expect(deriveObjectKey(dek, salt, { ...ctx, kind: 'journal' }).equals(k)).toBe(false);
    expect(deriveObjectKey(dek, salt, { ...ctx, kind: 'scan' }).equals(k)).toBe(false);
    expect(deriveObjectKey(dek, randomBytes(32), ctx).equals(k)).toBe(false);
    expect(deriveObjectKey(dek, salt, { ...ctx, organizationId: 43 }).equals(k)).toBe(false);
    expect(deriveObjectKey(dek, salt, { ...ctx, subjectId: CAP }).equals(k)).toBe(false);
    expect(deriveObjectKey(generateDataKey(), salt, ctx).equals(k)).toBe(false);
    expect(objectKeyInfo(ctx)).toBe(`eg-archive-object/v1\x00eml\x00${ORG}\x00${MSG}`);
  });

  it('refuses a short salt or DEK and an unknown kind', async () => {
    expect(await reason(() => deriveObjectKey(dek, randomBytes(16), ctx))).toBe('malformed');
    expect(await reason(() => deriveObjectKey(Buffer.alloc(31), salt, ctx))).toBe('malformed');
    expect(await reason(() => deriveObjectKey(dek, salt, { ...ctx, kind: 'body' as never }))).toBe(
      'malformed',
    );
  });
});
