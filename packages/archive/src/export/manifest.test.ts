import { describe, expect, it } from 'vitest';
import {
  generateExportSigningKeyPair,
  parseExportSigningPrivateKey,
  parseExportSigningPublicKey,
  verifyManifestSignature,
} from '../crypto/signing';
import { canonicalJson, sha256Hex } from '../documents/canonical';
import {
  buildExportManifest,
  buildSignedExportManifest,
  EXPORT_MALICIOUS_README_TEXT,
  EXPORT_README_TEXT,
  exportEntryPath,
  exportTimestamp,
  type ExportManifestInput,
  verifySignedExportManifest,
} from './manifest';

const id = (n: number) => `0190a5d0-0000-7000-8000-${String(n).padStart(12, '0')}`;
const input: ExportManifestInput = {
  exportId: id(1),
  caseId: id(2),
  searchId: id(3),
  organizationId: id(4),
  generatedAt: new Date('2026-11-16T12:00:00.000Z'),
  signingKeyId: 'es1',
  reviewTags: ['relevant', 'untagged'],
  items: [
    {
      messageId: id(10),
      receivedAt: new Date('2026-11-01T08:30:15.250Z'),
      internetMessageId: '<a@example.org>',
      sha256: 'a'.repeat(64),
      sizeBytes: 1000,
      verdict: 'clean',
      malicious: false,
    },
    {
      messageId: id(11),
      receivedAt: new Date('2026-11-02T09:00:00.000Z'),
      internetMessageId: null,
      sha256: 'b'.repeat(64),
      sizeBytes: 500,
      verdict: 'malware',
      malicious: true,
    },
  ],
};

describe('export entry paths', () => {
  it('messages/<receivedAt>_<messageId>.eml or malicious/…, with a file-name-safe timestamp', () => {
    expect(exportTimestamp(new Date('2026-11-01T08:30:15.250Z'))).toBe('20261101T083015.250Z');
    expect(
      exportEntryPath({
        receivedAt: new Date('2026-11-01T08:30:15.250Z'),
        messageId: id(10),
        malicious: false,
      }),
    ).toBe(`messages/20261101T083015.250Z_${id(10)}.eml`);
    expect(
      exportEntryPath({
        receivedAt: new Date('2026-11-01T08:30:15.250Z'),
        messageId: id(10),
        malicious: true,
      }),
    ).toBe(`malicious/20261101T083015.250Z_${id(10)}.eml`);
    expect(() =>
      exportEntryPath({ receivedAt: new Date(), messageId: '../../etc', malicious: false }),
    ).toThrow();
  });
});

describe('export manifest', () => {
  it('builds canonical bytes with computed counts and paths', () => {
    const built = buildExportManifest(input);
    expect(built.manifest.counts).toEqual({ items: 2, malicious: 1, bytes: 1500 });
    expect(built.manifest.items.map((i) => i.path)).toEqual([
      `messages/20261101T083015.250Z_${id(10)}.eml`,
      `malicious/20261102T090000.000Z_${id(11)}.eml`,
    ]);
    expect(built.bytes.toString('utf8')).toBe(canonicalJson(built.manifest));
    expect(built.sha256).toBe(sha256Hex(built.bytes));
    expect(built.manifest).toMatchObject({
      version: 'archive-export-manifest/1',
      generator: 'archive-worker',
    });
  });

  it('signs and verifies the exact manifest bytes', () => {
    const pair = generateExportSigningKeyPair();
    const signed = buildSignedExportManifest(input, parseExportSigningPrivateKey(pair.privateKey));
    const pub = parseExportSigningPublicKey(pair.publicKey);
    expect(verifyManifestSignature(signed.bytes, signed.signature, pub)).toBe(true);
    expect(verifySignedExportManifest(signed.bytes, signed.signature, pub)).toEqual(
      signed.manifest,
    );
    const altered = Buffer.from(
      signed.bytes.toString('utf8').replace('"bytes":1500', '"bytes":1501'),
    );
    expect(verifySignedExportManifest(altered, signed.signature, pub)).toBeNull();
  });

  it('refuses invalid items and duplicate entries', () => {
    expect(() =>
      buildExportManifest({ ...input, items: [{ ...input.items[0]!, sha256: 'xyz' }] }),
    ).toThrow(/archive-export-manifest/);
    expect(() =>
      buildExportManifest({ ...input, items: [input.items[0]!, input.items[0]!] }),
    ).toThrow(/archive-export-manifest/);
    expect(() => buildExportManifest({ ...input, signingKeyId: 'ES1' })).toThrow();
    expect(() => buildExportManifest({ ...input, reviewTags: [] })).toThrow();
  });

  it('README texts describe verification and warn about malicious content', () => {
    expect(EXPORT_README_TEXT).toContain('manifest.sig');
    expect(EXPORT_README_TEXT).toContain('export-signing-keys');
    expect(EXPORT_MALICIOUS_README_TEXT).toContain('MALICIOUS');
  });
});
