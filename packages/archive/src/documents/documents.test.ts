import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { canonicalJson, canonicalSha256, sha256Hex } from './canonical';
import { ArchiveDocumentError } from './common';
import {
  ARCHIVE_HOLD_CRITERIA_EXAMPLE,
  ARCHIVE_RETENTION_CRITERIA_EXAMPLE,
  archiveHoldCreateCriteriaSchema,
  archiveHoldCriteriaSchema,
  archiveRetentionCriteriaSchema,
  legacyLegalHoldCriteriaSchema,
} from './criteria';
import {
  ARCHIVE_JOURNAL_EXAMPLE,
  ARCHIVE_PARTIES_EXAMPLE,
  archiveJournalSchema,
  archivePartiesSchema,
  archiveRecordObjectsSchema,
  archiveScanRoundsSchema,
} from './records';
import {
  ARCHIVE_SEARCH_CRITERIA_EXAMPLE,
  archiveExportManifestSchema,
  archiveSearchCriteriaSchema,
} from './search';
import {
  ARCHIVE_SETTINGS_DEFAULTS,
  ARCHIVE_SETTINGS_EXAMPLE,
  archiveSettingsSchema,
  resolveArchiveSettings,
  validateArchiveSettingsChange,
} from './settings';

const UUID = '0190a5d0-0000-7000-8000-000000000001';

describe('canonical JSON', () => {
  it('sorts keys recursively, drops undefined properties and has no whitespace', () => {
    expect(canonicalJson({ b: 1, a: { d: [1, 'x', null], c: true }, z: undefined })).toBe(
      '{"a":{"c":true,"d":[1,"x",null]},"b":1}',
    );
    expect(canonicalSha256({ a: 1, b: 2 })).toBe(canonicalSha256({ b: 2, a: 1 }));
    expect(sha256Hex('abc')).toBe(createHash('sha256').update('abc').digest('hex'));
    expect(sha256Hex(Buffer.from('abc'))).toBe(sha256Hex('abc'));
  });

  it.each([
    ['bigint', 1n],
    ['date', new Date(0)],
    ['buffer', Buffer.from('x')],
    ['function', () => 1],
    ['NaN', Number.NaN],
    ['undefined in an array', [1, undefined]],
    ['symbol', Symbol('s')],
  ])('refuses %s', (_name, value) => {
    expect(() => canonicalJson({ v: value })).toThrow(TypeError);
  });

  it('refuses cycles', () => {
    const a: Record<string, unknown> = {};
    a.self = a;
    expect(() => canonicalJson(a)).toThrow(TypeError);
  });
});

describe('archive-settings/1', () => {
  it('accepts its example and the empty document', () => {
    expect(archiveSettingsSchema.parse(ARCHIVE_SETTINGS_EXAMPLE)).toEqual(ARCHIVE_SETTINGS_EXAMPLE);
    expect(archiveSettingsSchema.parse({})).toEqual({});
  });

  it.each([
    [{ extra: 1 }],
    [{ directions: { inbound: true, sideways: true } }],
    [{ scope: { mode: 'some' } }],
    [{ scope: { domainIds: ['not-a-uuid'] } }],
    [{ scope: { domainIds: [UUID, UUID] } }],
    [{ scope: { addresses: ['nobody'] } }],
    [
      {
        scope: {
          departmentIds: Array.from(
            { length: 51 },
            (_, i) => `0190a5d0-0000-7000-8000-${String(i).padStart(12, '0')}`,
          ),
        },
      },
    ],
    [{ access: { previewEnabled: 'yes' } }],
    [{ policyArchive: { enabled: true, rules: [] } }],
  ])('refuses %j', (doc) => {
    expect(archiveSettingsSchema.safeParse(doc).success).toBe(false);
  });

  it('resolves the defaults of A22 (null = every default)', () => {
    expect(resolveArchiveSettings(null)).toEqual(ARCHIVE_SETTINGS_DEFAULTS);
    expect(resolveArchiveSettings(undefined)).toEqual({
      directions: { inbound: true, outbound: true, internal: true },
      include: { rejected: false, quarantined: false, failed: false },
      scope: { mode: 'all', domainIds: [], departmentIds: [], userIds: [], addresses: [] },
      policyArchive: { enabled: true },
      access: { previewEnabled: true, downloadEnabled: false },
      intake: { scanEnabled: false },
    });
    const r = resolveArchiveSettings({
      directions: { internal: false },
      include: { failed: true },
      scope: { mode: 'exclude', addresses: ['Legal@Example.com'] },
      access: { downloadEnabled: true },
    });
    expect(r.directions).toEqual({ inbound: true, outbound: true, internal: false });
    expect(r.include).toEqual({ rejected: false, quarantined: false, failed: true });
    expect(r.scope).toMatchObject({ mode: 'exclude', addresses: ['legal@example.com'] });
    expect(r.access).toEqual({ previewEnabled: true, downloadEnabled: true });
    // The frozen defaults are never shared by reference.
    resolveArchiveSettings(null).scope.addresses.push('x@y.z');
    expect(ARCHIVE_SETTINGS_DEFAULTS.scope.addresses).toEqual([]);
  });

  it('throws a document error without content for an invalid stored document', () => {
    expect(() => resolveArchiveSettings({ secretField: 'value-123' })).toThrow(
      ArchiveDocumentError,
    );
    try {
      resolveArchiveSettings({ secretField: 'value-123' });
    } catch (error) {
      expect((error as Error).message).toBe('Invalid archive-settings/1 document');
    }
  });
});

describe('settings change rules (A10, A22)', () => {
  const on = (immutability: 'none' | 'governance' | 'compliance') => ({
    enabled: true,
    immutability,
  });
  const facts = { objectLockAvailable: true, entitled: true, defaultRetentionLive: true };

  it('enabling needs the entitlement and a default retention policy', () => {
    expect(validateArchiveSettingsChange(null, on('none'), { ...facts, entitled: false })).toEqual({
      ok: false,
      code: 'archiving_not_enabled',
    });
    expect(
      validateArchiveSettingsChange(null, on('none'), { ...facts, defaultRetentionLive: false }),
    ).toEqual({
      ok: false,
      code: 'archive_default_retention_required',
    });
    expect(validateArchiveSettingsChange(null, on('none'), facts)).toEqual({
      ok: true,
      enabling: true,
      applyLockPass: false,
      weakeningForNewCapturesOnly: false,
    });
    // Already enabled: losing the entitlement does not block other edits.
    expect(
      validateArchiveSettingsChange(on('none'), on('none'), { ...facts, entitled: false }),
    ).toMatchObject({
      ok: true,
      enabling: false,
    });
    // Disabling never needs a default policy.
    expect(
      validateArchiveSettingsChange(
        on('none'),
        { enabled: false, immutability: 'none' },
        {
          ...facts,
          defaultRetentionLive: false,
        },
      ),
    ).toMatchObject({ ok: true });
  });

  it('refuses compliance downgrades and applies a lock pass on upgrades', () => {
    expect(validateArchiveSettingsChange(on('compliance'), on('governance'), facts)).toEqual({
      ok: false,
      code: 'archive_immutability_downgrade_forbidden',
    });
    expect(validateArchiveSettingsChange(on('compliance'), on('none'), facts)).toMatchObject({
      ok: false,
      code: 'archive_immutability_downgrade_forbidden',
    });
    expect(validateArchiveSettingsChange(on('none'), on('governance'), facts)).toMatchObject({
      ok: true,
      applyLockPass: true,
    });
    expect(validateArchiveSettingsChange(on('governance'), on('compliance'), facts)).toMatchObject({
      ok: true,
      applyLockPass: true,
    });
    expect(validateArchiveSettingsChange(on('governance'), on('none'), facts)).toMatchObject({
      ok: true,
      applyLockPass: false,
      weakeningForNewCapturesOnly: true,
    });
    expect(validateArchiveSettingsChange(on('compliance'), on('compliance'), facts)).toMatchObject({
      ok: true,
    });
  });

  it('refuses a new lock mode without Object Lock on the bucket (honest fallback)', () => {
    const noLock = { ...facts, objectLockAvailable: false };
    expect(validateArchiveSettingsChange(on('none'), on('governance'), noLock)).toEqual({
      ok: false,
      code: 'archive_object_lock_unavailable',
    });
    expect(validateArchiveSettingsChange(null, on('compliance'), noLock)).toMatchObject({
      ok: false,
      code: 'archive_object_lock_unavailable',
    });
    expect(validateArchiveSettingsChange(on('none'), on('none'), noLock)).toMatchObject({
      ok: true,
    });
  });
});

describe('archive-retention/1 and archive-hold/1', () => {
  it('accept their examples and refuse unknown keys, duplicates and empty lists', () => {
    expect(archiveRetentionCriteriaSchema.parse(ARCHIVE_RETENTION_CRITERIA_EXAMPLE)).toEqual(
      ARCHIVE_RETENTION_CRITERIA_EXAMPLE,
    );
    expect(archiveRetentionCriteriaSchema.parse({})).toEqual({});
    for (const bad of [
      { other: 1 },
      { directions: [] },
      { directions: ['inbound', 'inbound'] },
      { categories: ['archived'] },
      { sources: ['manual'] },
      { policyRuleRefs: Array.from({ length: 51 }, (_, i) => `r${i}`) },
    ]) {
      expect(archiveRetentionCriteriaSchema.safeParse(bad).success, JSON.stringify(bad)).toBe(
        false,
      );
    }
    expect(archiveHoldCriteriaSchema.parse(ARCHIVE_HOLD_CRITERIA_EXAMPLE)).toEqual(
      ARCHIVE_HOLD_CRITERIA_EXAMPLE,
    );
    expect(
      archiveHoldCriteriaSchema.safeParse({ ...ARCHIVE_HOLD_CRITERIA_EXAMPLE, keywords: ['x'] })
        .success,
    ).toBe(false);
    expect(archiveHoldCriteriaSchema.safeParse({ from: '2026-13-01' }).success).toBe(false);
  });

  it('the legacy subset refuses directions', () => {
    expect(
      legacyLegalHoldCriteriaSchema.safeParse({ custodians: ['a@b.c'], from: '2026-01-01' })
        .success,
    ).toBe(true);
    expect(legacyLegalHoldCriteriaSchema.safeParse({ directions: ['inbound'] }).success).toBe(
      false,
    );
  });

  it('creation criteria need addresses and from ≤ to', () => {
    expect(archiveHoldCreateCriteriaSchema.safeParse(ARCHIVE_HOLD_CRITERIA_EXAMPLE).success).toBe(
      true,
    );
    expect(archiveHoldCreateCriteriaSchema.safeParse({ custodians: ['nobody'] }).success).toBe(
      false,
    );
    expect(
      archiveHoldCreateCriteriaSchema.safeParse({ from: '2026-02-01', to: '2026-01-31' }).success,
    ).toBe(false);
    expect(
      archiveHoldCreateCriteriaSchema.safeParse({ from: '2026-02-01', to: '2026-02-01' }).success,
    ).toBe(true);
  });
});

describe('record documents', () => {
  it('archive-parties/1 accepts its example and the null sender; refuses unknown keys', () => {
    expect(archivePartiesSchema.parse(ARCHIVE_PARTIES_EXAMPLE)).toEqual(ARCHIVE_PARTIES_EXAMPLE);
    expect(archivePartiesSchema.safeParse({ ...ARCHIVE_PARTIES_EXAMPLE, from: '' }).success).toBe(
      true,
    );
    expect(archivePartiesSchema.safeParse({ ...ARCHIVE_PARTIES_EXAMPLE, v: 2 }).success).toBe(
      false,
    );
    expect(
      archivePartiesSchema.safeParse({ ...ARCHIVE_PARTIES_EXAMPLE, subject: 'x' }).success,
    ).toBe(false);
    const r = { ...ARCHIVE_PARTIES_EXAMPLE.recipients[0]!, status: 'lost' };
    expect(
      archivePartiesSchema.safeParse({ ...ARCHIVE_PARTIES_EXAMPLE, recipients: [r] }).success,
    ).toBe(false);
  });

  it('archive-journal/1 accepts its example and refuses unknown keys at every level', () => {
    expect(archiveJournalSchema.parse(ARCHIVE_JOURNAL_EXAMPLE)).toEqual(ARCHIVE_JOURNAL_EXAMPLE);
    const j = ARCHIVE_JOURNAL_EXAMPLE;
    for (const bad of [
      { ...j, extra: true },
      { ...j, version: 'archive-journal/2' },
      { ...j, message: { ...j.message, body: 'x' } },
      { ...j, body: { ...j.body, attachmentsContent: 'x' } },
      { ...j, attachments: [{ ...j.attachments[0]!, content: 'x' }] },
      { ...j, messageId: 'ABC' },
      { ...j, message: { ...j.message, emlSha256: 'XYZ' } },
    ]) {
      expect(archiveJournalSchema.safeParse(bad).success).toBe(false);
    }
  });

  it('objects and scan rounds', () => {
    const ref = {
      key: 'org/1/archive/x/eml.bin',
      versionId: 'v1',
      sha256: 'c'.repeat(64),
      bytes: 10,
    };
    expect(
      archiveRecordObjectsSchema.safeParse({
        captureId: UUID,
        eml: ref,
        journal: ref,
        scans: [{ ...ref, round: 1, revision: 0 }],
      }).success,
    ).toBe(true);
    expect(
      archiveRecordObjectsSchema.safeParse({
        captureId: UUID,
        eml: ref,
        journal: ref,
        scans: [],
        x: 1,
      }).success,
    ).toBe(false);
    const rounds = Array.from({ length: 17 }, (_, i) => ({
      round: i,
      revision: 0,
      frozenAt: '2026-11-16T00:00:00.000Z',
    }));
    expect(archiveScanRoundsSchema.safeParse(rounds.slice(0, 16)).success).toBe(true);
    expect(archiveScanRoundsSchema.safeParse(rounds).success).toBe(false);
  });
});

describe('archive-search/1 and archive-export-manifest/1', () => {
  it('search accepts its example, custodians case or a list, and refuses unknown keys', () => {
    expect(archiveSearchCriteriaSchema.parse(ARCHIVE_SEARCH_CRITERIA_EXAMPLE)).toEqual(
      ARCHIVE_SEARCH_CRITERIA_EXAMPLE,
    );
    const base = { from: '2026-01-01T00:00:00Z', to: '2026-01-31' };
    expect(
      archiveSearchCriteriaSchema.safeParse({ ...base, custodians: ['a@example.com'] }).success,
    ).toBe(true);
    for (const bad of [
      { ...base, body: 'x' },
      { ...base, custodians: 'all' },
      { ...base, riskScoreGte: 1001 },
      { ...base, statuses: ['disposing', 'gone'] },
      { ...base, subject: 'x'.repeat(257) },
      { to: '2026-01-01' },
      { ...base, holdId: 'h1' },
      { ...base, attachmentSha256: ['ABC'] },
    ]) {
      expect(archiveSearchCriteriaSchema.safeParse(bad).success, JSON.stringify(bad)).toBe(false);
    }
  });

  it('manifest schema is strict', () => {
    const m = {
      version: 'archive-export-manifest/1',
      exportId: UUID,
      caseId: UUID,
      searchId: UUID,
      organizationId: UUID,
      generatedAt: '2026-11-16T00:00:00.000Z',
      generator: 'archive-worker',
      signingKeyId: 'es1',
      reviewTags: ['relevant'],
      counts: { items: 0, malicious: 0, bytes: 0 },
      items: [],
    };
    expect(archiveExportManifestSchema.safeParse(m).success).toBe(true);
    expect(archiveExportManifestSchema.safeParse({ ...m, generator: 'api' }).success).toBe(false);
    expect(archiveExportManifestSchema.safeParse({ ...m, extra: 1 }).success).toBe(false);
  });
});
