import {
  canonicalJson,
  platformProfile,
  RISK_HARD_BLOCKS,
  RISK_SIGNALS,
  sha256Hex,
} from '@email-gateway/risk-scoring';
import { describe, expect, it } from 'vitest';
import type { ProfileRow, VersionRow } from '../repositories/risk-profiles.repository';
import {
  changedPaths,
  checkOverrides,
  inlineProfile,
  platformProfileView,
  profileView,
  resolveActive,
  RISK_NOTICE,
  versionDetail,
  versionSummary,
} from './risk-profile';

const PLATFORM = 'rsk-default/1';
const AT = new Date('2026-11-11T09:00:00.000Z');
const USER = '0190f0f0-0000-7000-8000-0000000000aa';

const profile = (activeVersionId: bigint | null): ProfileRow => ({
  id: 1n,
  publicId: '0190f0f0-0000-7000-8000-000000000001',
  organizationId: 5n,
  activeVersionId,
  version: 3,
  updatedAt: AT,
  updatedBy: { publicId: USER },
});

const version = (patch: Partial<VersionRow> = {}): VersionRow => ({
  id: 11n,
  publicId: '0190f0f0-0000-7000-8000-000000000011',
  organizationId: 5n,
  profileId: 1n,
  versionNo: 2,
  status: 'published',
  baseProfile: PLATFORM,
  overrides: { thresholds: { medium: 350 } },
  overridesSha256: 'a'.repeat(64),
  profileSha256: 'b'.repeat(64),
  changeNote: 'raise medium',
  rowVersion: 2,
  publishedAt: AT,
  createdAt: AT,
  updatedAt: AT,
  createdBy: { publicId: USER },
  updatedBy: null,
  publishedBy: { publicId: USER },
  ...patch,
});

describe('checkOverrides (R10 bounds, violations by path)', () => {
  it('accepts an empty document and a document within bounds, normalized and hashed', () => {
    const empty = checkOverrides({}, PLATFORM);
    expect(empty).toEqual({ ok: true, overrides: {}, sha256: sha256Hex(canonicalJson({})) });
    const doc = { thresholds: { medium: 350 }, actions: { medium: 'require_approval' } };
    const ok = checkOverrides(doc, PLATFORM);
    expect(ok.ok).toBe(true);
    if (ok.ok) {
      expect(ok.overrides).toEqual(doc);
      expect(ok.sha256).toBe(sha256Hex(canonicalJson(doc)));
    }
  });

  it.each([
    [{ thresholds: { low: 10 } }, 'thresholds.low'],
    [{ thresholds: { high: 330 } }, 'thresholds.high'],
    [{ thresholds: { medium: 120 } }, 'thresholds.medium'],
    [{ actions: { critical: 'deliver' } }, 'actions.critical'],
    [
      { actions: { low: 'tag', medium: 'tag', high: 'require_approval', none: 'tag' } },
      'actions.none',
    ],
    [{ groupMultipliersPermille: { spam: 2001 } }, 'groupMultipliersPermille.spam'],
    [
      { groupMultipliersPermille: { attachment_malware: 500 } },
      'groupMultipliersPermille.attachment_malware',
    ],
    [
      { hardBlocks: { 'hb.malware_attachment': { enabled: false } } },
      'hardBlocks.hb.malware_attachment.enabled',
    ],
    [
      { hardBlocks: { 'hb.dlp_block': { action: 'quarantine' } } },
      'hardBlocks.hb.dlp_block.action',
    ],
    [{ failures: { minLevel: 'low' } }, 'failures.minLevel'],
    [{ failures: { action: 'tag' } }, 'failures.action'],
    [{ floors: { engineMalicious: 'medium' } }, 'floors.engineMalicious'],
    [{ trust: { contentFactorPermille: 100 } }, 'trust.contentFactorPermille'],
    [{ nonsense: true }, 'nonsense'],
    [{ thresholds: { extreme: 999 } }, 'thresholds.extreme'],
  ])('refuses %j at %s', (doc, path) => {
    const check = checkOverrides(doc, PLATFORM);
    expect(check.ok).toBe(false);
    if (!check.ok) expect(check.violations.map((v) => v.path)).toContain(path);
  });

  it('refuses a retired base profile', () => {
    const check = checkOverrides({}, 'rsk-default/0');
    expect(check).toEqual({
      ok: false,
      violations: [{ path: 'baseProfile', message: 'base_profile_retired' }],
    });
  });
});

describe('changedPaths (audit metadata: paths only, never values)', () => {
  it('lists added, removed and changed leaves, sorted', () => {
    expect(
      changedPaths(
        { thresholds: { low: 120, medium: 350 }, trust: { mode: 'off' } },
        { thresholds: { low: 120, medium: 360 }, ai: { tagOnAiOnlyRaise: false } },
      ),
    ).toEqual(['ai.tagOnAiOnlyRaise', 'thresholds.medium', 'trust.mode']);
    expect(changedPaths({}, { hardBlocks: { 'hb.dmarc_reject': { enabled: true } } })).toEqual([
      'hardBlocks.hb.dmarc_reject.enabled',
    ]);
    expect(changedPaths({ a: 1 }, { a: 1 })).toEqual([]);
  });

  it('never carries a value', () => {
    const paths = changedPaths({}, { thresholds: { medium: 377 } });
    expect(JSON.stringify(paths)).not.toContain('377');
  });
});

describe('resolveActive (pointer → effective profile, as the email-worker resolves it)', () => {
  it('is the platform default without a profile row or pointer', () => {
    expect(resolveActive(PLATFORM, null, null)).toMatchObject({
      source: 'platform',
      fallback: null,
    });
    expect(resolveActive(PLATFORM, profile(null), null)).toMatchObject({ source: 'platform' });
  });

  it('is the tenant version when the pointer names a published version of the organization', () => {
    const resolved = resolveActive(PLATFORM, profile(11n), version());
    expect(resolved).toMatchObject({
      source: 'tenant',
      id: `${PLATFORM}+t:0190f0f0-0000-7000-8000-000000000011#2`,
      versionNo: 2,
    });
    expect(resolved.profile.thresholds.medium).toBe(350);
  });

  it('falls back (missing / foreign / invalid) and never uses a draft', () => {
    expect(resolveActive(PLATFORM, profile(11n), null).fallback).toBe('missing');
    expect(resolveActive(PLATFORM, profile(11n), version({ status: 'draft' })).fallback).toBe(
      'foreign',
    );
    expect(resolveActive(PLATFORM, profile(11n), version({ organizationId: 6n })).fallback).toBe(
      'foreign',
    );
    const invalid = resolveActive(
      PLATFORM,
      profile(11n),
      version({ overrides: { thresholds: { low: 1 } } }),
    );
    expect(invalid).toMatchObject({ source: 'platform', fallback: 'invalid' });
    expect(invalid.violations.map((v) => v.path)).toContain('thresholds.low');
  });
});

describe('views', () => {
  it('maps a version to public ids only, with the active flag', () => {
    const summary = versionSummary(version(), 11n);
    expect(summary).toMatchObject({
      id: '0190f0f0-0000-7000-8000-000000000011',
      versionNo: 2,
      status: 'published',
      active: true,
      createdByUserId: USER,
      publishedAt: AT.toISOString(),
    });
    expect(JSON.stringify(summary)).not.toMatch(/"(11|1|5)"/);
    expect(versionSummary(version(), null).active).toBe(false);
  });

  it('resolves a version detail now, with violations when the bounds no longer accept it', () => {
    const ok = versionDetail(version(), null, PLATFORM);
    expect(ok.resolved).toMatchObject({ valid: true, violations: [] });
    const retired = versionDetail(version({ baseProfile: 'rsk-default/0' }), null, PLATFORM);
    expect(retired.resolved).toMatchObject({
      valid: false,
      profileId: PLATFORM,
      violations: [{ path: 'baseProfile', message: 'base_profile_retired' }],
    });
  });

  it('shows the active profile with counts and the limit', () => {
    const view = profileView(PLATFORM, 200, profile(11n), version(), { drafts: 1, published: 2 });
    expect(view).toMatchObject({
      profileVersion: 3,
      platformProfile: PLATFORM,
      active: { source: 'tenant', versionId: '0190f0f0-0000-7000-8000-000000000011', versionNo: 2 },
      counts: { drafts: 1, published: 2, limit: 200 },
      updatedByUserId: USER,
    });
    const none = profileView(PLATFORM, 200, null, null, { drafts: 0, published: 0 });
    expect(none).toMatchObject({
      id: null,
      profileVersion: 0,
      active: { source: 'platform', versionId: null, versionNo: null, fallback: null },
    });
    expect(none.active.sha256).toBe(platformProfile(PLATFORM).sha256);
  });

  it('describes the platform profile, its bounds, signals and hard blocks', () => {
    const view = platformProfileView(PLATFORM);
    expect(view.id).toBe(PLATFORM);
    expect(view.sha256).toBe(platformProfile(PLATFORM).sha256);
    expect(view.bounds.thresholds.low).toEqual({ min: 50, max: 250 });
    expect(view.bounds.lockedGroups).toEqual(
      expect.arrayContaining(['attachment_malware', 'engine_failure', 'engine_unknown', 'sandbox']),
    );
    expect(view.signals).toHaveLength(RISK_SIGNALS.length);
    expect(view.hardBlocks.map((h) => h.id)).toEqual(RISK_HARD_BLOCKS.map((h) => h.id));
    expect(view.notice).toBe(RISK_NOTICE);
    expect(view.notice).toContain('not validated detection accuracy');
    expect(view.notice).toContain('next scan round only');
  });

  it('labels an inline dry-run document without a version number', () => {
    const inline = inlineProfile(PLATFORM, { thresholds: { medium: 350 } });
    expect(inline).toMatchObject({
      source: 'tenant',
      id: `${PLATFORM}+t:inline`,
      versionNo: null,
      fallback: null,
    });
    expect(inline.profile.thresholds.medium).toBe(350);
    expect(inline.sha256).toBe(sha256Hex(canonicalJson(inline.profile)));
  });
});
