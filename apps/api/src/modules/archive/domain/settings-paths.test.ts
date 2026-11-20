import { describe, expect, it } from 'vitest';
import {
  changedSettingsPaths,
  type CurrentSettingsFacts,
  forbiddenSettingsPaths,
  journalingDocument,
  SETTINGS_PATH_PERMISSION,
} from './settings-paths';

const CURRENT: CurrentSettingsFacts = {
  enabled: true,
  immutability: 'governance',
  defaultRetentionPolicyId: '0193a1c2-1111-7a00-8000-000000000001',
  document: {
    directions: { inbound: true, outbound: true, internal: false },
    access: { previewEnabled: true, downloadEnabled: true },
  },
};

const JOURNAL = new Set(['journal:manage']);
const ARCHIVE = new Set(['archive:manage']);
const BOTH = new Set(['journal:manage', 'archive:manage']);

describe('archive settings per-path authorization (step 8.6 D11, ADR-0089)', () => {
  it('maps every path to its area permission', () => {
    expect(SETTINGS_PATH_PERMISSION).toEqual({
      enabled: 'journal:manage',
      'settings.directions': 'journal:manage',
      'settings.include': 'journal:manage',
      'settings.scope': 'journal:manage',
      'settings.policyArchive': 'journal:manage',
      'settings.intake': 'journal:manage',
      immutability: 'archive:manage',
      defaultRetentionPolicyId: 'archive:manage',
      'settings.access': 'archive:manage',
    });
  });

  it('a request equal to the stored values changes nothing', () => {
    expect(
      changedSettingsPaths(CURRENT, {
        enabled: true,
        immutability: 'governance',
        defaultRetentionPolicyId: CURRENT.defaultRetentionPolicyId!.toUpperCase(),
        document: CURRENT.document as never,
      }),
    ).toEqual([]);
  });

  it.each([
    [{ enabled: false }, ['enabled']],
    [{ immutability: 'compliance' as const }, ['immutability']],
    [{ defaultRetentionPolicyId: null }, ['defaultRetentionPolicyId']],
    [
      {
        document: {
          directions: { inbound: true, outbound: true, internal: false },
          access: { previewEnabled: true, downloadEnabled: true },
          intake: { scanEnabled: true },
        },
      },
      ['settings.intake'],
    ],
    [
      {
        document: {
          directions: { inbound: true, outbound: true, internal: true },
          access: { previewEnabled: true, downloadEnabled: true },
        },
      },
      ['settings.directions'],
    ],
    // A replacing document without `access` resets it to the defaults: a change of `access`.
    [
      { document: { directions: { inbound: true, outbound: true, internal: false } } },
      ['settings.access'],
    ],
    [
      {
        document: {
          directions: { inbound: true, outbound: true, internal: false },
          access: { previewEnabled: true, downloadEnabled: true },
          include: { quarantined: true },
          scope: { mode: 'exclude' as const, addresses: ['legal@example.com'] },
          policyArchive: { enabled: false },
        },
      },
      ['settings.include', 'settings.scope', 'settings.policyArchive'],
    ],
  ])('%j changes %j', (change, paths) => {
    expect(changedSettingsPaths(CURRENT, change)).toEqual(paths);
  });

  it('a first settings row (no stored row) compares with the defaults', () => {
    const none: CurrentSettingsFacts = {
      enabled: false,
      immutability: 'none',
      defaultRetentionPolicyId: null,
      document: null,
    };
    expect(changedSettingsPaths(none, { document: {} })).toEqual([]);
    expect(changedSettingsPaths(none, { enabled: true, immutability: 'governance' })).toEqual([
      'enabled',
      'immutability',
    ]);
  });

  it('refuses the paths of the other area, naming each with its permission', () => {
    const paths = changedSettingsPaths(CURRENT, {
      enabled: false,
      immutability: 'compliance',
      document: {
        directions: { inbound: true, outbound: true, internal: false },
        access: { previewEnabled: true, downloadEnabled: false },
      },
    });
    expect(paths).toEqual(['enabled', 'immutability', 'settings.access']);
    expect(forbiddenSettingsPaths(paths, JOURNAL)).toEqual([
      { path: 'immutability', permission: 'archive:manage' },
      { path: 'settings.access', permission: 'archive:manage' },
    ]);
    expect(forbiddenSettingsPaths(paths, ARCHIVE)).toEqual([
      { path: 'enabled', permission: 'journal:manage' },
    ]);
    expect(forbiddenSettingsPaths(paths, BOTH)).toEqual([]);
    expect(forbiddenSettingsPaths([], new Set())).toEqual([]);
  });

  it('a journaling update keeps the stored access section and only the journaling keys', () => {
    expect(
      journalingDocument(CURRENT.document, {
        directions: { inbound: true, outbound: false, internal: false },
        intake: { scanEnabled: true },
      }),
    ).toEqual({
      directions: { inbound: true, outbound: false, internal: false },
      intake: { scanEnabled: true },
      access: { previewEnabled: true, downloadEnabled: true },
    });
    expect(journalingDocument(null, { policyArchive: { enabled: false } })).toEqual({
      policyArchive: { enabled: false },
    });
    // The result never changes an Archive path.
    const stored = CURRENT.document;
    const next = journalingDocument(stored, { include: { failed: true } });
    expect(
      changedSettingsPaths(CURRENT, { document: next }).every(
        (p) => SETTINGS_PATH_PERMISSION[p] === 'journal:manage',
      ),
    ).toBe(true);
  });
});
