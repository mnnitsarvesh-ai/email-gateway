import {
  type ArchiveSettingsDocument,
  canonicalJson,
  resolveArchiveSettings,
  type ResolvedArchiveSettings,
} from '@email-gateway/archive';

/**
 * Per-path authorization of the archive settings (step 8.6 D11/D12, ADR-0089): the settings row
 * is shared by the Journaling area (capture: what is journaled) and the Archive area (storage
 * and use: immutability, default retention, access). A change is authorized path by path, so a
 * journaling manager (`journal:manage`) can never weaken immutability or open downloads, and an
 * archive manager (`archive:manage`) can never stop capture. Pure: no I/O.
 */

export const JOURNAL_MANAGE = 'journal:manage';
export const ARCHIVE_MANAGE = 'archive:manage';

/** Every authorizable path of the settings row with the permission that may change it. */
export const SETTINGS_PATH_PERMISSION = Object.freeze({
  enabled: JOURNAL_MANAGE,
  'settings.directions': JOURNAL_MANAGE,
  'settings.include': JOURNAL_MANAGE,
  'settings.scope': JOURNAL_MANAGE,
  'settings.policyArchive': JOURNAL_MANAGE,
  'settings.intake': JOURNAL_MANAGE,
  immutability: ARCHIVE_MANAGE,
  defaultRetentionPolicyId: ARCHIVE_MANAGE,
  'settings.access': ARCHIVE_MANAGE,
} as const);

export type SettingsPath = keyof typeof SETTINGS_PATH_PERMISSION;

/** The sections of `archive-settings/1` that belong to the Journaling area. */
export const JOURNALING_SETTINGS_KEYS = [
  'directions',
  'include',
  'scope',
  'policyArchive',
  'intake',
] as const satisfies readonly (keyof ResolvedArchiveSettings)[];

const SECTIONS = [...JOURNALING_SETTINGS_KEYS, 'access'] as const;

/** The stored row's values a change is compared with. */
export interface CurrentSettingsFacts {
  enabled: boolean;
  immutability: 'none' | 'governance' | 'compliance';
  /** Public id (lower-case) of the default retention policy, or null. */
  defaultRetentionPolicyId: string | null;
  /** The stored `archive-settings/1` document (raw; null = defaults). */
  document: unknown;
}

/** The requested change (absent = unchanged; `document` replaces the stored one when present). */
export interface RequestedSettingsChange {
  enabled?: boolean | undefined;
  immutability?: 'none' | 'governance' | 'compliance' | undefined;
  defaultRetentionPolicyId?: string | null | undefined;
  document?: ArchiveSettingsDocument | undefined;
}

const resolved = (raw: unknown): ResolvedArchiveSettings => {
  try {
    return resolveArchiveSettings(raw);
  } catch {
    return resolveArchiveSettings(null);
  }
};

/**
 * The paths a change really changes, compared on the effective (defaults-applied) values: an
 * omitted section of a replacing document that resolves to the stored effective value is not a
 * change, a section that differs is.
 */
export function changedSettingsPaths(
  current: CurrentSettingsFacts,
  change: RequestedSettingsChange,
): SettingsPath[] {
  const out: SettingsPath[] = [];
  if (change.enabled !== undefined && change.enabled !== current.enabled) out.push('enabled');
  if (change.immutability !== undefined && change.immutability !== current.immutability) {
    out.push('immutability');
  }
  if (change.defaultRetentionPolicyId !== undefined) {
    const next = change.defaultRetentionPolicyId?.toLowerCase() ?? null;
    if (next !== (current.defaultRetentionPolicyId?.toLowerCase() ?? null)) {
      out.push('defaultRetentionPolicyId');
    }
  }
  if (change.document !== undefined) {
    const before = resolved(current.document);
    const after = resolved(change.document);
    for (const section of SECTIONS) {
      if (canonicalJson(before[section]) !== canonicalJson(after[section])) {
        out.push(`settings.${section}`);
      }
    }
  }
  return out;
}

/** The changed paths the holder of `permissions` may not change (empty = authorized). */
export function forbiddenSettingsPaths(
  paths: readonly SettingsPath[],
  permissions: ReadonlySet<string>,
): Array<{ path: SettingsPath; permission: string }> {
  return paths
    .filter((p) => !permissions.has(SETTINGS_PATH_PERMISSION[p]))
    .map((p) => ({ path: p, permission: SETTINGS_PATH_PERMISSION[p] }));
}

/**
 * The document a Journaling-area update stores: the journaling sections of the request replace
 * the stored ones, and the stored Archive-area section (`access`) is kept as stored, so
 * `PUT /journaling/settings` can never change an Archive path.
 */
export function journalingDocument(
  stored: unknown,
  journaling: Pick<ArchiveSettingsDocument, (typeof JOURNALING_SETTINGS_KEYS)[number]>,
): ArchiveSettingsDocument {
  const access =
    stored !== null && typeof stored === 'object' && !Array.isArray(stored)
      ? (stored as ArchiveSettingsDocument).access
      : undefined;
  const out: ArchiveSettingsDocument = {};
  for (const key of JOURNALING_SETTINGS_KEYS) {
    if (journaling[key] !== undefined) {
      (out as Record<string, unknown>)[key] = journaling[key];
    }
  }
  if (access !== undefined) out.access = access;
  return out;
}
