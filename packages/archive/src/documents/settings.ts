import { z } from 'zod';
import { type ObjectLockMode } from '../vocabulary';
import { addressSchema, ArchiveDocumentError, uniqueListOf, uuidSchema } from './common';

/**
 * `archive-settings/1` (§4.2, A22): the per-organization journaling document stored in
 * `archive_settings.settings` (NULL = every default). Every key is optional; the typed columns
 * stay authoritative for `enabled`, `object_lock_mode` (API `immutability`) and
 * `default_retention_policy_id`.
 */

export const SCOPE_MODES = ['all', 'include', 'exclude'] as const;
export type ScopeMode = (typeof SCOPE_MODES)[number];

export const archiveSettingsSchema = z.strictObject({
  directions: z
    .strictObject({
      inbound: z.boolean().optional(),
      outbound: z.boolean().optional(),
      internal: z.boolean().optional(),
    })
    .optional(),
  include: z
    .strictObject({
      rejected: z.boolean().optional(),
      quarantined: z.boolean().optional(),
      failed: z.boolean().optional(),
    })
    .optional(),
  scope: z
    .strictObject({
      mode: z.enum(SCOPE_MODES).optional(),
      domainIds: uniqueListOf(uuidSchema, 100).optional(),
      departmentIds: uniqueListOf(uuidSchema, 50).optional(),
      userIds: uniqueListOf(uuidSchema, 1_000).optional(),
      addresses: uniqueListOf(addressSchema, 1_000).optional(),
    })
    .optional(),
  policyArchive: z.strictObject({ enabled: z.boolean().optional() }).optional(),
  access: z
    .strictObject({
      previewEnabled: z.boolean().optional(),
      downloadEnabled: z.boolean().optional(),
    })
    .optional(),
  /**
   * Step 8.6 D8: scanning of journal intake messages (default off). Applies to messages committed
   * afterwards (`journal_intake_messages.scan_requested` is the per-message snapshot).
   */
  intake: z.strictObject({ scanEnabled: z.boolean().optional() }).optional(),
});
export type ArchiveSettingsDocument = z.infer<typeof archiveSettingsSchema>;

export interface ResolvedArchiveSettings {
  directions: { inbound: boolean; outbound: boolean; internal: boolean };
  include: { rejected: boolean; quarantined: boolean; failed: boolean };
  scope: {
    mode: ScopeMode;
    domainIds: string[];
    departmentIds: string[];
    userIds: string[];
    /** Lower-cased. */
    addresses: string[];
  };
  policyArchive: { enabled: boolean };
  access: { previewEnabled: boolean; downloadEnabled: boolean };
  /** Step 8.6 D8. */
  intake: { scanEnabled: boolean };
}

/** The defaults of A22 (product owner decision 2). */
export const ARCHIVE_SETTINGS_DEFAULTS: Readonly<ResolvedArchiveSettings> =
  Object.freeze<ResolvedArchiveSettings>({
    directions: { inbound: true, outbound: true, internal: true },
    include: { rejected: false, quarantined: false, failed: false },
    scope: { mode: 'all', domainIds: [], departmentIds: [], userIds: [], addresses: [] },
    policyArchive: { enabled: true },
    access: { previewEnabled: true, downloadEnabled: false },
    intake: { scanEnabled: false },
  });

export const ARCHIVE_SETTINGS_EXAMPLE: ArchiveSettingsDocument = {
  directions: { inbound: true, outbound: true, internal: false },
  include: { quarantined: true },
  scope: {
    mode: 'include',
    domainIds: ['0190a5d0-0000-7000-8000-000000000001'],
    addresses: ['legal@example.com'],
  },
  policyArchive: { enabled: true },
  access: { previewEnabled: true, downloadEnabled: false },
};

/**
 * Applies the defaults to a stored document (`null`/`undefined` = every default). Throws
 * `ArchiveDocumentError` for a document that is not `archive-settings/1`.
 */
export function resolveArchiveSettings(raw: unknown): ResolvedArchiveSettings {
  const d = ARCHIVE_SETTINGS_DEFAULTS;
  if (raw === null || raw === undefined) {
    return {
      directions: { ...d.directions },
      include: { ...d.include },
      scope: { ...d.scope, domainIds: [], departmentIds: [], userIds: [], addresses: [] },
      policyArchive: { ...d.policyArchive },
      access: { ...d.access },
      intake: { ...d.intake },
    };
  }
  const parsed = archiveSettingsSchema.safeParse(raw);
  if (!parsed.success) throw new ArchiveDocumentError('archive-settings/1');
  const s = parsed.data;
  return {
    directions: {
      inbound: s.directions?.inbound ?? d.directions.inbound,
      outbound: s.directions?.outbound ?? d.directions.outbound,
      internal: s.directions?.internal ?? d.directions.internal,
    },
    include: {
      rejected: s.include?.rejected ?? d.include.rejected,
      quarantined: s.include?.quarantined ?? d.include.quarantined,
      failed: s.include?.failed ?? d.include.failed,
    },
    scope: {
      mode: s.scope?.mode ?? d.scope.mode,
      domainIds: [...(s.scope?.domainIds ?? [])],
      departmentIds: [...(s.scope?.departmentIds ?? [])],
      userIds: [...(s.scope?.userIds ?? [])],
      addresses: [...new Set((s.scope?.addresses ?? []).map((a) => a.trim().toLowerCase()))],
    },
    policyArchive: { enabled: s.policyArchive?.enabled ?? d.policyArchive.enabled },
    access: {
      previewEnabled: s.access?.previewEnabled ?? d.access.previewEnabled,
      downloadEnabled: s.access?.downloadEnabled ?? d.access.downloadEnabled,
    },
    intake: { scanEnabled: s.intake?.scanEnabled ?? d.intake.scanEnabled },
  };
}

export interface ArchiveSettingsState {
  enabled: boolean;
  /** `archive_settings.object_lock_mode`. */
  immutability: ObjectLockMode;
}

export interface ArchiveSettingsChangeFacts {
  /** `GetObjectLockConfiguration` probe of the archive bucket (A10). */
  objectLockAvailable: boolean;
  /** The organization's plan has the `archiving` feature (checked when enabling). */
  entitled?: boolean;
  /** The default retention policy pointer names a live policy (required while enabled). */
  defaultRetentionLive?: boolean;
}

export type ArchiveSettingsChangeRefusal =
  | 'archiving_not_enabled'
  | 'archive_default_retention_required'
  | 'archive_immutability_downgrade_forbidden'
  | 'archive_object_lock_unavailable';

export type ArchiveSettingsChangeDecision =
  | {
      ok: true;
      /** `enabled` goes false → true: set `journal_enabled_at` (no backfill, A4). */
      enabling: boolean;
      /** Stronger immutability: enqueue the bounded "apply lock" pass over active records (A10). */
      applyLockPass: boolean;
      /** `governance → none`: affects new captures only; existing locks expire naturally. */
      weakeningForNewCapturesOnly: boolean;
    }
  | { ok: false; code: ArchiveSettingsChangeRefusal };

const LOCK_RANK: Record<ObjectLockMode, number> = { none: 0, governance: 1, compliance: 2 };

/**
 * The settings rules of A10 and A22 (`PUT /archive/settings`): enabling needs the entitlement;
 * enabled settings need a live default retention policy; `compliance → governance|none` is
 * refused; a new non-`none` mode needs Object Lock on the bucket. A mode that is unchanged is not
 * re-checked against availability (the capture path refuses it, A10). `previous` null = no row.
 */
export function validateArchiveSettingsChange(
  previous: ArchiveSettingsState | null,
  next: ArchiveSettingsState,
  facts: ArchiveSettingsChangeFacts,
): ArchiveSettingsChangeDecision {
  const before: ArchiveSettingsState = previous ?? { enabled: false, immutability: 'none' };
  const enabling = next.enabled && !before.enabled;
  if (enabling && facts.entitled === false) return { ok: false, code: 'archiving_not_enabled' };
  if (next.enabled && facts.defaultRetentionLive === false) {
    return { ok: false, code: 'archive_default_retention_required' };
  }
  if (before.immutability === 'compliance' && next.immutability !== 'compliance') {
    return { ok: false, code: 'archive_immutability_downgrade_forbidden' };
  }
  if (
    next.immutability !== 'none' &&
    next.immutability !== before.immutability &&
    !facts.objectLockAvailable
  ) {
    return { ok: false, code: 'archive_object_lock_unavailable' };
  }
  return {
    ok: true,
    enabling,
    applyLockPass: LOCK_RANK[next.immutability] > LOCK_RANK[before.immutability],
    weakeningForNewCapturesOnly:
      before.immutability === 'governance' && next.immutability === 'none',
  };
}
