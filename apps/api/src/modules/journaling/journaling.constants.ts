import type { ApiConfig } from '../../config';

/**
 * Constants of the journaling module (step 8.6 D1, D10, D11,
 * docs/plan/steps/27-journal-intake-and-archive-split.md; ADR-0087, ADR-0089): permissions, the
 * plan features, audit actions and resource type, Idempotency-Key operation names, the v1 cursor
 * resource and bounds.
 */

/** Permission keys (ADR-0089; seeded by WP1). */
export const JOURNAL_PERMISSIONS = {
  read: 'journal:read',
  manage: 'journal:manage',
  archiveRead: 'archive:read',
} as const;

/** Plan features of journal intake (D1 entitlement). */
export const ARCHIVING_FEATURE = 'archiving';
export const JOURNAL_INTAKE_FEATURE = 'journal_intake';

/** `audit_logs.action` of the intake source routes (D11). Metadata: ids and enums only. */
export const JOURNAL_AUDIT = {
  sourceCreated: 'journal_intake.source_created',
  sourceUpdated: 'journal_intake.source_updated',
  sourcePaused: 'journal_intake.source_paused',
  sourceResumed: 'journal_intake.source_resumed',
  sourceDisabled: 'journal_intake.source_disabled',
  addressRotated: 'journal_intake.address_rotated',
  addressRevealed: 'journal_intake.address_revealed',
  attested: 'journal_intake.attested',
} as const;

/** `audit_logs.resource_type` of the intake source rows. */
export const JOURNAL_INTAKE_RESOURCE = 'journal_intake_source';

/** Stable Idempotency-Key operation names. */
export const JOURNAL_OPERATIONS = {
  settingsUpdate: 'journaling.settings_update',
  sourceCreate: 'journal_intake.source_create',
  sourceUpdate: 'journal_intake.source_update',
  rotateAddress: 'journal_intake.rotate_address',
} as const;

/** v1 cursor resource (ADR-0051). */
export const INTAKE_SOURCES_CURSOR_RESOURCE = 'journal_intake_sources';

/** Writer transaction budget of the module's mutations. */
export const JOURNAL_TX_TIMEOUT_MS = 30_000;

/** At most this many attestations are kept per source (`provider-attestations/1` shape). */
export const MAX_INTAKE_ATTESTATIONS = 32;
export const INTAKE_ATTESTATIONS_SCHEMA = 'provider-attestations/1';

/** Days of counters on the source detail. */
export const COUNTER_DAYS_SHOWN = 7;

/** The api config keys the journaling module reads. */
export type JournalingConfig = Pick<
  ApiConfig,
  | 'APP_ENV'
  | 'JOURNAL_INTAKE_DOMAIN'
  | 'JOURNAL_INTAKE_ADDRESS_SECRET'
  | 'JOURNAL_INTAKE_MAX_MESSAGE_BYTES'
  | 'JOURNAL_INTAKE_ROTATION_OVERLAP_DAYS'
  | 'JOURNAL_INTAKE_MAX_SOURCES_PER_ORG'
  | 'GATEWAY_MX_HOSTS'
>;

/** Status and health keys of the status view (every key present, 0 when none). */
export const INTAKE_STATUS_KEYS = ['pending_verification', 'active', 'paused', 'disabled'] as const;
export const INTAKE_HEALTH_KEYS = ['unknown', 'healthy', 'silent', 'failing', 'paused'] as const;
