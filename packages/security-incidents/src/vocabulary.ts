/**
 * Vocabulary of the security incident model shared by account takeover (step 8.4) and advanced
 * threat protection (ATP-4) (docs/plan/steps/24-account-takeover-core.md D24, §3.1; ADR-0075).
 * The lists themselves are defined once in `@email-gateway/security-contracts` (WP1) and only
 * re-exported here, so the policy DSL, this library and the ATO library share one definition.
 * Every list is **append-only**.
 */
import type { SecurityIncidentLinkType } from '@email-gateway/security-contracts';

export {
  SECURITY_INCIDENT_CATEGORIES,
  SECURITY_INCIDENT_SUBJECT_TYPES,
  SECURITY_INCIDENT_LINK_TYPES,
  SECURITY_INCIDENT_ORIGINS,
  SECURITY_INCIDENT_STATUSES,
  SECURITY_INCIDENT_ACTIVE_STATUSES,
  SECURITY_INCIDENT_SEVERITIES,
  SECURITY_INCIDENT_RESOLUTION_CODES,
  isActiveSecurityIncidentStatus,
  securityIncidentSeverityRank,
  securityIncidentCategorySchema,
  securityIncidentSubjectTypeSchema,
  securityIncidentLinkTypeSchema,
  securityIncidentOriginSchema,
  securityIncidentStatusSchema,
  securityIncidentActiveStatusSchema,
  securityIncidentSeveritySchema,
  securityIncidentResolutionCodeSchema,
  type SecurityIncidentCategory,
  type SecurityIncidentSubjectType,
  type SecurityIncidentLinkType,
  type SecurityIncidentOrigin,
  type SecurityIncidentStatus,
  type SecurityIncidentActiveStatus,
  type SecurityIncidentSeverity,
  type SecurityIncidentResolutionCode,
} from '@email-gateway/security-contracts';

/** Who acted (`security_incidents.created_by_type`, `security_incident_events.actor_type`). */
export const INCIDENT_ACTOR_TYPES = ['system', 'user', 'api_key'] as const;
export type IncidentActorType = (typeof INCIDENT_ACTOR_TYPES)[number];

/** An actor: the type and the public id of the user or API key (null for the system). */
export interface IncidentActor {
  type: IncidentActorType;
  /** Public id (UUID) of the user or API key; null for the system. */
  id: string | null;
  /** Internal id of a user actor (for `resolved_by_user_id`); never written to events. */
  userId?: bigint | null;
  /**
   * Platform override of the acting user (the api's `AuditActor.override`); copied into the audit
   * row's `metadata.override` exactly like `AuditService.record`. Never written to events.
   */
  override?: { id: string; reason: string };
}

export const SYSTEM_INCIDENT_ACTOR: IncidentActor = Object.freeze({ type: 'system', id: null });

/**
 * Generic timeline event types (`security_incident_events.event_type`, D24 §3.1). Categories add
 * prefixed types (ATO: `ato.response_requested`, …) through `IncidentStore.recordEvent`.
 */
export const INCIDENT_EVENT_TYPES = [
  'created',
  'evidence_linked',
  'severity_changed',
  'status_changed',
  'assigned',
  'note_added',
  'escalated',
  'report_exported',
] as const;
export type IncidentEventType = (typeof INCIDENT_EVENT_TYPES)[number];

/** A generic or category-prefixed event type (≤ 48 characters, `security_incident_events`). */
export const INCIDENT_EVENT_TYPE_PATTERN = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)?$/;
export const INCIDENT_EVENT_TYPE_MAX_LENGTH = 48;

/** Audit actions of the shared model (`audit_logs.action`, resource type `security_incident`). */
export const INCIDENT_AUDIT_RESOURCE_TYPE = 'security_incident';
export const INCIDENT_AUDIT_ACTIONS = [
  'security_incident.created',
  'security_incident.status_changed',
  'security_incident.assigned',
  'security_incident.note_added',
  'security_incident.severity_changed',
  'security_incident.report_exported',
] as const;
export type IncidentAuditAction = (typeof INCIDENT_AUDIT_ACTIONS)[number];

/** Notes: resolution and confirmation notes 10–4000 characters (D12); free notes 1–4000. */
export const INCIDENT_NOTE_MIN_LENGTH = 10;
export const INCIDENT_NOTE_MAX_LENGTH = 4000;
export const INCIDENT_FREE_NOTE_MIN_LENGTH = 1;

/** At most 16 reason codes per incident (`reason_codes`, `security.incident.created.v1`). */
export const INCIDENT_MAX_REASON_CODES = 16;
/** Dotted lower-case code (`ato.geo.impossible_travel`), ≤ 64 characters. */
export const INCIDENT_REASON_CODE_PATTERN = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/;

/** Evidence link caps per incident and link type (D12); beyond them only counts are kept. */
export const INCIDENT_LINK_CAPS: Readonly<Record<SecurityIncidentLinkType, number>> = Object.freeze(
  { ato_signal: 2000, ato_auth_event: 1000, message: 500 },
);

/** `security.incident.updated.v1` with only `evidence` at most once per 15 minutes per incident. */
export const INCIDENT_EVIDENCE_EVENT_THROTTLE_MS = 15 * 60 * 1000;

/** Codes listed per `evidence_linked` timeline entry (D12). */
export const INCIDENT_EVIDENCE_CODES_PER_EVENT = 10;

/** Fields of `security.incident.updated.v1` `changedFields`. */
export const INCIDENT_CHANGED_FIELDS = [
  'status',
  'severity',
  'assignee',
  'resolution',
  'evidence',
] as const;
export type IncidentChangedField = (typeof INCIDENT_CHANGED_FIELDS)[number];
