import { z } from 'zod';

/**
 * Vocabulary of the security incident model shared by account takeover (step 8.4) and advanced
 * threat protection (ATP-4) (docs/plan/steps/24-account-takeover-core.md D24, §3.1; ADR-0075).
 * Each list equals the matching Prisma enum of `security_incidents`, `security_incident_links`
 * (a test compares them with `schema.prisma`) and is **append-only**: a later step appends
 * values (for example ATP-4's categories `message_threat`, `threat_campaign`), never renames or
 * removes one, and consumers ignore values they do not know. The state machine, store and
 * category handlers live in `@email-gateway/security-incidents`.
 */

/** Incident categories (`security_incidents.category`). 8.4: account takeover only. */
export const SECURITY_INCIDENT_CATEGORIES = ['account_takeover'] as const;
export type SecurityIncidentCategory = (typeof SECURITY_INCIDENT_CATEGORIES)[number];
export const securityIncidentCategorySchema = z.enum(SECURITY_INCIDENT_CATEGORIES);

/** Subject types (`security_incidents.subject_type`): what the incident is about. */
export const SECURITY_INCIDENT_SUBJECT_TYPES = ['ato_account'] as const;
export type SecurityIncidentSubjectType = (typeof SECURITY_INCIDENT_SUBJECT_TYPES)[number];
export const securityIncidentSubjectTypeSchema = z.enum(SECURITY_INCIDENT_SUBJECT_TYPES);

/** Evidence link types (`security_incident_links.link_type`). */
export const SECURITY_INCIDENT_LINK_TYPES = ['message', 'ato_signal', 'ato_auth_event'] as const;
export type SecurityIncidentLinkType = (typeof SECURITY_INCIDENT_LINK_TYPES)[number];
export const securityIncidentLinkTypeSchema = z.enum(SECURITY_INCIDENT_LINK_TYPES);

/** How an incident was opened (`security_incidents.origin`). */
export const SECURITY_INCIDENT_ORIGINS = ['detection', 'manual'] as const;
export type SecurityIncidentOrigin = (typeof SECURITY_INCIDENT_ORIGINS)[number];
export const securityIncidentOriginSchema = z.enum(SECURITY_INCIDENT_ORIGINS);

/** The six incident states (brief §6; `security_incidents.status`). */
export const SECURITY_INCIDENT_STATUSES = [
  'open',
  'investigating',
  'confirmed',
  'false_positive',
  'mitigated',
  'resolved',
] as const;
export type SecurityIncidentStatus = (typeof SECURITY_INCIDENT_STATUSES)[number];
export const securityIncidentStatusSchema = z.enum(SECURITY_INCIDENT_STATUSES);

/**
 * Active (non-terminal) states: the generated `security_incidents.active_marker` is 1 exactly for
 * these (`IF(status IN ('open','investigating','confirmed','mitigated'), 1, NULL)`), which makes
 * one active incident per category and subject unique. `false_positive` and `resolved` are
 * terminal. Also the values of the DSL field `ato.incident_status` (D23).
 */
export const SECURITY_INCIDENT_ACTIVE_STATUSES = [
  'open',
  'investigating',
  'confirmed',
  'mitigated',
] as const satisfies readonly SecurityIncidentStatus[];
export type SecurityIncidentActiveStatus = (typeof SECURITY_INCIDENT_ACTIVE_STATUSES)[number];
export const securityIncidentActiveStatusSchema = z.enum(SECURITY_INCIDENT_ACTIVE_STATUSES);

/** Whether `status` is an active (non-terminal) state. */
export const isActiveSecurityIncidentStatus = (
  status: string,
): status is SecurityIncidentActiveStatus =>
  (SECURITY_INCIDENT_ACTIVE_STATUSES as readonly string[]).includes(status);

/** Incident severities in ascending order (`security_incidents.severity`; DSL `ato.incident_severity`). */
export const SECURITY_INCIDENT_SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;
export type SecurityIncidentSeverity = (typeof SECURITY_INCIDENT_SEVERITIES)[number];
export const securityIncidentSeveritySchema = z.enum(SECURITY_INCIDENT_SEVERITIES);

/** Rank of a severity (0 = `low`). */
export const securityIncidentSeverityRank = (severity: SecurityIncidentSeverity): number =>
  SECURITY_INCIDENT_SEVERITIES.indexOf(severity);

/**
 * Resolution codes (`security_incidents.resolution_code`). `false_positive` closes with one of
 * `false_positive`, `benign_activity`, `duplicate`; `resolved` with one of `remediated`,
 * `benign_activity`, `duplicate`, `other` (enforced by the shared store, D12).
 */
export const SECURITY_INCIDENT_RESOLUTION_CODES = [
  'remediated',
  'false_positive',
  'benign_activity',
  'duplicate',
  'other',
] as const;
export type SecurityIncidentResolutionCode = (typeof SECURITY_INCIDENT_RESOLUTION_CODES)[number];
export const securityIncidentResolutionCodeSchema = z.enum(SECURITY_INCIDENT_RESOLUTION_CODES);
