/**
 * ATO taxonomy (step 8.4 D1, D10, D11, D13, §3.2): account kinds, signal categories and strengths,
 * risk levels, response states and impacts, authentication sources and outcomes, and the per-group
 * caps of `ato-score/1`. Every list equals the matching Prisma enum (a unit test compares them with
 * `schema.prisma`) and is append-only.
 */
import { ATO_ACCOUNT_KINDS, ATO_RISK_LEVELS } from '@email-gateway/security-contracts';

export const ACCOUNT_KINDS = ATO_ACCOUNT_KINDS;
export type { AtoAccountKind as AccountKind } from '@email-gateway/security-contracts';

/** The eleven score groups (D10). */
export const SIGNAL_CATEGORIES = [
  'authentication',
  'access_context',
  'geography',
  'threat_intel',
  'account_change',
  'outbound_behaviour',
  'outbound_content',
  'mailbox_configuration',
  'oauth_activity',
  'provider_risk',
  'correlation',
] as const;
export type SignalCategory = (typeof SIGNAL_CATEGORIES)[number];

export const SIGNAL_STRENGTHS = ['weak', 'moderate', 'strong'] as const;
export type SignalStrength = (typeof SIGNAL_STRENGTHS)[number];

export const SIGNAL_STATUSES = ['active', 'dismissed', 'informational'] as const;
export type SignalStatus = (typeof SIGNAL_STATUSES)[number];

export const SIGNAL_SOURCE_KINDS = [
  'auth_event',
  'message',
  'telemetry',
  'audit',
  'provider',
  'correlation',
  'window',
] as const;
export type SignalSourceKind = (typeof SIGNAL_SOURCE_KINDS)[number];

export const RISK_LEVELS = ATO_RISK_LEVELS;
export type { AtoRiskLevel as RiskLevel } from '@email-gateway/security-contracts';

export const SCORE_TRIGGERS = [
  'signal',
  'decay',
  'override',
  'dismissal',
  'settings',
  'feedback',
] as const;
export type ScoreTrigger = (typeof SCORE_TRIGGERS)[number];

/** Response action states (D13; `ato_response_actions.status`). */
export const RESPONSE_STATUSES = [
  'pending_approval',
  'approved',
  'executing',
  'succeeded',
  'failed',
  'rejected',
  'cancelled',
  'expired',
  'unsupported',
  'rollback_requested',
  'rolled_back',
  'rollback_failed',
  'attested',
] as const;
export type ResponseStatus = (typeof RESPONSE_STATUSES)[number];

export const RESPONSE_IMPACTS = ['low', 'medium', 'high'] as const;
export type ResponseImpact = (typeof RESPONSE_IMPACTS)[number];

export const RESPONSE_AUTHORIZATIONS = [
  'manual',
  'automation_policy',
  'low_impact_default',
] as const;
export type ResponseAuthorization = (typeof RESPONSE_AUTHORIZATIONS)[number];

export const RESPONSE_PROVIDER_STATUSES = [
  'applied',
  'confirmed',
  'pending',
  'unconfirmed',
  'unsupported',
  'failed',
] as const;
export type ResponseProviderStatus = (typeof RESPONSE_PROVIDER_STATUSES)[number];

/** Authentication sources (`ato_auth_events.source`). */
export const AUTH_SOURCES = ['portal_login', 'portal_mfa', 'smtp_auth', 'idp_sign_in'] as const;
export type AuthSource = (typeof AUTH_SOURCES)[number];

export const AUTH_CHANNELS = ['portal', 'api', 'smtp', 'idp'] as const;
export type AuthChannel = (typeof AUTH_CHANNELS)[number];

/** Authentication outcomes (`ato_auth_events.outcome`). */
export const AUTH_OUTCOMES = [
  'success',
  'failure',
  'locked',
  'mfa_required',
  'mfa_failure',
  'rate_limited',
  'throttled',
  'blocked',
] as const;
export type AuthOutcome = (typeof AUTH_OUTCOMES)[number];

export const GEO_STATUSES = ['located', 'not_found', 'private', 'unavailable', 'stale'] as const;
export type GeoStatus = (typeof GEO_STATUSES)[number];

/** Per-group caps of `ato-score/1` (D11; part of the scorer version, not tunable). */
export const GROUP_CAPS: Readonly<Record<SignalCategory, number>> = Object.freeze({
  authentication: 50,
  access_context: 30,
  geography: 40,
  threat_intel: 60,
  account_change: 50,
  outbound_behaviour: 50,
  outbound_content: 70,
  mailbox_configuration: 60,
  oauth_activity: 50,
  provider_risk: 60,
  correlation: 60,
});

/** Default half-lives per category in minutes (D11; tenant-tunable 60–43 200). */
export const DEFAULT_HALF_LIFE_MINUTES: Readonly<Record<SignalCategory, number>> = Object.freeze({
  authentication: 360,
  access_context: 1440,
  geography: 1440,
  threat_intel: 4320,
  account_change: 4320,
  outbound_behaviour: 1440,
  outbound_content: 4320,
  mailbox_configuration: 10080,
  oauth_activity: 10080,
  provider_risk: 4320,
  correlation: 4320,
});

/** Stacking factor of the 2nd–4th contributions of a group, per mille (D11). */
export const GROUP_STACKING_PERMILLE = 250;
/** Contributions counted per group (the first plus three stacked). */
export const GROUP_MAX_CONTRIBUTIONS = 4;

/**
 * Capabilities a rule may require (D10): GeoIP databases, DNSBL zones, breach indicators, BEC
 * outbound observations and provider streams (`provider:<stream>`).
 */
export const STATIC_CAPABILITIES = [
  'geoip_city',
  'geoip_asn',
  'geoip_anonymous',
  'dnsbl',
  'breach_intel',
  'bec_observations',
] as const;
export type StaticCapability = (typeof STATIC_CAPABILITIES)[number];
export type Capability = StaticCapability | `provider:${string}`;

/** Anonymizer flags bitmask (`ato_auth_events.anonymizer_flags`, D7). */
export const ANONYMIZER_FLAGS = Object.freeze({
  anonymousVpn: 1,
  publicProxy: 2,
  torExitNode: 4,
  hostingProvider: 8,
  residentialProxy: 16,
  anonymous: 32,
});

/** Detection sources of observations (rules declare which they apply to). */
export const OBSERVATION_SOURCES = [
  'portal_login',
  'portal_mfa',
  'smtp_auth',
  'idp_sign_in',
  'account_change',
  'outbound_message',
  'smtp_submission',
  'provider',
] as const;
export type ObservationSource = (typeof OBSERVATION_SOURCES)[number];
