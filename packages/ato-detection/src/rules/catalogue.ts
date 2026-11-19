/**
 * The rule catalogue `ato-rules/1` (step 8.4 D10) as data: every rule's stable code, category,
 * strength, default weight, applicable account kinds and sources, bounded numeric parameters with
 * defaults, dedupe definition, required capabilities, whether it is baseline-relative, its title
 * and its explanation template. Tenants tune weights, parameters and enablement within bounds
 * (`ato-settings/1` `rules`); no tenant-defined logic is executed.
 */
import { z } from 'zod';
import type { AtoAccountKind } from '@email-gateway/security-contracts';
import type {
  Capability,
  ObservationSource,
  SignalCategory,
  SignalStrength,
  StaticCapability,
} from '../taxonomy';

export interface RuleParam {
  default: number;
  min: number;
  max: number;
}

/** Dedupe buckets and their windows in minutes (`event`: the subject is the event itself). */
export const DEDUPE_BUCKET_MINUTES = Object.freeze({
  hour: 60,
  day: 1440,
  week: 10080,
  month: 43200,
  event: 43200,
});
export type DedupeBucket = keyof typeof DEDUPE_BUCKET_MINUTES;

export interface RuleDefinition {
  id: string;
  code: string;
  category: SignalCategory;
  strength: SignalStrength;
  defaultWeight: number;
  kinds: readonly AtoAccountKind[];
  sources: readonly ObservationSource[];
  params: Readonly<Record<string, RuleParam>>;
  dedupe: { bucket: DedupeBucket; subject: string };
  capabilities: readonly Capability[];
  baselineRelative: boolean;
  /** Correlation rule (evaluated by `evaluateCorrelation` inside the transaction). */
  correlation: boolean;
  title: string;
  explanation: string;
}

const AUTH_SOURCES: readonly ObservationSource[] = [
  'portal_login',
  'portal_mfa',
  'smtp_auth',
  'idp_sign_in',
];
const USER_CONNECTOR_MAILBOX: readonly AtoAccountKind[] = [
  'gateway_user',
  'smtp_connector',
  'mailbox',
];
const MAILBOX: readonly AtoAccountKind[] = ['mailbox'];
const USER: readonly AtoAccountKind[] = ['gateway_user'];
const MAILBOX_CONNECTOR: readonly AtoAccountKind[] = ['mailbox', 'smtp_connector'];
const ALL: readonly AtoAccountKind[] = ['mailbox', 'gateway_user', 'smtp_connector'];
const OUTBOUND: readonly ObservationSource[] = ['outbound_message'];
const PROVIDER: readonly ObservationSource[] = ['provider'];

const p = (def: number, min: number, max: number): RuleParam => ({ default: def, min, max });

function rule(
  def: Omit<RuleDefinition, 'params' | 'capabilities' | 'baselineRelative' | 'correlation'> &
    Partial<Pick<RuleDefinition, 'params' | 'capabilities' | 'baselineRelative' | 'correlation'>>,
): RuleDefinition {
  return Object.freeze({
    params: {},
    capabilities: [],
    baselineRelative: false,
    correlation: false,
    ...def,
  });
}

export const ATO_RULES: readonly RuleDefinition[] = Object.freeze([
  // ------------------------------------------------------------- authentication
  rule({
    id: 'A1',
    code: 'ato.auth.bruteforce',
    category: 'authentication',
    strength: 'moderate',
    defaultWeight: 20,
    kinds: USER_CONNECTOR_MAILBOX,
    sources: AUTH_SOURCES,
    params: { failures: p(10, 3, 1000), windowMinutes: p(15, 5, 60) },
    dedupe: { bucket: 'hour', subject: 'account' },
    title: 'Repeated failed sign-ins',
    explanation:
      '{failures} failed sign-ins within {windowMinutes} minutes (threshold {threshold})',
  }),
  rule({
    id: 'A2',
    code: 'ato.auth.success_after_failures',
    category: 'authentication',
    strength: 'moderate',
    defaultWeight: 30,
    kinds: USER_CONNECTOR_MAILBOX,
    sources: AUTH_SOURCES,
    params: {
      failures: p(5, 2, 1000),
      windowMinutes: p(30, 5, 60),
      strongDistinctIps: p(3, 2, 50),
      strongWeight: p(40, 0, 100),
    },
    dedupe: { bucket: 'event', subject: 'success event' },
    title: 'Successful sign-in after failures',
    explanation:
      'Successful sign-in after {failures} failed attempts from {distinctIps} addresses within {windowMinutes} minutes',
  }),
  rule({
    id: 'A3',
    code: 'ato.auth.mfa_failures',
    category: 'authentication',
    strength: 'moderate',
    defaultWeight: 30,
    kinds: USER,
    sources: ['portal_login', 'portal_mfa'],
    params: { failures: p(3, 2, 100), windowMinutes: p(15, 5, 60) },
    dedupe: { bucket: 'hour', subject: 'account' },
    title: 'Repeated MFA failures after a correct password',
    explanation:
      '{failures} failed MFA codes within {windowMinutes} minutes after a correct password',
  }),
  rule({
    id: 'A4',
    code: 'ato.auth.lockout',
    category: 'authentication',
    strength: 'weak',
    defaultWeight: 8,
    kinds: USER,
    sources: ['portal_login', 'portal_mfa'],
    dedupe: { bucket: 'day', subject: 'account' },
    title: 'Account locked by the login throttle',
    explanation: 'The login throttle locked the account after repeated failures',
  }),
  // ------------------------------------------------------------- access context
  rule({
    id: 'C1',
    code: 'ato.access.new_ip_prefix',
    category: 'access_context',
    strength: 'weak',
    defaultWeight: 8,
    kinds: USER_CONNECTOR_MAILBOX,
    sources: AUTH_SOURCES,
    dedupe: { bucket: 'day', subject: 'prefix' },
    baselineRelative: true,
    title: 'Sign-in from a new network',
    explanation: 'Sign-in from network {ipPrefix}, not seen for this account before',
  }),
  rule({
    id: 'C2',
    code: 'ato.access.new_asn',
    category: 'access_context',
    strength: 'weak',
    defaultWeight: 10,
    kinds: USER_CONNECTOR_MAILBOX,
    sources: AUTH_SOURCES,
    dedupe: { bucket: 'day', subject: 'ASN' },
    capabilities: ['geoip_asn'],
    baselineRelative: true,
    title: 'Sign-in from a new network operator',
    explanation: 'Sign-in from AS{asn} ({asnOrg}), not seen for this account before',
  }),
  rule({
    id: 'C3',
    code: 'ato.access.new_device',
    category: 'access_context',
    strength: 'weak',
    defaultWeight: 10,
    kinds: ['gateway_user', 'mailbox'],
    sources: AUTH_SOURCES,
    dedupe: { bucket: 'day', subject: 'device' },
    baselineRelative: true,
    title: 'Sign-in from a new device',
    explanation: 'Sign-in from a new device ({deviceLabel})',
  }),
  rule({
    id: 'C4',
    code: 'ato.access.unusual_hour',
    category: 'access_context',
    strength: 'weak',
    defaultWeight: 5,
    kinds: ['gateway_user', 'smtp_connector'],
    sources: AUTH_SOURCES,
    params: {
      minBaselineEvents: p(30, 10, 10000),
      maxSharePermille: p(20, 1, 200),
      toleranceHours: p(1, 0, 3),
    },
    dedupe: { bucket: 'day', subject: 'account' },
    baselineRelative: true,
    title: 'Sign-in at an unusual hour',
    explanation:
      'Sign-in at a local hour holding {permille} per mille of {baseline} previous sign-ins',
  }),
  rule({
    id: 'C5',
    code: 'ato.access.channel_change',
    category: 'access_context',
    strength: 'weak',
    defaultWeight: 5,
    kinds: USER,
    sources: ['portal_login'],
    dedupe: { bucket: 'week', subject: 'account' },
    baselineRelative: true,
    title: 'First direct API sign-in',
    explanation: 'First direct API sign-in of an account that only signed in through the portal',
  }),
  rule({
    id: 'C6',
    code: 'ato.access.concurrent_ips',
    category: 'access_context',
    strength: 'moderate',
    defaultWeight: 20,
    kinds: MAILBOX_CONNECTOR,
    sources: ['smtp_auth', 'idp_sign_in'],
    params: { distinctPrefixes: p(4, 2, 100) },
    dedupe: { bucket: 'hour', subject: 'account' },
    title: 'Sign-ins from many networks at once',
    explanation:
      'Successful sign-ins from {count} networks within {windowMinutes} minutes (usual maximum {baseline})',
  }),
  // ------------------------------------------------------------- geography
  rule({
    id: 'G1',
    code: 'ato.geo.new_country',
    category: 'geography',
    strength: 'weak',
    defaultWeight: 12,
    kinds: USER_CONNECTOR_MAILBOX,
    sources: AUTH_SOURCES,
    dedupe: { bucket: 'day', subject: 'country' },
    capabilities: ['geoip_city'],
    baselineRelative: true,
    title: 'Sign-in from a new country',
    explanation: 'Sign-in from {country}, a country not seen for this account before',
  }),
  rule({
    id: 'G2',
    code: 'ato.geo.impossible_travel',
    category: 'geography',
    strength: 'moderate',
    defaultWeight: 30,
    kinds: ['gateway_user', 'mailbox'],
    sources: AUTH_SOURCES,
    params: { downgradedWeight: p(10, 0, 100) },
    dedupe: { bucket: 'hour', subject: 'country pair' },
    capabilities: ['geoip_city'],
    title: 'Impossible travel',
    explanation:
      'Sign-ins from {fromCountry} and {toCountry} {distanceKm} km apart within {elapsedMinutes} minutes (about {speedKmh} km/h)',
  }),
  rule({
    id: 'G3',
    code: 'ato.geo.inconsistent_sessions',
    category: 'geography',
    strength: 'moderate',
    defaultWeight: 20,
    kinds: ['gateway_user', 'smtp_connector'],
    sources: AUTH_SOURCES,
    params: { windowMinutes: p(60, 15, 240) },
    dedupe: { bucket: 'hour', subject: 'account' },
    capabilities: ['geoip_city'],
    title: 'Simultaneous activity from distant countries',
    explanation:
      'Activity from {count} countries at least {distanceKm} km apart within {windowMinutes} minutes',
  }),
  rule({
    id: 'G4',
    code: 'ato.geo.anonymizer',
    category: 'geography',
    strength: 'weak',
    defaultWeight: 10,
    kinds: USER_CONNECTOR_MAILBOX,
    sources: AUTH_SOURCES,
    dedupe: { bucket: 'day', subject: 'IP' },
    capabilities: ['geoip_anonymous'],
    title: 'Sign-in through an anonymizer',
    explanation: 'Sign-in from {ip}, an anonymous VPN, proxy, Tor exit or hosting range',
  }),
  // ------------------------------------------------------------- threat intelligence
  rule({
    id: 'T1',
    code: 'ato.ti.malicious_ip_success',
    category: 'threat_intel',
    strength: 'strong',
    defaultWeight: 45,
    kinds: ALL,
    sources: AUTH_SOURCES,
    params: { moderateWeight: p(25, 0, 100) },
    dedupe: { bucket: 'day', subject: 'IP' },
    title: 'Successful sign-in from a known malicious address',
    explanation: 'Successful sign-in from {ip}, listed by threat intelligence ({codes})',
  }),
  rule({
    id: 'T2',
    code: 'ato.ti.dnsbl_listed_success',
    category: 'threat_intel',
    strength: 'moderate',
    defaultWeight: 20,
    kinds: ALL,
    sources: AUTH_SOURCES,
    dedupe: { bucket: 'day', subject: 'IP' },
    capabilities: ['dnsbl'],
    title: 'Successful sign-in from a blocklisted address',
    explanation: 'Successful sign-in from {ip}, listed by a configured DNS blocklist',
  }),
  rule({
    id: 'T3',
    code: 'ato.ti.attack_source_success',
    category: 'threat_intel',
    strength: 'strong',
    defaultWeight: 45,
    kinds: ALL,
    sources: AUTH_SOURCES,
    dedupe: { bucket: 'day', subject: 'IP' },
    title: 'Successful sign-in from an attacking address',
    explanation:
      'Successful sign-in from {ip}, which failed against {distinctAccounts} accounts across the platform in the last hour',
  }),
  rule({
    id: 'T4',
    code: 'ato.ti.breach_listed',
    category: 'threat_intel',
    strength: 'weak',
    defaultWeight: 10,
    kinds: ['mailbox', 'gateway_user'],
    sources: [...AUTH_SOURCES, 'outbound_message'],
    dedupe: { bucket: 'month', subject: 'account' },
    capabilities: ['breach_intel'],
    title: 'Address found in breach intelligence',
    explanation: 'The account address appears in operator-provided breach intelligence',
  }),
  rule({
    id: 'T5',
    code: 'ato.ti.targeted_by_campaign',
    category: 'threat_intel',
    strength: 'weak',
    defaultWeight: 5,
    kinds: ALL,
    sources: AUTH_SOURCES,
    dedupe: { bucket: 'day', subject: 'account' },
    title: 'Targeted by a credential attack campaign',
    explanation:
      'Failed sign-ins from {ip}, which failed against {distinctAccounts} accounts across the platform',
  }),
  rule({
    id: 'T6',
    code: 'ato.ti.malicious_ip_attempt',
    category: 'threat_intel',
    strength: 'weak',
    defaultWeight: 5,
    kinds: ALL,
    sources: AUTH_SOURCES,
    dedupe: { bucket: 'day', subject: 'account' },
    title: 'Failed sign-in from a known malicious address',
    explanation: 'Failed sign-in from {ip}, listed by threat intelligence',
  }),
  // ------------------------------------------------------------- account changes
  rule({
    id: 'K1',
    code: 'ato.account.refresh_token_reuse',
    category: 'account_change',
    strength: 'strong',
    defaultWeight: 50,
    kinds: USER,
    sources: ['account_change'],
    dedupe: { bucket: 'event', subject: 'event' },
    title: 'Refresh token reused',
    explanation: 'A revoked refresh token was presented again (session theft indicator)',
  }),
  rule({
    id: 'K2',
    code: 'ato.account.mfa_disabled',
    category: 'account_change',
    strength: 'weak',
    defaultWeight: 10,
    kinds: USER,
    sources: ['account_change'],
    dedupe: { bucket: 'event', subject: 'event' },
    title: 'MFA disabled',
    explanation: 'Multi-factor authentication was disabled for the account',
  }),
  rule({
    id: 'K3',
    code: 'ato.account.credentials_changed',
    category: 'account_change',
    strength: 'weak',
    defaultWeight: 5,
    kinds: USER,
    sources: ['account_change'],
    dedupe: { bucket: 'day', subject: 'account' },
    title: 'Credentials changed',
    explanation: 'Credentials of the account changed ({action})',
  }),
  rule({
    id: 'K4',
    code: 'ato.account.persistence_created',
    category: 'account_change',
    strength: 'weak',
    defaultWeight: 10,
    kinds: USER,
    sources: ['account_change'],
    dedupe: { bucket: 'event', subject: 'event' },
    title: 'Persistent access created',
    explanation: 'The account created persistent access ({action})',
  }),
  rule({
    id: 'K5',
    code: 'ato.account.privilege_change',
    category: 'account_change',
    strength: 'weak',
    defaultWeight: 10,
    kinds: USER,
    sources: ['account_change'],
    dedupe: { bucket: 'day', subject: 'account' },
    title: 'Privilege change',
    explanation: 'The account changed privileges ({action})',
  }),
  rule({
    id: 'K6',
    code: 'ato.account.bulk_data_access',
    category: 'account_change',
    strength: 'moderate',
    defaultWeight: 20,
    kinds: USER,
    sources: ['account_change'],
    params: { count: p(20, 5, 1000), windowMinutes: p(60, 15, 60) },
    dedupe: { bucket: 'hour', subject: 'account' },
    title: 'Bulk access to sensitive mail data',
    explanation:
      '{count} message reveals, quarantine downloads or releases within {windowMinutes} minutes',
  }),
  // ------------------------------------------------------------- outbound behaviour
  rule({
    id: 'O1',
    code: 'ato.outbound.volume_spike',
    category: 'outbound_behaviour',
    strength: 'moderate',
    defaultWeight: 25,
    kinds: MAILBOX_CONNECTOR,
    sources: OUTBOUND,
    params: {
      immaturePerHour: p(200, 10, 100000),
      immaturePerDay: p(1000, 50, 1000000),
      absMinPerHour: p(20, 1, 100000),
      absMinPerDay: p(100, 1, 1000000),
      hourlyMultiplierPermille: p(3000, 1500, 20000),
      strongMultiplier: p(3, 2, 20),
      strongMinMessages: p(200, 10, 100000),
      strongWeight: p(40, 0, 100),
    },
    dedupe: { bucket: 'hour', subject: 'account' },
    baselineRelative: true,
    title: 'Outbound volume spike',
    explanation: '{count} messages within {windowMinutes} minutes (threshold {threshold})',
  }),
  rule({
    id: 'O2',
    code: 'ato.outbound.recipient_fanout',
    category: 'outbound_behaviour',
    strength: 'moderate',
    defaultWeight: 20,
    kinds: MAILBOX_CONNECTOR,
    sources: OUTBOUND,
    params: { minDomains: p(20, 5, 10000), baselineMultiplier: p(3, 2, 20) },
    dedupe: { bucket: 'hour', subject: 'account' },
    baselineRelative: true,
    title: 'Mail to an unusual number of external domains',
    explanation: 'Mail to {count} external domains within 60 minutes (threshold {threshold})',
  }),
  rule({
    id: 'O3',
    code: 'ato.outbound.new_recipient_domains',
    category: 'outbound_behaviour',
    strength: 'moderate',
    defaultWeight: 20,
    kinds: MAILBOX,
    sources: OUTBOUND,
    params: { minRecipients: p(20, 5, 10000), newSharePermille: p(800, 300, 1000) },
    dedupe: { bucket: 'hour', subject: 'account' },
    baselineRelative: true,
    title: 'Mail to never-contacted domains',
    explanation:
      '{permille} per mille of {count} external recipients within 60 minutes were in never-contacted domains',
  }),
  rule({
    id: 'O4',
    code: 'ato.outbound.attachment_spread',
    category: 'outbound_behaviour',
    strength: 'moderate',
    defaultWeight: 20,
    kinds: MAILBOX_CONNECTOR,
    sources: OUTBOUND,
    params: { minRecipients: p(20, 5, 10000), minDomains: p(5, 2, 1000) },
    dedupe: { bucket: 'day', subject: 'attachment hash' },
    title: 'One attachment sent widely',
    explanation:
      'One {attachmentType} attachment sent to {count} external recipients in {domainCount} domains within 60 minutes',
  }),
  rule({
    id: 'O5',
    code: 'ato.outbound.mass_subject',
    category: 'outbound_behaviour',
    strength: 'moderate',
    defaultWeight: 15,
    kinds: MAILBOX,
    sources: OUTBOUND,
    params: { minMessages: p(30, 5, 10000) },
    dedupe: { bucket: 'hour', subject: 'account' },
    title: 'Mass mailing with one subject',
    explanation: '{count} messages with the same subject within 60 minutes',
  }),
  rule({
    id: 'O6',
    code: 'ato.outbound.unusual_hour',
    category: 'outbound_behaviour',
    strength: 'weak',
    defaultWeight: 5,
    kinds: MAILBOX,
    sources: OUTBOUND,
    params: { minMessages: p(10, 2, 10000), maxSharePermille: p(20, 1, 200) },
    dedupe: { bucket: 'day', subject: 'account' },
    baselineRelative: true,
    title: 'Sending at an unusual hour',
    explanation: '{count} messages in a local hour holding {permille} per mille of usual sending',
  }),
  rule({
    id: 'O7',
    code: 'ato.outbound.new_client_ip',
    category: 'outbound_behaviour',
    strength: 'weak',
    defaultWeight: 8,
    kinds: MAILBOX_CONNECTOR,
    sources: ['outbound_message', 'smtp_submission'],
    dedupe: { bucket: 'day', subject: 'prefix' },
    baselineRelative: true,
    title: 'Mail submitted from a new network',
    explanation: 'Mail submitted from network {ipPrefix}, never used by this account',
  }),
  rule({
    id: 'O8',
    code: 'ato.outbound.connector_sender_spread',
    category: 'outbound_behaviour',
    strength: 'moderate',
    defaultWeight: 20,
    kinds: ['smtp_connector'],
    sources: ['smtp_submission'],
    params: { minSenders: p(20, 3, 10000), baselineMultiplier: p(3, 2, 20) },
    dedupe: { bucket: 'hour', subject: 'account' },
    title: 'Connector sending as many senders',
    explanation:
      'The connector sent as {count} different senders within 60 minutes (usual maximum {baseline})',
  }),
  rule({
    id: 'O9',
    code: 'ato.outbound.reply_without_parent',
    category: 'outbound_behaviour',
    strength: 'weak',
    defaultWeight: 8,
    kinds: MAILBOX,
    sources: OUTBOUND,
    params: { minReplies: p(5, 2, 1000) },
    dedupe: { bucket: 'hour', subject: 'account' },
    title: 'Replies to unknown conversations',
    explanation: '{count} replies within 60 minutes to messages unknown to the organization',
  }),
  rule({
    id: 'O10',
    code: 'ato.outbound.sender_identity_mismatch',
    category: 'outbound_behaviour',
    strength: 'weak',
    defaultWeight: 8,
    kinds: MAILBOX_CONNECTOR,
    sources: OUTBOUND,
    params: { minMessages: p(10, 2, 10000) },
    dedupe: { bucket: 'hour', subject: 'account' },
    baselineRelative: true,
    title: 'Header sender differs from envelope sender',
    explanation: '{count} messages within 60 minutes with a header From different from the sender',
  }),
  // ------------------------------------------------------------- outbound content
  rule({
    id: 'P1',
    code: 'ato.content.phishing_sent',
    category: 'outbound_content',
    strength: 'strong',
    defaultWeight: 45,
    kinds: MAILBOX_CONNECTOR,
    sources: OUTBOUND,
    dedupe: { bucket: 'event', subject: 'message' },
    title: 'Phishing sent from the account',
    explanation: 'An outbound message carried phishing indicators ({codes})',
  }),
  rule({
    id: 'P2',
    code: 'ato.content.malware_sent',
    category: 'outbound_content',
    strength: 'strong',
    defaultWeight: 50,
    kinds: MAILBOX_CONNECTOR,
    sources: OUTBOUND,
    dedupe: { bucket: 'event', subject: 'message' },
    title: 'Malware sent from the account',
    explanation: 'An outbound message carried a malicious attachment',
  }),
  rule({
    id: 'P3',
    code: 'ato.content.spam_sent',
    category: 'outbound_content',
    strength: 'moderate',
    defaultWeight: 20,
    kinds: MAILBOX_CONNECTOR,
    sources: OUTBOUND,
    params: { minSpam: p(3, 1, 1000) },
    dedupe: { bucket: 'hour', subject: 'account' },
    title: 'Spam sent from the account',
    explanation: '{count} outbound messages classified as spam within 60 minutes',
  }),
  rule({
    id: 'P4',
    code: 'ato.content.bec_language',
    category: 'outbound_content',
    strength: 'moderate',
    defaultWeight: 20,
    kinds: MAILBOX,
    sources: OUTBOUND,
    dedupe: { bucket: 'day', subject: 'category' },
    capabilities: ['bec_observations'],
    baselineRelative: true,
    title: 'Payment-fraud language sent',
    explanation:
      'Outbound mail with payment-fraud language ({categories}), unusual for the account',
  }),
  rule({
    id: 'P5',
    code: 'ato.content.financial_identifiers',
    category: 'outbound_content',
    strength: 'weak',
    defaultWeight: 10,
    kinds: MAILBOX,
    sources: OUTBOUND,
    dedupe: { bucket: 'day', subject: 'account' },
    baselineRelative: true,
    title: 'Financial identifiers sent',
    explanation: 'Outbound mail with financial identifiers, unusual for the account',
  }),
  // ------------------------------------------------------------- mailbox configuration (provider)
  rule({
    id: 'M1',
    code: 'ato.mailbox.external_forwarding',
    category: 'mailbox_configuration',
    strength: 'strong',
    defaultWeight: 45,
    kinds: MAILBOX,
    sources: PROVIDER,
    dedupe: { bucket: 'event', subject: 'target domain' },
    capabilities: ['provider:mailbox_audit'],
    title: 'External forwarding added',
    explanation: 'Mail forwarding to {domain}, a domain never contacted, was added',
  }),
  rule({
    id: 'M2',
    code: 'ato.mailbox.suspicious_inbox_rule',
    category: 'mailbox_configuration',
    strength: 'moderate',
    defaultWeight: 30,
    kinds: MAILBOX,
    sources: PROVIDER,
    dedupe: { bucket: 'event', subject: 'rule hash' },
    capabilities: ['provider:mailbox_audit'],
    title: 'Suspicious inbox rule',
    explanation: 'An inbox rule that hides or diverts mail was created ({codes})',
  }),
  rule({
    id: 'M3',
    code: 'ato.mailbox.delegation_added',
    category: 'mailbox_configuration',
    strength: 'moderate',
    defaultWeight: 20,
    kinds: MAILBOX,
    sources: PROVIDER,
    dedupe: { bucket: 'event', subject: 'delegate hash' },
    capabilities: ['provider:delegation_changes'],
    title: 'Mailbox delegation added',
    explanation: 'A delegate or full-access permission was added to the mailbox',
  }),
  rule({
    id: 'M4',
    code: 'ato.mailbox.unusual_access',
    category: 'mailbox_configuration',
    strength: 'moderate',
    defaultWeight: 20,
    kinds: MAILBOX,
    sources: PROVIDER,
    dedupe: { bucket: 'day', subject: 'account' },
    capabilities: ['provider:mailbox_audit'],
    title: 'Unusual mailbox access',
    explanation: 'The mailbox was accessed by another identity or an unusual client type',
  }),
  // ------------------------------------------------------------- OAuth (provider)
  rule({
    id: 'Q1',
    code: 'ato.oauth.risky_consent',
    category: 'oauth_activity',
    strength: 'moderate',
    defaultWeight: 25,
    kinds: MAILBOX,
    sources: PROVIDER,
    params: { strongWeight: p(40, 0, 100) },
    dedupe: { bucket: 'event', subject: 'app hash' },
    capabilities: ['provider:oauth_consents'],
    title: 'Risky OAuth consent',
    explanation: 'Consent granted to an application with mail access ({codes})',
  }),
  rule({
    id: 'Q2',
    code: 'ato.oauth.token_anomaly',
    category: 'oauth_activity',
    strength: 'moderate',
    defaultWeight: 20,
    kinds: MAILBOX,
    sources: PROVIDER,
    dedupe: { bucket: 'day', subject: 'account' },
    capabilities: ['provider:session_events'],
    title: 'Token anomaly reported by the provider',
    explanation: 'The identity provider reported a token anomaly',
  }),
  // ------------------------------------------------------------- provider risk
  rule({
    id: 'R1',
    code: 'ato.provider.risk_event',
    category: 'provider_risk',
    strength: 'strong',
    defaultWeight: 40,
    kinds: MAILBOX,
    sources: PROVIDER,
    params: { mediumWeight: p(25, 0, 100), lowWeight: p(10, 0, 100) },
    dedupe: { bucket: 'event', subject: 'provider event' },
    capabilities: ['provider:risk_events'],
    title: 'Identity provider risk detection',
    explanation: 'The identity provider ({provider}) reported a {action} risk detection',
  }),
  // ------------------------------------------------------------- correlation
  rule({
    id: 'X1',
    code: 'ato.correlation.login_then_outbound',
    category: 'correlation',
    strength: 'strong',
    defaultWeight: 40,
    kinds: MAILBOX,
    sources: [],
    params: { windowHours: p(24, 1, 72) },
    dedupe: { bucket: 'day', subject: 'account' },
    correlation: true,
    title: 'Suspicious sign-in followed by abnormal sending',
    explanation:
      'A suspicious sign-in ({codes}) was followed within {windowMinutes} minutes by abnormal outbound mail',
  }),
  rule({
    id: 'X2',
    code: 'ato.correlation.attack_then_change',
    category: 'correlation',
    strength: 'strong',
    defaultWeight: 45,
    kinds: ['gateway_user', 'smtp_connector'],
    sources: [],
    params: { windowMinutes: p(120, 30, 1440) },
    dedupe: { bucket: 'day', subject: 'account' },
    correlation: true,
    title: 'Attack, successful sign-in, then account change',
    explanation:
      'An authentication attack, a successful sign-in and an account change ({codes}) within {windowMinutes} minutes',
  }),
  rule({
    id: 'X3',
    code: 'ato.correlation.connector_compromise',
    category: 'correlation',
    strength: 'strong',
    defaultWeight: 45,
    kinds: ['smtp_connector'],
    sources: [],
    params: { windowMinutes: p(120, 30, 1440) },
    dedupe: { bucket: 'day', subject: 'account' },
    correlation: true,
    title: 'Connector sign-in anomaly followed by abuse',
    explanation:
      'A connector authentication anomaly was followed within {windowMinutes} minutes by abnormal outbound mail ({codes})',
  }),
  rule({
    id: 'X4',
    code: 'ato.correlation.multi_category',
    category: 'correlation',
    strength: 'moderate',
    defaultWeight: 20,
    kinds: ALL,
    sources: [],
    params: { minCategories: p(3, 2, 6), windowHours: p(24, 1, 72) },
    dedupe: { bucket: 'day', subject: 'account' },
    correlation: true,
    title: 'Evidence in several categories',
    explanation: 'Moderate or strong evidence in {count} categories within 24 hours ({categories})',
  }),
  rule({
    id: 'X5',
    code: 'ato.correlation.config_change_after_login',
    category: 'correlation',
    strength: 'strong',
    defaultWeight: 40,
    kinds: MAILBOX,
    sources: [],
    params: { windowHours: p(24, 1, 72) },
    dedupe: { bucket: 'day', subject: 'account' },
    correlation: true,
    title: 'Mailbox change after a suspicious sign-in',
    explanation: 'A suspicious sign-in was followed by a mailbox or consent change ({codes})',
  }),
]);

const BY_CODE: ReadonlyMap<string, RuleDefinition> = new Map(ATO_RULES.map((r) => [r.code, r]));

/** Every rule code of `ato-rules/1`. */
export const ATO_RULE_CODES: readonly string[] = ATO_RULES.map((r) => r.code);

/** The rule of a code, or undefined. */
export function ruleByCode(code: string): RuleDefinition | undefined {
  return BY_CODE.get(code);
}

/** Default parameters of a rule. */
export function ruleDefaults(rule: RuleDefinition): Record<string, number> {
  return Object.fromEntries(Object.entries(rule.params).map(([k, v]) => [k, v.default]));
}

/** Strict zod schema of a rule's tunable parameters (every key optional, integer within bounds). */
export function ruleParamsSchema(rule: RuleDefinition): z.ZodType<Record<string, number>> {
  const shape: Record<string, z.ZodOptional<z.ZodNumber>> = {};
  for (const [name, def] of Object.entries(rule.params)) {
    shape[name] = z.number().int().min(def.min).max(def.max).optional();
  }
  return z.strictObject(shape) as unknown as z.ZodType<Record<string, number>>;
}

/** Capabilities known to the platform at evaluation time (D17 `ato.worker.capabilities`). */
export interface CapabilitySet {
  has(capability: Capability): boolean;
}

/** A capability set from static flags and the provider streams of the account's integration. */
export function capabilitySet(
  flags: Partial<Record<StaticCapability, boolean>>,
  providerStreams: Iterable<string> = [],
): CapabilitySet {
  const streams = new Set(providerStreams);
  return {
    has(capability: Capability): boolean {
      if (capability.startsWith('provider:')) return streams.has(capability.slice(9));
      return flags[capability as StaticCapability] === true;
    },
  };
}

export type RuleAvailability =
  | { available: true }
  | { available: false; reason: 'capability_unavailable'; missing: Capability[] };

/** Whether every capability a rule requires is present. */
export function ruleAvailability(
  rule: RuleDefinition,
  capabilities: CapabilitySet,
): RuleAvailability {
  const missing = rule.capabilities.filter((c) => !capabilities.has(c));
  return missing.length === 0
    ? { available: true }
    : { available: false, reason: 'capability_unavailable', missing: [...missing] };
}
