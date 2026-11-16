import { makeMe, type SystemRoleKey } from '@/test';
import type {
  DlpCompliance,
  DlpDictionary,
  DlpExceptionRow,
  DlpPatternRow,
  DlpPolicyDetail,
  DlpPolicyRow,
  DlpRule,
  Executive,
  Suppression,
  TrustedSender,
  Vendor,
} from './model';

/** Synthetic rows of the DLP and BEC editor tests (`*.example.test`, invented ids). */

export const T = '2026-10-01T09:00:00.000Z';
export const FUTURE = '2027-01-15T23:59:59.000Z';
export const ADMIN = '01930000-0000-7000-8000-000000000101';

export const POLICY_ID = '01933c3a-1b2c-7d4e-8f00-0000000d0001';
export const RULE_ID = '01933c3a-1b2c-7d4e-8f00-0000000d0101';
export const PATTERN_ID = '01933c3a-1b2c-7d4e-8f00-0000000d0201';
export const DICTIONARY_ID = '01933c3a-1b2c-7d4e-8f00-0000000d0301';
export const EXCEPTION_ID = '01933c3a-1b2c-7d4e-8f00-0000000d0401';
export const EXECUTIVE_ID = '01933c3a-1b2c-7d4e-8f00-0000000be001';
export const VENDOR_ID = '01933c3a-1b2c-7d4e-8f00-0000000be101';
export const TRUSTED_ID = '01933c3a-1b2c-7d4e-8f00-0000000be201';
export const SUPPRESSION_ID = '01933c3a-1b2c-7d4e-8f00-0000000be301';

const audit = { createdByUserId: ADMIN, updatedByUserId: ADMIN, createdAt: T, updatedAt: T };

export function dlpPolicy(overrides: Partial<DlpPolicyRow> = {}): DlpPolicyRow {
  return {
    id: POLICY_ID,
    name: 'Payment cards outbound',
    description: null,
    enabled: true,
    mode: 'enforce',
    priority: 10,
    directions: ['outbound'],
    ruleCount: 1,
    version: 3,
    ...audit,
    ...overrides,
  };
}

export function dlpRule(overrides: Partial<DlpRule> = {}): DlpRule {
  return {
    id: RULE_ID,
    policyId: POLICY_ID,
    name: 'Block card numbers',
    enabled: true,
    priority: 10,
    conditions: {
      selectors: { categories: ['payment_card'] },
      recipients: { externalOnly: true },
    },
    action: 'block',
    version: 2,
    ...audit,
    ...overrides,
  };
}

export function dlpPolicyDetail(overrides: Partial<DlpPolicyDetail> = {}): DlpPolicyDetail {
  return { ...dlpPolicy(), rules: [dlpRule()], ...overrides };
}

export function dlpPattern(overrides: Partial<DlpPatternRow> = {}): DlpPatternRow {
  return {
    id: PATTERN_ID,
    name: 'Employee ID',
    pattern: 'EMP-[0-9]{6}',
    caseInsensitive: false,
    validator: 'none',
    contextKeywords: ['employee'],
    requireContext: false,
    severity: 'medium',
    baseConfidence: 0.8,
    maskStyle: 'last4',
    enabled: true,
    version: 2,
    ...audit,
    ...overrides,
  };
}

export function dlpDictionary(overrides: Partial<DlpDictionary> = {}): DlpDictionary {
  return {
    id: DICTIONARY_ID,
    name: 'Project names',
    category: 'confidential',
    terms: ['falcon roadmap', 'heron merger'],
    termCount: 2,
    severity: 'high',
    baseConfidence: 0.7,
    minMatches: 1,
    enabled: true,
    version: 4,
    ...audit,
    ...overrides,
  };
}

export function dlpDictionaryRow(overrides: Partial<DlpDictionary> = {}) {
  const { terms, ...row } = dlpDictionary(overrides);
  void terms;
  return row;
}

export function dlpException(overrides: Partial<DlpExceptionRow> = {}): DlpExceptionRow {
  return {
    id: EXCEPTION_ID,
    scope: 'recipient_domain',
    value: 'auditor.example.test',
    policyId: POLICY_ID,
    ruleId: null,
    filters: { categories: ['payment_card'] },
    reason: 'Auditors receive statements',
    expiresAt: FUTURE,
    expired: false,
    enabled: true,
    version: 5,
    ...audit,
    ...overrides,
  };
}

export function compliance(overrides: Partial<DlpCompliance['aadhaar']> = {}, version = 0) {
  return {
    aadhaar: {
      enabled: false,
      active: false,
      basis: null,
      reference: null,
      attested: false,
      recordedByUserId: null,
      recordedAt: null,
      reviewDueAt: null,
      ...overrides,
    },
    version,
    updatedAt: version ? T : null,
  } satisfies DlpCompliance;
}

export function executive(overrides: Partial<Executive> = {}): Executive {
  return {
    id: EXECUTIVE_ID,
    displayName: 'Dana Whitfield',
    normalizedName: 'dana whitfield',
    aliases: [],
    knownAddresses: ['ceo@alpha.example.test'],
    title: 'CEO',
    enabled: true,
    updatedByUserId: ADMIN,
    version: 1,
    createdByUserId: ADMIN,
    createdAt: T,
    updatedAt: T,
    ...overrides,
  };
}

export function vendor(overrides: Partial<Vendor> = {}): Vendor {
  return {
    id: VENDOR_ID,
    name: 'Bravo Logistics',
    normalizedName: 'bravo logistics',
    aliases: [],
    domains: ['bravo.example.test'],
    knownSenders: ['billing@bravo.example.test'],
    paymentChangeSensitive: true,
    enabled: true,
    updatedByUserId: ADMIN,
    version: 2,
    createdByUserId: ADMIN,
    createdAt: T,
    updatedAt: T,
    ...overrides,
  };
}

export function trustedSender(overrides: Partial<TrustedSender> = {}): TrustedSender {
  return {
    id: TRUSTED_ID,
    kind: 'domain',
    value: 'partner.example.test',
    reason: 'Long-standing partner',
    expiresAt: null,
    expired: false,
    version: 1,
    createdByUserId: ADMIN,
    createdAt: T,
    updatedAt: T,
    ...overrides,
  };
}

export function suppression(overrides: Partial<Suppression> = {}): Suppression {
  return {
    id: SUPPRESSION_ID,
    reasonCode: 'bec.content.urgency',
    senderScope: 'domain',
    senderValue: 'partner.example.test',
    expiresAt: FUTURE,
    expired: false,
    feedbackId: null,
    createdByUserId: ADMIN,
    createdAt: T,
    ...overrides,
  };
}

export const page = <Row>(rows: Row[]) => ({ data: rows, nextCursor: null });

/** A `GET /auth/me` of a role whose session was (or was not) signed in with MFA. */
export function meWithMfa(role: SystemRoleKey, mfaAuthenticated: boolean) {
  const me = makeMe({ role });
  return { ...me, session: { ...me.session, mfaAuthenticated } };
}

/** `YYYY-MM-DD` of today plus `days` (UTC). */
export function dayAhead(days: number): string {
  return new Date(Date.now() + days * 86_400_000).toISOString().slice(0, 10);
}
