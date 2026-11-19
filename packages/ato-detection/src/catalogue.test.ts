import { describe, expect, it } from 'vitest';
import {
  ATO_RULE_CODES,
  ATO_RULES,
  capabilitySet,
  ruleAvailability,
  ruleByCode,
  ruleDefaults,
  ruleParamsSchema,
} from './rules/catalogue';

/** The D10 table: id, code, category, strength, default weight. */
const D10: ReadonlyArray<[string, string, string, string, number]> = [
  ['A1', 'ato.auth.bruteforce', 'authentication', 'moderate', 20],
  ['A2', 'ato.auth.success_after_failures', 'authentication', 'moderate', 30],
  ['A3', 'ato.auth.mfa_failures', 'authentication', 'moderate', 30],
  ['A4', 'ato.auth.lockout', 'authentication', 'weak', 8],
  ['C1', 'ato.access.new_ip_prefix', 'access_context', 'weak', 8],
  ['C2', 'ato.access.new_asn', 'access_context', 'weak', 10],
  ['C3', 'ato.access.new_device', 'access_context', 'weak', 10],
  ['C4', 'ato.access.unusual_hour', 'access_context', 'weak', 5],
  ['C5', 'ato.access.channel_change', 'access_context', 'weak', 5],
  ['C6', 'ato.access.concurrent_ips', 'access_context', 'moderate', 20],
  ['G1', 'ato.geo.new_country', 'geography', 'weak', 12],
  ['G2', 'ato.geo.impossible_travel', 'geography', 'moderate', 30],
  ['G3', 'ato.geo.inconsistent_sessions', 'geography', 'moderate', 20],
  ['G4', 'ato.geo.anonymizer', 'geography', 'weak', 10],
  ['T1', 'ato.ti.malicious_ip_success', 'threat_intel', 'strong', 45],
  ['T2', 'ato.ti.dnsbl_listed_success', 'threat_intel', 'moderate', 20],
  ['T3', 'ato.ti.attack_source_success', 'threat_intel', 'strong', 45],
  ['T4', 'ato.ti.breach_listed', 'threat_intel', 'weak', 10],
  ['T5', 'ato.ti.targeted_by_campaign', 'threat_intel', 'weak', 5],
  ['T6', 'ato.ti.malicious_ip_attempt', 'threat_intel', 'weak', 5],
  ['K1', 'ato.account.refresh_token_reuse', 'account_change', 'strong', 50],
  ['K2', 'ato.account.mfa_disabled', 'account_change', 'weak', 10],
  ['K3', 'ato.account.credentials_changed', 'account_change', 'weak', 5],
  ['K4', 'ato.account.persistence_created', 'account_change', 'weak', 10],
  ['K5', 'ato.account.privilege_change', 'account_change', 'weak', 10],
  ['K6', 'ato.account.bulk_data_access', 'account_change', 'moderate', 20],
  ['O1', 'ato.outbound.volume_spike', 'outbound_behaviour', 'moderate', 25],
  ['O2', 'ato.outbound.recipient_fanout', 'outbound_behaviour', 'moderate', 20],
  ['O3', 'ato.outbound.new_recipient_domains', 'outbound_behaviour', 'moderate', 20],
  ['O4', 'ato.outbound.attachment_spread', 'outbound_behaviour', 'moderate', 20],
  ['O5', 'ato.outbound.mass_subject', 'outbound_behaviour', 'moderate', 15],
  ['O6', 'ato.outbound.unusual_hour', 'outbound_behaviour', 'weak', 5],
  ['O7', 'ato.outbound.new_client_ip', 'outbound_behaviour', 'weak', 8],
  ['O8', 'ato.outbound.connector_sender_spread', 'outbound_behaviour', 'moderate', 20],
  ['O9', 'ato.outbound.reply_without_parent', 'outbound_behaviour', 'weak', 8],
  ['O10', 'ato.outbound.sender_identity_mismatch', 'outbound_behaviour', 'weak', 8],
  ['P1', 'ato.content.phishing_sent', 'outbound_content', 'strong', 45],
  ['P2', 'ato.content.malware_sent', 'outbound_content', 'strong', 50],
  ['P3', 'ato.content.spam_sent', 'outbound_content', 'moderate', 20],
  ['P4', 'ato.content.bec_language', 'outbound_content', 'moderate', 20],
  ['P5', 'ato.content.financial_identifiers', 'outbound_content', 'weak', 10],
  ['M1', 'ato.mailbox.external_forwarding', 'mailbox_configuration', 'strong', 45],
  ['M2', 'ato.mailbox.suspicious_inbox_rule', 'mailbox_configuration', 'moderate', 30],
  ['M3', 'ato.mailbox.delegation_added', 'mailbox_configuration', 'moderate', 20],
  ['M4', 'ato.mailbox.unusual_access', 'mailbox_configuration', 'moderate', 20],
  ['Q1', 'ato.oauth.risky_consent', 'oauth_activity', 'moderate', 25],
  ['Q2', 'ato.oauth.token_anomaly', 'oauth_activity', 'moderate', 20],
  ['R1', 'ato.provider.risk_event', 'provider_risk', 'strong', 40],
  ['X1', 'ato.correlation.login_then_outbound', 'correlation', 'strong', 40],
  ['X2', 'ato.correlation.attack_then_change', 'correlation', 'strong', 45],
  ['X3', 'ato.correlation.connector_compromise', 'correlation', 'strong', 45],
  ['X4', 'ato.correlation.multi_category', 'correlation', 'moderate', 20],
  ['X5', 'ato.correlation.config_change_after_login', 'correlation', 'strong', 40],
];

describe('ato-rules/1 catalogue', () => {
  it('holds exactly the D10 rules with their category, strength and default weight', () => {
    expect(ATO_RULES.map((r) => [r.id, r.code, r.category, r.strength, r.defaultWeight])).toEqual(
      D10,
    );
    expect(new Set(ATO_RULE_CODES).size).toBe(ATO_RULES.length);
  });

  it('every rule has a title, an explanation, kinds and a dedupe definition', () => {
    for (const r of ATO_RULES) {
      expect(r.title.length).toBeGreaterThan(0);
      expect(r.explanation.length).toBeGreaterThan(0);
      expect(r.kinds.length).toBeGreaterThan(0);
      expect(r.defaultWeight).toBeGreaterThanOrEqual(0);
      expect(r.defaultWeight).toBeLessThanOrEqual(100);
      expect(['hour', 'day', 'week', 'month', 'event']).toContain(r.dedupe.bucket);
      expect(r.correlation).toBe(r.category === 'correlation');
      for (const p of Object.values(r.params)) {
        expect(p.default).toBeGreaterThanOrEqual(p.min);
        expect(p.default).toBeLessThanOrEqual(p.max);
      }
    }
  });

  it('baseline-relative rules are those of D9', () => {
    expect(ATO_RULES.filter((r) => r.baselineRelative).map((r) => r.id)).toEqual([
      'C1',
      'C2',
      'C3',
      'C4',
      'C5',
      'G1',
      'O1',
      'O2',
      'O3',
      'O6',
      'O7',
      'O10',
      'P4',
      'P5',
    ]);
  });

  it('capabilities and availability', () => {
    expect(ruleByCode('ato.geo.new_country')!.capabilities).toEqual(['geoip_city']);
    expect(ruleByCode('ato.access.new_asn')!.capabilities).toEqual(['geoip_asn']);
    expect(ruleByCode('ato.geo.anonymizer')!.capabilities).toEqual(['geoip_anonymous']);
    expect(ruleByCode('ato.ti.dnsbl_listed_success')!.capabilities).toEqual(['dnsbl']);
    expect(ruleByCode('ato.ti.breach_listed')!.capabilities).toEqual(['breach_intel']);
    expect(ruleByCode('ato.content.bec_language')!.capabilities).toEqual(['bec_observations']);
    expect(ruleByCode('ato.mailbox.external_forwarding')!.capabilities).toEqual([
      'provider:mailbox_audit',
    ]);
    const none = capabilitySet({});
    expect(ruleAvailability(ruleByCode('ato.geo.new_country')!, none)).toEqual({
      available: false,
      reason: 'capability_unavailable',
      missing: ['geoip_city'],
    });
    expect(
      ruleAvailability(ruleByCode('ato.geo.new_country')!, capabilitySet({ geoip_city: true })),
    ).toEqual({ available: true });
    expect(
      ruleAvailability(
        ruleByCode('ato.mailbox.external_forwarding')!,
        capabilitySet({}, ['mailbox_audit']),
      ).available,
    ).toBe(true);
    expect(ruleAvailability(ruleByCode('ato.auth.bruteforce')!, none).available).toBe(true);
  });

  it('params schemas are strict and bounded', () => {
    const a1 = ruleByCode('ato.auth.bruteforce')!;
    expect(ruleDefaults(a1)).toEqual({ failures: 10, windowMinutes: 15 });
    expect(ruleParamsSchema(a1).safeParse({ failures: 10 }).success).toBe(true);
    expect(ruleParamsSchema(a1).safeParse({ failures: 2 }).success).toBe(false);
    expect(ruleParamsSchema(a1).safeParse({ failures: 10.5 }).success).toBe(false);
    expect(ruleParamsSchema(a1).safeParse({ other: 1 }).success).toBe(false);
  });
});
