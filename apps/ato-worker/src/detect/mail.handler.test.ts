import { describe, expect, it } from 'vitest';
import { bareAddress, outboundFindings } from './mail.handler';

const none = {
  reasonCodes: [],
  verdict: 'clean',
  hardBlocks: [],
  dlpCategories: [],
  observations: null,
};

describe('outboundFindings (D6, P1–P5)', () => {
  it('phishing from Rspamd, URL codes, the known-phishing hard block and BEC link flags', () => {
    expect(outboundFindings(none)).toEqual({
      phishing: false,
      phishingCodes: [],
      malware: false,
      spam: false,
      becCategories: null,
      financial: false,
    });
    const f = outboundFindings({
      ...none,
      reasonCodes: ['phishing.known_bad_url', 'url.phishing_high_confidence', 'url.new_domain'],
      hardBlocks: [{ id: 'hb.known_phishing', verdict: 'phishing', action: 'quarantine' }],
      observations: {
        status: 'complete',
        categories: {},
        links: { credentialHarvesting: true, malicious: false },
      },
    });
    expect(f.phishing).toBe(true);
    expect(f.phishingCodes).toEqual([
      'bec.link_credential_harvesting',
      'hb.known_phishing',
      'phishing.known_bad_url',
      'url.phishing_high_confidence',
    ]);
  });

  it('malware from the attachment code or a malware hard block; spam from the verdict', () => {
    expect(outboundFindings({ ...none, reasonCodes: ['attachment.malware'] }).malware).toBe(true);
    expect(outboundFindings({ ...none, hardBlocks: [{ id: 'hb.malware_sandbox' }] }).malware).toBe(
      true,
    );
    expect(outboundFindings({ ...none, verdict: 'spam' }).spam).toBe(true);
    expect(outboundFindings({ ...none, reasonCodes: ['spam.score'] }).spam).toBe(true);
    expect(outboundFindings({ ...none, reasonCodes: ['spam.suspicious_score'] }).spam).toBe(false);
  });

  it('BEC categories (counts > 0) unless observations are unavailable; financial identifiers', () => {
    const obs = {
      status: 'complete',
      categories: { bank_change: 2, urgency: 1, gift_card: 0 },
      financialIdentifiers: { iban: 1, swift: 0, ifsc_account: 0, amount: 4 },
      links: {},
    };
    const f = outboundFindings({ ...none, observations: obs });
    expect(f.becCategories).toEqual(['bank_change', 'urgency']);
    expect(f.financial).toBe(true);
    expect(
      outboundFindings({ ...none, observations: { ...obs, status: 'unavailable' } }).becCategories,
    ).toBeNull();
    const amountOnly = {
      ...obs,
      financialIdentifiers: { iban: 0, swift: 0, ifsc_account: 0, amount: 9 },
    };
    expect(outboundFindings({ ...none, observations: amountOnly }).financial).toBe(false);
    expect(
      outboundFindings({ ...none, dlpCategories: [{ category: 'bank_account', count: 1 }] })
        .financial,
    ).toBe(true);
    expect(
      outboundFindings({ ...none, dlpCategories: [{ category: 'source_code', count: 3 }] })
        .financial,
    ).toBe(false);
  });
});

describe('bareAddress', () => {
  it('extracts and lower-cases the address of a From value', () => {
    expect(bareAddress('Jane <Jane@Example.TEST>')).toBe('jane@example.test');
    expect(bareAddress('a@b.test')).toBe('a@b.test');
    expect(bareAddress('')).toBeNull();
    expect(bareAddress('<>')).toBeNull();
    expect(bareAddress(null)).toBeNull();
  });
});
