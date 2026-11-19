import { describe, expect, it } from 'vitest';
import { loadBecStaticData } from '../static-data';
import { Deadline } from '../text/deadline';
import {
  evaluateOutboundObservations,
  OUTBOUND_OBSERVATION_CATEGORIES,
  OUTBOUND_OBSERVATIONS_VERSION,
  outboundLinkFlags,
  unavailableOutboundObservations,
} from './outbound-observations';
import type { BecUrlInput } from './types';

const data = loadBecStaticData();
const options = { maxChars: 40_000 };
const text = (body: string, subject: string | null = null) => ({
  subject,
  textBody: { content: body, truncated: false },
  htmlBody: null,
  parseIncomplete: false,
});
const noUrls: BecUrlInput = { state: 'available', rows: [] };

describe('evaluateOutboundObservations (step 8.4 D6)', () => {
  it('counts the intent categories and financial identifiers; counts and booleans only', () => {
    const result = evaluateOutboundObservations(
      {
        text: text(
          'Buy gift cards please. Make the payment today, this is urgent. Keep this confidential. ' +
            'Verify your account now. IBAN DE89 3704 0044 0532 0130 00, amount €2,500',
          'Updated invoice',
        ),
        url: noUrls,
      },
      data.lexicon,
      options,
    );
    expect(result.version).toBe(OUTBOUND_OBSERVATIONS_VERSION);
    expect(result.status).toBe('complete');
    expect(result.reason).toBeNull();
    expect(Object.keys(result.categories)).toEqual([...OUTBOUND_OBSERVATION_CATEGORIES]);
    expect(result.categories.gift_card).toBeGreaterThanOrEqual(1);
    expect(result.categories.urgency).toBeGreaterThanOrEqual(1);
    expect(result.categories.secrecy).toBeGreaterThanOrEqual(1);
    expect(result.categories.credential_request).toBeGreaterThanOrEqual(1);
    expect(result.categories.invoice_change).toBeGreaterThanOrEqual(1);
    expect(result.financialIdentifiers).toMatchObject({ iban: 1, amount: 1 });
    // No text, spans or lexicon ids anywhere.
    const json = JSON.stringify(result);
    expect(json).not.toMatch(/gift cards|keep this|DE89|lexicon|"start"|"end"|"spans"/i);
  });

  it('is all zeros for neutral text and deterministic', () => {
    const input = { text: text('Meeting at 10 in room 4.'), url: noUrls };
    const a = evaluateOutboundObservations(input, data.lexicon, options);
    expect(Object.values(a.categories).every((n) => n === 0)).toBe(true);
    expect(a.links).toEqual({
      credentialHarvesting: false,
      credentialForm: false,
      lookalike: false,
      malicious: false,
    });
    expect(evaluateOutboundObservations(input, data.lexicon, options)).toEqual(a);
  });

  it('derives link flags from the round URL results like inbound K1–K4', () => {
    expect(
      outboundLinkFlags([
        { urlSeq: 1, verdict: 'suspicious', reasonCodes: ['url.credential_form'] },
        { urlSeq: 2, verdict: 'clean', reasonCodes: ['url.lookalike_brand'] },
      ]),
    ).toEqual({
      credentialHarvesting: false,
      credentialForm: true,
      lookalike: true,
      malicious: false,
    });
    expect(
      outboundLinkFlags([
        { urlSeq: 1, verdict: 'malicious', reasonCodes: ['url.phishing_high_confidence'] },
      ]),
    ).toMatchObject({ credentialHarvesting: true, malicious: true });
    expect(
      outboundLinkFlags([
        {
          urlSeq: 1,
          verdict: 'suspicious',
          reasonCodes: ['url.credential_form_cross_origin', 'url.mixed_script'],
        },
      ]),
    ).toMatchObject({ credentialHarvesting: true, credentialForm: true, lookalike: true });
  });

  it('is incomplete when text was cut or URL results are missing (first reason reported)', () => {
    const cut = evaluateOutboundObservations(
      {
        text: {
          ...text('Make the payment.'),
          textBody: { content: 'Make the payment.', truncated: true },
        },
        url: { state: 'failed' },
      },
      data.lexicon,
      options,
    );
    expect(cut.status).toBe('incomplete');
    expect(cut.reason).toBe('text_part_truncated');
    const noUrl = evaluateOutboundObservations(
      { text: text('Hello'), url: { state: 'not_in_round' } },
      data.lexicon,
      options,
    );
    expect(noUrl).toMatchObject({ status: 'incomplete', reason: 'url_unavailable' });
  });

  it('throws on an expired deadline (the caller records unavailable/timeout)', () => {
    expect(() =>
      evaluateOutboundObservations({ text: text('Make the payment.'), url: noUrls }, data.lexicon, {
        ...options,
        deadline: Deadline.after(-1),
      }),
    ).toThrow();
  });

  it('unavailable observations carry zero counts and the reason', () => {
    expect(unavailableOutboundObservations('read_failed')).toMatchObject({
      status: 'unavailable',
      reason: 'read_failed',
      financialIdentifiers: { iban: 0, swift: 0, ifsc_account: 0, amount: 0 },
    });
  });
});
