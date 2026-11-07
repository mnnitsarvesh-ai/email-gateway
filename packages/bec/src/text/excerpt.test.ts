import { describe, expect, it } from 'vitest';
import { analyzeText } from './analyze';
import {
  buildExcerpt,
  EXCERPT_SEPARATOR,
  mapExcerptSpan,
  REDACTION_PLACEHOLDERS,
  type RedactionContext,
} from './excerpt';
import { Lexicon } from './lexicon';

const lexicon = Lexicon.load();
const context: RedactionContext = {
  executiveNames: ['Zorawar Quixley', 'Z Quixley'],
  vendorNames: ['Blorptek Industries'],
  tenantLabels: ['acmecorp'],
};
const analysis = (text: string, subject: string | null = null) =>
  analyzeText(
    {
      subject,
      textBody: { content: text, truncated: false },
      htmlBody: null,
      parseIncomplete: false,
    },
    lexicon,
    {
      maxChars: 40_000,
    },
  );

const MARKERS = [
  'mrkaddr7f3k',
  'mrkdom9z1',
  'mrkurl4q2',
  '998877665544',
  '4111 1111 1111 1111',
  '98765',
  'Zorawar',
  'Quixley',
  'Blorptek',
  'acmecorp',
  'DE89370400440532013000',
  'HDFC0001234',
  'DEUTDEFF500',
];

describe('buildExcerpt redaction', () => {
  const text =
    'Hi, this is Zorawar Quixley from acmecorp, call +91 98765 43210 or (022) 2345-6789. Please buy gift cards today and keep this confidential. ' +
    'Send them to mrkaddr7f3k@mrkdom9z1.example or open https://mrkurl4q2.example/login and mrkdom9z1.example. ' +
    'Account 998877665544, IBAN DE89370400440532013000, IFSC HDFC0001234, SWIFT DEUTDEFF500, card 4111 1111 1111 1111. ' +
    'Our vendor Blorptek Industries is waiting. Quixley. Also update my direct deposit.';
  const a = analysis(text, 'Urgent: Zorawar needs 4000 gift cards at mrkaddr7f3k@x.example');
  const excerpt = buildExcerpt(a, context, 1500);

  it('never lets addresses, URLs, digits, phones, profile names or tenant labels through', () => {
    const all = `${excerpt.subject}\n${excerpt.text}`;
    for (const marker of MARKERS) expect(all).not.toContain(marker);
    expect(all).not.toMatch(/\d{4}/);
    for (const placeholder of [
      '[EMAIL]',
      '[URL]',
      '[NUMBER]',
      '[PHONE]',
      '[EXECUTIVE]',
      '[VENDOR]',
      '[ORG]',
    ]) {
      expect(excerpt.text).toContain(placeholder);
    }
    expect(excerpt.redactions.email).toBeGreaterThanOrEqual(1);
    expect(excerpt.redactions.phone).toBeGreaterThanOrEqual(1);
    expect(excerpt.subject).toContain('[EXECUTIVE]');
  });

  it('applies the replacement order: e-mail before URL (an address is one [EMAIL])', () => {
    expect(excerpt.text).toContain('Send them to [EMAIL] or open [URL]');
  });

  it('maps excerpt spans back to exact source offsets through the window map', () => {
    const at = excerpt.text.indexOf('gift cards');
    const span = mapExcerptSpan(excerpt, at, at + 'gift cards'.length)!;
    expect(span.source).toBe('text');
    expect(text.slice(span.start, span.end)).toBe('gift cards');
    const ph = excerpt.text.indexOf(REDACTION_PLACEHOLDERS.email);
    const mapped = mapExcerptSpan(excerpt, ph, ph + REDACTION_PLACEHOLDERS.email.length)!;
    expect(text.slice(mapped.start, mapped.end)).toBe('mrkaddr7f3k@mrkdom9z1.example');
    expect(mapExcerptSpan(excerpt, 5, 5)).toBeNull();
    expect(mapExcerptSpan(excerpt, 0, excerpt.text.length + 1)).toBeNull();
  });
});

describe('buildExcerpt non-ASCII digits', () => {
  it('redacts digit runs of any script (Devanagari digits)', () => {
    const text = 'तुरंत भुगतान कर दो, खाता ९८७६५४३२१० में, किसी को मत बताना';
    const excerpt = buildExcerpt(analysis(text), context, 1500);
    expect(excerpt.text).not.toMatch(/\p{Nd}{4}/u);
    expect(excerpt.text).toContain('[NUMBER]');
  });
});

describe('buildExcerpt windows', () => {
  const filler = (n: number) => 'lorem ipsum dolor sit amet '.repeat(n);
  const text = `${filler(40)}please buy gift cards ${filler(40)}update my direct deposit ${filler(40)}keep this confidential ${filler(40)}urgent ${filler(40)}`;
  const a = analysis(text);

  it('takes ≤ 3 windows of ±200 characters around the strongest matches, in source order', () => {
    const excerpt = buildExcerpt(
      a,
      { executiveNames: [], vendorNames: [], tenantLabels: [] },
      1500,
    );
    const windows = new Set(
      excerpt.segments.filter((s) => s.kind !== 'separator').map((s) => s.window),
    );
    expect(windows.size).toBe(3);
    expect(excerpt.text.split(EXCERPT_SEPARATOR)).toHaveLength(3);
    expect(excerpt.text).toContain('gift cards');
    expect(excerpt.text).toContain('direct deposit');
    expect(excerpt.text).toContain('confidential');
    expect(excerpt.text).not.toContain('urgent'); // weakest category, 4th window
    for (const s of excerpt.segments.filter((x) => x.kind === 'text')) {
      expect(s.sourceEnd - s.sourceStart).toBeLessThanOrEqual(2 * 200 + 30);
    }
  });

  it('respects the total character budget', () => {
    const excerpt = buildExcerpt(a, { executiveNames: [], vendorNames: [], tenantLabels: [] }, 500);
    expect(excerpt.text.length).toBeLessThanOrEqual(500);
    expect(excerpt.truncated).toBe(true);
  });

  it('falls back to the first 600 characters when nothing matched; subject ≤ 200', () => {
    const plain = analysis(filler(100), 's'.repeat(400));
    const excerpt = buildExcerpt(
      plain,
      { executiveNames: [], vendorNames: [], tenantLabels: [] },
      1500,
    );
    expect(excerpt.text.length).toBe(600);
    expect(excerpt.subject!.length).toBe(200);
  });

  it('returns an empty excerpt without body text', () => {
    const none = analyzeText(
      { subject: null, textBody: null, htmlBody: null, parseIncomplete: false },
      lexicon,
      { maxChars: 10 },
    );
    const excerpt = buildExcerpt(none, context, 1500);
    expect(excerpt).toMatchObject({ subject: null, text: '', segments: [] });
  });
});
