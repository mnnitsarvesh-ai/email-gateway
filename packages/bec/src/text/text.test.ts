import { describe, expect, it } from 'vitest';
import { analyzeText, type TextInput } from './analyze';
import { BecTextTimeoutError, Deadline } from './deadline';
import { htmlToText } from './html';
import { Lexicon, LEXICON_CATEGORIES } from './lexicon';
import { normalizeForMatching, toSourceRange, wordTokens } from './normalize';
import { detectPatterns, ibanChecksumValid } from './patterns';

const lexicon = Lexicon.load();
const input = (text: string, over: Partial<TextInput> = {}): TextInput => ({
  subject: null,
  textBody: { content: text, truncated: false },
  htmlBody: null,
  parseIncomplete: false,
  ...over,
});
const analyze = (text: string, over: Partial<TextInput> = {}) =>
  analyzeText(input(text, over), lexicon, { maxChars: 40_000 });

describe('htmlToText', () => {
  it('keeps text nodes, drops script/style/head/template/noscript, decodes entities', () => {
    const r = htmlToText(
      '<html><head><title>T</title><style>p{}</style></head><body><script>alert(1)</script><noscript>ns</noscript><template>tp</template><p>Buy&nbsp;gift &amp; cards</p><div>next</div></body></html>',
    );
    expect(r.text).toBe('Buy\u00a0gift & cards\nnext\n');
    expect(r.incomplete).toBe(false);
  });
  it('inserts newlines at block elements and <br>', () => {
    expect(htmlToText('<p>a</p><p>b<br>c</p><li>d</li>').text).toBe('a\nb\nc\nd\n');
  });
  it('marks the result incomplete beyond the node bound', () => {
    const html = '<p>x</p>'.repeat(200);
    const r = htmlToText(html, { maxNodes: 50 });
    expect(r.incomplete).toBe(true);
  });
  it('handles deeply nested markup iteratively', () => {
    const html = '<div>'.repeat(5000) + 'deep' + '</div>'.repeat(5000);
    expect(htmlToText(html).text).toContain('deep');
  });
});

describe('normalizeForMatching', () => {
  it('maps every normalized unit back to the exact source range', () => {
    const source = 'Ｇｉｆｔ​  CARD — ﬁnal 😀 gіft';
    const n = normalizeForMatching(source);
    expect(n.text).toBe('gift card — final 😀 gift');
    expect(n.start).toHaveLength(n.text.length);
    for (const token of wordTokens(n.text)) {
      const range = toSourceRange(n, token.start, token.end);
      const back = source
        .slice(range.start, range.end)
        .normalize('NFKC')
        .replace(/\p{Cf}/gu, '')
        .toLowerCase();
      expect(back.length).toBeGreaterThan(0);
    }
    const last = wordTokens(n.text).at(-1)!;
    const range = toSourceRange(n, last.start, last.end);
    expect(source.slice(range.start, range.end)).toBe('gіft'); // Cyrillic і mapped by skeleton
  });
  it('leaves Devanagari untouched and skeletons Latin tokens only', () => {
    expect(normalizeForMatching('तुरंत भुगतान').text).toBe('तुरंत भुगतान');
    expect(normalizeForMatching('pаypal').text).toBe('paypal'); // Cyrillic а in a Latin token
  });
});

describe('lexicons', () => {
  it('meets the minimum sizes per language and category', () => {
    const count = (language: string, category: string) =>
      lexicon.entries.filter((e) => e.language === language && e.category === category).length;
    for (const category of LEXICON_CATEGORIES)
      expect(count('en', category)).toBeGreaterThanOrEqual(15);
    for (const category of [
      'payment_request',
      'bank_change',
      'gift_card',
      'wire_transfer',
      'urgency',
      'secrecy',
    ]) {
      expect(count('hi', category)).toBeGreaterThanOrEqual(5);
      expect(count('hi-Latn', category)).toBeGreaterThanOrEqual(5);
    }
    expect(lexicon.version).toMatch(/^[0-9a-f]{8}$/);
  });
  it('rejects duplicate ids and ids outside language/category', () => {
    const file = (entries: object[]) => JSON.stringify({ language: 'en', version: 1, entries });
    const ok = JSON.stringify({
      language: 'hi',
      version: 1,
      entries: [{ id: 'hi.urgency.001', category: 'urgency', phrase: 'तुरंत' }],
    });
    const okLatn = JSON.stringify({
      language: 'hi-Latn',
      version: 1,
      entries: [{ id: 'hi-Latn.urgency.001', category: 'urgency', phrase: 'turant' }],
    });
    const dup = { id: 'en.urgency.001', category: 'urgency', phrase: 'urgent' };
    expect(() => new Lexicon({ en: file([dup, dup]), hi: ok, 'hi-Latn': okLatn })).toThrow(
      /duplicate/,
    );
    expect(
      () =>
        new Lexicon({
          en: file([{ id: 'en.secrecy.001', category: 'urgency', phrase: 'x' }]),
          hi: ok,
          'hi-Latn': okLatn,
        }),
    ).toThrow(/does not match/);
  });
  it('matches English, Devanagari Hindi and Hinglish phrases with exact source spans', () => {
    const en = analyze('Please BUY gift-cards today, keep this between us.');
    expect(en.categories.gift_card.count).toBeGreaterThan(0);
    expect(en.categories.secrecy.lexiconIds[0]).toMatch(/^en\.secrecy\.\d{3}$/);
    const span = en.categories.secrecy.spans[0]!;
    expect('Please BUY gift-cards today, keep this between us.'.slice(span.start, span.end)).toBe(
      'keep this between us',
    );

    const hi = analyze('कृपया तुरंत भुगतान कर दो, किसी को मत बताना');
    expect(hi.categories.payment_request.languages).toEqual(['hi']);
    expect(hi.categories.urgency.count).toBe(1);
    expect(hi.categories.secrecy.count).toBe(1);

    const latn = analyze('boss ne bola hai turant paise transfer karo, kisi ko mat batana');
    expect(latn.categories.wire_transfer.languages).toEqual(['hi-Latn']);
    expect(latn.categories.urgency.count).toBe(1);
    expect(latn.categories.secrecy.count).toBe(1);
  });
  it('defeats Latin confusables (Cyrillic і in gіft card)', () => {
    const text = 'please send a gіft card now';
    const r = analyze(text);
    expect(r.categories.gift_card.count).toBe(1);
    const span = r.categories.gift_card.spans[0]!;
    expect(text.slice(span.start, span.end)).toBe('gіft card');
  });
  it('does not match phrases across sources and records the source', () => {
    const r = analyzeText(
      {
        subject: 'gift',
        textBody: { content: 'card', truncated: false },
        htmlBody: { content: '<p>urgent</p>', truncated: false },
        parseIncomplete: false,
      },
      lexicon,
      { maxChars: 1000 },
    );
    expect(r.categories.gift_card.count).toBe(0);
    expect(r.categories.urgency.spans[0]).toEqual({ source: 'html_text', start: 0, end: 6 });
  });
});

describe('analyzeText bounds and states', () => {
  it('caps matches (≤ 64 total, ≤ 16 per category, ≤ 5 spans)', () => {
    const r = analyze('urgent '.repeat(500) + ' gift card');
    expect(r.categories.urgency.count).toBe(16);
    expect(r.categories.urgency.spans).toHaveLength(5);
    expect(r.categories.gift_card.count).toBe(1);
    expect(r.matches.length).toBeLessThanOrEqual(64);
  });
  it('states: complete / absent / incomplete with reasons', () => {
    expect(analyze('hello').state).toBe('complete');
    expect(
      analyzeText(
        { subject: 'x', textBody: null, htmlBody: null, parseIncomplete: false },
        lexicon,
        { maxChars: 10 },
      ).state,
    ).toBe('absent');
    expect(analyze('hello', { parseIncomplete: true }).incompleteReasons).toEqual(['parse_limits']);
    expect(
      analyze('hello', { textBody: { content: 'hello', truncated: true } }).incompleteReasons,
    ).toEqual(['part_truncated']);
    const capped = analyzeText(input('a'.repeat(100)), lexicon, { maxChars: 10 });
    expect(capped).toMatchObject({
      state: 'incomplete',
      incompleteReasons: ['max_chars'],
      length: 10,
    });
    const nodes = analyzeText(
      {
        subject: null,
        textBody: null,
        htmlBody: { content: '<p>x</p>'.repeat(100), truncated: false },
        parseIncomplete: false,
      },
      lexicon,
      { maxChars: 1000, maxHtmlNodes: 20 },
    );
    expect(nodes.incompleteReasons).toEqual(['html_nodes']);
  });
  it('enforces the time budget', () => {
    let t = 0;
    const deadline = new Deadline(5, () => (t += 1));
    expect(() =>
      analyzeText(input('word '.repeat(5000)), lexicon, { maxChars: 40_000, deadline }),
    ).toThrow(BecTextTimeoutError);
  });
});

describe('pattern detectors', () => {
  it('IBAN mod-97 (valid / invalid), print form with spaces', () => {
    expect(ibanChecksumValid('DE89370400440532013000')).toBe(true);
    expect(ibanChecksumValid('DE89370400440532013001')).toBe(false);
    expect(detectPatterns('IBAN: DE89 3704 0044 0532 0130 00 thanks').iban).toBe(1);
    expect(detectPatterns('IBAN GB82WEST12345698765432.').iban).toBe(1);
    expect(detectPatterns('IBAN: DE89 3704 0044 0532 0130 01').iban).toBe(0);
  });
  it('SWIFT/BIC needs a context word within 5 tokens', () => {
    expect(detectPatterns('SWIFT code: DEUTDEFF500').swift).toBe(1);
    expect(detectPatterns('Our BIC is HDFCINBB').swift).toBe(1);
    expect(detectPatterns('PAYMENTS DEPARTMENT').swift).toBe(0);
  });
  it('IFSC with an account number nearby', () => {
    expect(detectPatterns('A/c 123456789012 IFSC HDFC0001234').ifscAccount).toBe(1);
    expect(detectPatterns('IFSC HDFC0001234 only').ifscAccount).toBe(0);
  });
  it('amounts with a currency', () => {
    expect(
      detectPatterns('pay ₹50,000 or Rs. 12000 or INR 5000 or $48,500 or 300 USD or €20').amount,
    ).toBe(6);
    expect(detectPatterns('call me at 5 pm').amount).toBe(0);
  });
  it('is linear on adversarial input', () => {
    const started = performance.now();
    detectPatterns('DE89'.repeat(10_000));
    detectPatterns('AAAAAAAA '.repeat(5000) + 'swift');
    expect(performance.now() - started).toBeLessThan(2000);
  });
});
