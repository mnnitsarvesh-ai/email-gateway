import { describe, expect, it } from 'vitest';
import { MAX_PHRASE_TOKENS, PhraseTrie, phraseTokens } from '../context/trie';
import { DLP_DICTIONARY_FILES, readDataFile } from '../data';
import {
  DlpDictionarySet,
  builtInDictionaries,
  checkDictionaryTerms,
  parseBuiltInDictionaries,
  type TenantDictionaryInput,
} from './index';

const files = () =>
  Object.fromEntries(
    DLP_DICTIONARY_FILES.map((n) => [n, readDataFile('dictionaries', n)]),
  ) as Record<(typeof DLP_DICTIONARY_FILES)[number], string>;

const tenant = (overrides: Partial<TenantDictionaryInput> = {}): TenantDictionaryInput => ({
  id: '0196f3a0-0000-7000-8000-000000000001',
  version: 1,
  category: 'confidential',
  terms: ['Project Nightingale'],
  severity: 'high',
  baseConfidence: 0.7,
  minMatches: 1,
  ...overrides,
});

describe('built-in dictionaries (D8)', () => {
  it('load en, hi and hi-Latn entries for every dictionary with stable ids', () => {
    const built = builtInDictionaries();
    for (const kind of ['label', 'business', 'financial', 'context', 'negative'] as const) {
      const ids = built.entries.filter((e) => e.payload.kind === kind).map((e) => e.id);
      expect(
        ids.some((id) => id.startsWith('en.')),
        kind,
      ).toBe(true);
      expect(
        ids.some((id) => id.startsWith('hi.')),
        kind,
      ).toBe(true);
      expect(
        ids.some((id) => id.startsWith('hi-Latn.')),
        kind,
      ).toBe(true);
    }
    expect(built.version).toMatch(/^[0-9a-f]{8}$/);
    expect(built.byId.get('en.labels.001')?.phrase).toBe('confidential');
  });

  it('versions by SHA-256: a change of any file changes the version', () => {
    const base = parseBuiltInDictionaries(files());
    const changed = files();
    changed['labels.json'] = changed['labels.json'].replace(
      '"strictly confidential"',
      '"very confidential"',
    );
    expect(parseBuiltInDictionaries(changed).version).not.toBe(base.version);
  });

  it('refuses duplicate ids, bad ids and phrases over 8 tokens', () => {
    const dup = files();
    dup['labels.json'] = dup['labels.json'].replace('"en.labels.002"', '"en.labels.001"');
    expect(() => parseBuiltInDictionaries(dup)).toThrow(/duplicate/);
    const bad = files();
    bad['business.json'] = bad['business.json'].replace('"en.business.001"', '"en.wrong.001"');
    expect(() => parseBuiltInDictionaries(bad)).toThrow();
    const long = files();
    long['labels.json'] = long['labels.json'].replace(
      '"strictly confidential"',
      '"a b c d e f g h i"',
    );
    expect(() => parseBuiltInDictionaries(long)).toThrow(/1..8 tokens/);
  });
});

describe('phrase trie on the bec normalization', () => {
  const trie = new PhraseTrie<string>();
  trie.add(phraseTokens('term sheet'), 'ts');
  trie.add(phraseTokens('ग्राहक सूची'), 'hi');
  trie.add(phraseTokens('grahak suchi'), 'hinglish');

  it('matches through case, NFKC, zero-width and confusables and maps back to source offsets', () => {
    for (const text of [
      'TERM SHEET',
      'ｔｅｒｍ ｓｈｅｅｔ',
      'te​rm  sheet',
      'tеrm sheet' /* Cyrillic е */,
    ]) {
      const matches = trie.match(`see ${text}.`, 10);
      expect(
        matches.map((m) => m.payload),
        text,
      ).toEqual(['ts']);
      expect(`see ${text}.`.slice(matches[0]!.start, matches[0]!.end).replace(/\s+/g, ' ')).toMatch(
        /sheet|ｓｈｅｅｔ/i,
      );
    }
  });

  it('matches Devanagari and Hinglish phrases', () => {
    expect(trie.match('कृपया ग्राहक सूची भेजें', 10).map((m) => m.payload)).toEqual(['hi']);
    expect(trie.match('Grahak Suchi bhejo', 10).map((m) => m.payload)).toEqual(['hinglish']);
  });

  it('bounds phrases to 8 tokens and matches to the cap', () => {
    expect(() => phraseTokens('one two three four five six seven eight nine')).toThrow();
    expect(phraseTokens('one two three four five six seven eight')).toHaveLength(MAX_PHRASE_TOKENS);
    expect(trie.match('term sheet '.repeat(100), 7)).toHaveLength(7);
    expect(() => trie.add([], 'x')).toThrow();
  });
});

describe('tenant dictionaries (DC1)', () => {
  it('validates terms: count, length, tokens, duplicates after normalization', () => {
    expect(checkDictionaryTerms([], 10)).toEqual({ ok: false, code: 'dictionary_terms_count' });
    expect(checkDictionaryTerms(['a', 'b', 'c'], 2)).toEqual({
      ok: false,
      code: 'dictionary_terms_count',
    });
    expect(checkDictionaryTerms(['x'.repeat(65)], 10)).toMatchObject({ ok: false, index: 0 });
    expect(checkDictionaryTerms(['ok', '...'], 10)).toMatchObject({ ok: false, index: 1 });
    expect(checkDictionaryTerms(['Falcon', 'FALCON'], 10)).toMatchObject({ ok: false, index: 1 });
    expect(checkDictionaryTerms(['a b c d e f g h i'], 10)).toMatchObject({ ok: false });
    expect(checkDictionaryTerms(['Project Nightingale', 'ग्राहक सूची'], 10)).toMatchObject({
      ok: true,
    });
  });

  it('compiles with the built-ins into one trie; invalid rows are skipped by id', () => {
    const set = DlpDictionarySet.create([
      tenant(),
      tenant({ id: '0196f3a0-0000-7000-8000-000000000002', terms: [] }),
    ]);
    expect(set.tenant.map((d) => d.id)).toEqual(['0196f3a0-0000-7000-8000-000000000001']);
    expect(set.invalid).toEqual(['0196f3a0-0000-7000-8000-000000000002']);
    const matches = set.trie.match('PROJECT NIGHTINGALE is confidential', 10);
    expect(matches.map((m) => m.payload.kind).sort()).toEqual(['label', 'tenant']);
    expect(set.trie.phrases).toBe(builtInDictionaries().entries.length + 1);
  });

  it('is order independent and versioned by ids and versions', () => {
    const a = tenant();
    const b = tenant({ id: '0196f3a0-0000-7000-8000-000000000003', terms: ['Falcon'] });
    expect(DlpDictionarySet.create([a, b]).tenantVersion).toBe(
      DlpDictionarySet.create([b, a]).tenantVersion,
    );
    expect(DlpDictionarySet.create([a, { ...b, version: 2 }]).tenantVersion).not.toBe(
      DlpDictionarySet.create([a, b]).tenantVersion,
    );
  });

  it('honours the maximum number of terms', () => {
    const many = tenant({ terms: Array.from({ length: 11 }, (_, i) => `term${i}`) });
    expect(DlpDictionarySet.create([many], { maxTerms: 10 }).invalid).toHaveLength(1);
    expect(DlpDictionarySet.create([many], { maxTerms: 11 }).invalid).toHaveLength(0);
  });
});
