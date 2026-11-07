import { z } from 'zod';
import { readDataFile, sha256Hex } from '../data';
import { Deadline } from './deadline';
import { normalizeForMatching, wordTokens, type WordToken } from './normalize';

/**
 * Lexicons (B8): `data/lexicon/{en,hi,hi-Latn}.json`, compiled at load into one token trie
 * (phrases normalized exactly like the analysed text, `bec-text/1`). Matching walks the trie
 * from every token start, bounded by the longest phrase: linear time, no user-controlled
 * regular expressions. `lexiconVersion` = first 8 hex of a SHA-256 over the files.
 */

export const LEXICON_CATEGORIES = [
  'payment_request',
  'bank_change',
  'gift_card',
  'wire_transfer',
  'invoice_change',
  'payroll_change',
  'urgency',
  'secrecy',
  'credential_request',
  'authority',
] as const;
export type LexiconCategory = (typeof LEXICON_CATEGORIES)[number];

export const LEXICON_LANGUAGES = ['en', 'hi', 'hi-Latn'] as const;
export type LexiconLanguage = (typeof LEXICON_LANGUAGES)[number];

export const LEXICON_FILES: Readonly<Record<LexiconLanguage, string>> = {
  en: 'en.json',
  hi: 'hi.json',
  'hi-Latn': 'hi-Latn.json',
};

/** Longest phrase in tokens (bounds the trie walk). */
export const MAX_PHRASE_TOKENS = 8;

export interface LexiconEntry {
  id: string;
  category: LexiconCategory;
  phrase: string;
  weight: number;
  language: LexiconLanguage;
}

const entrySchema = z.strictObject({
  id: z.string().regex(/^[a-z]{2}(-Latn)?\.[a-z_]+\.\d{3}$/),
  category: z.enum(LEXICON_CATEGORIES),
  phrase: z.string().min(1).max(120),
  weight: z.number().int().min(1).max(5).optional(),
});
const fileSchema = z.strictObject({
  language: z.enum(LEXICON_LANGUAGES),
  version: z.number().int().min(1),
  entries: z.array(entrySchema).min(1).max(2000),
});

interface TrieNode {
  next: Map<string, TrieNode>;
  entries: LexiconEntry[];
}

const node = (): TrieNode => ({ next: new Map(), entries: [] });

export interface LexiconMatch {
  entry: LexiconEntry;
  /** Token index range [tokenStart, tokenEnd) in the matched token list. */
  tokenStart: number;
  tokenEnd: number;
}

export class Lexicon {
  readonly entries: readonly LexiconEntry[];
  readonly version: string;
  private readonly root: TrieNode;

  constructor(files: Readonly<Record<LexiconLanguage, string>>) {
    const entries: LexiconEntry[] = [];
    const ids = new Set<string>();
    const hash = sha256Hex(
      LEXICON_LANGUAGES.map((language) => `${LEXICON_FILES[language]}\0${files[language]}`).join(
        '\0',
      ),
    );
    this.root = node();
    for (const language of LEXICON_LANGUAGES) {
      const parsed = fileSchema.parse(JSON.parse(files[language]));
      if (parsed.language !== language) throw new Error(`lexicon ${language}: language mismatch`);
      for (const raw of parsed.entries) {
        if (ids.has(raw.id)) throw new Error(`duplicate lexicon id ${raw.id}`);
        if (!raw.id.startsWith(`${language}.${raw.category}.`)) {
          throw new Error(`lexicon id ${raw.id} does not match ${language}/${raw.category}`);
        }
        ids.add(raw.id);
        const entry: LexiconEntry = { ...raw, weight: raw.weight ?? 1, language };
        const tokens = wordTokens(normalizeForMatching(raw.phrase).text).map((t) => t.value);
        if (tokens.length === 0 || tokens.length > MAX_PHRASE_TOKENS) {
          throw new Error(`lexicon ${raw.id}: phrase must have 1..${MAX_PHRASE_TOKENS} tokens`);
        }
        let current = this.root;
        for (const token of tokens) {
          let child = current.next.get(token);
          if (!child) {
            child = node();
            current.next.set(token, child);
          }
          current = child;
        }
        current.entries.push(entry);
        entries.push(entry);
      }
    }
    this.entries = entries;
    this.version = hash.slice(0, 8);
  }

  static load(): Lexicon {
    const files = Object.fromEntries(
      LEXICON_LANGUAGES.map((language) => [
        language,
        readDataFile('lexicon', LEXICON_FILES[language]),
      ]),
    ) as Record<LexiconLanguage, string>;
    return new Lexicon(files);
  }

  /**
   * Phrase matches over a token list in token order: at most `maxMatches` in total and
   * `maxPerCategory` per category (a flood of one category cannot hide the others).
   */
  match(
    tokens: readonly WordToken[],
    maxMatches: number,
    maxPerCategory: number = maxMatches,
    deadline: Deadline = Deadline.none(),
  ): LexiconMatch[] {
    const matches: LexiconMatch[] = [];
    const perCategory = new Map<LexiconCategory, number>();
    for (let i = 0; i < tokens.length && matches.length < maxMatches; i += 1) {
      let current = this.root;
      for (let j = i; j < tokens.length && j - i < MAX_PHRASE_TOKENS; j += 1) {
        deadline.check();
        const child = current.next.get(tokens[j]!.value);
        if (!child) break;
        current = child;
        for (const entry of current.entries) {
          if (matches.length >= maxMatches) break;
          const count = perCategory.get(entry.category) ?? 0;
          if (count >= maxPerCategory) continue;
          perCategory.set(entry.category, count + 1);
          matches.push({ entry, tokenStart: i, tokenEnd: j + 1 });
        }
      }
    }
    return matches;
  }
}
