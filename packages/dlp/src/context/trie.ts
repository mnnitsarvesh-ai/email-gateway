import { Deadline, normalizeForMatching, wordTokens } from '@email-gateway/bec';

/**
 * The DLP phrase trie (step 4.5 D7, D8): phrases are token sequences of the bec normalization
 * (`normalizeForMatching`: NFKC, `\p{Cf}` removal, case fold, Latin confusable skeletons; then
 * `wordTokens`), so case, compatibility forms, zero-width characters and Latin confusables do
 * not hide a keyword. Matching walks the token list once with phrases of at most
 * `MAX_PHRASE_TOKENS` tokens: linear, no regular expression.
 */

export const MAX_PHRASE_TOKENS = 8;
export const MAX_PHRASE_CHARS = 64;

interface TrieNode<T> {
  next: Map<string, TrieNode<T>>;
  payloads: T[];
}

const node = <T>(): TrieNode<T> => ({ next: new Map(), payloads: [] });

/** The normalized tokens of a phrase; throws when it has 0 or more than 8 tokens. */
export function phraseTokens(phrase: string): string[] {
  const tokens = wordTokens(normalizeForMatching(phrase).text).map((t) => t.value);
  if (tokens.length === 0 || tokens.length > MAX_PHRASE_TOKENS) {
    throw new Error(`phrase must have 1..${MAX_PHRASE_TOKENS} tokens`);
  }
  return tokens;
}

/** A phrase match in source offsets of the matched text. */
export interface PhraseMatch<T> {
  payload: T;
  start: number;
  end: number;
}

export class PhraseTrie<T> {
  private readonly root: TrieNode<T> = node();
  private size = 0;

  get phrases(): number {
    return this.size;
  }

  add(tokens: readonly string[], payload: T): void {
    if (tokens.length === 0 || tokens.length > MAX_PHRASE_TOKENS) {
      throw new Error(`phrase must have 1..${MAX_PHRASE_TOKENS} tokens`);
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
    current.payloads.push(payload);
    this.size += 1;
  }

  /**
   * Every phrase occurrence in `text` (source offsets of `text`), in token order, at most
   * `maxMatches` in total; `accept` may refuse a payload (per-kind caps).
   */
  match(
    text: string,
    maxMatches: number,
    deadline: Deadline = Deadline.none(),
    accept: (payload: T) => boolean = () => true,
  ): PhraseMatch<T>[] {
    const normalized = normalizeForMatching(text, deadline);
    const tokens = wordTokens(normalized.text, deadline);
    const matches: PhraseMatch<T>[] = [];
    for (let i = 0; i < tokens.length && matches.length < maxMatches; i += 1) {
      let current = this.root;
      for (let j = i; j < tokens.length && j - i < MAX_PHRASE_TOKENS; j += 1) {
        deadline.check();
        const child = current.next.get(tokens[j]!.value);
        if (!child) break;
        current = child;
        for (const payload of current.payloads) {
          if (matches.length >= maxMatches) break;
          if (!accept(payload)) continue;
          matches.push({
            payload,
            start: normalized.start[tokens[i]!.start]!,
            end: normalized.end[tokens[j]!.end - 1]!,
          });
        }
      }
    }
    return matches;
  }
}
