import { PSEUDONYM_TOKEN_WORDS } from './detect';
import { PLACEHOLDER_MAX_LENGTH, PLACEHOLDER_PATTERN } from './tokens';

/**
 * De-mapping of model output (step AI-6 D3): known bracketed tokens become the real values the
 * user sees; unknown tokens stay as written. `TextDemapper` does it on streamed `text.delta`
 * events with a hold-back buffer of at most one token (15 characters), so a token split across
 * deltas is still replaced: the concatenation of every `push` and the final `flush` equals
 * `demapText` of the whole text.
 */

/** Resolves a bracketed token (`[EMAIL_3]`) to its value, or null when unknown. */
export type PlaceholderResolver = (token: string) => string | null;

/** Replaces the known bracketed tokens of the text (unknown ones stay). */
export function demapTokens(text: string, resolve: PlaceholderResolver): string {
  if (!text.includes('[')) return text;
  return text.replace(
    new RegExp(PLACEHOLDER_PATTERN.source, 'g'),
    (token) => resolve(token) ?? token,
  );
}

/** Every proper prefix of a token: `[`, `[E`, …, `[EMAIL_`, `[EMAIL_12345` (no `]`). */
const TOKEN_PREFIX = new RegExp(
  `^\\[(?:${Object.values(PSEUDONYM_TOKEN_WORDS)
    .map((word) => {
      let pattern = '';
      for (let i = word.length - 1; i >= 0; i -= 1)
        pattern = `${word[i]}(?:${pattern}${i === word.length - 1 ? '_[0-9]{0,6}' : ''})?`;
      return pattern;
    })
    .join('|')})?$`,
);

/** True when `tail` (starting with `[`) may still grow into a token. */
export function isPlaceholderPrefix(tail: string): boolean {
  return tail.length < PLACEHOLDER_MAX_LENGTH && TOKEN_PREFIX.test(tail);
}

export class TextDemapper {
  private buffer = '';

  constructor(private readonly resolve: PlaceholderResolver) {}

  /** Adds a delta; returns the de-mapped text that is safe to emit now (may be empty). */
  push(delta: string): string {
    this.buffer += delta;
    const open = this.buffer.lastIndexOf('[');
    const hold =
      open >= 0 && isPlaceholderPrefix(this.buffer.slice(open)) ? this.buffer.length - open : 0;
    const ready = this.buffer.slice(0, this.buffer.length - hold);
    this.buffer = this.buffer.slice(this.buffer.length - hold);
    return demapTokens(ready, this.resolve);
  }

  /** Emits what is held back (at the end of the stream). */
  flush(): string {
    const rest = this.buffer;
    this.buffer = '';
    return demapTokens(rest, this.resolve);
  }
}
