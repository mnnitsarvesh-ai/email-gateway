import { describe, expect, it } from 'vitest';
import { SNIPPET_MAX_CHARS } from '../insights.constants';
import {
  foldedIndexOf,
  likeContainsPattern,
  sanitizeLine,
  sanitizeUserText,
  snippetOf,
} from './search-text';

describe('likeContainsPattern (D4: escaped LIKE)', () => {
  it('escapes %, _ and the escape character so every character matches literally', () => {
    expect(likeContainsPattern('quarantine')).toBe('%quarantine%');
    expect(likeContainsPattern('50%')).toBe('%50!%%');
    expect(likeContainsPattern('a_b')).toBe('%a!_b%');
    expect(likeContainsPattern('hi!')).toBe('%hi!!%');
    expect(likeContainsPattern('!%_')).toBe('%!!!%!_%');
    // Backslashes and quotes have no meaning with ESCAPE '!' and stay as they are.
    expect(likeContainsPattern(`a\\'b`)).toBe(`%a\\'b%`);
  });
});

describe('sanitizeLine / sanitizeUserText', () => {
  it('removes C0/C1 controls, bidi and zero-width characters and joins lines', () => {
    const raw = 'a\u0000b\u0007c\u0085d\u202Ee\u2066f\u200Bg\uFEFFh\u00ADi\nj\tk\u061Cl';
    expect(sanitizeLine(raw)).toBe('abcdefghi j kl');
  });

  it('keeps line breaks of user text but drops the invisible characters', () => {
    expect(sanitizeUserText('  Line one\r\nline\u200B two\u202E\tend \u0001 ')).toBe(
      'Line one\nline two\tend',
    );
  });

  it('drops lone surrogates and keeps paired ones', () => {
    expect(sanitizeLine('x\uD800y\uDC00z 😀')).toBe('xyz 😀');
  });
});

describe('foldedIndexOf', () => {
  it('matches case- and accent-insensitively and returns the code point index', () => {
    const points = Array.from('Le résumé est prêt');
    expect(foldedIndexOf(points, 'RESUME')).toBe(3);
    expect(foldedIndexOf(points, 'pret')).toBe(14);
    expect(foldedIndexOf(points, 'absent')).toBe(-1);
    expect(foldedIndexOf(Array.from('😀 Ärger'), 'arger')).toBe(2);
  });
});

describe('snippetOf (D4: ≤ 160 characters around the first match, sanitized)', () => {
  const filler = (n: number, ch = 'x') => ch.repeat(n);

  it('returns a short text whole (sanitized, one line)', () => {
    expect(snippetOf('Release\nthe \u202Emessage', 'message')).toBe('Release the message');
  });

  it('cuts a long text around the match with ellipses on both sides', () => {
    const text = `${filler(300)} needle ${filler(300, 'y')}`;
    const snippet = snippetOf(text, 'needle');
    expect(Array.from(snippet).length).toBeLessThanOrEqual(SNIPPET_MAX_CHARS);
    expect(snippet.startsWith('…')).toBe(true);
    expect(snippet.endsWith('…')).toBe(true);
    expect(snippet).toContain('needle');
    // Context on both sides of the match.
    const at = snippet.indexOf('needle');
    expect(at).toBeGreaterThan(50);
    expect(snippet.length - at - 'needle'.length).toBeGreaterThan(50);
  });

  it('starts at the beginning when the match is early and ends at the end when it is late', () => {
    const early = snippetOf(`needle ${filler(400)}`, 'NEEDLE');
    expect(early.startsWith('needle')).toBe(true);
    expect(early.endsWith('…')).toBe(true);
    expect(Array.from(early)).toHaveLength(SNIPPET_MAX_CHARS);
    const late = snippetOf(`${filler(400)} needle`, 'needle');
    expect(late.startsWith('…')).toBe(true);
    expect(late.endsWith('needle')).toBe(true);
    expect(Array.from(late)).toHaveLength(SNIPPET_MAX_CHARS);
  });

  it('finds accented matches and keeps the original spelling', () => {
    const snippet = snippetOf(`${filler(200)} Résumé ${filler(200)}`, 'resume');
    expect(snippet).toContain('Résumé');
  });

  it('starts at the beginning when only the title matched', () => {
    const snippet = snippetOf(filler(400), 'needle');
    expect(snippet).toBe(`${filler(SNIPPET_MAX_CHARS - 1)}…`);
  });

  it('never splits a surrogate pair and counts code points', () => {
    const snippet = snippetOf(`${'😀'.repeat(300)} needle ${'😀'.repeat(300)}`, 'needle');
    expect(Array.from(snippet).length).toBeLessThanOrEqual(SNIPPET_MAX_CHARS);
    expect(snippet).toContain('needle');
    expect(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/.test(snippet)).toBe(false);
  });

  it('removes invisible and control characters before cutting', () => {
    const snippet = snippetOf(`${filler(200)}\u202E\u0000 nee\u200Bdle ${filler(200)}`, 'needle');
    expect(snippet).toContain('needle');
    expect(/[\u0000-\u001F\u202E\u200B]/.test(snippet)).toBe(false); // eslint-disable-line no-control-regex
  });
});
