import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { contrastRatio, parseOklch } from './contrast';
import { CONTRAST_THRESHOLD, TOKEN_PAIRS, parseThemeTokens } from './tokens';

const css = readFileSync(join(__dirname, '../../app/globals.css'), 'utf8');
const themes = parseThemeTokens(css);

describe('design tokens (WCAG 2.2 AA, design P14)', () => {
  it('converts OKLCH to sRGB contrast like reference values', () => {
    expect(contrastRatio(parseOklch('oklch(0 0 0)')!, parseOklch('oklch(1 0 0)')!)).toBeCloseTo(
      21,
      0,
    );
    expect(contrastRatio(parseOklch('oklch(1 0 0)')!, parseOklch('oklch(1 0 0)')!)).toBeCloseTo(
      1,
      5,
    );
  });

  for (const [theme, tokens] of Object.entries(themes)) {
    it.each(TOKEN_PAIRS.map((p) => [p.foreground, p.background, p.kind] as const))(
      `${theme}: --%s on --%s meets AA (%s)`,
      (foreground, background, kind) => {
        const fg = tokens.get(foreground);
        const bg = tokens.get(background);
        expect(fg, `--${foreground}`).toBeDefined();
        expect(bg, `--${background}`).toBeDefined();
        const ratio = contrastRatio(parseOklch(fg!)!, parseOklch(bg!)!);
        expect(ratio).toBeGreaterThanOrEqual(CONTRAST_THRESHOLD[kind]);
      },
    );
  }

  it('defines every token in both themes (sidebar stays navy)', () => {
    for (const name of ['sidebar', 'chart-8', 'tone-danger', 'banner']) {
      expect(themes.light.get(name)).toMatch(/^oklch/);
      expect(themes.dark.get(name)).toMatch(/^oklch/);
    }
    const hue = (v: string) => parseOklch(v)!.h;
    expect(hue(themes.light.get('sidebar')!)).toBeGreaterThan(240);
    expect(hue(themes.dark.get('sidebar')!)).toBeGreaterThan(240);
  });
});
