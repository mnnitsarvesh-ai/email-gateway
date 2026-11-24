import type { SemanticColor, SeriesColor } from './types';

/**
 * Report colors (design D4): a fixed 8-color categorical palette chosen by series index and
 * semantic colors for verdicts and statuses chosen by fixed key, never by a data string. The
 * categorical order is the validated default of the `dataviz` method (adjacent-pair CVD ΔE ≥ 9.1,
 * normal-vision ΔE ≥ 19.6 on a white surface); three slots are below 3:1 contrast on white, so
 * every chart has a legend with values and a data table (the relief rule).
 */

export const CATEGORICAL_PALETTE = [
  '#2a78d6',
  '#eb6834',
  '#1baf7a',
  '#eda100',
  '#e87ba4',
  '#008300',
  '#6250d6',
  '#e34948',
] as const;

/** Verdict and status colors: clean neutral, threats warm, status as in the dataviz palette. */
export const SEMANTIC_COLORS: Readonly<Record<SemanticColor, string>> = {
  clean: '#898781',
  bulk: '#c3c2b7',
  none: '#e1e0d9',
  unknown: '#52514e',
  spam: '#fab219',
  suspicious: '#ec835a',
  phishing: '#d03b3b',
  malware: '#8f1d3a',
  bec: '#6250d6',
  dlp_violation: '#2a78d6',
  other: '#b4b2a9',
  good: '#0ca30c',
  warning: '#fab219',
  serious: '#ec835a',
  critical: '#d03b3b',
};

/** Chart chrome (constants, never data). */
export const CHROME = {
  surface: '#ffffff',
  ink: '#0b0b0b',
  secondary: '#52514e',
  muted: '#6b6a65',
  grid: '#e1e0d9',
  axis: '#c3c2b7',
} as const;

/** The hex color of a series color (an index wraps never: out-of-range indexes use `other`). */
export function colorOf(color: SeriesColor): string {
  if (typeof color === 'number')
    return Number.isInteger(color) && color >= 0 && color < CATEGORICAL_PALETTE.length
      ? CATEGORICAL_PALETTE[color]!
      : SEMANTIC_COLORS.other;
  return Object.prototype.hasOwnProperty.call(SEMANTIC_COLORS, color)
    ? SEMANTIC_COLORS[color]
    : SEMANTIC_COLORS.other;
}

/** The CSS class of a legend swatch (`sw-c3`, `sw-spam`); the classes are in the constant style. */
export function swatchClass(color: SeriesColor): string {
  if (typeof color === 'number')
    return Number.isInteger(color) && color >= 0 && color < CATEGORICAL_PALETTE.length
      ? `sw-c${color}`
      : 'sw-other';
  return Object.prototype.hasOwnProperty.call(SEMANTIC_COLORS, color) ? `sw-${color}` : 'sw-other';
}

/** The swatch rules of the constant `<style>` block. */
export function swatchCss(): string {
  const rules = CATEGORICAL_PALETTE.map((hex, i) => `.sw-c${i}{background:${hex}}`);
  for (const [key, hex] of Object.entries(SEMANTIC_COLORS))
    rules.push(`.sw-${key}{background:${hex}}`);
  return rules.join('');
}
