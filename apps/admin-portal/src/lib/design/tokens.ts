/**
 * Token contrast manifest (design P14): every foreground/background pair the components use,
 * with its WCAG 2.2 AA threshold. `tokens.test.ts` evaluates each pair in both themes.
 */
export type ContrastKind = 'text' | 'large-text' | 'ui';

export const CONTRAST_THRESHOLD: Readonly<Record<ContrastKind, number>> = {
  text: 4.5,
  'large-text': 3,
  ui: 3,
};

export interface TokenPair {
  readonly foreground: string;
  readonly background: string;
  readonly kind: ContrastKind;
}

const text = (foreground: string, background: string): TokenPair => ({
  foreground,
  background,
  kind: 'text',
});
const ui = (foreground: string, background: string): TokenPair => ({
  foreground,
  background,
  kind: 'ui',
});

export const TONES = [
  'neutral',
  'info',
  'success',
  'warning',
  'orange',
  'danger',
  'purple',
  'magenta',
] as const;
export type Tone = (typeof TONES)[number];

export const TOKEN_PAIRS: readonly TokenPair[] = [
  text('foreground', 'background'),
  text('foreground', 'card'),
  text('foreground', 'muted'),
  text('card-foreground', 'card'),
  text('popover-foreground', 'popover'),
  text('muted-foreground', 'background'),
  text('muted-foreground', 'card'),
  text('muted-foreground', 'muted'),
  text('primary-foreground', 'primary'),
  text('secondary-foreground', 'secondary'),
  text('accent-foreground', 'accent'),
  text('destructive-foreground', 'destructive'),
  text('success-foreground', 'success'),
  text('warning-foreground', 'warning'),
  text('info-foreground', 'info'),
  text('primary', 'background'),
  text('primary', 'card'),
  text('destructive', 'card'),
  text('destructive', 'background'),
  text('sidebar-foreground', 'sidebar'),
  text('sidebar-muted', 'sidebar'),
  text('sidebar-accent-foreground', 'sidebar-accent'),
  text('sidebar-foreground', 'sidebar-accent'),
  text('banner-foreground', 'banner'),
  ...TONES.map((tone) => text(`tone-${tone}-foreground`, `tone-${tone}`)),
  ...TONES.map((tone) => text(`tone-${tone}-foreground`, 'card')),
  // Non-text: input borders, focus rings, the active-item indicator and chart marks.
  ui('input', 'background'),
  ui('input', 'card'),
  ui('ring', 'background'),
  ui('ring', 'card'),
  ui('primary', 'background'),
  ui('sidebar-ring', 'sidebar'),
  ui('sidebar-primary', 'sidebar'),
  ...[1, 2, 3, 4, 5, 6, 7, 8].map((n) => ui(`chart-${n}`, 'card')),
];

/** Extracts `--name: value;` declarations of the `:root` and `.dark` blocks of globals.css. */
export function parseThemeTokens(css: string): {
  light: Map<string, string>;
  dark: Map<string, string>;
} {
  const block = (selector: string): Map<string, string> => {
    const start = css.indexOf(`${selector} {`);
    if (start < 0) throw new Error(`${selector} block not found`);
    const end = css.indexOf('\n}', start);
    const body = css.slice(start, end);
    const map = new Map<string, string>();
    for (const match of body.matchAll(/--([a-z0-9-]+):\s*([^;]+);/g)) {
      if (match[1] && match[2]) map.set(match[1], match[2].trim());
    }
    return map;
  };
  const light = block(':root');
  const darkOnly = block('.dark');
  // Dark inherits every light token it does not redefine.
  const dark = new Map([...light, ...darkOnly]);
  return { light, dark };
}
