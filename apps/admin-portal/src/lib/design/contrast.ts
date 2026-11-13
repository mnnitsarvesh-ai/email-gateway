/**
 * OKLCH → sRGB → WCAG 2.2 contrast (used by the token contrast test and the design docs).
 * Out-of-gamut channels are clamped, which is what browsers approximate when they map a CSS
 * color into sRGB.
 */
export interface Oklch {
  l: number;
  c: number;
  h: number;
  alpha: number;
}

export function parseOklch(value: string): Oklch | null {
  const match =
    /^oklch\(\s*([\d.]+)(%?)\s+([\d.]+)\s+([\d.]+)(?:deg)?\s*(?:\/\s*([\d.]+)(%?))?\s*\)$/i.exec(
      value.trim(),
    );
  if (!match) return null;
  const l = Number(match[1]) / (match[2] ? 100 : 1);
  const alpha = match[5] === undefined ? 1 : Number(match[5]) / (match[6] ? 100 : 1);
  return { l, c: Number(match[3]), h: Number(match[4]), alpha };
}

/** Linear-light sRGB channels in [0, 1] (clamped). */
export function oklchToLinearSrgb({ l, c, h }: Oklch): [number, number, number] {
  const rad = (h * Math.PI) / 180;
  const a = c * Math.cos(rad);
  const b = c * Math.sin(rad);
  const l_ = l + 0.3963377774 * a + 0.2158037573 * b;
  const m_ = l - 0.1055613458 * a - 0.0638541728 * b;
  const s_ = l - 0.0894841775 * a - 1.291485548 * b;
  const L = l_ ** 3;
  const M = m_ ** 3;
  const S = s_ ** 3;
  const clamp = (v: number) => Math.min(1, Math.max(0, v));
  return [
    clamp(4.0767416621 * L - 3.3077115913 * M + 0.2309699292 * S),
    clamp(-1.2684380046 * L + 2.6097574011 * M - 0.3413193965 * S),
    clamp(-0.0041960863 * L - 0.7034186147 * M + 1.707614701 * S),
  ];
}

function toGamma(v: number): number {
  return v <= 0.0031308 ? 12.92 * v : 1.055 * v ** (1 / 2.4) - 0.055;
}
function toLinear(v: number): number {
  return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
}

/** Composites `top` (with alpha) over an opaque `bottom`, in gamma-encoded sRGB like browsers. */
export function composite(top: Oklch, bottom: Oklch): [number, number, number] {
  const t = oklchToLinearSrgb(top).map(toGamma);
  const b = oklchToLinearSrgb(bottom).map(toGamma);
  return [0, 1, 2].map((i) =>
    toLinear((t[i] ?? 0) * top.alpha + (b[i] ?? 0) * (1 - top.alpha)),
  ) as [number, number, number];
}

export function relativeLuminance([r, g, b]: [number, number, number]): number {
  // Round-trip through 8-bit gamma values like a rendered pixel.
  const q = (v: number) => toLinear(Math.round(toGamma(v) * 255) / 255);
  return 0.2126 * q(r) + 0.7152 * q(g) + 0.0722 * q(b);
}

export function contrastRatio(foreground: Oklch, background: Oklch): number {
  const bg = oklchToLinearSrgb(background);
  const fg =
    foreground.alpha < 1 ? composite(foreground, background) : oklchToLinearSrgb(foreground);
  const l1 = relativeLuminance(fg);
  const l2 = relativeLuminance(bg);
  const [hi, lo] = l1 > l2 ? [l1, l2] : [l2, l1];
  return (hi + 0.05) / (lo + 0.05);
}
