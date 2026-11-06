/**
 * C0-control/space trimming as the URL Standard does before parsing (no control-character
 * regular expressions).
 */
export function trimC0Space(value: string, side: 'both' | 'start' = 'both'): string {
  let start = 0;
  let end = value.length;
  while (start < end && value.charCodeAt(start) <= 0x20) start += 1;
  if (side === 'both') while (end > start && value.charCodeAt(end - 1) <= 0x20) end -= 1;
  return value.slice(start, end);
}

/** Any C0 control or DEL inside the value (after trimming C0/space at both ends). */
export function hasInnerControlChars(value: string): boolean {
  const inner = trimC0Space(value);
  for (let i = 0; i < inner.length; i += 1) {
    const code = inner.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}
