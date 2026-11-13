/** Reads the double-submit CSRF cookie (`__Host-eg_csrf`, or `eg_csrf` on http local/ci). */
export function readCsrfToken(cookieString?: string): string | null {
  const source = cookieString ?? (typeof document === 'undefined' ? '' : document.cookie);
  let fallback: string | null = null;
  for (const part of source.split(';')) {
    const index = part.indexOf('=');
    if (index <= 0) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (!value) continue;
    if (name === '__Host-eg_csrf') return value;
    if (name === 'eg_csrf') fallback = value;
  }
  return fallback;
}
