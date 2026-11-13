/** Display formatting (browser locale; UTC on hover is handled by DateTime). */
export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '';
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 }).format(value);
}

/** `0.9734` → `97.3 %` (one decimal). */
export function formatPercent(ratio: number | null | undefined): string {
  if (ratio === null || ratio === undefined || !Number.isFinite(ratio)) return '';
  return `${new Intl.NumberFormat(undefined, { minimumFractionDigits: 1, maximumFractionDigits: 1 }).format(ratio * 100)} %`;
}

/** Milliseconds as `850 ms`, `4.2 s`, `3 min`, `2 h`. */
export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return '';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} s`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)} min`;
  return `${(ms / 3_600_000).toFixed(ms < 36_000_000 ? 1 : 0)} h`;
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return '';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${unit === 0 ? value : value.toFixed(1)} ${units[unit]}`;
}

/** `dlp_violation` → `DLP violation`, `in_progress` → `In progress`. */
export function humanize(value: string): string {
  const special: Record<string, string> = {
    dlp: 'DLP',
    bec: 'BEC',
    url: 'URL',
    ip: 'IP',
    mfa: 'MFA',
    api: 'API',
  };
  const words = value.split(/[_\s-]+/).filter(Boolean);
  return words
    .map((word, index) => {
      const lower = word.toLowerCase();
      if (special[lower]) return special[lower];
      return index === 0 ? lower.charAt(0).toUpperCase() + lower.slice(1) : lower;
    })
    .join(' ');
}

/** Absolute UTC timestamp, e.g. `2026-11-13 09:14:03 UTC`. */
export function formatUtc(iso: string | Date): string {
  const date = typeof iso === 'string' ? new Date(iso) : iso;
  if (Number.isNaN(date.getTime())) return '';
  return `${date.toISOString().slice(0, 19).replace('T', ' ')} UTC`;
}
