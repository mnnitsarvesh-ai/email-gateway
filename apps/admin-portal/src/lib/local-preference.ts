/**
 * Per-viewer UI conveniences in localStorage (column visibility, sidebar collapsed, density).
 * Never tokens or user data (design P2). Every access is guarded: storage may be unavailable.
 */
const PREFIX = 'eg:';

export function readPreference<T>(
  key: string,
  fallback: T,
  validate: (value: unknown) => value is T,
): T {
  try {
    const raw = window.localStorage.getItem(PREFIX + key);
    if (raw === null) return fallback;
    const parsed = JSON.parse(raw) as unknown;
    return validate(parsed) ? parsed : fallback;
  } catch {
    return fallback;
  }
}

export function writePreference(key: string, value: unknown): void {
  try {
    window.localStorage.setItem(PREFIX + key, JSON.stringify(value));
  } catch {
    // storage unavailable (private mode, quota): the preference is simply not remembered
  }
}

export const isBooleanRecord = (value: unknown): value is Record<string, boolean> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Object.values(value).every((v) => typeof v === 'boolean');

export const isBoolean = (value: unknown): value is boolean => typeof value === 'boolean';
