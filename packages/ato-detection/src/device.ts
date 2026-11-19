/**
 * Device fingerprints (step 8.4 D7): user agents parsed with `bowser` into a family label
 * `<browser> <major> · <os> · <platform>` (≤ 96 characters) and a device hash (first 16 hex of
 * SHA-256 of `browser|major|os|platform`). The raw user agent is never stored.
 */
import { createHash } from 'node:crypto';
import Bowser from 'bowser';

export interface DeviceFingerprint {
  label: string;
  hash: string;
  browser: string;
  major: string;
  os: string;
  platform: string;
}

export const DEVICE_LABEL_MAX_LENGTH = 96;
const UA_MAX_LENGTH = 1024;

const clean = (value: string | undefined, fallback: string): string => {
  const v = (value ?? '').replace(/[^\p{L}\p{N} ._-]/gu, '').trim();
  return v.length > 0 ? v.slice(0, 32) : fallback;
};

/** Parses a user agent; null for an empty one. Never throws. */
export function deviceFromUserAgent(ua: string | null | undefined): DeviceFingerprint | null {
  if (!ua || ua.trim().length === 0) return null;
  let browser = 'Unknown';
  let major = '0';
  let os = 'Unknown';
  let platform = 'unknown';
  try {
    const parsed = Bowser.parse(ua.slice(0, UA_MAX_LENGTH));
    browser = clean(parsed.browser.name, 'Unknown');
    major = clean(parsed.browser.version?.split('.')[0], '0');
    os = clean(parsed.os.name, 'Unknown');
    platform = clean(parsed.platform.type, 'unknown');
  } catch {
    // bowser throws on malformed input; the "Unknown" fingerprint is still deterministic.
  }
  const label = `${browser} ${major} · ${os} · ${platform}`.slice(0, DEVICE_LABEL_MAX_LENGTH);
  const hash = createHash('sha256')
    .update(`${browser}|${major}|${os}|${platform}`, 'utf8')
    .digest('hex')
    .slice(0, 16);
  return { label, hash, browser, major, os, platform };
}
