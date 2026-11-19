import { describe, expect, it } from 'vitest';
import { deviceFromUserAgent } from './device';

const CHROME =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
const SAFARI_IOS =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1';

describe('deviceFromUserAgent', () => {
  it('labels browser, major version, OS and platform', () => {
    const d = deviceFromUserAgent(CHROME)!;
    expect(d.label).toBe('Chrome 120 · Windows · desktop');
    expect(d.hash).toMatch(/^[0-9a-f]{16}$/);
    expect(deviceFromUserAgent(SAFARI_IOS)!.label).toBe('Safari 17 · iOS · mobile');
  });

  it('is deterministic and ignores minor versions', () => {
    const minor = CHROME.replace('120.0.0.0', '120.0.6099.71');
    expect(deviceFromUserAgent(minor)!.hash).toBe(deviceFromUserAgent(CHROME)!.hash);
    expect(deviceFromUserAgent(CHROME.replace('120.', '121.'))!.hash).not.toBe(
      deviceFromUserAgent(CHROME)!.hash,
    );
  });

  it('handles empty and unknown agents', () => {
    expect(deviceFromUserAgent(null)).toBeNull();
    expect(deviceFromUserAgent('   ')).toBeNull();
    const unknown = deviceFromUserAgent('curl/8.4.0')!;
    expect(unknown.label.length).toBeLessThanOrEqual(96);
    expect(unknown.hash).toMatch(/^[0-9a-f]{16}$/);
  });
});
