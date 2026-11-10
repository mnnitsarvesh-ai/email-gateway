import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { findingCodes, harness, probe } from './support';

/**
 * Browser profile of the hardened-container runner (step 4.6 X6, §9.3 "browser"): a synthetic
 * HTML probe fetches the metadata address and an internal service name via JavaScript, shows a
 * cross-origin password form, triggers a Blob download and an alert. Rendered by
 * `dist/sandbox-render/render-main.js` of `email-gateway/url-browser-worker:local` in a
 * disposable hardened runner. LOCAL/CI ONLY, NOT A VM BOUNDARY.
 */

const h = harness();

beforeAll(async () => {
  await h.setup();
}, 180_000);

afterAll(async () => {
  await h.teardown();
}, 180_000);

describe('browser runner', () => {
  it('renders the probe: screenshot, sinkhole records, download attempt, no real fetch', async () => {
    const run = await h.run(probe('browser-probe.html'), 'html', 'browser', {
      wallTimeoutMs: 25_000,
      memoryMb: 1024,
      pids: 256,
      scratchMb: 128,
    });
    const o = run.observation;
    expect(o.status, JSON.stringify(o.observations.limitsHit)).toBe('completed');
    expect(o.executed).toBe(true);
    expect(o.analyzerVersion).toBe('sandbox-render/1');

    const screenshot = o.artifacts.find((a) => a.kind === 'screenshot');
    expect(screenshot?.contentType).toBe('image/png');
    expect(screenshot?.bytes.subarray(0, 8)).toEqual(
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    );
    // 1280×800: width and height in the IHDR chunk.
    expect(screenshot?.bytes.readUInt32BE(16)).toBe(1280);
    expect(screenshot?.bytes.readUInt32BE(20)).toBe(800);

    const browser = o.observations.browser!;
    expect(browser.downloadsAttempted).toBeGreaterThanOrEqual(1);
    expect(browser.dialogs).toBeGreaterThanOrEqual(1);
    expect(browser.passwordFields).toBe(1);
    expect(browser.forms).toBe(1);
    expect(browser.requests).toBeGreaterThanOrEqual(3);

    // The internal name and the beacon host were resolved by the sinkhole and answered by it;
    // the metadata IP has no route (no record, no answer).
    const dnsNames = o.observations.network.dns.map((d) => d.name);
    expect(dnsNames).toEqual(expect.arrayContaining(['mysql', 'eg-browser-probe.sandbox.invalid']));
    const httpHosts = o.observations.network.http.map((r) => r.host);
    expect(httpHosts).toEqual(
      expect.arrayContaining(['169.254.169.254', 'eg-browser-probe.sandbox.invalid']),
    );

    expect(findingCodes(o)).toEqual(
      expect.arrayContaining([
        'browser.download_attempt',
        'browser.password_form',
        'browser.cross_origin_form',
        'browser.dialogs',
        'behaviour.metadata_access',
        'behaviour.internal_network_access',
        'behaviour.dns_queries',
      ]),
    );
    expect(
      o.observations.findings.find((f) => f.code === 'browser.download_attempt')?.severity,
    ).toBe('high');
  });

  it('an SVG sample is rendered too', async () => {
    const svg = Buffer.from(
      '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="100"><text x="10" y="50">eg probe</text></svg>',
    );
    const run = await h.run(svg, 'svg', 'browser', {
      wallTimeoutMs: 15_000,
      memoryMb: 1024,
      pids: 256,
      scratchMb: 128,
    });
    expect(run.observation.status).toBe('completed');
    expect(run.observation.artifacts.some((a) => a.kind === 'screenshot')).toBe(true);
    expect(
      run.observation.observations.findings.filter((f) => f.code.startsWith('browser.')),
    ).toEqual([]);
  });
});
