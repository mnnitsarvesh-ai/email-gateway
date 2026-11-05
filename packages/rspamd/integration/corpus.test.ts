import { createReadStream, statSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { normalizeReply } from '../src';
import { corpusRoot, loadManifest, makeClient, requireRspamd, toEnvelope } from './support/env';

/**
 * Every scan-corpus fixture through the real /checkv2 (tests/fixtures/scan-corpus/manifest.json):
 * required and absent symbols, SPF/DKIM/DMARC/ARC outcomes of normalizeReply, the score inside
 * the calibrated range (margins, not exact scores) and the pre-filter result of GTUBE.
 */
const manifest = loadManifest();
const client = makeClient();

beforeAll(requireRspamd);

describe('scan corpus through the real rspamd', () => {
  it('reports the Rspamd version in the Server header and through the controller', async () => {
    const version = await client.version();
    expect(version).toBe(manifest.rspamdVersion);
  });

  it.each(manifest.fixtures.map((f) => [f.file, f] as const))('%s', async (_file, fixture) => {
    const path = join(corpusRoot, fixture.file);
    const result = await client.check({
      body: createReadStream(path),
      sizeBytes: statSync(path).size,
      envelope: toEnvelope(fixture),
      logTag: 'itcorpus',
    });
    expect(result.serverVersion).toBe(manifest.rspamdVersion);
    const normalized = normalizeReply(result.reply, {
      envelopeFrom: fixture.envelope.from,
      helo: fixture.envelope.helo,
    });
    const names = new Set(normalized.symbols.map((s) => s.name));
    for (const symbol of fixture.expect.symbols) {
      expect(names, `${fixture.file}: symbol ${symbol}`).toContain(symbol);
    }
    for (const symbol of fixture.expect.absentSymbols ?? []) {
      expect(names, `${fixture.file}: no symbol ${symbol}`).not.toContain(symbol);
    }
    if (fixture.expect.auth) expect(normalized.auth).toMatchObject(fixture.expect.auth);
    const [min, max] = fixture.expect.scoreRange;
    expect(normalized.score, `${fixture.file}: score`).toBeGreaterThanOrEqual(min);
    expect(normalized.score, `${fixture.file}: score`).toBeLessThan(max);
    if (fixture.expect.action) expect(normalized.action).toBe(fixture.expect.action);
    if (fixture.expect.passthroughModule) {
      expect(normalized.passthroughModule).toBe(fixture.expect.passthroughModule);
      expect(normalized.skipped).toBe(false);
    } else {
      expect(normalized.passthroughModule).toBeNull();
      expect(normalized.skipped).toBe(false);
      // The milter-only action thresholds: only reject exists (ADR-0027).
      expect(['no action', 'reject']).toContain(normalized.action);
    }
    expect(result.reply.required_score).toBe(15);
  });

  it('uses the eg_outbound settings and User for outbound mail (no IP blocklist, no HELO checks)', async () => {
    const fixture = manifest.fixtures.find((f) => f.file === 'spam/rbl-dbl-lottery.eml')!;
    const path = join(corpusRoot, fixture.file);
    const scan = async (direction: 'inbound' | 'outbound') =>
      normalizeReply(
        (
          await client.check({
            body: createReadStream(path),
            sizeBytes: statSync(path).size,
            envelope: { ...toEnvelope(fixture), direction, clientHelo: '203.0.113.9' },
            logTag: `itsettings-${direction}`,
          })
        ).reply,
      );
    const inbound = await scan('inbound');
    const outbound = await scan('outbound');
    const inboundNames = inbound.symbols.map((s) => s.name);
    const outboundNames = outbound.symbols.map((s) => s.name);
    expect(inboundNames).toContain('EG_TEST_RBL');
    expect(inboundNames.some((n) => n.startsWith('HFILTER_HELO'))).toBe(true);
    expect(outboundNames).not.toContain('EG_TEST_RBL');
    expect(outboundNames.some((n) => n.startsWith('HFILTER_HELO'))).toBe(false);
    // Domain/URL blocklists still apply to authenticated senders.
    expect(outboundNames).toContain('EG_TEST_DBL');
  });

  it('sends at most 100 recipients and flags the rest', async () => {
    const fixture = manifest.fixtures[0]!;
    const path = join(corpusRoot, fixture.file);
    const recipients = Array.from({ length: 130 }, (_, i) => `user${i}@customer.scan.test`);
    const result = await client.check({
      body: createReadStream(path),
      sizeBytes: statSync(path).size,
      envelope: { ...toEnvelope(fixture), recipients },
      logTag: 'itrcpt',
    });
    expect(result.rcptTruncated).toBe(true);
    expect(result.reply.symbols).toHaveProperty('R_SPF_ALLOW');
  });
});
