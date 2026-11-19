import { mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { GeoIpService } from './geoip';
import { ANONYMIZER_FLAGS } from './taxonomy';
import {
  buildSyntheticGeoIp,
  SYNTHETIC_GEOIP,
  SYNTHETIC_GEOIP_FILES,
  type SyntheticGeoSpec,
} from './testing';

const fixtures = resolve(__dirname, '..', 'test-fixtures', 'geoip');
const paths = {
  city: join(fixtures, SYNTHETIC_GEOIP_FILES.city),
  asn: join(fixtures, SYNTHETIC_GEOIP_FILES.asn),
  anonymous: join(fixtures, SYNTHETIC_GEOIP_FILES.anonymous),
};
const BUILT = new Date(SYNTHETIC_GEOIP.buildEpoch * 1000);
const scratch = mkdtempSync(join(tmpdir(), 'ato-geoip-'));

afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const open = (now: Date = BUILT, allowDocumentationRanges = true, p: typeof paths = paths) =>
  GeoIpService.open(p, { maxAgeDays: 35, allowDocumentationRanges, now: () => now });

describe('synthetic GeoIP databases (D7)', () => {
  it('the JSON source equals SYNTHETIC_GEOIP', () => {
    const json = JSON.parse(
      readFileSync(join(fixtures, SYNTHETIC_GEOIP_FILES.spec), 'utf8'),
    ) as SyntheticGeoSpec;
    expect(json).toEqual(SYNTHETIC_GEOIP);
  });

  it('regenerates the committed files byte-identically (twice)', () => {
    const a = buildSyntheticGeoIp(SYNTHETIC_GEOIP);
    const b = buildSyntheticGeoIp(SYNTHETIC_GEOIP);
    for (const kind of ['city', 'asn', 'anonymous'] as const) {
      expect(a[kind].equals(b[kind])).toBe(true);
      expect(a[kind].equals(readFileSync(paths[kind]))).toBe(true);
    }
  });

  it('holds exactly the documentation ranges of D7 (no real address space)', () => {
    expect(SYNTHETIC_GEOIP.networks.map((n) => n.cidr)).toEqual([
      '192.0.2.0/25',
      '192.0.2.128/25',
      '198.51.100.0/24',
      '203.0.113.0/25',
      '203.0.113.128/25',
      '2001:db8::/48',
      '2001:db8:1::/48',
    ]);
    for (const n of SYNTHETIC_GEOIP.networks) {
      expect(n.asn).toBeGreaterThanOrEqual(64496);
      expect(n.asn).toBeLessThanOrEqual(64511);
    }
  });
});

describe('GeoIpService with the production reader', () => {
  it('locates every synthetic network with city, coordinates, accuracy and ASN', async () => {
    const geo = await open();
    const cases: Array<[string, string, string | null, number, number, number, number]> = [
      ['192.0.2.10', 'IN', 'Mumbai', 19.076, 72.8777, 20, 64500],
      ['192.0.2.200', 'IN', 'Pune', 18.5204, 73.8567, 20, 64500],
      ['198.51.100.7', 'GB', 'London', 51.5074, -0.1278, 10, 64501],
      ['203.0.113.5', 'BR', 'São Paulo', -23.5505, -46.6333, 20, 64502],
      ['203.0.113.200', 'US', 'New York', 40.7128, -74.006, 10, 64503],
      ['2001:db8::1', 'AU', 'Sydney', -33.8688, 151.2093, 50, 64504],
      ['2001:db8:1::1', 'DE', null, 0, 0, 1000, 64505],
    ];
    for (const [ip, country, city, lat, lon, accuracy, asn] of cases) {
      const r = geo.lookup(ip);
      expect(r.status, ip).toBe('located');
      expect(r.country, ip).toBe(country);
      expect(r.city, ip).toBe(city);
      if (city !== null) {
        expect(r.latitude, ip).toBe(lat);
        expect(r.longitude, ip).toBe(lon);
      }
      expect(r.accuracyKm, ip).toBe(accuracy);
      expect(r.asn, ip).toBe(asn);
      expect(r.asnOrg, ip).toBe(`Synthetic Documentation AS${asn}`);
      expect(r.results).toEqual({
        city: 'hit',
        asn: 'hit',
        anonymous: ip.startsWith('203.0.113.2') ? 'hit' : 'miss',
      });
    }
  });

  it('flags the anonymous VPN range and nothing else', async () => {
    const geo = await open();
    const vpn = geo.lookup('203.0.113.200');
    expect(vpn.anonymizerFlags! & ANONYMIZER_FLAGS.anonymousVpn).toBeTruthy();
    expect(geo.lookup('198.51.100.7').anonymizerFlags).toBe(0);
  });

  it('documentation ranges are private unless explicitly allowed (tests only)', async () => {
    const geo = await open(BUILT, false);
    const r = geo.lookup('198.51.100.7');
    expect(r.status).toBe('private');
    expect(r.country).toBeNull();
    expect(r.results).toEqual({ city: 'skipped', asn: 'skipped', anonymous: 'skipped' });
  });

  it('never looks up private, loopback or invalid addresses', async () => {
    const geo = await open();
    expect(geo.lookup('10.1.2.3').status).toBe('private');
    expect(geo.lookup('127.0.0.1').status).toBe('private');
    expect(geo.lookup('100.64.0.1').status).toBe('private');
    expect(geo.lookup('fe80::1').status).toBe('private');
    expect(geo.lookup('not-an-ip').status).toBe('not_found');
  });

  it('a public address outside the database is not_found (never guessed)', async () => {
    const geo = await open();
    const r = geo.lookup('8.8.8.8');
    expect(r.status).toBe('not_found');
    expect(r.country).toBeNull();
    expect(r.results.city).toBe('miss');
  });

  it('marks located lookups stale past maxAgeDays and reports status', async () => {
    const fresh = await open(new Date(BUILT.getTime() + 10 * 86_400_000));
    expect(fresh.lookup('198.51.100.7').status).toBe('located');
    expect(fresh.status().city).toMatchObject({
      configured: true,
      loaded: true,
      databaseType: 'GeoLite2-City',
      buildEpoch: SYNTHETIC_GEOIP.buildEpoch,
      ageSeconds: 10 * 86_400,
      stale: false,
      error: null,
    });
    const old = await open(new Date(BUILT.getTime() + 36 * 86_400_000));
    expect(old.lookup('198.51.100.7').status).toBe('stale');
    expect(old.status().city.stale).toBe(true);
  });

  it('without the City database every lookup is unavailable', async () => {
    const geo = await GeoIpService.open(
      { city: null, asn: paths.asn },
      { maxAgeDays: 35, allowDocumentationRanges: true, now: () => BUILT },
    );
    const r = geo.lookup('198.51.100.7');
    expect(r.status).toBe('unavailable');
    expect(r.country).toBeNull();
    expect(r.asn).toBe(64501);
    expect(r.results.city).toBe('unavailable');
    expect(geo.status().city).toMatchObject({ configured: false, loaded: false });
    expect(geo.status().anonymous.configured).toBe(false);
  });

  it('reports a missing file and a database of the wrong type without throwing', async () => {
    const geo = await GeoIpService.open(
      { city: join(scratch, 'missing.mmdb'), asn: paths.city },
      { maxAgeDays: 35, allowDocumentationRanges: true, now: () => BUILT },
    );
    expect(geo.status().city).toMatchObject({ loaded: false, error: 'file_not_found' });
    expect(geo.status().asn).toMatchObject({ loaded: false, error: 'unexpected_database_type' });
    expect(geo.lookup('198.51.100.7').status).toBe('unavailable');
  });

  it('reloads a database when its modification time changes; a broken file keeps the reader', async () => {
    const city = join(scratch, 'city.mmdb');
    writeFileSync(city, readFileSync(paths.city));
    utimesSync(city, new Date('2026-11-01T00:00:00Z'), new Date('2026-11-01T00:00:00Z'));
    const geo = await open(BUILT, true, { ...paths, city });
    expect(geo.lookup('198.51.100.7').city).toBe('London');
    expect(await geo.reloadIfChanged()).toEqual([]);

    const renamed: SyntheticGeoSpec = {
      ...SYNTHETIC_GEOIP,
      networks: SYNTHETIC_GEOIP.networks.map((n) =>
        n.cidr === '198.51.100.0/24' ? { ...n, city: 'Reloaded' } : n,
      ),
    };
    writeFileSync(city, buildSyntheticGeoIp(renamed).city);
    utimesSync(city, new Date('2026-11-02T00:00:00Z'), new Date('2026-11-02T00:00:00Z'));
    expect(await geo.reloadIfChanged()).toEqual(['city']);
    expect(geo.lookup('198.51.100.7').city).toBe('Reloaded');

    writeFileSync(city, Buffer.from('not a database'));
    utimesSync(city, new Date('2026-11-03T00:00:00Z'), new Date('2026-11-03T00:00:00Z'));
    expect(await geo.reloadIfChanged()).toEqual([]);
    expect(geo.status().city).toMatchObject({ loaded: true, error: 'unreadable_database' });
    expect(geo.lookup('198.51.100.7').city).toBe('Reloaded');
  });
});
