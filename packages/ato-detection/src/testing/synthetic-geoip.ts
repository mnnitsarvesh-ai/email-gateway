/**
 * The synthetic GeoIP test database (step 8.4 D7, PO2): documentation ranges (RFC 5737, RFC 3849)
 * and documentation ASNs (RFC 5398) with fixed cities, coordinates and accuracy radii. The JSON
 * source `test-fixtures/geoip/synthetic-geoip.json` equals `SYNTHETIC_GEOIP` (a unit test asserts
 * it); `pnpm --filter @email-gateway/ato-detection geoip:synthetic` writes the three `.mmdb` files
 * from it with `writeMmdb`, byte-identically on every run. Never real geolocation data.
 */
import { mmdb, writeMmdb, type MmdbSpec, type MmdbValue } from './mmdb-writer';

export interface SyntheticGeoNetwork {
  cidr: string;
  /** City name; null for a country-only record. */
  city: string | null;
  region: string | null;
  country: string;
  countryName: string;
  continent: string;
  continentName: string;
  latitude: number;
  longitude: number;
  accuracyKm: number;
  timeZone: string;
  geonameId: number;
  asn: number;
  asnOrg: string;
  anonymous: null | {
    vpn?: boolean;
    publicProxy?: boolean;
    torExitNode?: boolean;
    hostingProvider?: boolean;
    residentialProxy?: boolean;
  };
}

export interface SyntheticGeoSpec {
  version: 'synthetic-geoip/1';
  /** Seconds since the epoch: 2026-11-18T00:00:00Z (lookups read as stale 35 days later). */
  buildEpoch: number;
  networks: SyntheticGeoNetwork[];
}

const net = (
  cidr: string,
  city: string | null,
  region: string | null,
  country: string,
  countryName: string,
  continent: string,
  continentName: string,
  latitude: number,
  longitude: number,
  accuracyKm: number,
  timeZone: string,
  geonameId: number,
  asn: number,
  anonymous: SyntheticGeoNetwork['anonymous'] = null,
): SyntheticGeoNetwork => ({
  cidr,
  city,
  region,
  country,
  countryName,
  continent,
  continentName,
  latitude,
  longitude,
  accuracyKm,
  timeZone,
  geonameId,
  asn,
  asnOrg: `Synthetic Documentation AS${asn}`,
  anonymous,
});

/** `SYNTHETIC_GEOIP` (D7 content, exactly). */
export const SYNTHETIC_GEOIP: SyntheticGeoSpec = {
  version: 'synthetic-geoip/1',
  buildEpoch: 1794960000,
  networks: [
    net(
      '192.0.2.0/25',
      'Mumbai',
      'Maharashtra',
      'IN',
      'India',
      'AS',
      'Asia',
      19.076,
      72.8777,
      20,
      'Asia/Kolkata',
      1275339,
      64500,
    ),
    net(
      '192.0.2.128/25',
      'Pune',
      'Maharashtra',
      'IN',
      'India',
      'AS',
      'Asia',
      18.5204,
      73.8567,
      20,
      'Asia/Kolkata',
      1259229,
      64500,
    ),
    net(
      '198.51.100.0/24',
      'London',
      'England',
      'GB',
      'United Kingdom',
      'EU',
      'Europe',
      51.5074,
      -0.1278,
      10,
      'Europe/London',
      2643743,
      64501,
    ),
    net(
      '203.0.113.0/25',
      'São Paulo',
      'São Paulo',
      'BR',
      'Brazil',
      'SA',
      'South America',
      -23.5505,
      -46.6333,
      20,
      'America/Sao_Paulo',
      3448439,
      64502,
    ),
    net(
      '203.0.113.128/25',
      'New York',
      'New York',
      'US',
      'United States',
      'NA',
      'North America',
      40.7128,
      -74.006,
      10,
      'America/New_York',
      5128581,
      64503,
      { vpn: true },
    ),
    net(
      '2001:db8::/48',
      'Sydney',
      'New South Wales',
      'AU',
      'Australia',
      'OC',
      'Oceania',
      -33.8688,
      151.2093,
      50,
      'Australia/Sydney',
      2147714,
      64504,
    ),
    net(
      '2001:db8:1::/48',
      null,
      null,
      'DE',
      'Germany',
      'EU',
      'Europe',
      51.1657,
      10.4515,
      1000,
      'Europe/Berlin',
      2921044,
      64505,
    ),
  ],
};

const COUNTRY_IDS: Readonly<Record<string, number>> = {
  IN: 1269750,
  GB: 2635167,
  BR: 3469034,
  US: 6252001,
  AU: 2077456,
  DE: 2921044,
};
const CONTINENT_IDS: Readonly<Record<string, number>> = {
  AS: 6255147,
  EU: 6255148,
  SA: 6255150,
  NA: 6255149,
  OC: 6255151,
};

function cityRecord(n: SyntheticGeoNetwork): Record<string, MmdbValue> {
  const country = {
    geoname_id: mmdb.uint32(COUNTRY_IDS[n.country] ?? n.geonameId),
    iso_code: n.country,
    names: { en: n.countryName },
  };
  return {
    ...(n.city !== null && {
      city: { geoname_id: mmdb.uint32(n.geonameId), names: { en: n.city } },
    }),
    continent: {
      code: n.continent,
      geoname_id: mmdb.uint32(CONTINENT_IDS[n.continent] ?? 0),
      names: { en: n.continentName },
    },
    country,
    location: {
      accuracy_radius: mmdb.uint16(n.accuracyKm),
      latitude: mmdb.double(n.latitude),
      longitude: mmdb.double(n.longitude),
      time_zone: n.timeZone,
    },
    registered_country: country,
    ...(n.region !== null && {
      subdivisions: [{ geoname_id: mmdb.uint32(n.geonameId + 1), names: { en: n.region } }],
    }),
  };
}

/** The three database specs of a synthetic GeoIP spec. */
export function syntheticGeoIpSpecs(spec: SyntheticGeoSpec = SYNTHETIC_GEOIP): {
  city: MmdbSpec;
  asn: MmdbSpec;
  anonymous: MmdbSpec;
} {
  const description = (what: string) => ({
    en: `Synthetic ${what} test database for documentation ranges (step 8.4); not real data`,
  });
  return {
    city: {
      databaseType: 'GeoLite2-City',
      description: description('City'),
      buildEpoch: spec.buildEpoch,
      networks: spec.networks.map((n) => ({ cidr: n.cidr, data: cityRecord(n) })),
    },
    asn: {
      databaseType: 'GeoLite2-ASN',
      description: description('ASN'),
      buildEpoch: spec.buildEpoch,
      networks: spec.networks.map((n) => ({
        cidr: n.cidr,
        data: {
          autonomous_system_number: mmdb.uint32(n.asn),
          autonomous_system_organization: n.asnOrg,
        },
      })),
    },
    anonymous: {
      databaseType: 'GeoIP2-Anonymous-IP',
      description: description('Anonymous IP'),
      buildEpoch: spec.buildEpoch,
      networks: spec.networks
        .filter((n) => n.anonymous !== null)
        .map((n) => ({
          cidr: n.cidr,
          data: {
            is_anonymous: true,
            ...(n.anonymous?.vpn && { is_anonymous_vpn: true }),
            ...(n.anonymous?.publicProxy && { is_public_proxy: true }),
            ...(n.anonymous?.torExitNode && { is_tor_exit_node: true }),
            ...(n.anonymous?.hostingProvider && { is_hosting_provider: true }),
            ...(n.anonymous?.residentialProxy && { is_residential_proxy: true }),
          },
        })),
    },
  };
}

/** Builds the three synthetic databases (deterministic bytes). */
export function buildSyntheticGeoIp(spec: SyntheticGeoSpec = SYNTHETIC_GEOIP): {
  city: Buffer;
  asn: Buffer;
  anonymous: Buffer;
} {
  const specs = syntheticGeoIpSpecs(spec);
  return {
    city: writeMmdb(specs.city),
    asn: writeMmdb(specs.asn),
    anonymous: writeMmdb(specs.anonymous),
  };
}

/** File names of the committed fixtures. */
export const SYNTHETIC_GEOIP_FILES = Object.freeze({
  spec: 'synthetic-geoip.json',
  city: 'synthetic-city.mmdb',
  asn: 'synthetic-asn.mmdb',
  anonymous: 'synthetic-anonymous.mmdb',
});
