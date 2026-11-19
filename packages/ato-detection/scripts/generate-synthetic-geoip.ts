/**
 * `pnpm --filter @email-gateway/ato-detection geoip:synthetic` (step 8.4 D7): writes
 * `test-fixtures/geoip/synthetic-{city,asn,anonymous}.mmdb` from `synthetic-geoip.json` with the
 * test kit's minimal MMDB writer. Deterministic: rerunning produces byte-identical files (a unit
 * test asserts it). Synthetic documentation-range data only; production uses operator-provided
 * MaxMind databases.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
  buildSyntheticGeoIp,
  SYNTHETIC_GEOIP_FILES,
  type SyntheticGeoSpec,
} from '../src/testing/synthetic-geoip';

const dir = resolve(__dirname, '..', 'test-fixtures', 'geoip');
const spec = JSON.parse(
  readFileSync(join(dir, SYNTHETIC_GEOIP_FILES.spec), 'utf8'),
) as SyntheticGeoSpec;
const built = buildSyntheticGeoIp(spec);
for (const kind of ['city', 'asn', 'anonymous'] as const) {
  writeFileSync(join(dir, SYNTHETIC_GEOIP_FILES[kind]), built[kind]);
  process.stdout.write(`wrote ${SYNTHETIC_GEOIP_FILES[kind]} (${built[kind].length} bytes)\n`);
}
