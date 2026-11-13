import 'server-only';
import { createHash } from 'node:crypto';
import type { ListItem } from '@/lib/api/types';
import { SeededRandom, fixtureAnchor, paginate } from '../generator';
import { apiError, noContent, ok, type FixtureHandlers } from '../types';
import { bodyOf, withPrincipal, str } from './reports';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Platform threat intelligence (WP3): a known-threat hash catalogue and platform indicators
 * (synthetic `*.example.test` values), plus the tenant lookup that matches against both. Try
 * the lookup with `login.evil-example.test` (domain, known) or `example.com` (not known).
 */

type Hash = ListItem<'ThreatHashesController_list_v1'>;
type Indicator = ListItem<'ThreatIndicatorsController_list_v1'>;

const sha = (value: string) => createHash('sha256').update(value).digest('hex');
const anchor = fixtureAnchor();
const at = (daysAgo: number) => new Date(anchor - daysAgo * 86_400_000).toISOString();

interface TiState {
  hashes: Map<string, Hash>;
  indicators: Map<string, Indicator>;
  nextId: number;
}
const store = globalThis as typeof globalThis & { __egDevFixtureThreatIntel?: TiState };

function tiState(): TiState {
  if (store.__egDevFixtureThreatIntel) return store.__egDevFixtureThreatIntel;
  const r = new SeededRandom('threat-intel');
  const hashes = new Map<string, Hash>();
  for (let i = 0; i < 40; i += 1) {
    const h = sha(`synthetic-sample-${i}`);
    hashes.set(h, {
      sha256: h,
      md5: i % 3 === 0 ? createHash('md5').update(`synthetic-sample-${i}`).digest('hex') : null,
      severity: r.pick(['medium', 'high', 'critical'] as const),
      family:
        i % 4 === 0
          ? null
          : r.pick(['agenttesla-like', 'qakbot-like', 'emotet-like', 'invoice-dropper']),
      source: i % 5 === 0 ? 'sandbox' : i % 7 === 0 ? 'feed:synthetic' : 'analyst',
      reason: i % 5 === 0 ? 'Sandbox verdict malicious' : 'Seen in a synthetic campaign',
      expiresAt: i % 6 === 0 ? at(-30) : null,
      addedByUserId: null,
      firstSeenAt: at(40 - i),
      lastSeenAt: at(Math.max(0, 10 - i)),
      createdAt: at(40 - i),
      updatedAt: at(40 - i),
    });
  }
  const indicators = new Map<string, Indicator>();
  const values: [Indicator['type'], string, Indicator['category']][] = [
    ['domain', 'login.evil-example.test', 'phishing'],
    ['domain', 'invoice-portal.bad-example.test', 'phishing'],
    ['url', 'https://cdn.bad-example.test/payload.bin', 'malware'],
    ['ip', '192.0.2.66', 'c2'],
    ['domain', 'giftcards.scam-example.test', 'scam'],
    ...Array.from(
      { length: 30 },
      (_, i) =>
        ['domain', `tracker${i}.spam-example.test`, 'spam'] as [
          Indicator['type'],
          string,
          Indicator['category'],
        ],
    ),
  ];
  values.forEach(([type, value, category], i) => {
    const id = String(700 + i);
    indicators.set(id, {
      id,
      type,
      value,
      valueSha256: sha(value),
      severity: category === 'spam' ? 'low' : category === 'c2' ? 'critical' : 'high',
      category,
      source: i % 4 === 0 ? 'feed:synthetic' : 'analyst',
      reason: `Synthetic ${category} indicator`,
      expiresAt: i % 3 === 0 ? at(-60) : null,
      addedByUserId: null,
      firstSeenAt: at(30 - (i % 30)),
      lastSeenAt: at(i % 5),
      createdAt: at(30 - (i % 30)),
      updatedAt: at(30 - (i % 30)),
    });
  });
  store.__egDevFixtureThreatIntel = { hashes, indicators, nextId: 900 };
  return store.__egDevFixtureThreatIntel;
}

function normalize(type: string, value: string): string {
  if (type === 'domain') return value.toLowerCase().replace(/\.$/, '');
  if (type === 'sha256') return value.toLowerCase();
  return value;
}

export const fixtures: FixtureHandlers = {
  ThreatIntelligenceController_lookup_v1: (request) =>
    withPrincipal(request, () => {
      const type = request.query.get('type');
      const raw = request.query.get('value') ?? '';
      if (!type || !['sha256', 'url', 'domain', 'ip'].includes(type) || !raw)
        return apiError(400, 'validation_failed', ['value: required']);
      const value = normalize(type, raw);
      const state = tiState();
      const matches: {
        source: 'platform_indicator' | 'hash_catalog';
        severity: Hash['severity'];
        category: Indicator['category'];
        firstSeenAt: string;
        lastSeenAt: string;
        expiresAt: string | null;
      }[] = [];
      if (type === 'sha256') {
        const h = state.hashes.get(value);
        if (h)
          matches.push({
            source: 'hash_catalog',
            severity: h.severity,
            category: 'malware',
            firstSeenAt: h.firstSeenAt,
            lastSeenAt: h.lastSeenAt,
            expiresAt: h.expiresAt,
          });
      } else {
        for (const i of state.indicators.values()) {
          const domainMatch =
            type === 'domain' &&
            i.type === 'domain' &&
            (value === i.value || value.endsWith(`.${i.value}`));
          if ((i.type === type && i.value === value) || domainMatch)
            matches.push({
              source: 'platform_indicator',
              severity: i.severity,
              category: i.category,
              firstSeenAt: i.firstSeenAt,
              lastSeenAt: i.lastSeenAt,
              expiresAt: i.expiresAt,
            });
        }
      }
      return ok('ThreatIntelligenceController_lookup_v1', {
        type: type as 'sha256' | 'url' | 'domain' | 'ip',
        valueSha256: sha(value),
        known: matches.length > 0,
        matches,
      });
    }),

  ThreatHashesController_list_v1: (request) =>
    withPrincipal(request, () => {
      const source = request.query.get('source');
      const filter = request.query.get('sha256');
      const rows = [...tiState().hashes.values()].filter(
        (h) => (!source || h.source === source) && (!filter || h.sha256 === filter),
      );
      return { status: 200, body: paginate(rows, request.query) };
    }),

  ThreatHashesController_add_v1: (request) =>
    withPrincipal(request, () => {
      const b = bodyOf(request);
      const h = str(b, 'sha256', '');
      if (!/^[0-9a-f]{64}$/.test(h))
        return apiError(400, 'validation_failed', ['sha256: 64 lower-case hexadecimal characters']);
      const state = tiState();
      if (state.hashes.has(h))
        return apiError(409, 'hash_exists', 'This hash is already in the catalogue');
      const now = new Date().toISOString();
      const row: Hash = {
        sha256: h,
        md5: typeof b.md5 === 'string' ? b.md5 : null,
        severity: b.severity as Hash['severity'],
        family: typeof b.family === 'string' ? b.family : null,
        source: 'analyst',
        reason: str(b, 'reason', ''),
        expiresAt: typeof b.expiresAt === 'string' ? b.expiresAt : null,
        addedByUserId: null,
        firstSeenAt: now,
        lastSeenAt: now,
        createdAt: now,
        updatedAt: now,
      };
      state.hashes.set(h, row);
      return ok('ThreatHashesController_add_v1', row, 201);
    }),

  ThreatHashesController_remove_v1: (request) =>
    withPrincipal(request, () => {
      if (!request.query.get('reason'))
        return apiError(400, 'validation_failed', ['reason: required']);
      return tiState().hashes.delete(request.params.sha256 ?? '')
        ? noContent()
        : apiError(404, 'threat_hash_not_found', 'Hash not found');
    }),

  ThreatIndicatorsController_list_v1: (request) =>
    withPrincipal(request, () => {
      const q = request.query;
      if (q.get('value') && !q.get('type'))
        return apiError(400, 'validation_failed', ['value: requires type']);
      const rows = [...tiState().indicators.values()].filter(
        (i) =>
          (!q.get('type') || i.type === q.get('type')) &&
          (!q.get('source') || i.source === q.get('source')) &&
          (!q.get('value') || i.value === normalize(i.type, q.get('value') ?? '')),
      );
      return { status: 200, body: paginate(rows, q) };
    }),

  ThreatIndicatorsController_add_v1: (request) =>
    withPrincipal(request, () => {
      const b = bodyOf(request);
      const state = tiState();
      const type = b.type as Indicator['type'];
      const value = normalize(type, str(b, 'value', ''));
      if ([...state.indicators.values()].some((i) => i.type === type && i.value === value))
        return apiError(409, 'indicator_exists', 'This indicator already exists');
      const now = new Date().toISOString();
      const id = String((state.nextId += 1));
      const row: Indicator = {
        id,
        type,
        value,
        valueSha256: sha(value),
        severity: b.severity as Indicator['severity'],
        category: b.category as Indicator['category'],
        source: 'analyst',
        reason: str(b, 'reason', ''),
        expiresAt: typeof b.expiresAt === 'string' ? b.expiresAt : null,
        addedByUserId: null,
        firstSeenAt: now,
        lastSeenAt: now,
        createdAt: now,
        updatedAt: now,
      };
      state.indicators.set(id, row);
      return ok('ThreatIndicatorsController_add_v1', row, 201);
    }),

  ThreatIndicatorsController_remove_v1: (request) =>
    withPrincipal(request, () => {
      if (!request.query.get('reason'))
        return apiError(400, 'validation_failed', ['reason: required']);
      return tiState().indicators.delete(request.params.id ?? '')
        ? noContent()
        : apiError(404, 'threat_indicator_not_found', 'Indicator not found');
    }),
};
