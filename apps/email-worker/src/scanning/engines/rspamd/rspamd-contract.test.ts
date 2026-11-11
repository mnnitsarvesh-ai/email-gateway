import { Readable } from 'node:stream';
import type {
  NormalizedRspamdResult,
  RspamdAuthResults,
  RspamdCheckResult,
} from '@email-gateway/rspamd';
import {
  isRspamdReasonCode,
  resolveRspamdSettings,
  RSPAMD_MAPPING_VERSION as CONTRACT_MAPPING_VERSION,
  RSPAMD_PLATFORM_DEFAULTS,
  RSPAMD_REASON_CODES,
  type RspamdEffectiveSettings,
} from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import type { EngineScanContext } from '../../engine';
import { RspamdEngine } from './rspamd.engine';
import { SYMBOL_CATEGORIES, type SymbolMatcher } from './symbol-catalog';
import { mapRspamdVerdict, RSPAMD_MAPPING_VERSION } from './verdict-mapper';

/**
 * Step 5.1 R18: `RSPAMD_REASON_CODES` of @email-gateway/security-contracts is exactly what the
 * Rspamd engine can emit. This drives the mapper through every rule (R1–R10) with every symbol of
 * every category of the catalog, under the platform and tenant settings that change a rule's
 * branch, plus the engine's own size refusal, and checks both directions: nothing outside the
 * contract list, and every listed code reachable. The risk scorer's exhaustiveness test relies
 * on the list, so a new mapper code must be added there (and to the signal map) first.
 */

const effective = (override: Record<string, unknown> | null): RspamdEffectiveSettings => {
  const r = resolveRspamdSettings(RSPAMD_PLATFORM_DEFAULTS, override);
  if (!r.ok) throw new Error(JSON.stringify(r.violations));
  return r.settings;
};

const SETTINGS: RspamdEffectiveSettings[] = [
  effective(null),
  effective({ phishingVerdict: 'malicious' }),
  effective({ authFailureVerdict: 'suspicious' }),
  effective({ dmarcRejectVerdict: 'malicious' }),
];

const noAuth = (): RspamdAuthResults => ({
  spf: { result: null, domain: null },
  dkim: { result: null, signatures: [] },
  dmarc: { result: null, policy: null, domain: null },
  arc: { result: null },
});
const dmarcFailAuth = (): RspamdAuthResults => ({
  ...noAuth(),
  dmarc: { result: 'fail', policy: 'reject', domain: null },
  spf: { result: 'fail', domain: null },
});

type Symbol = NormalizedRspamdResult['symbols'][number];
const sym = (name: string, score = 0.1, options: string[] = []): Symbol => ({
  name,
  score,
  options,
});

function reply(
  symbols: Symbol[],
  extra: Partial<NormalizedRspamdResult> = {},
): NormalizedRspamdResult {
  return {
    score: 0,
    requiredScore: 15,
    action: 'no action',
    skipped: false,
    passthroughModule: null,
    symbols,
    symbolsTruncated: false,
    auth: noAuth(),
    ...extra,
  };
}

/** One symbol per exact name, prefix and positive-only name of every category. */
function catalogSymbols(): Symbol[] {
  const out: Symbol[] = [];
  for (const matcher of Object.values(SYMBOL_CATEGORIES) as SymbolMatcher[]) {
    for (const name of matcher.exact ?? []) out.push(sym(name));
    for (const prefix of matcher.prefixes ?? []) out.push(sym(`${prefix}CONTRACT`));
    for (const name of matcher.positive ?? []) out.push(sym(name, 1), sym(name, -1));
  }
  return out;
}

/** Every reply shape that reaches a different branch of R1–R10 under `settings`. */
function replies(settings: RspamdEffectiveSettings): NormalizedRspamdResult[] {
  const all: NormalizedRspamdResult[] = [];
  const trustedArc = [
    sym('ARC_ALLOW', -1, ['sealer.test:s=a:i=2']),
    sym('ARC_ALLOW_TRUSTED', -0.1, ['sealer.test:s=a:i=2']),
  ];
  for (const symbol of catalogSymbols()) {
    for (const score of [0, settings.suspiciousScore, settings.spamScore]) {
      all.push(reply([symbol], { score }));
      all.push(reply([symbol], { score, auth: dmarcFailAuth() }));
      all.push(reply([symbol, ...trustedArc], { score }));
    }
    all.push(reply([symbol], { action: 'reject', score: 20 }));
    all.push(reply([symbol], { passthroughModule: 'multimap' }));
  }
  all.push(reply([sym('R_SPF_ALLOW')], { skipped: true }));
  all.push(reply([]));
  all.push(reply([sym('R_SPF_ALLOW')], { score: 0.1 }));
  all.push(reply([sym('GTUBE')], { passthroughModule: 'GTUBE', action: 'reject' }));
  all.push(reply([sym('DMARC_POLICY_REJECT'), ...trustedArc]));
  all.push(reply([sym('DMARC_POLICY_QUARANTINE'), ...trustedArc]));
  return all;
}

async function tooLargeCodes(): Promise<string[]> {
  const engine = new RspamdEngine({
    client: {
      check: (): Promise<RspamdCheckResult> => Promise.reject(new Error('must not be called')),
      version: () => Promise.resolve('3.12.1'),
    },
    maxBytes: 4,
    versionTtlMs: 60_000,
    controllerConfigured: true,
  });
  const ctx = {
    organizationId: 42n,
    messageId: 7n,
    receivedAt: new Date(),
    round: 0,
    scanId: 9n,
    scanKind: 'initial',
    direction: 'inbound',
    envelope: {
      clientIp: null,
      clientHelo: null,
      clientName: null,
      envelopeFrom: '',
      recipients: [],
      queueId: null,
    },
    eml: {
      key: 'org/42/eml/x.eml',
      sizeBytes: 5,
      open: () => Promise.resolve(Readable.from([Buffer.from('hello')])),
    },
    settings: SETTINGS[0]!,
    settingsVersion: 'rspamd-map/2;p=000000000000;t=none',
  } satisfies EngineScanContext;
  const outcome = await engine.scan(ctx, AbortSignal.timeout(1000));
  if (outcome.kind !== 'definite') throw new Error('expected a definite result');
  return outcome.result.reasonCodes;
}

describe('Rspamd reason codes contract (step 5.1 R18)', () => {
  it('the mapping version equals the contract version', () => {
    expect(RSPAMD_MAPPING_VERSION).toBe(CONTRACT_MAPPING_VERSION);
    expect(RSPAMD_MAPPING_VERSION).toBe('rspamd-map/2');
  });

  it('the mapper and the engine emit only listed codes, and every listed code is reachable', async () => {
    const emitted = new Set<string>();
    for (const settings of SETTINGS) {
      for (const r of replies(settings)) {
        for (const code of mapRspamdVerdict(r, settings).reasonCodes) emitted.add(code);
      }
    }
    for (const code of await tooLargeCodes()) emitted.add(code);
    const outside = [...emitted].filter((code) => !isRspamdReasonCode(code));
    expect(outside).toEqual([]);
    const unreached = RSPAMD_REASON_CODES.filter((code) => !emitted.has(code));
    expect(unreached).toEqual([]);
    expect(emitted.has('engine.too_large')).toBe(true);
  });
});
