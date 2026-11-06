import {
  URL_CODE_EFFECTS,
  isUrlReasonCode,
  mostSevereVerdict,
  sortCodes,
  type UrlVerdict,
} from './codes';

/**
 * Engine-level aggregation (U10 "Engine level", U0, E1): the outcome of the `url` engine for one
 * round from the per-URL verdicts and the message codes.
 */

export const MAX_ENGINE_REASON_CODES = 32;
export const MAX_ENGINE_SIGNALS = 200;
/** security-contracts MAX_SIGNAL_OPTIONS. */
export const MAX_SIGNAL_OPTIONS = 5;

/** Message codes that raise the engine verdict to at least suspicious. */
const RAISING_MESSAGE_CODES = [
  'url.script_scheme',
  'url.data_uri',
  'url.unsafe_scheme',
  'limit.url_count',
] as const;

export interface EngineAggregationInput {
  /**
   * Extraction complete (E1 false): parse row final, no `body_size` or structural limit in
   * `limits_exceeded`.
   */
  contentComplete: boolean;
  urls: ReadonlyArray<{ seq: number; verdict: UrlVerdict; reasonCodes: readonly string[] }>;
  /** Message codes with counts (extraction). */
  messageCodes: Readonly<Partial<Record<string, number>>>;
}

export interface EngineSignal {
  name: string;
  score: number;
  options: string[];
}

export interface EngineAggregation {
  outcome: UrlVerdict | 'skipped';
  reasonCodes: string[];
  signals: EngineSignal[];
}

export function aggregateUrlEngine(input: EngineAggregationInput): EngineAggregation {
  const dangerous = RAISING_MESSAGE_CODES.filter((code) => (input.messageCodes[code] ?? 0) > 0);
  const scriptLike = ['url.script_scheme', 'url.data_uri', 'url.unsafe_scheme'].some(
    (code) => (input.messageCodes[code] ?? 0) > 0,
  );

  // U0: complete extraction, zero http(s) URLs and zero dangerous-scheme links.
  if (input.contentComplete && input.urls.length === 0 && !scriptLike && dangerous.length === 0) {
    return { outcome: 'skipped', reasonCodes: ['url.none'], signals: [] };
  }

  const codes = new Set<string>();
  const seqsByCode = new Map<string, number[]>();
  for (const url of input.urls) {
    for (const code of url.reasonCodes) {
      codes.add(code);
      const seqs = seqsByCode.get(code) ?? [];
      seqs.push(url.seq);
      seqsByCode.set(code, seqs);
    }
  }
  const verdicts: UrlVerdict[] = input.urls.map((u) => u.verdict);
  for (const code of dangerous) {
    codes.add(code);
    verdicts.push('suspicious');
  }
  if (!input.contentComplete) {
    codes.add('url.content_incomplete');
    verdicts.push('suspicious');
  }
  let outcome = mostSevereVerdict(verdicts) ?? 'unknown';
  // clean.no_findings stays only when the engine outcome is clean.
  if (outcome !== 'clean') codes.delete('clean.no_findings');
  if (outcome === 'clean' && codes.size === 0) codes.add('clean.no_findings');
  // Never clean with a raising code present (defensive: the inputs come from the mapper).
  if (
    outcome === 'clean' &&
    [...codes].some(
      (c) =>
        isUrlReasonCode(c) && URL_CODE_EFFECTS[c] !== 'none' && URL_CODE_EFFECTS[c] !== 'clean',
    )
  ) {
    outcome = 'unknown';
  }

  const reasonCodes = sortCodes(codes, MAX_ENGINE_REASON_CODES);
  const signals: EngineSignal[] = sortCodes(codes)
    .slice(0, MAX_ENGINE_SIGNALS)
    .map((code) => ({
      name: `url:${code}`,
      score: 0,
      options: (seqsByCode.get(code) ?? []).slice(0, MAX_SIGNAL_OPTIONS).map((seq) => `seq ${seq}`),
    }));
  return { outcome, reasonCodes, signals };
}
