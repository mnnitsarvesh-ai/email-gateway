import {
  levelRank,
  platformProfile,
  RISK_ACTIONS,
  RISK_DEFAULT_PLATFORM_PROFILE_ID,
  RISK_HARD_BLOCK_IDS,
  RISK_LEVELS,
  RISK_SCORER_VERSION,
  RISK_SIGNAL_MAP_VERSION,
  RISK_VERDICTS,
  type RiskResult,
  scoreRisk,
} from '../src/index';
import { DATASET_CLASSES, DATASET_ID, type DatasetClass, type DatasetFixture } from './dataset';

/**
 * The calibration report (step 5.1 §9.2): every fixture of `risk-calibration-1` scored with the
 * platform default profile, summarized as per-class score distributions, confusion matrices of the
 * produced levels against the classes and against the labelled bands, hard-block and failure-floor
 * counts, and the rationale of the thresholds and weights. `calibrate:check` regenerates it and
 * compares it with the committed docs/performance/risk-scoring-calibration.md.
 */

export const REPORT_PATH = '../../docs/performance/risk-scoring-calibration.md';

export const DISCLAIMER =
  '**"Synthetic, self-constructed data. These numbers show that the defaults behave as designed on the cases we wrote; they are not detection accuracy, precision or recall, and no such claim is made without a validated real-world dataset."**';

export interface ScoredFixture {
  fixture: DatasetFixture;
  result: RiskResult;
}

export interface ClassSummary {
  cls: DatasetClass;
  count: number;
  min: number;
  p10: number;
  p50: number;
  p90: number;
  max: number;
  histogram: number[];
  levels: Record<string, number>;
  actions: Record<string, number>;
  inBand: number;
  belowBand: number;
  aboveBand: number;
}

export function scoreDataset(fixtures: readonly DatasetFixture[]): ScoredFixture[] {
  const profile = platformProfile(RISK_DEFAULT_PLATFORM_PROFILE_ID);
  return fixtures.map((fixture) => ({ fixture, result: scoreRisk(fixture.input, profile) }));
}

/** Nearest-rank percentile of sorted integers. */
const percentile = (sorted: readonly number[], q: number): number =>
  sorted[Math.max(0, Math.ceil(q * sorted.length) - 1)] ?? 0;

const bucket = (score: number): number => Math.min(9, Math.floor(score / 100));

export function summarize(scored: readonly ScoredFixture[]): ClassSummary[] {
  return DATASET_CLASSES.map((cls) => {
    const rows = scored.filter((s) => s.fixture.class === cls);
    const scores = rows.map((r) => r.result.score).sort((a, b) => a - b);
    const histogram = Array.from({ length: 10 }, () => 0);
    const levels = Object.fromEntries(RISK_LEVELS.map((l) => [l, 0]));
    const actions = Object.fromEntries(RISK_ACTIONS.map((a) => [a, 0]));
    let inBand = 0;
    let belowBand = 0;
    let aboveBand = 0;
    for (const { fixture, result } of rows) {
      histogram[bucket(result.score)]! += 1;
      levels[result.level]! += 1;
      actions[result.recommendedAction]! += 1;
      const [min, max] = fixture.expectedLevelBand;
      if (levelRank(result.level) < levelRank(min)) belowBand += 1;
      else if (levelRank(result.level) > levelRank(max)) aboveBand += 1;
      else inBand += 1;
    }
    return {
      cls,
      count: rows.length,
      min: scores[0] ?? 0,
      p10: percentile(scores, 0.1),
      p50: percentile(scores, 0.5),
      p90: percentile(scores, 0.9),
      max: scores[scores.length - 1] ?? 0,
      histogram,
      levels,
      actions,
      inBand,
      belowBand,
      aboveBand,
    };
  });
}

const table = (header: string[], rows: (string | number)[][]): string =>
  [
    `| ${header.join(' | ')} |`,
    `| ${header.map(() => '---').join(' | ')} |`,
    ...rows.map((r) => `| ${r.join(' | ')} |`),
  ].join('\n');

/** The report markdown (before Prettier formatting). */
export function reportMarkdown(scored: readonly ScoredFixture[]): string {
  const summaries = summarize(scored);
  const total = scored.length;
  const outOfBand = scored.filter(({ fixture, result }) => {
    const [min, max] = fixture.expectedLevelBand;
    return levelRank(result.level) < levelRank(min) || levelRank(result.level) > levelRank(max);
  });
  const hardBlockCounts = RISK_HARD_BLOCK_IDS.map((id) => [
    id,
    ...DATASET_CLASSES.map(
      (cls) =>
        scored.filter(
          (s) => s.fixture.class === cls && s.result.hardBlocks.some((h) => h.id === id),
        ).length,
    ),
  ]);
  const floorSources = [
    'engine_failure',
    'engine_unknown',
    'engine_malicious',
    'bec_suspicious',
  ] as const;
  const floorCounts = floorSources.map((source) => [
    source,
    ...DATASET_CLASSES.map(
      (cls) =>
        scored.filter(
          (s) => s.fixture.class === cls && s.result.floors.some((f) => f.source === source),
        ).length,
    ),
  ]);
  const raisedByFloor = scored.filter((s) => {
    const noFloor = s.result.groups.reduce((sum, g) => sum + g.total, 0);
    return s.result.hardBlocks.length === 0 && s.result.score > Math.min(1000, noFloor);
  }).length;
  const bands = [...new Set(scored.map((s) => s.fixture.expectedLevelBand.join('–')))];

  const lines: string[] = [];
  lines.push('# Risk scoring calibration report (`rsk-default/1`)');
  lines.push('');
  lines.push(
    `Generated by \`pnpm --filter @email-gateway/risk-scoring calibrate\` from the synthetic dataset \`${DATASET_ID}\` (\`packages/risk-scoring/fixtures/calibration/risk-calibration-1.jsonl\`, ${total} fixtures), scored with the platform default profile \`${RISK_DEFAULT_PLATFORM_PROFILE_ID}\`, scorer \`${RISK_SCORER_VERSION}\` and signal map \`${RISK_SIGNAL_MAP_VERSION}\`. Do not edit by hand: \`calibrate:check\` (a unit test) fails when this file differs from the regenerated report. Design: [step 5.1 §9.2](../plan/steps/15-risk-scoring.md), [ADR-0041](../architecture/adr/0041-risk-scoring-model.md).`,
  );
  lines.push('');
  lines.push(`> ${DISCLAIMER}`);
  lines.push('');
  lines.push('## Dataset');
  lines.push('');
  lines.push(
    'Every fixture is a `risk-input/1` built by `buildScoringInput` from round rows that use only codes and outcomes the real verdict maps (`rspamd-map/2`, `attachment-map/1`, `url-map/1`, `bec-map/1`, `dlp-map/1`) can produce; `dataset.test.ts` validates every code against its engine code list and the outcome/code consistency rules. The rows carry no addresses, domains, URLs or text. Each fixture is labelled with its class and an expected level band, written by hand from the design rationale below before scoring. The labels describe what the defaults are designed to do with a case; they are not ground truth about real mail.',
  );
  lines.push('');
  lines.push(
    table(
      ['Class', 'Fixtures', 'What it contains'],
      [
        [
          'clean',
          classCount(scored, 'clean'),
          'complete clean rounds in every direction, with reason-only hygiene noise (SPF-only failure, Bayes spam, Office macros, a first contact)',
        ],
        [
          'clean_trusted',
          classCount(scored, 'clean_trusted'),
          'authenticated trusted senders (BEC T1, DMARC pass) with content-type signals the trust factor reduces',
        ],
        [
          'spam',
          classCount(scored, 'spam'),
          'GTUBE / reject action, tenant spam score or fuzzy spam (with Bayes and IP listing), suspicious score with domain reputation',
        ],
        [
          'phishing',
          classCount(scored, 'phishing'),
          'known phishing URLs, lookalike links with credential forms, link mismatch with authentication failure, brand display-name lookalikes',
        ],
        [
          'bec',
          classCount(scored, 'bec'),
          'deterministic malicious BEC, impersonation with payment intent, lookalike senders, AI-only raises',
        ],
        [
          'malware',
          classCount(scored, 'malware'),
          'known hash / ClamAV / YARA high attachments, malware and C2 URLs',
        ],
        [
          'dlp',
          classCount(scored, 'dlp'),
          'outbound and internal DLP findings with every tenant action, partial coverage',
        ],
        [
          'failure',
          classCount(scored, 'failure'),
          'timeouts and errors, two failures, missing finals, missing BEC/DLP rows, unknown results, missing authentication rows',
        ],
        [
          'spoof',
          classCount(scored, 'spoof'),
          'tenant-domain spoofs under `p=reject` and `p=quarantine`, DMARC reject spoofs of other domains',
        ],
      ],
    ),
  );
  lines.push('');
  lines.push('## Score distribution per class');
  lines.push('');
  lines.push(
    table(
      ['Class', 'n', 'min', 'p10', 'p50', 'p90', 'max'],
      summaries.map((s) => [s.cls, s.count, s.min, s.p10, s.p50, s.p90, s.max]),
    ),
  );
  lines.push('');
  lines.push('Histogram (10 buckets of 100 points; the last bucket includes 1000):');
  lines.push('');
  lines.push(
    table(
      [
        'Class',
        '0–99',
        '100–199',
        '200–299',
        '300–399',
        '400–499',
        '500–599',
        '600–699',
        '700–799',
        '800–899',
        '900–1000',
      ],
      summaries.map((s) => [s.cls, ...s.histogram]),
    ),
  );
  lines.push('');
  lines.push('## Produced levels against classes');
  lines.push('');
  lines.push(
    table(
      ['Class', ...RISK_LEVELS],
      summaries.map((s) => [s.cls, ...RISK_LEVELS.map((l) => s.levels[l] ?? 0)]),
    ),
  );
  lines.push('');
  lines.push('Recommended actions:');
  lines.push('');
  lines.push(
    table(
      ['Class', ...RISK_ACTIONS],
      summaries.map((s) => [s.cls, ...RISK_ACTIONS.map((a) => s.actions[a] ?? 0)]),
    ),
  );
  lines.push('');
  lines.push('Verdicts (`bulk` is never produced by `risk-signals/1`):');
  lines.push('');
  lines.push(
    table(
      ['Class', ...RISK_VERDICTS.filter((v) => v !== 'bulk')],
      DATASET_CLASSES.map((cls) => [
        cls,
        ...RISK_VERDICTS.filter((v) => v !== 'bulk').map(
          (v) => scored.filter((s) => s.fixture.class === cls && s.result.verdict === v).length,
        ),
      ]),
    ),
  );
  lines.push('');
  lines.push(
    'Rounds with a failed, missing or `unknown` required engine or a missing result row are never `clean`; an `unknown` result alone adds the unknown floors (level `low`, action `tag`: it is never recommended for plain delivery), while a failed engine or a missing authentication, BEC or DLP row always adds the failure floor (`medium`, `quarantine`).',
  );
  lines.push('');
  lines.push('## Produced levels against the labelled bands');
  lines.push('');
  lines.push(
    table(
      ['Class', 'in band', 'below band', 'above band'],
      summaries.map((s) => [s.cls, s.inBand, s.belowBand, s.aboveBand]),
    ),
  );
  lines.push('');
  lines.push(
    table(
      ['Expected band', 'fixtures', ...RISK_LEVELS],
      bands.map((band) => {
        const rows = scored.filter((s) => s.fixture.expectedLevelBand.join('–') === band);
        return [
          band,
          rows.length,
          ...RISK_LEVELS.map((l) => rows.filter((r) => r.result.level === l).length),
        ];
      }),
    ),
  );
  lines.push('');
  if (outOfBand.length === 0) {
    lines.push('Every fixture falls inside its labelled band.');
  } else {
    lines.push(
      `${outOfBand.length} fixtures fall outside their labelled band. The labels were not changed to match the scores; each miss is analysed in the step note (docs/plan/steps/15-risk-scoring.md §12.2):`,
    );
    lines.push('');
    lines.push(
      table(
        ['Fixture', 'Band', 'Produced', 'Score', 'Top reason codes'],
        outOfBand.slice(0, 50).map(({ fixture, result }) => [
          fixture.id,
          fixture.expectedLevelBand.join('–'),
          result.level,
          result.score,
          result.reasonCodes
            .slice(0, 4)
            .map((c) => `\`${c}\``)
            .join(', '),
        ]),
      ),
    );
  }
  lines.push('');
  lines.push('## Hard blocks and floors');
  lines.push('');
  lines.push('Fixtures with each hard-block indicator (a fixture can fire several):');
  lines.push('');
  lines.push(table(['Indicator', ...DATASET_CLASSES], hardBlockCounts));
  lines.push('');
  lines.push('Fixtures with each floor applicable:');
  lines.push('');
  lines.push(table(['Floor', ...DATASET_CLASSES], floorCounts));
  lines.push('');
  lines.push(
    `${raisedByFloor} fixtures without a hard block had their score raised by a floor to the threshold of the floored level (R8: score and level agree).`,
  );
  lines.push('');
  lines.push('## Threshold rationale (`low 100`, `medium 300`, `high 550`, `critical 800`)');
  lines.push('');
  lines.push(
    '- **`low ≥ 100`**: one weak hygiene fact (an SPF-only failure 60, a long URL 40, urgency words 60, a first contact 40) stays below `low` on its own; Bayes spam (100), Office macros (100) or one DLP alert finding reach `low` and stay at `deliver` by default. An `unknown` engine (60 points, floor `low`, action floor `tag`) is always at least `low` and at least `tag`.',
  );
  lines.push(
    '- **`medium ≥ 300`**: the level of a single moderate, independent fact: the tenant spam score (450), a DMARC `reject` failure (300), a tenant-domain spoof without `p=reject` (400), a vendor or executive name impersonation with one intent cue, one failed required engine (300). Default action `tag`; the failure floor adds `quarantine` for failures.',
  );
  lines.push(
    "- **`high ≥ 550`**: reached by one strong phishing fact on its own (link mismatch with authentication failure 600), by Rspamd's own reject-level spam evidence (GTUBE, reject action 600), by combinations of independent groups (a lookalike link with a credential form 750, spam score plus IP listing 600) and by the `malicious` engine floor. Default action `quarantine`.",
  );
  lines.push(
    '- **`critical ≥ 800`**: a known phishing URL (800) or malware (1000) alone, or three independent strong groups; every hard block forces `critical`. Default action `quarantine`; `block` only where a hard block selects it (malware, DLP block).',
  );
  lines.push(
    '- The gaps (200, 250, 250) leave room for the bounded tenant thresholds (R10: `low` 50–250, `medium` 200–450, `high` 400–700, `critical` 650–950, ≥ 50 apart).',
  );
  lines.push('');
  lines.push('## Weight rationale (design R3)');
  lines.push('');
  lines.push(
    '- A single strong, independent phishing or malware fact reaches `high`/`critical` on its own (known phishing URL 800, malware 1000, credential link 450–500 with a lookalike 300–450).',
  );
  lines.push(
    "- Spam alone reaches `high` only for Rspamd's own reject-level evidence (GTUBE, reject action), otherwise `medium` (spam score, fuzzy spam 450) or `low` (suspicious score 200, Bayes 100).",
  );
  lines.push(
    '- Weak hygiene signals stay below `low` alone and add up only within capped groups (`auth_other` 150, `url_structure` 300, `bec_identity` 250, `bec_intent` 350, `bec_history` 150, `coverage` 200), so many weak cues of one kind never outweigh one strong fact.',
  );
  lines.push(
    '- Overlapping evidence shares a `max` group so it is counted once: DMARC failure and BEC tenant-domain spoofing (`auth_dmarc`), URL and BEC lookalikes (`lookalike`), ClamAV, YARA and known hashes (`attachment_malware`); the same fact from two engines (SPF failure from Rspamd and BEC) is one signal.',
  );
  lines.push(
    '- Failures and unknown results are explicit points (300 and 60) with level and action floors, so a failed or incomplete round is never `clean` and never delivered by the recommendation of a failed round.',
  );
  lines.push('');
  lines.push(`> ${DISCLAIMER}`);
  lines.push('');
  return lines.join('\n');
}

function classCount(scored: readonly ScoredFixture[], cls: DatasetClass): number {
  return scored.filter((s) => s.fixture.class === cls).length;
}

/** The report formatted by the repository's Prettier configuration (stable under `pnpm format`). */
export async function formattedReport(
  scored: readonly ScoredFixture[],
  filepath: string,
): Promise<string> {
  const prettier = await import('prettier');
  const options = (await prettier.resolveConfig(filepath)) ?? {};
  return prettier.format(reportMarkdown(scored), { ...options, filepath, parser: 'markdown' });
}
