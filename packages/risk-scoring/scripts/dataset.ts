import type { EngineOutcome } from '@email-gateway/security-contracts';
import {
  buildScoringInput,
  canonicalJson,
  type RiskLevel,
  type RoundRows,
  type ScoringInput,
} from '../src/index';
import { Prng } from './prng';

/**
 * The synthetic calibration dataset `risk-calibration-1` (step 5.1 §9.2). Every fixture is a
 * `ScoringInput` assembled by `buildScoringInput` from round rows that use only codes and
 * outcomes the real verdict maps can produce (validated by `dataset.test.ts`), plus a label
 * `{ class, expectedLevelBand }`. Never real mail and never personal data: no addresses, domains,
 * URLs or text at all. Deterministic: a seeded PRNG and fixed timestamps, so `dataset:check`
 * can regenerate the committed file byte for byte.
 */

export const DATASET_ID = 'risk-calibration-1';
export const DATASET_SEED = 0x5101_2026;
export const DATASET_PATH = 'fixtures/calibration/risk-calibration-1.jsonl';

export const DATASET_CLASSES = [
  'clean',
  'clean_trusted',
  'spam',
  'phishing',
  'bec',
  'malware',
  'dlp',
  'failure',
  'spoof',
] as const;
export type DatasetClass = (typeof DATASET_CLASSES)[number];

/** Class sizes of §9.2. */
export const DATASET_CLASS_SIZES: Readonly<Record<DatasetClass, number>> = Object.freeze({
  clean: 200,
  clean_trusted: 50,
  spam: 150,
  phishing: 150,
  bec: 150,
  malware: 100,
  dlp: 100,
  failure: 100,
  spoof: 50,
});

export interface DatasetFixture {
  id: string;
  class: DatasetClass;
  expectedLevelBand: [RiskLevel, RiskLevel];
  input: ScoringInput;
}

type Engine = 'rspamd' | 'attachment' | 'url' | 'bec' | 'dlp';
type Direction = RoundRows['message']['direction'];

interface EngineDraft {
  outcome: EngineOutcome;
  codes: string[];
}

/** A round under construction (codes and outcomes only). */
interface Draft {
  direction: Direction;
  attachments: number;
  status: RoundRows['scan']['status'];
  engines: Partial<Record<Engine, EngineDraft>>;
  auth: RoundRows['auth'];
  bec: {
    det: string;
    verdict: string;
    rules: { code: string; suppressed: 'trust' | null }[];
  } | null;
  dlp: { action: string; verdict: string; coverage: string; severities: string[] } | null;
}

const PASS_AUTH: NonNullable<RoundRows['auth']> = {
  spf: 'pass',
  dkim: 'pass',
  dmarc: 'pass',
  dmarcPolicy: 'none',
  arc: 'none',
};

const RSPAMD_INFORMATIONAL = ['bayes.ham', 'fuzzy.unknown'] as const;
const URL_INFORMATIONAL = [
  'url.shortened',
  'url.redirected',
  'url.idn',
  'url.in_attachment',
] as const;

const REQUIRED: readonly Engine[] = ['rspamd', 'attachment', 'url', 'bec', 'dlp'];

/** A clean round in `direction`, the starting point of every class. */
function baseDraft(rng: Prng, direction: Direction): Draft {
  const attachments = rng.int(0, 3);
  const policy = rng.pick(['none', 'quarantine', 'reject'] as const);
  const draft: Draft = {
    direction,
    attachments,
    status: 'completed',
    engines: {
      rspamd: {
        outcome: 'clean',
        codes: ['clean.below_threshold', ...rng.sample(RSPAMD_INFORMATIONAL, rng.int(0, 1))],
      },
      attachment:
        attachments === 0
          ? { outcome: 'skipped', codes: ['attachment.none'] }
          : { outcome: 'clean', codes: ['clean.no_findings'] },
      url: rng.chance(0.25)
        ? { outcome: 'skipped', codes: ['url.none'] }
        : {
            outcome: 'clean',
            codes: ['clean.no_findings', ...rng.sample(URL_INFORMATIONAL, rng.int(0, 2))],
          },
    },
    auth: { ...PASS_AUTH, dmarcPolicy: policy },
    bec: null,
    dlp: null,
  };
  if (direction === 'inbound') {
    draft.engines.bec = { outcome: 'clean', codes: ['clean.below_threshold'] };
    draft.bec = { det: 'clean', verdict: 'clean', rules: [] };
    draft.engines.dlp = { outcome: 'skipped', codes: ['dlp.not_inbound'] };
  } else {
    draft.engines.bec = { outcome: 'skipped', codes: ['bec.not_inbound'] };
    draft.engines.dlp = { outcome: 'clean', codes: ['dlp.no_findings'] };
    draft.dlp = { action: 'allow', verdict: 'clean', coverage: 'complete', severities: [] };
  }
  return draft;
}

/** Sets the BEC result from its active rules (the final carries the same codes). */
function setBec(
  draft: Draft,
  det: 'clean' | 'suspicious' | 'malicious',
  rules: string[],
  options: { suppressed?: string[]; verdict?: string; extraCodes?: string[] } = {},
): void {
  const verdict = options.verdict ?? det;
  const codes = [...rules, ...(options.extraCodes ?? [])];
  draft.engines.bec = {
    outcome: verdict as EngineOutcome,
    codes: codes.length > 0 ? codes : ['clean.below_threshold'],
  };
  draft.bec = {
    det,
    verdict,
    rules: [
      ...rules.map((code) => ({ code, suppressed: null })),
      ...(options.suppressed ?? []).map((code) => ({ code, suppressed: 'trust' as const })),
    ],
  };
}

const unique = (codes: string[]): string[] => [...new Set(codes)];

function toRows(draft: Draft, index: number): RoundRows {
  const completedAt = new Date(Date.UTC(2026, 0, 1, 0, 0, 0) + index * 1000);
  const finals: RoundRows['finals'][number][] = [];
  for (const engine of REQUIRED) {
    const e = draft.engines[engine];
    if (!e) continue;
    const failed = e.outcome === 'timeout' || e.outcome === 'error';
    finals.push({
      engine,
      outcome: e.outcome,
      errorCode: failed ? (e.outcome === 'timeout' ? 'engine.timeout' : 'engine.error') : null,
      reasonCodes: unique(e.codes),
      score: null,
      engineVersion: `${engine}/synthetic-1`,
      settingsVersion: `${engine}-map/synthetic-1`,
      attempt: failed ? 3 : 1,
      completedAt,
    });
  }
  return {
    scan: {
      requiredEngines: [...REQUIRED],
      scanKind: 'initial',
      lifecycleRound: 1,
      status: draft.status,
    },
    message: { direction: draft.direction, attachmentCount: draft.attachments, recipientCount: 1 },
    finals,
    auth: draft.auth,
    bec: draft.bec
      ? { deterministicVerdict: draft.bec.det, verdict: draft.bec.verdict, rules: draft.bec.rules }
      : null,
    dlp: draft.dlp
      ? {
          action: draft.dlp.action,
          verdict: draft.dlp.verdict,
          coverage: draft.dlp.coverage,
          categories: draft.dlp.severities.map((maxSeverity) => ({ maxSeverity })),
        }
      : null,
  };
}

type Built = { draft: Draft; band: [RiskLevel, RiskLevel] };

// ---------------------------------------------------------------------------------------------
// Class generators
// ---------------------------------------------------------------------------------------------

function clean(rng: Prng): Built {
  const direction = rng.pick([
    'inbound',
    'inbound',
    'inbound',
    'inbound',
    'outbound',
    'internal',
  ] as const);
  const draft = baseDraft(rng, direction);
  // Hygiene noise that Rspamd reports without raising its verdict (R7 reason-only, R9).
  if (direction === 'inbound' && rng.chance(0.15))
    draft.engines.rspamd!.codes.push('auth.spf_fail');
  if (direction === 'inbound' && rng.chance(0.15)) draft.engines.rspamd!.codes.push('bayes.spam');
  if (draft.attachments > 0 && rng.chance(0.1))
    draft.engines.attachment!.codes.push('office.macros');
  if (direction === 'inbound' && rng.chance(0.2)) {
    setBec(draft, 'clean', [rng.pick(['bec.history.first_contact', 'bec.content.urgency'])]);
  }
  return { draft, band: ['none', 'low'] };
}

function cleanTrusted(rng: Prng): Built {
  const draft = baseDraft(rng, 'inbound');
  draft.auth = { ...PASS_AUTH, dmarcPolicy: rng.pick(['quarantine', 'reject'] as const) };
  if (rng.chance(0.6)) {
    draft.engines.rspamd = {
      outcome: 'suspicious',
      codes: ['spam.suspicious_score', ...rng.sample(['bayes.spam'], rng.int(0, 1))],
    };
  }
  if (draft.engines.url!.outcome !== 'skipped' && rng.chance(0.3)) {
    draft.engines.url = { outcome: 'suspicious', codes: ['url.new_domain'] };
  }
  // T1 neutralizes identity, history and intent rules inside the BEC engine (suppressed: trust).
  const suppressed = rng.sample(
    [
      'bec.content.payment_request',
      'bec.content.invoice_change',
      'bec.content.urgency',
      'bec.history.first_contact',
    ],
    rng.int(0, 2),
  );
  setBec(draft, 'clean', ['bec.trusted_sender'], { suppressed });
  return { draft, band: ['none', 'low'] };
}

function spam(rng: Prng): Built {
  const direction = rng.chance(0.9) ? 'inbound' : 'outbound';
  const draft = baseDraft(rng, direction);
  const kind = rng.pick(['strong', 'score', 'score', 'score', 'grey', 'grey'] as const);
  if (kind === 'strong') {
    draft.engines.rspamd = {
      outcome: 'spam',
      codes: [
        rng.pick(['spam.gtube', 'spam.reject_action']),
        ...rng.sample(['bayes.spam'], rng.int(0, 1)),
      ],
    };
    return { draft, band: ['high', 'high'] };
  }
  if (kind === 'score') {
    const codes = [
      rng.pick(['spam.score', 'fuzzy.spam']),
      ...rng.sample(['bayes.spam'], rng.int(0, 1)),
    ];
    if (direction === 'inbound' && rng.chance(0.4)) codes.push('reputation.ip_listed');
    draft.engines.rspamd = { outcome: 'spam', codes };
    return { draft, band: ['medium', 'high'] };
  }
  draft.engines.rspamd = {
    outcome: 'suspicious',
    codes: [
      'spam.suspicious_score',
      ...rng.sample(['bayes.spam', 'reputation.domain_listed'], rng.int(0, 1)),
    ],
  };
  if (draft.engines.url!.outcome !== 'skipped' && rng.chance(0.3)) {
    draft.engines.url = {
      outcome: 'suspicious',
      codes: [rng.pick(['url.new_domain', 'url.dnsbl_spam'])],
    };
  }
  return { draft, band: ['low', 'medium'] };
}

function phishing(rng: Prng): Built {
  const draft = baseDraft(rng, 'inbound');
  const kind = rng.pick(['known_url', 'credential', 'credential', 'link_auth', 'brand'] as const);
  if (kind === 'known_url') {
    draft.engines.url = {
      outcome: 'malicious',
      codes: [
        rng.pick(['url.feed_malicious', 'url.dnsbl_phishing', 'url.phishing_high_confidence']),
        ...rng.sample(['url.shortened', 'url.redirected'], rng.int(0, 1)),
      ],
    };
    if (rng.chance(0.3))
      draft.engines.rspamd = { outcome: 'malicious', codes: ['phishing.known_bad_url'] };
    return { draft, band: ['critical', 'critical'] };
  }
  if (kind === 'credential') {
    draft.engines.url = {
      outcome: 'suspicious',
      codes: [
        rng.pick([
          'url.lookalike_homoglyph',
          'url.lookalike_combosquat',
          'url.lookalike_edit_distance',
        ]),
        rng.pick(['url.credential_form', 'url.credential_form_cross_origin']),
        ...rng.sample(['url.new_domain', 'url.text_mismatch'], rng.int(0, 1)),
      ],
    };
    setBec(draft, 'suspicious', [
      'bec.link.lookalike',
      rng.pick(['bec.link.credential_form', 'bec.link.credential_harvesting']),
    ]);
    return { draft, band: ['high', 'critical'] };
  }
  if (kind === 'link_auth') {
    draft.engines.rspamd = {
      outcome: 'malicious',
      codes: ['phishing.link_mismatch_auth_failure', 'auth.spf_fail'],
    };
    draft.auth = { ...PASS_AUTH, spf: 'fail', dmarc: rng.pick(['pass', 'none'] as const) };
    return { draft, band: ['high', 'critical'] };
  }
  draft.engines.rspamd = { outcome: 'suspicious', codes: ['phishing.link_mismatch'] };
  setBec(draft, 'suspicious', ['bec.display_name.brand_mismatch', 'bec.lookalike.sender_brand']);
  return { draft, band: ['high', 'critical'] };
}

function bec(rng: Prng): Built {
  const draft = baseDraft(rng, 'inbound');
  const kind = rng.pick([
    'malicious',
    'impersonation',
    'impersonation',
    'impersonation',
    'lookalike',
    'lookalike',
    'ai_only',
  ] as const);
  if (kind === 'malicious') {
    setBec(draft, 'malicious', [
      rng.pick([
        'bec.impersonation.executive_freemail',
        'bec.impersonation.executive_reply_to',
        'bec.impersonation.vendor_unauthenticated',
      ]),
      rng.pick([
        'bec.vendor.payment_change',
        'bec.content.bank_detail_change',
        'bec.content.wire_transfer',
        'bec.content.gift_card',
      ]),
      ...rng.sample(
        ['bec.content.urgency', 'bec.content.secrecy', 'bec.reply_to.freemail'],
        rng.int(0, 2),
      ),
    ]);
    return { draft, band: ['critical', 'critical'] };
  }
  if (kind === 'impersonation') {
    setBec(draft, 'suspicious', [
      rng.pick([
        'bec.impersonation.executive_name',
        'bec.impersonation.vendor_name',
        'bec.impersonation.vendor_unauthenticated',
      ]),
      rng.pick([
        'bec.content.payment_request',
        'bec.content.wire_transfer',
        'bec.content.urgency',
        'bec.content.secrecy',
        'bec.content.gift_card',
      ]),
      ...rng.sample(['bec.reply_to.freemail', 'bec.reply_to.domain_mismatch'], rng.int(0, 1)),
    ]);
    return { draft, band: ['medium', 'high'] };
  }
  if (kind === 'lookalike') {
    setBec(draft, 'suspicious', [
      rng.pick([
        'bec.lookalike.sender_vendor',
        'bec.lookalike.sender_tenant',
        'bec.history.first_contact_lookalike',
      ]),
      rng.pick([
        'bec.vendor.payment_change',
        'bec.content.invoice_change',
        'bec.content.payment_request',
      ]),
      ...rng.sample(
        ['bec.history.first_contact', 'bec.history.first_contact_payment'],
        rng.int(0, 1),
      ),
    ]);
    return { draft, band: ['medium', 'high'] };
  }
  // The AI layer alone raised the verdict (ADR-0034): at most a tag.
  setBec(
    draft,
    'clean',
    rng.sample(['bec.content.urgency', 'bec.history.first_contact'], rng.int(0, 1)),
    {
      verdict: 'suspicious',
      extraCodes: ['bec.ai.flagged'],
    },
  );
  return { draft, band: ['none', 'low'] };
}

function malware(rng: Prng): Built {
  const draft = baseDraft(rng, rng.chance(0.85) ? 'inbound' : 'outbound');
  const kind = rng.pick(['attachment', 'attachment', 'attachment', 'url', 'rspamd_url'] as const);
  if (kind === 'attachment') {
    draft.attachments = Math.max(1, draft.attachments);
    draft.engines.attachment = {
      outcome: 'malicious',
      codes: [
        ...rng.sample(['malware.known_hash', 'malware.clamav', 'yara.high'], rng.int(1, 3)),
        ...rng.sample(
          ['type.mismatch', 'filename.double_extension', 'office.macros'],
          rng.int(0, 1),
        ),
      ],
    };
  } else if (kind === 'url') {
    draft.engines.url = {
      outcome: 'malicious',
      codes: [rng.pick(['url.dnsbl_malware', 'url.dnsbl_c2'])],
    };
  } else {
    draft.engines.rspamd = { outcome: 'malicious', codes: ['malware.known_bad_url'] };
  }
  return { draft, band: ['critical', 'critical'] };
}

function dlp(rng: Prng): Built {
  const draft = baseDraft(rng, rng.chance(0.85) ? 'outbound' : 'internal');
  const action = rng.pick(['alert', 'alert', 'require_approval', 'quarantine', 'block'] as const);
  const severities = rng.sample(['medium', 'high', 'critical', 'low'], rng.int(1, 2));
  const coverage = rng.chance(0.2) ? 'partial' : 'complete';
  const codes = [
    rng.pick([
      'dlp.payment_card.number',
      'dlp.bank_account.iban',
      'dlp.national_id.india_pan',
      'dlp.credential.private_key',
    ]),
    `dlp.action.${action}`,
    ...(coverage === 'partial' ? ['dlp.coverage.partial', 'dlp.not_extracted.encrypted'] : []),
  ];
  draft.engines.dlp = { outcome: 'suspicious', codes };
  draft.dlp = { action, verdict: 'suspicious', coverage, severities };
  const band: Record<typeof action, [RiskLevel, RiskLevel]> = {
    alert: ['low', 'medium'],
    require_approval: ['medium', 'medium'],
    quarantine: ['medium', 'medium'],
    block: ['critical', 'critical'],
  };
  return { draft, band: band[action] };
}

function failure(rng: Prng): Built {
  const direction = rng.chance(0.8) ? 'inbound' : 'outbound';
  const draft = baseDraft(rng, direction);
  const kind = rng.pick([
    'failed',
    'failed',
    'two_failed',
    'missing',
    'row_missing',
    'unknown',
    'url_unknown',
    'auth_missing',
  ] as const);
  const failEngine = (engine: Engine) => {
    draft.engines[engine] = { outcome: rng.pick(['timeout', 'error'] as const), codes: [] };
    if (engine === 'bec') draft.bec = null;
    if (engine === 'dlp') draft.dlp = null;
    if (engine === 'rspamd') draft.auth = null;
    draft.status = 'failed';
  };
  switch (kind) {
    case 'failed':
      failEngine(rng.pick(REQUIRED));
      return { draft, band: ['medium', 'high'] };
    case 'two_failed':
      for (const engine of rng.sample(REQUIRED, 2)) failEngine(engine);
      return { draft, band: ['medium', 'high'] };
    case 'missing': {
      const engine = rng.pick(REQUIRED);
      delete draft.engines[engine];
      if (engine === 'bec') draft.bec = null;
      if (engine === 'dlp') draft.dlp = null;
      if (engine === 'rspamd') draft.auth = null;
      draft.status = 'timed_out';
      return { draft, band: ['medium', 'high'] };
    }
    case 'row_missing':
      if (direction === 'inbound') {
        setBec(draft, 'suspicious', [
          rng.pick(['bec.content.urgency', 'bec.reply_to.domain_mismatch']),
        ]);
        draft.bec = null;
      } else {
        draft.engines.dlp = {
          outcome: 'suspicious',
          codes: ['dlp.payment_card.number', 'dlp.action.alert'],
        };
        draft.dlp = null;
      }
      return { draft, band: ['medium', 'high'] };
    case 'unknown':
      draft.engines.rspamd = {
        outcome: 'unknown',
        codes: [rng.pick(['engine.too_large', 'engine.skipped', 'engine.empty_result'])],
      };
      draft.auth = null;
      return { draft, band: ['low', 'low'] };
    case 'url_unknown':
      draft.engines.url = {
        outcome: 'unknown',
        codes: [
          rng.pick(['url.fetch_timeout', 'url.fetch_dns_error', 'url.reputation_unavailable']),
        ],
      };
      return { draft, band: ['low', 'medium'] };
    case 'auth_missing':
      // A successful Rspamd check always writes email_auth_results: a missing row is a lost
      // input, scored like a missing BEC/DLP row (R2, R6; review round 1).
      draft.auth = null;
      return { draft, band: ['medium', 'high'] };
  }
}

function spoof(rng: Prng): Built {
  const draft = baseDraft(rng, 'inbound');
  const kind = rng.pick(['tenant_reject', 'tenant_quarantine', 'generic_reject'] as const);
  const authFails = rng.sample(['auth.spf_fail', 'auth.dkim_fail'], rng.int(1, 2));
  const becAuth = authFails.map((c) => `bec.${c}`);
  if (kind === 'tenant_reject') {
    draft.engines.rspamd = { outcome: 'suspicious', codes: ['auth.dmarc_reject', ...authFails] };
    draft.auth = { spf: 'fail', dkim: 'fail', dmarc: 'fail', dmarcPolicy: 'reject', arc: 'none' };
    setBec(draft, 'suspicious', [
      'bec.auth.tenant_domain_spoof',
      'bec.auth.dmarc_fail',
      ...becAuth,
    ]);
    return { draft, band: ['critical', 'critical'] };
  }
  if (kind === 'tenant_quarantine') {
    draft.engines.rspamd = {
      outcome: 'suspicious',
      codes: ['auth.dmarc_quarantine', ...authFails],
    };
    draft.auth = {
      spf: 'fail',
      dkim: 'fail',
      dmarc: 'fail',
      dmarcPolicy: 'quarantine',
      arc: 'none',
    };
    setBec(draft, 'suspicious', [
      'bec.auth.tenant_domain_spoof',
      'bec.auth.dmarc_fail',
      ...becAuth,
    ]);
    return { draft, band: ['medium', 'high'] };
  }
  draft.engines.rspamd = { outcome: 'suspicious', codes: ['auth.dmarc_reject', ...authFails] };
  draft.auth = { spf: 'fail', dkim: 'fail', dmarc: 'fail', dmarcPolicy: 'reject', arc: 'none' };
  setBec(draft, 'suspicious', [
    'bec.auth.dmarc_fail',
    ...becAuth,
    ...rng.sample(['bec.display_name.obfuscated', 'bec.reply_to.domain_mismatch'], rng.int(0, 1)),
  ]);
  return { draft, band: ['medium', 'high'] };
}

const GENERATORS: Readonly<Record<DatasetClass, (rng: Prng) => Built>> = {
  clean,
  clean_trusted: cleanTrusted,
  spam,
  phishing,
  bec,
  malware,
  dlp,
  failure,
  spoof,
};

/** Generates every fixture (class order, then sequence). */
export function generateDataset(seed: number = DATASET_SEED): DatasetFixture[] {
  const rng = new Prng(seed);
  const fixtures: DatasetFixture[] = [];
  let index = 0;
  for (const cls of DATASET_CLASSES) {
    for (let n = 1; n <= DATASET_CLASS_SIZES[cls]; n += 1) {
      const { draft, band } = GENERATORS[cls](rng);
      fixtures.push({
        id: `${cls}-${String(n).padStart(3, '0')}`,
        class: cls,
        expectedLevelBand: band,
        input: buildScoringInput(toRows(draft, index), 0),
      });
      index += 1;
    }
  }
  return fixtures;
}

/** The JSONL text of the dataset (one canonical JSON object per line). */
export function datasetJsonl(fixtures: readonly DatasetFixture[] = generateDataset()): string {
  return `${fixtures.map((f) => canonicalJson(f)).join('\n')}\n`;
}

export function parseDatasetJsonl(text: string): DatasetFixture[] {
  return text
    .split('\n')
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as DatasetFixture);
}
