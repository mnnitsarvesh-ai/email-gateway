import {
  canonicalJson,
  RISK_ACTIONS,
  RISK_HARD_BLOCK_IDS,
  RISK_LEVELS,
} from '@email-gateway/risk-scoring';
import { describe, expect, it } from 'vitest';
import { leavesOf } from './conditions';
import { validatePolicyDefinition } from './definition';
import { evaluatePolicy } from './evaluate';
import { POLICY_FIELDS, type PolicyFieldName } from './fields';
import { DEPT, PID, sampleValue, snapshotOf, type Def } from './fixtures.test-support';
import { computeFloor } from './floor';
import { POLICY_PLATFORM_DEFAULTS } from './platform';
import { policyEvaluationResultSchema } from './result';
import type { CompiledSnapshot } from './snapshot';
import { buildSyntheticInput, type SyntheticFacts } from './synthetic';
import { dispositionRank, POLICY_HOLD_DISPOSITIONS, type PolicyDisposition } from './vocabulary';
import type { PolicyInput } from './input';

/** mulberry32: a small seeded PRNG (deterministic test data). */
function prng(seed: number) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n: number) => Math.floor(next() * n);
  const pick = <T>(xs: readonly T[]): T => xs[int(xs.length)]!;
  const chance = (p: number) => next() < p;
  const subset = <T>(xs: readonly T[], max = xs.length): T[] =>
    xs.filter(() => chance(0.3)).slice(0, max);
  return { next, int, pick, chance, subset };
}
type Rng = ReturnType<typeof prng>;

const DOMAINS = [
  'corp.example',
  'partner.example',
  'evil.test',
  'bücher.example',
  'mail.example.org',
  'qzx.example.co.uk',
];
const word = (r: Rng, n = 7) =>
  Array.from({ length: n }, () => r.pick([...'bcdfghjkmnpqrvwxz'])).join('');
const domain = (r: Rng) => (r.chance(0.4) ? `${word(r, 4)}.${r.pick(DOMAINS)}` : r.pick(DOMAINS));
const address = (r: Rng) => `${word(r, 6)}@${domain(r)}`;
const EXTS = ['pdf', 'iso', 'zip', 'exe', 'docx', 'html'];
const CODES = [
  'spam.gtube',
  'archive.encrypted',
  'url.phishing',
  'malware.clamav',
  'bec.trusted_sender',
  'risk.level.high',
];

function randomRisk(r: Rng) {
  const recommendedAction = r.pick(RISK_ACTIONS);
  const hardBlocks = r.chance(0.15)
    ? [{ id: r.pick(RISK_HARD_BLOCK_IDS), action: r.pick(['quarantine', 'block'] as const) }]
    : [];
  return {
    status: r.chance(0.05) ? ('error' as const) : ('scored' as const),
    score: r.int(1001),
    level: r.pick(RISK_LEVELS),
    verdict: r.pick([
      'clean',
      'spam',
      'phishing',
      'malware',
      'bec',
      'suspicious',
      'unknown',
    ] as const),
    recommendedAction,
    hardBlocks,
    reasonCodes: r.subset(CODES, 4),
    failureStatuses: r.chance(0.15)
      ? [r.pick(['timeout', 'error', 'missing', 'row_missing', 'unknown'] as const)]
      : [],
    aiRaiseOnly: r.chance(0.1),
    ...(r.chance(0.3)
      ? { sandboxOutcome: r.pick(['clean', 'malicious', 'unknown'] as const) }
      : {}),
  };
}

export function randomFacts(r: Rng): SyntheticFacts {
  const recipients = Array.from({ length: r.int(5) }, () => ({ address: address(r) }));
  const departments: Record<string, string[]> = {};
  for (const rc of recipients)
    if (r.chance(0.4)) departments[rc.address] = r.subset(Object.values(DEPT)).sort();
  const envelope = r.chance(0.1) ? null : address(r);
  if (envelope && r.chance(0.5)) departments[envelope] = [DEPT.finance];
  return {
    trigger: r.chance(0.8) ? 'scanned' : r.pick(['scan_failed', 'parse_failed'] as const),
    direction: r.pick(['inbound', 'outbound', 'internal'] as const),
    evaluationTime: new Date(Date.UTC(2026, 0, 1) + r.int(365 * 24 * 60) * 60_000).toISOString(),
    sender: {
      envelope,
      headerFrom: r.chance(0.8) ? envelope : address(r),
      authenticated: r.chance(0.5),
    },
    recipients,
    client: {
      ip: r.pick([null, '10.1.2.3', '198.51.100.7', '2001:db8::25', '::ffff:10.9.9.9']),
      hostname: r.chance(0.5) ? `mx.${domain(r)}` : null,
    },
    auth: r.chance(0.7)
      ? {
          spf: r.pick(['pass', 'fail'] as const),
          dkim: r.pick(['pass', 'none'] as const),
          dmarc: r.pick(['pass', 'fail', 'none'] as const),
          dmarcPolicy: 'reject',
          arc: 'none',
        }
      : null,
    attachments: Array.from({ length: r.int(4) }, () => ({
      filename: r.chance(0.9) ? `${word(r)}.${r.pick(EXTS)}` : null,
      declaredType: r.pick(['application/pdf', 'application/zip', 'text/html']),
      detectedType: r.pick(['pdf', 'zip', 'iso9660', 'pe']),
      typeFamily: r.pick(['document', 'archive', 'disk_image', 'executable'] as const),
      sizeBytes: r.int(5_000_000),
      verdict: r.pick([null, 'clean', 'suspicious', 'malicious', 'unknown'] as const),
      reasonCodes: r.chance(0.8) ? r.subset(CODES, 3) : null,
      encrypted: r.chance(0.1),
      typeMismatch: r.pick([null, true, false]),
    })),
    urls: Array.from({ length: r.int(4) }, () => ({
      host: r.chance(0.1) ? '192.0.2.44' : `${word(r, 5)}.${r.pick(DOMAINS)}`,
      verdict: r.pick([null, 'clean', 'suspicious', 'malicious'] as const),
      reasonCodes: r.subset(CODES, 2),
    })),
    urlRewriteStatus: r.pick(['rewritten', 'skipped', 'none'] as const),
    risk: r.chance(0.1)
      ? null
      : { rev0: r.chance(0.05) ? null : randomRisk(r), rev1: r.chance(0.2) ? randomRisk(r) : null },
    dlp: r.chance(0.5)
      ? {
          action: r.pick(['allow', 'alert', 'require_approval', 'quarantine', 'block'] as const),
          categories: r.subset(['payment_card', 'national_id'] as const),
          maxSeverity: r.pick([null, 'low', 'high'] as const),
        }
      : null,
    ...(r.chance(0.2)
      ? { dlpFinal: r.pick(['definite', 'skipped', 'failed', 'absent'] as const) }
      : {}),
    bec: r.chance(0.6)
      ? {
          deterministicVerdict: r.pick(['clean', 'suspicious', 'malicious', 'unknown'] as const),
          verdict: r.pick(['clean', 'suspicious', 'malicious'] as const),
          aiRaised: r.chance(0.2),
          trustedCode: r.pick(['authenticated', 'none'] as const),
        }
      : null,
    scan: {
      verdict: r.pick([null, 'clean', 'spam', 'malicious'] as const),
      engines: r.subset([
        { engine: 'url', outcome: 'unknown' as const },
        { engine: 'dlp', outcome: 'timeout' as const },
      ]),
    },
    directory: { departments },
  };
}

// ---------------------------------------------------------------------------------------------
// Random valid policies
// ---------------------------------------------------------------------------------------------

const FIELD_NAMES = Object.keys(POLICY_FIELDS) as PolicyFieldName[];

function leafValue(r: Rng, field: PolicyFieldName, op: string): unknown {
  const def = POLICY_FIELDS[field];
  if (def.type === 'domain' && ['equals'].includes(op)) return r.pick(DOMAINS);
  if (def.type === 'domain' && ['in', 'not_in', 'domain_in'].includes(op))
    return r.subset(DOMAINS).concat(r.pick(DOMAINS));
  if (def.type === 'enum' && op === 'in')
    return [...new Set([r.pick(def.values!), r.pick(def.values!)])];
  if (def.type === 'enum' && ['equals', 'gte', 'lte'].includes(op)) return r.pick(def.values!);
  if (def.type === 'int' && ['gt', 'gte', 'lt', 'lte', 'eq'].includes(op))
    return r.int(Math.min(def.max!, 2000));
  if (def.type === 'id') return r.subset(Object.values(DEPT)).concat(DEPT.finance);
  if (def.type === 'codes' && !def.values) return [r.pick(CODES)];
  if (def.type === 'codes' && def.values) return [r.pick(def.values)];
  if (field === 'attachment.extension') return [r.pick(EXTS)];
  if (field === 'attachment.filename' && op === 'glob') return [`*.${r.pick(EXTS)}`];
  if (op === 'is') return r.chance(0.5);
  if (op === 'in_cidr') return [r.pick(['10.0.0.0/8', '2001:db8::/32', '198.51.100.0/24'])];
  if (op === 'within' && field === 'time.window') {
    return {
      timeZone: r.pick([
        'Asia/Kolkata',
        'America/New_York',
        'Europe/London',
        'Australia/Lord_Howe',
      ]),
      days: r.subset(['mon', 'tue', 'wed', 'sat', 'sun']).concat('fri'),
      from: r.pick(['00:00', '09:00', '22:00']),
      to: r.pick(['06:00', '17:00', '24:00']),
    };
  }
  return sampleValue(field, op);
}

function randomLeaf(r: Rng, exception: boolean): Record<string, unknown> {
  const field = r.pick(FIELD_NAMES);
  const def = POLICY_FIELDS[field];
  const op = r.pick(def.ops);
  const value = leafValue(r, field, op);
  const leaf: Record<string, unknown> = { field, op };
  if (value !== undefined) leaf.value = value;
  if (def.quantified) {
    if (exception) leaf.quantifier = 'all';
    else if (r.chance(0.5)) leaf.quantifier = r.pick(['any', 'all']);
  }
  return leaf;
}

function randomNode(r: Rng, depth: number, exception: boolean): unknown {
  const roll = r.next();
  if (depth >= 3 || roll < 0.5) return randomLeaf(r, exception);
  if (!exception && roll < 0.6) return { not: randomNode(r, depth + 1, exception) };
  const kind = r.chance(0.5) ? 'all' : 'any';
  return {
    [kind]: Array.from({ length: 1 + r.int(3) }, () => randomNode(r, depth + 1, exception)),
  };
}

function randomActions(r: Rng): Array<Record<string, unknown>> {
  const actions: Array<Record<string, unknown>> = [];
  if (r.chance(0.7)) {
    const type = r.pick(['ALLOW', 'REQUIRE_APPROVAL', 'QUARANTINE', 'REJECT']);
    actions.push(
      type === 'REJECT' && r.chance(0.5) ? { type, notifySender: r.chance(0.5) } : { type },
    );
  }
  if (r.chance(0.3))
    actions.push({
      type: 'TAG',
      label: r.pick(['ext', 'vip', 'x-1']),
      ...(r.chance(0.3) ? { subjectPrefix: '[EXT]' } : {}),
      ...(r.chance(0.2) ? { addHeader: false } : {}),
    });
  if (r.chance(0.2))
    actions.push({
      type: 'WARN',
      level: r.pick(['caution', 'warning', 'danger']),
      ...(r.chance(0.5) ? { text: 'Check the sender' } : {}),
    });
  if (r.chance(0.15))
    actions.push({ type: 'URL_REWRITE', ifNotRewritten: r.pick(['deliver', 'quarantine']) });
  if (r.chance(0.15)) actions.push({ type: 'ARCHIVE' });
  if (r.chance(0.15))
    actions.push({ type: 'ALERT', severity: r.pick(['info', 'warning', 'critical']) });
  if (actions.length === 0) actions.push({ type: 'TAG', label: 'fallback' });
  return actions;
}

function randomPolicy(r: Rng): Def {
  const direction = r.pick(['inbound', 'outbound', 'internal', 'any']);
  const rules: Array<Record<string, unknown>> = [];
  const count = 1 + r.int(6);
  for (let i = 0; rules.length < count && i < count * 30; i += 1) {
    const actions = randomActions(r);
    const hasDisposition = actions.some((a) =>
      ['ALLOW', 'REQUIRE_APPROVAL', 'QUARANTINE', 'REJECT'].includes(a.type as string),
    );
    const candidate: Record<string, unknown> = {
      id: `r${rules.length}`,
      priority: rules.length * 10 + r.int(10),
      when: randomNode(r, 1, false),
      actions,
      ...(r.chance(0.3) ? { unless: [randomNode(r, 1, true)] } : {}),
      ...(r.chance(0.2) ? { stop: r.chance(0.5) } : {}),
      ...(hasDisposition && r.chance(0.3) ? { override: true } : {}),
      ...(r.chance(0.05) ? { enabled: false } : {}),
    };
    if (
      validatePolicyDefinition({
        dslVersion: 'policy-dsl/1',
        direction,
        priority: 1,
        rules: [candidate],
      }).ok
    )
      rules.push(candidate);
  }
  const doc: Def = { dslVersion: 'policy-dsl/1', direction, priority: r.int(1000), rules };
  if (r.chance(0.15)) {
    const ex = randomNode(r, 1, true);
    if (validatePolicyDefinition({ ...doc, exceptions: [ex] }).ok) doc.exceptions = [ex];
  }
  return doc;
}

// ---------------------------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------------------------

const pd = POLICY_PLATFORM_DEFAULTS['pol-default/1']!;
const atLeast = (a: PolicyDisposition, b: PolicyDisposition) =>
  dispositionRank(a) >= dispositionRank(b);

function contentOf(input: PolicyInput): string[] {
  const out = new Set<string>();
  const add = (v: string | null | undefined) => {
    if (v && v.length >= 4) out.add(v);
  };
  for (const a of [input.sender.envelope, input.sender.headerFrom, input.sender.authenticated]) {
    add(a?.address);
    add(a?.domain);
  }
  for (const r of input.recipients) {
    add(r.address);
    add(r.domain);
  }
  for (const a of input.attachments.items) add(a.filename);
  for (const u of input.urls.items) {
    add(u.host);
    add(u.domain);
  }
  add(input.client.hostname);
  return [...out];
}

function checkInvariants(input: PolicyInput, compiled: CompiledSnapshot) {
  const result = evaluatePolicy(input, compiled);
  const floor = computeFloor(input, pd);
  if (floor.disposition !== null) expect(atLeast(result.disposition, floor.disposition)).toBe(true);
  for (const rev of [input.risk.rev0, input.risk.rev1]) {
    for (const hb of rev?.hardBlocks ?? []) {
      expect(atLeast(result.disposition, pd.riskActionMap[hb.action])).toBe(true);
    }
    if (rev && !rev.levelOnly)
      expect(atLeast(result.disposition, pd.riskActionMap[rev.recommendedAction])).toBe(true);
  }
  if (input.trigger !== 'parse_failed' && input.risk.rev0 === null) {
    expect(atLeast(result.disposition, 'quarantine')).toBe(true);
  }
  if (input.trigger !== 'scanned') expect(atLeast(result.disposition, 'quarantine')).toBe(true);
  if (input.dlp) {
    const binding = pd.dlpBinding[input.dlp.action];
    if (binding) expect(atLeast(result.disposition, binding)).toBe(true);
  }
  // No hold decided by an AI-derived rule.
  if (
    result.decisive.source === 'tenant_rule' &&
    POLICY_HOLD_DISPOSITIONS.includes(result.disposition)
  ) {
    const rule = compiled.policies
      .flatMap((p) => p.rules)
      .find(
        (r) =>
          r.policyPublicId === result.decisive.policyPublicId &&
          r.ruleId === result.decisive.ruleId,
      )!;
    expect(
      [rule.when, ...rule.unless].some((n) => [...leavesOf(n)].some((l) => l.def.aiDerived)),
    ).toBe(false);
  }
  // An override never goes below the floor and needs flag + setting + level-only.
  if (result.override !== null) {
    expect(compiled.settings.allowRecommendationOverrides).toBe(true);
    expect(result.recommendation.levelOnly).toBe(true);
  }
  // Explanation and delivery headers never carry message content.
  const text = result.explanation.text;
  expect(text.length).toBeLessThanOrEqual(2048);
  expect(text.includes('@') || text.includes('://')).toBe(false);
  const headers = JSON.stringify(result.delivery ?? {});
  for (const c of contentOf(input)) {
    expect(text.includes(c), c).toBe(false);
    expect(headers.includes(c), c).toBe(false);
  }
  return result;
}

describe('determinism', () => {
  it('same input and snapshot → deep-equal results and identical canonical JSON', () => {
    const r = prng(7);
    for (let i = 0; i < 200; i += 1) {
      const compiled = snapshotOf([randomPolicy(r), randomPolicy(r)]);
      const input = buildSyntheticInput(randomFacts(r));
      const a = evaluatePolicy(input, compiled);
      const b = evaluatePolicy(structuredClone(input), compiled);
      expect(b).toEqual(a);
      expect(canonicalJson(b)).toBe(canonicalJson(a));
    }
  });
  it('recompiling the same source gives the same result', () => {
    const r = prng(11);
    const defs = [randomPolicy(r), randomPolicy(r), randomPolicy(r)];
    const facts = randomFacts(r);
    const a = evaluatePolicy(buildSyntheticInput(facts), snapshotOf(defs));
    const b = evaluatePolicy(
      buildSyntheticInput(structuredClone(facts)),
      snapshotOf(structuredClone(defs)),
    );
    expect(canonicalJson(b)).toBe(canonicalJson(a));
  });
  it('key order of the input does not change the hash or the result', () => {
    const input = buildSyntheticInput(randomFacts(prng(3)));
    const shuffled = Object.fromEntries(Object.entries(input).reverse()) as PolicyInput;
    const compiled = snapshotOf([]);
    expect(evaluatePolicy(shuffled, compiled).inputSha256).toBe(
      evaluatePolicy(input, compiled).inputSha256,
    );
  });
});

describe('property: 10 000 seeded random inputs × random valid policies', () => {
  it('never throw and always satisfy the strictness contract', () => {
    const r = prng(20261111);
    const snapshots: CompiledSnapshot[] = [];
    for (let s = 0; s < 200; s += 1) {
      const defs = Array.from({ length: r.int(4) }, () => randomPolicy(r));
      const compiled = snapshotOf(
        defs.map((def, k) => ({ def, publicId: Object.values(PID)[k]! })),
        {
          settings: {
            allowRecommendationOverrides: r.chance(0.5),
            notices: { senderNonDelivery: r.chance(0.5) },
            tagging: { platformTagOutbound: r.chance(0.3) },
          },
          generation: String(s),
        },
      );
      expect(compiled.invalid).toEqual([]);
      snapshots.push(compiled);
    }
    let holds = 0;
    let overrides = 0;
    let tenantDecided = 0;
    for (let i = 0; i < 10_000; i += 1) {
      const input = buildSyntheticInput(randomFacts(r));
      const result = checkInvariants(input, snapshots[i % snapshots.length]!);
      if (i % 50 === 0) policyEvaluationResultSchema.parse(result);
      if (result.disposition !== 'allow') holds += 1;
      if (result.override) overrides += 1;
      if (result.decisive.source === 'tenant_rule') tenantDecided += 1;
    }
    // The generator exercises every path (not only floors).
    expect(holds).toBeGreaterThan(1000);
    expect(tenantDecided).toBeGreaterThan(100);
    expect(overrides).toBeGreaterThan(0);
  });
});
