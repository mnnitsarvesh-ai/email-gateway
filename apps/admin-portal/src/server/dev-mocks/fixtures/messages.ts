import 'server-only';
import type { ListItem, OperationId, SuccessBody } from '@/lib/api/types';
import { canPerform } from '@/lib/auth/permissions';
import { SeededRandom, fixtureAnchor, stableUuid, syntheticPerson } from '../generator';
import {
  apiError,
  ok,
  type FixtureHandlers,
  type FixtureRequest,
  type FixtureResponse,
} from '../types';
import { resolveFixturePrincipal } from './session';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of the mail pages (WP5): the v1 message list with filters and scan-budget short
 * pages, message detail, scan rounds (engines, auth, risk, policy), attachments, URLs and policy
 * evaluations. Everything is synthetic (`*.example.test`, `example.com`); subjects, filenames,
 * symbol options and URLs deliberately include hostile and very long strings so the portal's
 * text-only rendering is exercised.
 */

type MessageDetail = SuccessBody<'MessagesController_detail_v1'>;
type ScanRound = ListItem<'MessageScansController_scansOf_v1'>;
type Evaluation = SuccessBody<'PolicyMessagesController_evaluations_v1'>['data'][number];
type AttachmentRow = ListItem<'AttachmentsController_ofMessage_v1'>;
type UrlRow = ListItem<'UrlProtectionController_ofMessage_v1'>;

export interface FixtureMessage {
  readonly detail: MessageDetail;
  readonly recipients: readonly string[];
  readonly attachments: readonly AttachmentRow[];
  readonly urls: readonly UrlRow[];
  readonly rounds: readonly ScanRound[];
  readonly evaluations: readonly Evaluation[];
}

/** 403 unless the caller's role grants the operation (mirrors `x-eg-permissions`). */
export function fixtureGuard(request: FixtureRequest): FixtureResponse | null {
  const principal = resolveFixturePrincipal(request.token);
  if (!principal) return apiError(401, 'unauthorized', 'Authentication required');
  if (!canPerform(request.operationId, principal.permissions)) {
    return apiError(403, 'forbidden', 'You do not have permission to perform this action');
  }
  return null;
}

/** Wraps a handler with the permission guard. */
export function guarded(
  handler: (request: FixtureRequest) => FixtureResponse | Promise<FixtureResponse>,
): (request: FixtureRequest) => FixtureResponse | Promise<FixtureResponse> {
  return (request) => fixtureGuard(request) ?? handler(request);
}

export const HOSTILE_SUBJECTS = [
  '<script>alert("xss")</script> Invoice 4471 overdue',
  '<img src=x onerror=alert(document.cookie)> Payment details changed',
  'Re: shared document ‮gnp.exe',
  `URGENT ${'wire transfer approval required — please confirm today '.repeat(8)}`.trim(),
  '"><svg/onload=alert(1)> Your mailbox is full',
] as const;

const NORMAL_SUBJECTS = [
  'Quarterly report Q3',
  'Team offsite agenda',
  'Your invoice from Bravo Logistics',
  'Password expiry notice',
  'Meeting notes: platform review',
  'Shipping confirmation #88231',
  'Weekly newsletter',
  'Contract draft for review',
] as const;

const VERDICTS = [
  'clean',
  'clean',
  'clean',
  'spam',
  'bulk',
  'phishing',
  'malware',
  'bec',
  'suspicious',
] as const;

function actionFor(verdict: (typeof VERDICTS)[number]): MessageDetail['finalAction'] {
  switch (verdict) {
    case 'clean':
      return 'deliver';
    case 'bulk':
      return 'tag';
    case 'spam':
    case 'phishing':
    case 'malware':
      return 'quarantine';
    case 'bec':
      return 'require_approval';
    default:
      return 'tag';
  }
}

function statusFor(action: MessageDetail['finalAction']): MessageDetail['status'] {
  if (action === 'quarantine') return 'quarantined';
  if (action === 'require_approval') return 'held_for_review';
  return 'delivered';
}

function riskFor(verdict: (typeof VERDICTS)[number], random: SeededRandom): number {
  switch (verdict) {
    case 'clean':
      return random.int(0, 180);
    case 'bulk':
      return random.int(150, 320);
    case 'spam':
      return random.int(350, 620);
    case 'suspicious':
      return random.int(450, 700);
    case 'bec':
      return random.int(700, 880);
    default:
      return random.int(820, 1000);
  }
}

const sha = (seed: string) =>
  Array.from({ length: 4 }, (_, i) => stableUuid(`${seed}:${i}`).replace(/-/g, ''))
    .join('')
    .slice(0, 64);

const HOSTILE_FILENAMES = [
  'invoice<script>.pdf',
  'report.pdf‮exe.scr',
  `${'very-long-file-name-'.repeat(6)}.docx`,
  'payroll.xlsm',
  'photo.png',
];

const HOSTILE_URLS = [
  'https://login.micr0soft-example.example.test/oauth?session=<script>alert(1)</script>',
  'http://198.51.100.23/download/invoice.zip',
  'https://cdn.example.test/newsletter/2026/11/unsubscribe?u=12345',
  `https://tracking.example.test/${'a'.repeat(400)}`,
  'javascript:alert(document.domain)',
];

const anchor = fixtureAnchor();

function buildAttachments(id: string, count: number, verdict: string, random: SeededRandom) {
  return Array.from({ length: count }, (_, i): AttachmentRow => {
    const filename = random.pick(HOSTILE_FILENAMES);
    const malicious = verdict === 'malware' && i === 0;
    return {
      partIndex: i + 2,
      filename,
      declaredContentType: filename.endsWith('.pdf')
        ? 'application/pdf'
        : 'application/octet-stream',
      detectedContentType: malicious ? 'application/x-dosexec' : 'application/pdf',
      sizeBytes: random.int(8_000, 2_400_000),
      sha256: sha(`${id}:att:${i}`),
      disposition: 'attachment',
      depth: 0,
      verdict: malicious ? 'malicious' : 'clean',
      latestScan: {
        verdict: malicious ? 'malicious' : 'clean',
        reasonCodes: malicious
          ? ['malware.clamav', 'type.executable_disguised']
          : ['clean.no_findings'],
        detectedType: malicious ? 'pe_executable' : 'pdf',
        typeFamily: malicious ? 'executable' : 'document',
        typeMismatch: malicious,
        clamav: {
          signature: malicious ? 'Win.Trojan.Agent-EXAMPLE' : null,
          engineVersion: '1.4.1',
          dbVersion: 27450,
        },
        yara: malicious
          ? {
              bundleId: 'yara-2026-11',
              matches: [{ rule: 'EXAMPLE_PE_dropper', severity: 'high', scope: 'attachment' }],
            }
          : null,
        archive: null,
        knownHash: malicious ? { severity: 'high', family: null } : null,
        round: 0,
      },
    };
  });
}

function buildUrls(id: string, count: number, verdict: string, random: SeededRandom) {
  return Array.from({ length: count }, (_, i): UrlRow => {
    const url =
      HOSTILE_URLS[(i + random.int(0, 4)) % HOSTILE_URLS.length] ?? 'https://example.test/';
    const bad = verdict === 'phishing' && i === 0;
    return {
      urlSeq: i,
      url,
      host: bad ? 'login.micr0soft-example.example.test' : 'cdn.example.test',
      unicodeHost: null,
      registrableDomain: bad ? 'micr0soft-example.example.test' : 'example.test',
      hostKind: 'domain',
      sources: { html_href: 1 },
      flags: bad ? ['url.lookalike_homoglyph', 'url.credential_form'] : [],
      latest: {
        round: 0,
        verdict: bad ? 'malicious' : 'clean',
        reasonCodes: bad ? ['phishing.lookalike'] : ['clean.no_findings'],
        rewritten: true,
      },
      rewrite: { status: 'rewritten', skipReason: null, round: 0 },
      clicks: bad
        ? { total: 3, byDecision: { blocked: 2, warned: 1 } }
        : { total: random.int(0, 4), byDecision: {} },
    };
  });
}

function evaluationFor(m: MessageDetail, scanId: string, round: number): Evaluation {
  const verdict = m.finalVerdict ?? 'unknown';
  const action = m.finalAction ?? 'deliver';
  const disposition: Evaluation['disposition'] =
    action === 'quarantine'
      ? 'quarantine'
      : action === 'require_approval'
        ? 'require_approval'
        : 'allow';
  const tenantRule = disposition !== 'allow';
  const ref = 'pol-inbound-threats/3#block-high-risk';
  return {
    status: 'evaluated',
    round: { trigger: 'scanned', direction: m.direction, lifecycleRound: round, scanId },
    disposition,
    finalVerdict: verdict,
    riskScore: m.riskScore,
    decisive: {
      source: tenantRule ? 'tenant_rule' : 'platform_default',
      policyPublicId: tenantRule ? 'pol-inbound-threats' : null,
      versionNo: tenantRule ? 3 : null,
      ruleId: tenantRule ? 'block-high-risk' : null,
      reason: tenantRule ? 'policy.rule.matched' : 'policy.platform_default',
    },
    actions: [
      {
        type:
          disposition === 'allow'
            ? 'ALLOW'
            : disposition === 'quarantine'
              ? 'QUARANTINE'
              : 'REQUIRE_APPROVAL',
        params: {},
        origin: tenantRule ? 'tenant_rule' : 'platform_default',
        ruleRefs: tenantRule ? [ref] : [],
        applicability: 'applies',
      },
    ],
    delivery: null,
    notices: { senderNonDelivery: false },
    matchedRules: tenantRule
      ? [
          {
            ref,
            policyPublicId: 'pol-inbound-threats',
            versionNo: 3,
            ruleId: 'block-high-risk',
            disposition,
            actionTypes: [disposition === 'quarantine' ? 'QUARANTINE' : 'REQUIRE_APPROVAL'],
            override: false,
          },
        ]
      : [],
    trace: [],
    traceTruncated: false,
    floor: { disposition: null, tag: false, reasons: [] },
    recommendation: {
      disposition,
      tag: false,
      levelOnly: false,
      riskAction: null,
      revisions: [0],
    },
    override: null,
    clamps: [],
    reasonCodes: [tenantRule ? 'policy.rule.matched' : 'policy.platform_default'],
    explanation: {
      lines: [],
      text: tenantRule
        ? `Decided by rule block-high-risk of policy pol-inbound-threats v3: ${disposition}.`
        : 'No tenant rule matched; the platform default allowed the message.',
    },
    versions: {
      dsl: 'policy-dsl/1',
      evaluator: 'policy-eval/2',
      input: 'policy-input/1',
      platformDefault: 'platform-default/1',
      snapshotSha256: sha(`${m.id}:snap`),
      generation: '42',
      tzdata: '2026a',
      policies: [
        { policyPublicId: 'pol-inbound-threats', versionNo: 3, definitionSha256: sha('pol:3') },
      ],
    },
    inputSha256: sha(`${m.id}:input:${round}`),
    lifecycleRound: round,
    trigger: 'scanned',
    direction: m.direction,
    finalAction: action,
    actionStatuses: ['enforced'],
    deliveredObject: disposition === 'allow' ? 'original' : 'none',
    evaluatedAt: new Date(Date.parse(m.receivedAt) + 4_000 + round * 60_000).toISOString(),
    durationUs: 1_850 + round * 30,
    recipientSplit: false,
    recipientDecisions: null,
  };
}

function roundFor(m: MessageDetail, round: number, random: SeededRandom): ScanRound {
  const scanId = String(900_000 + hashIndex(m.id) * 3 + round);
  const started = Date.parse(m.receivedAt) + 200 + round * 60_000;
  const verdict = m.finalVerdict;
  const scanVerdict: ScanRound['verdict'] =
    verdict === 'clean' || verdict === 'bulk'
      ? 'clean'
      : verdict === 'spam'
        ? 'spam'
        : verdict === 'suspicious' || verdict === 'bec'
          ? 'suspicious'
          : 'malicious';
  const level =
    (m.riskScore ?? 0) >= 800
      ? 'critical'
      : (m.riskScore ?? 0) >= 600
        ? 'high'
        : (m.riskScore ?? 0) >= 300
          ? 'medium'
          : 'low';
  const engines: ScanRound['engines'] = [
    {
      engine: 'rspamd',
      final: true,
      engineVersion: '3.10.2',
      outcome: scanVerdict === 'spam' ? 'spam' : 'clean',
      score: scanVerdict === 'spam' ? 9.4 : 1.2,
      requiredScore: 6,
      action: scanVerdict === 'spam' ? 'add header' : 'no action',
      reasonCodes: scanVerdict === 'spam' ? ['spam.score'] : ['clean.no_findings'],
      symbols: [
        { name: 'DMARC_POLICY_ALLOW', score: -0.5, options: ['example.test', 'none'] },
        {
          name: 'FROM_NEQ_ENVFROM',
          score: 0.4,
          options: [m.envelopeFrom, '<b onmouseover=alert(1)>spoof@example.test</b>'],
        },
        {
          name: 'URIBL_EXAMPLE',
          score: scanVerdict === 'spam' ? 4.5 : 0,
          options: ['http://198.51.100.23/download'],
        },
      ],
      attempts: [
        {
          attempt: 1,
          outcome: 'clean',
          errorCode: null,
          durationMs: random.int(80, 400),
          at: new Date(started + 100).toISOString(),
        },
      ],
      durationMs: random.int(90, 450),
      settingsVersion: 'rspamd/4',
      completedAt: new Date(started + 600).toISOString(),
    },
    {
      engine: 'attachment',
      final: true,
      engineVersion: 'attachment/2.1.0',
      outcome: verdict === 'malware' ? 'malicious' : m.attachmentCount > 0 ? 'clean' : 'skipped',
      score: null,
      requiredScore: null,
      action: null,
      reasonCodes:
        verdict === 'malware'
          ? ['malware.clamav']
          : m.attachmentCount > 0
            ? ['clean.no_findings']
            : ['attachment.none'],
      symbols: [],
      attempts: [
        {
          attempt: 1,
          outcome: verdict === 'malware' ? 'malicious' : 'clean',
          errorCode: null,
          durationMs: null,
          at: new Date(started + 1000).toISOString(),
        },
      ],
      durationMs: null,
      settingsVersion: 'attachment/3',
      completedAt: new Date(started + 2000).toISOString(),
    },
    {
      engine: 'url',
      final: true,
      engineVersion: 'url/1.6.0',
      outcome: verdict === 'phishing' ? 'malicious' : 'clean',
      score: null,
      requiredScore: null,
      action: null,
      reasonCodes: verdict === 'phishing' ? ['phishing.lookalike'] : ['clean.no_findings'],
      symbols: [],
      attempts: [
        {
          attempt: 1,
          outcome: 'timeout',
          errorCode: 'engine.timeout',
          durationMs: null,
          at: new Date(started + 900).toISOString(),
        },
        {
          attempt: 2,
          outcome: verdict === 'phishing' ? 'malicious' : 'clean',
          errorCode: null,
          durationMs: null,
          at: new Date(started + 1900).toISOString(),
        },
      ],
      durationMs: null,
      settingsVersion: 'url/2',
      completedAt: new Date(started + 2000).toISOString(),
    },
    {
      engine: 'bec',
      final: true,
      engineVersion: 'bec/1.2.0',
      outcome: verdict === 'bec' ? 'suspicious' : 'clean',
      score: verdict === 'bec' ? 640 : 40,
      requiredScore: null,
      action: null,
      reasonCodes:
        verdict === 'bec'
          ? ['bec.exec_impersonation', 'bec.payment_change']
          : ['clean.no_findings'],
      symbols: [],
      attempts: [],
      durationMs: null,
      settingsVersion: 'bec/1',
      completedAt: new Date(started + 2000).toISOString(),
    },
    {
      engine: 'dlp',
      final: true,
      engineVersion: 'dlp/1.1.0',
      outcome: 'clean',
      score: null,
      requiredScore: null,
      action: null,
      reasonCodes: ['clean.no_findings'],
      symbols: [],
      attempts: [],
      durationMs: null,
      settingsVersion: 'dlp/2',
      completedAt: new Date(started + 2000).toISOString(),
      dlp: null,
    },
  ];
  return {
    scanId,
    round,
    scanKind: round === 0 ? 'initial' : 'rescan',
    status: 'completed',
    verdict: scanVerdict,
    reasonCodes: engines
      .flatMap((e) => e.reasonCodes)
      .filter((c) => c !== 'clean.no_findings')
      .slice(0, 6),
    requiredEngines: ['rspamd', 'attachment', 'url', 'bec', 'dlp'],
    startedAt: new Date(started).toISOString(),
    completedAt: new Date(started + 2_400).toISOString(),
    deadlineAt: new Date(started + 120_000).toISOString(),
    auth: {
      spf: verdict === 'bec' || verdict === 'phishing' ? 'softfail' : 'pass',
      spfDomain: m.envelopeFrom.split('@')[1] ?? null,
      dkim: verdict === 'phishing' ? 'fail' : 'pass',
      dkimSignatures: [
        {
          domain: m.envelopeFrom.split('@')[1] ?? 'example.test',
          result: verdict === 'phishing' ? 'fail' : 'pass',
          selector: 's2026',
        },
      ],
      dmarc: verdict === 'phishing' ? 'fail' : 'pass',
      dmarcPolicy: 'quarantine',
      dmarcDomain: m.envelopeFrom.split('@')[1] ?? null,
      arc: 'none',
    },
    engines,
    risk: [
      {
        status: 'scored',
        score: m.riskScore ?? 0,
        level,
        verdict: verdict ?? 'unknown',
        recommendedAction:
          m.finalAction === 'deliver' ? 'deliver' : m.finalAction === 'tag' ? 'tag' : 'quarantine',
        hardBlocks:
          verdict === 'malware'
            ? [{ id: 'hb.malware_attachment', verdict: 'malware', action: 'block' }]
            : [],
        reasonCodes: verdict === 'clean' ? [] : [`risk.${verdict}`],
        contributions: [],
        groups: [],
        engines: [],
        failures: [],
        floors: [],
        trust: { status: 'off', factorPermille: 1000, reducedGroups: [], pointsRemoved: 0 },
        evidence: {
          auth: null,
          dlp: null,
          bec: null,
          sandbox: null,
          unmappedCodes: [],
          aiRaiseOnly: false,
        },
        explanation: {
          lines: [],
          text: `Risk ${m.riskScore ?? 0} (${level}); top signal ${verdict === 'clean' ? 'none' : verdict}.`,
        },
        versions: {
          scorer: 'risk-score/1',
          signalMap: 'risk-signals/1',
          input: 'risk-input/1',
          profile: {
            source: 'platform',
            id: 'rsk-default/1',
            versionNo: null,
            sha256: sha('rsk-default'),
          },
        },
        inputSha256: sha(`${m.id}:risk:${round}`),
        revision: 0,
        createdAt: new Date(started + 2_500).toISOString(),
      },
    ],
    policy: evaluationFor(m, scanId, round),
  };
}

function hashIndex(id: string): number {
  let h = 0;
  for (const char of id) h = (h * 31 + char.charCodeAt(0)) % 100_000;
  return h;
}

function buildMessages(): FixtureMessage[] {
  const random = new SeededRandom('messages-fixtures');
  const out: FixtureMessage[] = [];
  for (let i = 0; i < 180; i += 1) {
    const id = stableUuid(`message:${i}`);
    const verdict = random.pick(VERDICTS);
    const action = actionFor(verdict);
    const direction = random.pick([
      'inbound',
      'inbound',
      'inbound',
      'outbound',
      'internal',
    ] as const);
    const sender = syntheticPerson(random).email;
    const recipients = Array.from({ length: random.int(1, 3) }, () =>
      syntheticPerson(random).email.replace('@example.com', '@alpha.example.test'),
    );
    // Message 0 is always a malicious one addressed to the dev mailbox user (self-service flows).
    if (i < 3) recipients[0] = 'mailbox_user@example.com';
    const subject =
      i % 9 === 0
        ? (HOSTILE_SUBJECTS[(i / 9) % HOSTILE_SUBJECTS.length] ?? HOSTILE_SUBJECTS[0])
        : random.bool(0.05)
          ? null
          : random.pick(NORMAL_SUBJECTS);
    const attachmentCount =
      verdict === 'malware' ? random.int(1, 2) : random.bool(0.35) ? random.int(1, 3) : 0;
    const receivedAt = new Date(
      anchor - Math.floor((i / 180) * 29 * 86_400_000) - random.int(0, 3_000_000),
    ).toISOString();
    const riskScore = random.bool(0.04) ? null : riskFor(verdict, random);
    const detail: MessageDetail = {
      id,
      receivedAt,
      direction,
      status: statusFor(action),
      statusChangedAt: new Date(Date.parse(receivedAt) + 5_000).toISOString(),
      subject,
      envelopeFrom: sender,
      headerFrom: random.bool(0.2) ? `"IT Support" <${sender}>`.slice(0, 120) : sender,
      recipientCount: recipients.length,
      attachmentCount,
      sizeBytes: random.int(4_000, 9_000_000),
      finalVerdict: verdict,
      finalAction: action,
      riskScore,
      domainId: direction === 'outbound' ? null : stableUuid('domain:alpha.example.test'),
      internetMessageId: `<${id.slice(0, 8)}.${i}@mail.example.test>`,
      lifecycleRound: i % 11 === 0 ? 1 : 0,
      version: i % 11 === 0 ? 9 : 6,
      statusReason:
        action === 'quarantine'
          ? 'policy_quarantine'
          : action === 'require_approval'
            ? 'policy_review'
            : null,
      clientIp: `198.51.100.${(i % 200) + 1}`,
      clientHelo: i % 13 === 0 ? 'mx.<script>.example.test' : 'mx1.example.test',
      mtaQueueId: `4X${id.slice(0, 10).toUpperCase().replace(/-/g, '')}`,
    };
    const urlCount =
      verdict === 'phishing' ? random.int(1, 4) : random.bool(0.5) ? random.int(1, 3) : 0;
    const roundsCount = detail.lifecycleRound + 1;
    const rounds = Array.from({ length: roundsCount }, (_, r) =>
      roundFor(detail, r, random),
    ).reverse();
    out.push({
      detail,
      recipients,
      attachments: buildAttachments(id, attachmentCount, verdict, random),
      urls: buildUrls(id, urlCount, verdict, random),
      rounds,
      evaluations: rounds.map((round) => evaluationFor(detail, round.scanId, round.round)),
    });
  }
  return out.sort((a, b) => b.detail.receivedAt.localeCompare(a.detail.receivedAt));
}

export const FIXTURE_MESSAGES: readonly FixtureMessage[] = buildMessages();
const BY_ID = new Map(FIXTURE_MESSAGES.map((m) => [m.detail.id, m]));

export function fixtureMessage(id: string): FixtureMessage | undefined {
  return BY_ID.get(id);
}

/** Rows examined per request by scan-bounded filters (the api's `API_LIST_SCAN_BUDGET_ROWS`). */
const SCAN_BUDGET = 40;

function encodeCursor(offset: number, filterHash: string): string {
  return Buffer.from(JSON.stringify({ v: 1, o: offset, f: filterHash })).toString('base64url');
}

function decodeCursor(cursor: string, filterHash: string): number | null {
  try {
    const parsed = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as {
      o?: unknown;
      f?: unknown;
    };
    if (typeof parsed.o !== 'number' || parsed.f !== filterHash) return null;
    return parsed.o;
  } catch {
    return null;
  }
}

const LIST_FILTERS = [
  'direction',
  'status',
  'verdict',
  'action',
  'domainId',
  'sender',
  'headerFrom',
  'recipient',
  'internetMessageId',
  'hasAttachments',
  'riskScore',
  'riskScore.gte',
  'riskScore.lte',
  'riskScore.gt',
  'riskScore.lt',
] as const;
const ALLOWED_QUERY = new Set<string>(['limit', 'cursor', 'sort', 'from', 'to', ...LIST_FILTERS]);

function listOf(name: string, query: URLSearchParams): string[] | null {
  const value = query.get(name);
  return value ? value.split(',').filter(Boolean) : null;
}

function listMessages(request: FixtureRequest): FixtureResponse {
  const q = request.query;
  for (const key of q.keys()) {
    if (!ALLOWED_QUERY.has(key))
      return apiError(400, 'validation_failed', [`${key}: unknown parameter`]);
  }
  for (const name of ['direction', 'status', 'verdict', 'action'] as const) {
    const values = listOf(name, q);
    if (values && values.length > 5) {
      return apiError(400, 'validation_failed', [`${name}: at most 5 values`]);
    }
  }
  const to = q.get('to') ? Date.parse(q.get('to') ?? '') : anchor + 3_600_000;
  const from = q.get('from') ? Date.parse(q.get('from') ?? '') : to - 86_400_000;
  if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from) {
    return apiError(400, 'validation_failed', ['from: must be before to']);
  }
  if (to - from > 31 * 86_400_000) {
    return apiError(400, 'validation_failed', ['to: the range is at most 31 days']);
  }
  const limit = Math.min(100, Math.max(1, Number(q.get('limit') ?? '25') || 25));
  const ascending = q.get('sort') === 'receivedAt';
  const direction = listOf('direction', q);
  const status = listOf('status', q);
  const verdict = listOf('verdict', q);
  const action = listOf('action', q);
  const sender = q.get('sender')?.toLowerCase();
  const headerFrom = q.get('headerFrom')?.toLowerCase();
  const recipient = q.get('recipient')?.toLowerCase();
  const hasAttachments = q.get('hasAttachments');
  const gte = q.get('riskScore.gte') ? Number(q.get('riskScore.gte')) : null;
  const lte = q.get('riskScore.lte') ? Number(q.get('riskScore.lte')) : null;

  const inRange = FIXTURE_MESSAGES.filter((m) => {
    const t = Date.parse(m.detail.receivedAt);
    return t >= from && t < to;
  });
  const ordered = ascending ? [...inRange].reverse() : inRange;
  const matches = (m: FixtureMessage) => {
    const d = m.detail;
    return (
      (!direction || direction.includes(d.direction)) &&
      (!status || status.includes(d.status)) &&
      (!verdict || (d.finalVerdict !== null && verdict.includes(d.finalVerdict))) &&
      (!action || (d.finalAction !== null && action.includes(d.finalAction))) &&
      (!sender || d.envelopeFrom.toLowerCase() === sender) &&
      (!headerFrom || (d.headerFrom ?? '').toLowerCase() === headerFrom) &&
      (!recipient || m.recipients.some((r) => r.toLowerCase() === recipient)) &&
      (!hasAttachments || (hasAttachments === 'true') === d.attachmentCount > 0) &&
      (gte === null || (d.riskScore !== null && d.riskScore >= gte)) &&
      (lte === null || (d.riskScore !== null && d.riskScore <= lte))
    );
  };
  // Index-served reads: none, exactly one verdict, or recipient alone; anything else is
  // scan-bounded (short pages with a nextCursor), as the api documents.
  const filterKeys = LIST_FILTERS.filter((name) => q.has(name));
  const indexed =
    filterKeys.length === 0 ||
    (filterKeys.length === 1 && filterKeys[0] === 'verdict' && verdict?.length === 1) ||
    (filterKeys.length === 1 && filterKeys[0] === 'recipient');
  const filterHash = String(
    hashIndex(JSON.stringify([...q.entries()].filter(([k]) => k !== 'cursor' && k !== 'limit'))),
  );
  const cursor = q.get('cursor');
  let offset = 0;
  if (cursor) {
    const decoded = decodeCursor(cursor, filterHash);
    if (decoded === null) {
      return apiError(
        400,
        'cursor_invalid',
        'The cursor is invalid for these filters; restart the list',
      );
    }
    offset = decoded;
  }
  if (indexed) {
    const all = ordered.filter(matches);
    const page = all.slice(offset, offset + limit).map((m) => listItem(m.detail));
    const next = offset + limit < all.length ? encodeCursor(offset + limit, filterHash) : null;
    return ok('MessagesController_list_v1', { data: page, nextCursor: next });
  }
  const page: ListItem<'MessagesController_list_v1'>[] = [];
  let position = offset;
  let examined = 0;
  while (position < ordered.length && examined < SCAN_BUDGET && page.length < limit) {
    const m = ordered[position];
    position += 1;
    examined += 1;
    if (m && matches(m)) page.push(listItem(m.detail));
  }
  const next = position < ordered.length ? encodeCursor(position, filterHash) : null;
  return ok('MessagesController_list_v1', { data: page, nextCursor: next });
}

function listItem(d: MessageDetail): ListItem<'MessagesController_list_v1'> {
  return {
    id: d.id,
    receivedAt: d.receivedAt,
    direction: d.direction,
    status: d.status,
    statusChangedAt: d.statusChangedAt,
    subject: d.subject,
    envelopeFrom: d.envelopeFrom,
    headerFrom: d.headerFrom,
    recipientCount: d.recipientCount,
    attachmentCount: d.attachmentCount,
    sizeBytes: d.sizeBytes,
    finalVerdict: d.finalVerdict,
    finalAction: d.finalAction,
    riskScore: d.riskScore,
    domainId: d.domainId,
  };
}

function withMessage(
  operationId: OperationId,
  handler: (message: FixtureMessage, request: FixtureRequest) => FixtureResponse,
) {
  return guarded((request) => {
    const message = fixtureMessage(request.params.messageId ?? '');
    if (!message) return apiError(404, 'message_not_found', 'Message not found');
    void operationId;
    return handler(message, request);
  });
}

function offsetPage<T>(items: readonly T[], query: URLSearchParams, max = 100) {
  const limit = Math.min(max, Math.max(1, Number(query.get('limit') ?? '25') || 25));
  const cursor = query.get('cursor');
  const offset = cursor ? Number(Buffer.from(cursor, 'base64url').toString('utf8')) || 0 : 0;
  const page = items.slice(offset, offset + limit);
  const next =
    offset + limit < items.length
      ? Buffer.from(String(offset + limit)).toString('base64url')
      : null;
  return { page, next };
}

export const fixtures: FixtureHandlers = {
  MessagesController_list_v1: guarded(listMessages),
  MessagesController_detail_v1: withMessage('MessagesController_detail_v1', (m) =>
    ok('MessagesController_detail_v1', m.detail),
  ),
  MessageScansController_scansOf_v1: withMessage(
    'MessageScansController_scansOf_v1',
    (m, request) => {
      const { page, next } = offsetPage(m.rounds, request.query, 20);
      return ok('MessageScansController_scansOf_v1', {
        messageId: m.detail.id,
        data: page,
        nextCursor: next,
      });
    },
  ),
  AttachmentsController_ofMessage_v1: withMessage(
    'AttachmentsController_ofMessage_v1',
    (m, request) => {
      const { page, next } = offsetPage(m.attachments, request.query);
      return ok('AttachmentsController_ofMessage_v1', { data: page, nextCursor: next });
    },
  ),
  UrlProtectionController_ofMessage_v1: withMessage(
    'UrlProtectionController_ofMessage_v1',
    (m, request) => {
      const { page, next } = offsetPage(m.urls, request.query);
      return ok('UrlProtectionController_ofMessage_v1', { data: page, nextCursor: next });
    },
  ),
  PolicyMessagesController_evaluations_v1: withMessage(
    'PolicyMessagesController_evaluations_v1',
    (m) =>
      ok('PolicyMessagesController_evaluations_v1', {
        messageId: m.detail.id,
        data: [...m.evaluations],
      }),
  ),
};
