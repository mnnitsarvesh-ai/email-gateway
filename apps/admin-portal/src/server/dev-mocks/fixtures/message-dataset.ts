import 'server-only';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import { SeededRandom, stableUuid } from '../generator';

export { DEV_MOCK_MARKER } from '../types';

/**
 * The synthetic message dataset of dev fixture mode (step 7.2 §2 E14; design P9): about 1 500
 * messages over the last 31 days, deterministic (seeded generator, stable ids), never copied from
 * real data (`*.example.test`, `example.com`). Around 60 sender domains (one IDN in A-label
 * form, one lookalike), subjects with reply markers, non-ASCII, right-to-left and hostile
 * strings, Message-IDs, outbound recipient domains, every delivery status and quarantine state
 * per recipient, a risk spread and SMTP texts that contain addresses.
 *
 * The dataset holds clear subjects and addresses **for the fixture handlers only**: every read
 * handler applies the api's masks (`messageListItem`, `messageDetailView`, `maskAddress`,
 * `maskAddressesInText`), exactly as the api does since step 7.2 (E5–E9). Built once per process
 * on `globalThis` (each `next dev` route handler is its own bundle). The details operations of
 * step 7.2 WP4 read it through `fixtureMessageById` / `fixtureDataset`.
 */

type MessageDetail = SuccessBody<'MessagesController_detail_v1'>;
type ScanRound = ListItem<'MessageScansController_scansOf_v1'>;
type Evaluation = SuccessBody<'PolicyMessagesController_evaluations_v1'>['data'][number];
type AttachmentRow = ListItem<'AttachmentsController_ofMessage_v1'>;
type UrlRow = ListItem<'UrlProtectionController_ofMessage_v1'>;

export const FIXTURE_DELIVERY_STATUSES = [
  'pending',
  'in_progress',
  'queued',
  'delivered',
  'deferred',
  'bounced',
  'failed',
  'suppressed',
  'expired',
  'unknown',
] as const;
export type FixtureDeliveryStatus = (typeof FIXTURE_DELIVERY_STATUSES)[number];

export const FIXTURE_QUARANTINE_STATES = [
  'held',
  'pending_approval',
  'releasing',
  'released',
  'rejected',
  'deleted',
  'expired',
  'superseded',
] as const;
export type FixtureQuarantineState = (typeof FIXTURE_QUARANTINE_STATES)[number];

/** One envelope recipient of a dataset message (RCPT order). */
export interface FixtureRecipient {
  readonly rcptSeq: number;
  /** Clear address (fixture handlers mask it: `maskAddress`). */
  readonly address: string;
  /** Current status of the recipient's delivery, `null` when no delivery exists. */
  readonly delivery: FixtureDeliveryStatus | null;
  readonly attemptCount: number;
  /** Final SMTP reply (contains addresses: mask with `maskAddressesInText`). */
  readonly smtpResponse: string | null;
  /** Initial state of the recipient's quarantine entry, `null` when none. */
  readonly quarantine: FixtureQuarantineState | null;
}

export interface FixtureMessage {
  /** The message as stored: `subject` in clear (mask it with `messageDetailView`). */
  readonly detail: MessageDetail;
  /** Clear recipient addresses in RCPT order (compatibility with the 7.1 fixtures). */
  readonly recipients: readonly string[];
  readonly recipientRows: readonly FixtureRecipient[];
  /** Index of the tenant domain (`domains.ts` entry) the message belongs to, or null. */
  readonly domainIndex: number | null;
  readonly attachments: readonly AttachmentRow[];
  readonly urls: readonly UrlRow[];
  /** Scan rounds, newest first (built on first access). */
  readonly rounds: readonly ScanRound[];
  /** Policy evaluations of the rounds (built on first access). */
  readonly evaluations: readonly Evaluation[];
}

export const DATASET_SIZE = 1500;
export const DATASET_DAYS = 31;
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

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
  'Contract draft for review',
  'Project kickoff',
  'Holiday schedule 2026',
  'Updated price list',
  'Security awareness training',
  'Purchase order 5521',
  'Invoice 4471 overdue',
  'Invoice 4472 reminder',
  'Invoice 4480 paid',
] as const;
const NON_ASCII_SUBJECTS = [
  'Rechnung für Oktober',
  'Счёт-фактура № 4471',
  '请查收：十一月发票',
  'Ödeme bildirimi – Kasım',
  'Réunion de l’équipe à 15 h',
  'Überweisung bestätigt',
] as const;
const RTL_SUBJECTS = ['فاتورة شهر نوفمبر', 'חשבונית מס׳ 4471 לתשלום'] as const;
const REPLY_PREFIXES = ['Re: ', 'RE: ', 'Fwd: ', 'FW: ', 'AW: ', 'SV: ', 'Re[2]: ', 'Re: Fwd: '];

const SENDER_WORDS = [
  'northwind',
  'contoso',
  'fabrikam',
  'tailspin',
  'wingtip',
  'litware',
  'adatum',
  'proseware',
  'fourthcoffee',
  'lucerne',
  'margie',
  'alpine',
  'blueyonder',
  'coho',
  'datum',
  'graphic',
  'humongous',
  'southridge',
  'trey',
  'woodgrove',
] as const;
/** The IDN sender domain (münchen) in A-label form, as the api stores and searches it. */
export const IDN_SENDER_DOMAIN = 'xn--mnchen-3ya.example.test';
export const LOOKALIKE_SENDER_DOMAIN = 'micr0soft-example.example.test';
/** About 60 sender domains of inbound mail. */
export const SENDER_DOMAINS: readonly string[] = [
  ...Array.from({ length: 57 }, (_, i) => {
    const word = SENDER_WORDS[i % SENDER_WORDS.length] ?? 'sender';
    const n = Math.floor(i / SENDER_WORDS.length);
    return `${word}${n === 0 ? '' : `-${n + 1}`}.example.test`;
  }),
  'example.com',
  LOOKALIKE_SENDER_DOMAIN,
  IDN_SENDER_DOMAIN,
];
/** The tenant's domains (indices of `domains.ts` entries 0–2, present in every organization). */
export const TENANT_DOMAINS = [
  'alpha-1.example.test',
  'bravo-2.example.test',
  'charlie-3.example.test',
];
/** Recipient domains of outbound mail. */
export const OUTBOUND_DOMAINS = [
  'customer1.example.com',
  'customer2.example.com',
  'customer3.example.com',
  'partner1.example.test',
  'partner2.example.test',
  'partner3.example.test',
  'supplier.example.test',
  'agency.example.test',
];
const FIRST = ['alex', 'sam', 'jordan', 'priya', 'chen', 'maria', 'omar', 'lena', 'ravi', 'noor'];
const LAST = ['lee', 'patel', 'garcia', 'nguyen', 'kim', 'silva', 'novak', 'haddad', 'berg', 'rao'];
const ROLE_LOCALS = ['billing', 'noreply', 'newsletter', 'support', 'ceo', 'payroll', 'hr', 'it'];

const VERDICTS = [
  'clean',
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
type Verdict = NonNullable<MessageDetail['finalVerdict']>;

const DELIVERY_WEIGHTS: readonly [FixtureDeliveryStatus, number][] = [
  ['delivered', 80],
  ['deferred', 5],
  ['bounced', 4],
  ['failed', 2],
  ['suppressed', 2],
  ['expired', 2],
  ['queued', 2],
  ['in_progress', 1],
  ['pending', 1],
  ['unknown', 1],
];
const QUARANTINE_WEIGHTS: readonly [FixtureQuarantineState, number][] = [
  ['held', 58],
  ['released', 10],
  ['rejected', 8],
  ['deleted', 6],
  ['expired', 8],
  ['releasing', 5],
  ['superseded', 5],
];

function weighted<T>(random: SeededRandom, weights: readonly [T, number][]): T {
  const total = weights.reduce((sum, [, w]) => sum + w, 0);
  let roll = random.next() * total;
  for (const [value, weight] of weights) {
    roll -= weight;
    if (roll < 0) return value;
  }
  return (weights[0] as [T, number])[0];
}

const person = (random: SeededRandom) =>
  `${random.pick(FIRST)}.${random.pick(LAST)}${random.int(1, 99)}`;

/** `f***@example.com`: the api's `maskAddress` (first code point of the local part, §3.4). */
export function maskAddress(value: string): string {
  if (value === '') return '';
  const at = value.lastIndexOf('@');
  if (at < 0) return `${Array.from(value)[0] ?? ''}***`;
  const first = Array.from(value.slice(0, at))[0] ?? '';
  return `${first}***@${value.slice(at + 1)}`;
}

const ADDRESS_IN_TEXT =
  /(?<![\p{L}\p{N}._%+\-!#$&'*/=?^`{|}~])(?:"[^"\r\n]*"|[\p{L}\p{N}._%+\-!#$&'*/=?^`{|}~]+)@[\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)+/gu;

/** The api's `maskAddressesInText`: the local part of every address-shaped substring masked. */
export function maskAddressesInText(text: string): string {
  return text.replace(ADDRESS_IN_TEXT, (match) =>
    match.startsWith('"') ? `"***@${match.slice(match.lastIndexOf('@') + 1)}` : maskAddress(match),
  );
}

/** The public id of tenant domain `index` in an organization (as `domains.ts` creates it). */
export function domainIdFor(organizationId: string, index: number): string {
  return stableUuid(`${organizationId}:domain:${index}`);
}

const sha = (seed: string) =>
  Array.from({ length: 4 }, (_, i) => stableUuid(`${seed}:${i}`).replace(/-/g, ''))
    .join('')
    .slice(0, 64);

function hashIndex(id: string): number {
  let h = 0;
  for (const char of id) h = (h * 31 + char.charCodeAt(0)) % 100_000;
  return h;
}

function actionFor(verdict: Verdict | null, random: SeededRandom): MessageDetail['finalAction'] {
  switch (verdict) {
    case null:
      return null;
    case 'clean':
      return 'deliver';
    case 'bulk':
    case 'suspicious':
    case 'unknown':
      return 'tag';
    case 'spam':
      return random.bool(0.85) ? 'quarantine' : 'tag';
    case 'phishing':
      return random.bool(0.9) ? 'quarantine' : 'reject';
    case 'malware':
      return random.bool(0.75) ? 'quarantine' : random.bool(0.5) ? 'reject' : 'discard';
    case 'bec':
      return 'require_approval';
    case 'dlp_violation':
      return random.bool(0.5) ? 'require_approval' : 'quarantine';
  }
}

function riskFor(verdict: Verdict | null, random: SeededRandom): number | null {
  if (verdict === null || random.bool(0.04)) return null;
  switch (verdict) {
    case 'clean':
      return random.int(0, 180);
    case 'bulk':
      return random.int(150, 320);
    case 'spam':
      return random.int(350, 620);
    case 'suspicious':
    case 'unknown':
      return random.int(450, 700);
    case 'bec':
    case 'dlp_violation':
      return random.int(600, 880);
    default:
      return random.int(820, 1000);
  }
}

function subjectFor(i: number, verdict: Verdict | null, random: SeededRandom): string | null {
  if (i % 6 === 0) return `Weekly newsletter #${1000 + Math.floor(i / 6)}`;
  if (i % 37 === 0) return HOSTILE_SUBJECTS[(i / 37) % HOSTILE_SUBJECTS.length] ?? null;
  if (random.bool(0.03)) return null;
  const roll = random.next();
  const base =
    roll < 0.1
      ? random.pick(NON_ASCII_SUBJECTS)
      : roll < 0.14
        ? random.pick(RTL_SUBJECTS)
        : verdict === 'bec'
          ? random.pick(['Urgent: payment details changed', 'Wire transfer today', 'Gift cards'])
          : verdict === 'phishing'
            ? random.pick(['Verify your account', 'Your mailbox is full', 'Unusual sign-in'])
            : random.pick(NORMAL_SUBJECTS);
  return random.bool(0.25) ? `${random.pick(REPLY_PREFIXES)}${base}` : base;
}

function statusFor(
  verdict: Verdict | null,
  action: MessageDetail['finalAction'],
  recipients: readonly FixtureRecipient[],
): MessageDetail['status'] {
  if (verdict === null) return 'scanning';
  if (action === 'quarantine') return 'quarantined';
  if (action === 'require_approval') return 'held_for_review';
  if (action === 'reject' || action === 'discard') return 'rejected';
  if (recipients.some((r) => r.delivery === 'deferred')) return 'delivery_retry';
  if (recipients.some((r) => r.delivery === 'queued' || r.delivery === 'pending')) {
    return 'delivery_pending';
  }
  return 'delivered';
}

function smtpResponseFor(
  status: FixtureDeliveryStatus,
  address: string,
  id: string,
): string | null {
  const domain = address.slice(address.lastIndexOf('@') + 1);
  switch (status) {
    case 'delivered':
      return `250 2.0.0 Ok: queued as 4X${id.slice(0, 8).toUpperCase()} for <${address}>`;
    case 'deferred':
      return `451 4.7.1 <${address}>: Recipient address rejected: greylisted, try again later`;
    case 'bounced':
      return `550 5.1.1 <${address}>: Recipient address rejected: User unknown in virtual mailbox table`;
    case 'failed':
      return `554 5.7.1 Service unavailable; contact postmaster@${domain} about ${address}`;
    case 'expired':
      return `421 4.4.2 Connection timed out while delivering to ${address}`;
    default:
      return null;
  }
}

function buildRecipients(
  addresses: readonly string[],
  action: MessageDetail['finalAction'],
  status: 'review' | 'quarantine' | 'deliver' | 'none',
  receivedMs: number,
  anchor: number,
  id: string,
  random: SeededRandom,
): FixtureRecipient[] {
  return addresses.map((address, rcptSeq) => {
    let quarantine: FixtureQuarantineState | null = null;
    let delivery: FixtureDeliveryStatus | null = null;
    if (status === 'review') {
      quarantine = random.bool(0.8)
        ? 'pending_approval'
        : random.bool(0.5)
          ? 'released'
          : 'rejected';
    } else if (status === 'quarantine') {
      quarantine = weighted(random, QUARANTINE_WEIGHTS);
      if (quarantine === 'expired' && anchor - receivedMs < 20 * DAY) quarantine = 'held';
    } else if (status === 'deliver') {
      delivery = weighted(random, DELIVERY_WEIGHTS);
    }
    if (quarantine === 'released') delivery = 'delivered';
    if (quarantine === 'releasing') delivery = 'queued';
    void action;
    return {
      rcptSeq,
      address,
      delivery,
      attemptCount: delivery === 'deferred' ? random.int(2, 6) : delivery ? 1 : 0,
      smtpResponse: delivery ? smtpResponseFor(delivery, address, id) : null,
      quarantine,
    };
  });
}

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

function buildUrls(count: number, verdict: string, random: SeededRandom) {
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

export function evaluationFor(m: MessageDetail, scanId: string, round: number): Evaluation {
  const verdict = m.finalVerdict ?? 'unknown';
  const action = m.finalAction ?? 'deliver';
  const disposition: Evaluation['disposition'] =
    action === 'quarantine'
      ? 'quarantine'
      : action === 'require_approval'
        ? 'require_approval'
        : action === 'reject' || action === 'discard'
          ? 'reject'
          : 'allow';
  const tenantRule = disposition !== 'allow';
  const ref = 'pol-inbound-threats/3#block-high-risk';
  const actionType =
    disposition === 'allow'
      ? 'ALLOW'
      : disposition === 'quarantine'
        ? 'QUARANTINE'
        : disposition === 'reject'
          ? 'REJECT'
          : 'REQUIRE_APPROVAL';
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
        type: actionType,
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
            actionTypes: [actionType],
            override: false,
          },
        ]
      : [],
    trace: [],
    traceTruncated: false,
    floor: { disposition: null, tag: false, reasons: [] },
    recommendation: { disposition, tag: false, levelOnly: false, riskAction: null, revisions: [0] },
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

export function roundFor(m: MessageDetail, round: number, random: SeededRandom): ScanRound {
  const scanId = String(900_000 + hashIndex(m.id) * 3 + round);
  const started = Date.parse(m.receivedAt) + 200 + round * 60_000;
  const verdict = m.finalVerdict;
  const scanVerdict: ScanRound['verdict'] =
    verdict === 'clean' || verdict === 'bulk'
      ? 'clean'
      : verdict === 'spam'
        ? 'spam'
        : verdict === 'suspicious' || verdict === 'bec' || verdict === 'dlp_violation'
          ? 'suspicious'
          : 'malicious';
  const score = m.riskScore ?? 0;
  const level = score >= 800 ? 'critical' : score >= 600 ? 'high' : score >= 300 ? 'medium' : 'low';
  const domain = m.envelopeFrom.split('@')[1] ?? null;
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
          // Addresses in symbol options are masked for every caller (§2 E9).
          options: [
            maskAddressesInText(m.envelopeFrom),
            maskAddressesInText('<b onmouseover=alert(1)>spoof@example.test</b>'),
          ],
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
      spfDomain: domain,
      dkim: verdict === 'phishing' ? 'fail' : 'pass',
      dkimSignatures: [
        {
          domain: domain ?? 'example.test',
          result: verdict === 'phishing' ? 'fail' : 'pass',
          selector: 's2026',
        },
      ],
      dmarc: verdict === 'phishing' ? 'fail' : 'pass',
      dmarcPolicy: 'quarantine',
      dmarcDomain: domain,
      arc: 'none',
    },
    engines,
    risk: [
      {
        status: 'scored',
        score,
        level,
        verdict: verdict ?? 'unknown',
        recommendedAction:
          m.finalAction === 'deliver' ? 'deliver' : m.finalAction === 'tag' ? 'tag' : 'quarantine',
        hardBlocks:
          verdict === 'malware'
            ? [{ id: 'hb.malware_attachment', verdict: 'malware', action: 'block' }]
            : [],
        reasonCodes: verdict === 'clean' ? [] : [`risk.${verdict ?? 'unknown'}`],
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
          text: `Risk ${score} (${level}); top signal ${verdict === 'clean' ? 'none' : (verdict ?? 'none')}.`,
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

type MessageState = MessageDetail['status'];

/**
 * The lifecycle states a message went through (step 3.3), oldest first, by round: the version of
 * the message is the number of transitions (each change increments it). A message in round 1 was
 * rescanned by an operator after its first round ended quarantined.
 */
export function transitionsFor(
  status: MessageState,
  lifecycleRound: number,
): { state: MessageState; round: number }[] {
  const finalPath = (final: MessageState): MessageState[] => {
    switch (final) {
      case 'delivered':
        return ['delivery_pending', 'delivered'];
      case 'delivery_retry':
        return ['delivery_pending', 'delivery_retry'];
      default:
        return [final];
    }
  };
  const out: { state: MessageState; round: number }[] = [
    { state: 'received', round: 0 },
    { state: 'persisted', round: 0 },
    { state: 'scanning', round: 0 },
  ];
  if (status === 'scanning' && lifecycleRound === 0) return out;
  out.push({ state: 'scanned', round: 0 }, { state: 'policy_evaluated', round: 0 });
  if (lifecycleRound === 0) {
    for (const state of finalPath(status)) out.push({ state, round: 0 });
    return out;
  }
  out.push({ state: 'quarantined', round: 0 });
  for (let round = 1; round <= lifecycleRound; round += 1) {
    out.push({ state: 'scanning', round });
    if (status === 'scanning' && round === lifecycleRound) return out;
    out.push({ state: 'scanned', round }, { state: 'policy_evaluated', round });
    if (round < lifecycleRound) out.push({ state: 'quarantined', round });
  }
  for (const state of finalPath(status)) out.push({ state, round: lifecycleRound });
  return out;
}

/** Lazily built scan rounds and evaluations (most dataset messages are never opened). */
function withLazyRounds(base: Omit<FixtureMessage, 'rounds' | 'evaluations'>): FixtureMessage {
  let rounds: ScanRound[] | null = null;
  let evaluations: Evaluation[] | null = null;
  const build = () => {
    if (rounds) return rounds;
    const d = base.detail;
    if (d.finalVerdict === null) {
      rounds = [];
      return rounds;
    }
    const random = new SeededRandom(`${d.id}:rounds`);
    rounds = Array.from({ length: d.lifecycleRound + 1 }, (_, r) =>
      roundFor(d, r, random),
    ).reverse();
    return rounds;
  };
  return Object.defineProperties({ ...base } as FixtureMessage, {
    rounds: { enumerable: true, get: build },
    evaluations: {
      enumerable: true,
      get: () => {
        evaluations ??= build().map((r) => evaluationFor(base.detail, r.scanId, r.round));
        return evaluations;
      },
    },
  });
}

/** The self-service owners of fixture mode get a few held entries (7.1 WP5 behaviour). */
const SELF_OWNERS = [
  'mailbox_user@example.com',
  'mailbox_user@example.com',
  'mailbox_user@example.com',
  'mailbox_user@example.com',
  'organization_admin@example.com',
];

function buildDataset(anchor: number): FixtureMessage[] {
  const random = new SeededRandom('message-dataset-7.2');
  const owners = [...SELF_OWNERS];
  const out: FixtureMessage[] = [];
  for (let i = 0; i < DATASET_SIZE; i += 1) {
    const id = stableUuid(`message:${i}`);
    const direction = random.pick([
      'inbound',
      'inbound',
      'inbound',
      'inbound',
      'inbound',
      'inbound',
      'inbound',
      'outbound',
      'outbound',
      'internal',
    ] as const);
    const ageMs = Math.floor(((i + 0.5) / DATASET_SIZE) ** 1.35 * DATASET_DAYS * DAY);
    const receivedMs =
      anchor - Math.min(ageMs + random.int(0, 90) * 1_000, DATASET_DAYS * DAY - HOUR);
    const tenantIndex = random.pick([0, 0, 0, 1, 1, 2]);
    const tenantDomain = TENANT_DOMAINS[tenantIndex] ?? 'alpha-1.example.test';
    let verdict: Verdict | null =
      direction === 'inbound'
        ? random.pick(VERDICTS)
        : random.bool(0.08)
          ? 'dlp_violation'
          : random.bool(0.04)
            ? 'suspicious'
            : 'clean';
    if (i < 4 || (i % 211 === 5 && receivedMs > anchor - 2 * DAY)) verdict = null; // still scanning
    if (i % 173 === 9) verdict = 'unknown';
    let envelopeFrom: string;
    let recipientAddresses: string[];
    if (direction === 'inbound') {
      const senderDomain =
        verdict === 'phishing' && random.bool(0.4)
          ? LOOKALIKE_SENDER_DOMAIN
          : (SENDER_DOMAINS[(i * 7 + random.int(0, 3)) % SENDER_DOMAINS.length] ?? 'example.com');
      envelopeFrom =
        i % 97 === 3
          ? '' // the null sender (a bounce)
          : `${random.bool(0.3) ? random.pick(ROLE_LOCALS) : person(random)}@${senderDomain}`;
      recipientAddresses = Array.from(
        { length: random.int(1, 3) },
        () => `${person(random)}@${tenantDomain}`,
      );
    } else if (direction === 'outbound') {
      envelopeFrom = `${person(random)}@${tenantDomain}`;
      recipientAddresses = Array.from(
        { length: random.int(1, 4) },
        () =>
          `${random.bool(0.4) ? random.pick(['info', 'sales', 'accounts']) : person(random)}@${random.pick(OUTBOUND_DOMAINS)}`,
      );
    } else {
      envelopeFrom = `${person(random)}@${tenantDomain}`;
      recipientAddresses = Array.from(
        { length: random.int(1, 2) },
        () => `${person(random)}@${random.pick(TENANT_DOMAINS)}`,
      );
    }
    const action = actionFor(verdict, random);
    if (action === 'quarantine' && direction === 'inbound' && owners.length > 0) {
      recipientAddresses[0] = owners.shift() ?? recipientAddresses[0] ?? '';
    }
    const kind =
      action === 'require_approval'
        ? 'review'
        : action === 'quarantine'
          ? 'quarantine'
          : action === 'deliver' || action === 'tag'
            ? 'deliver'
            : 'none';
    const recipientRows = buildRecipients(
      recipientAddresses,
      action,
      kind,
      receivedMs,
      anchor,
      id,
      random,
    );
    const subject = subjectFor(i, verdict, random);
    const attachmentCount =
      verdict === 'malware' ? random.int(1, 2) : random.bool(0.3) ? random.int(1, 3) : 0;
    const receivedAt = new Date(receivedMs).toISOString();
    const status = statusFor(verdict, action, recipientRows);
    const headerFrom =
      envelopeFrom === ''
        ? null
        : verdict === 'bec' && random.bool(0.6)
          ? `ceo@${LOOKALIKE_SENDER_DOMAIN}`
          : random.bool(0.1)
            ? `${random.pick(ROLE_LOCALS)}@${envelopeFrom.slice(envelopeFrom.indexOf('@') + 1)}`
            : envelopeFrom;
    const lifecycleRound = verdict !== null && i % 11 === 0 ? 1 : 0;
    const detail: MessageDetail = {
      id,
      receivedAt,
      direction,
      status,
      statusChangedAt: new Date(receivedMs + 5_000).toISOString(),
      subject,
      subjectMasked: subject !== null,
      envelopeFrom,
      headerFrom,
      recipientCount: recipientRows.length,
      attachmentCount,
      sizeBytes: random.int(4_000, 9_000_000),
      finalVerdict: verdict,
      finalAction: action,
      riskScore: riskFor(verdict, random),
      domainId: null,
      internetMessageId:
        i % 89 === 7
          ? null
          : `<${id.slice(0, 8)}.${i}@mail.${direction === 'inbound' ? (envelopeFrom.split('@')[1] ?? 'example.test') : tenantDomain}>`,
      lifecycleRound,
      version: transitionsFor(status, lifecycleRound).length,
      statusReason:
        action === 'quarantine'
          ? 'policy_quarantine'
          : action === 'require_approval'
            ? 'policy_review'
            : action === 'reject' || action === 'discard'
              ? 'policy_reject'
              : null,
      clientIp:
        direction === 'inbound' ? `198.51.100.${(i % 200) + 1}` : `192.0.2.${(i % 50) + 10}`,
      clientHelo: i % 13 === 0 ? 'mx.<script>.example.test' : 'mx1.example.test',
      mtaQueueId: `4X${id.slice(0, 10).toUpperCase().replace(/-/g, '')}`,
    };
    const urlCount =
      verdict === 'phishing' ? random.int(1, 4) : random.bool(0.5) ? random.int(1, 3) : 0;
    out.push(
      withLazyRounds({
        detail,
        recipients: recipientRows.map((r) => r.address),
        recipientRows,
        domainIndex: tenantIndex,
        attachments: buildAttachments(id, attachmentCount, verdict ?? 'unknown', random),
        urls: buildUrls(urlCount, verdict ?? 'unknown', random),
      }),
    );
  }
  return out.sort(
    (a, b) =>
      b.detail.receivedAt.localeCompare(a.detail.receivedAt) ||
      b.detail.id.localeCompare(a.detail.id),
  );
}

interface DatasetState {
  anchor: number;
  messages: FixtureMessage[];
  byId: Map<string, FixtureMessage>;
}
const globalState = globalThis as typeof globalThis & {
  __egDevFixtureMessageDataset?: DatasetState;
};

function dataset(): DatasetState {
  if (!globalState.__egDevFixtureMessageDataset) {
    // Anchored at the current minute once per process: the newest mail is minutes old, so the
    // "Last hour" preset has data, and every bundle of `next dev` shares the same dataset.
    const now = Date.now();
    const anchor = now - (now % MINUTE);
    const messages = buildDataset(anchor);
    globalState.__egDevFixtureMessageDataset = {
      anchor,
      messages,
      byId: new Map(messages.map((m) => [m.detail.id, m])),
    };
  }
  return globalState.__egDevFixtureMessageDataset;
}

/** Every dataset message, newest first. */
export function fixtureDataset(): readonly FixtureMessage[] {
  return dataset().messages;
}

/** The instant the dataset was anchored at (its newest message is at most this recent). */
export function fixtureDatasetAnchor(): number {
  return dataset().anchor;
}

/** A dataset message by public id (case-insensitive), or undefined. */
export function fixtureMessageById(id: string): FixtureMessage | undefined {
  return dataset().byId.get(id.toLowerCase());
}

/**
 * Live quarantine entry states of a message: `quarantine.ts` registers its store (entries change
 * with releases and rejections); without it the dataset's initial states apply.
 */
type QuarantineStateProvider = (messageId: string) => readonly string[] | null;
const providerState = globalThis as typeof globalThis & {
  __egDevFixtureQuarantineStates?: QuarantineStateProvider;
};
export function registerQuarantineStates(provider: QuarantineStateProvider): void {
  providerState.__egDevFixtureQuarantineStates = provider;
}
export function quarantineStatesOf(message: FixtureMessage): readonly string[] {
  const live = providerState.__egDevFixtureQuarantineStates?.(message.detail.id);
  if (live) return live;
  return message.recipientRows.flatMap((r) => (r.quarantine ? [r.quarantine] : []));
}

/** The message as `GET /messages/{id}` returns it to an organization (subject withheld, E5). */
export function messageDetailView(message: FixtureMessage, organizationId: string): MessageDetail {
  return {
    ...message.detail,
    subject: null,
    subjectMasked: message.detail.subject !== null,
    domainId:
      message.domainIndex === null ? null : domainIdFor(organizationId, message.domainIndex),
  };
}

/** The message as an item of `GET /messages` (subject withheld, E5). */
export function messageListItem(
  message: FixtureMessage,
  organizationId: string,
): ListItem<'MessagesController_list_v1'> {
  const d = messageDetailView(message, organizationId);
  return {
    id: d.id,
    receivedAt: d.receivedAt,
    direction: d.direction,
    status: d.status,
    statusChangedAt: d.statusChangedAt,
    subject: null,
    subjectMasked: d.subjectMasked,
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
