/**
 * The deterministic data plan of one seeding run (pure; no I/O): message specs of both
 * organizations relative to `now`, and the expected dashboard figures computed independently
 * from those specs (never from the api or the portal code).
 */
import type {
  DeliveryStatus,
  MessageAction,
  MessageDirection,
  MessageVerdict,
  QuarantineReason,
  QuarantineStatus,
  ScanStatus,
} from '@email-gateway/database';
import type { DashboardExpectation } from '../support/state';

export const MINUTE = 60_000;
export const HOUR = 60 * MINUTE;
export const DAY = 24 * HOUR;

export type DomainRef = 'primary' | 'deleted' | null;

export interface DeliveryPlan {
  status: DeliveryStatus;
  deliveredAfterMs: number | null;
  /** Recipient position of the delivery (default 0); one delivery (sequence 0) per recipient. */
  rcptSeq?: number;
}

/** An attachment row of a message (metadata only; content never stored anywhere). */
export interface AttachmentPlan {
  filename: string;
  contentType: string;
  sizeBytes: number;
  verdict: 'clean' | 'suspicious' | 'malicious';
}

/** A URL of a message as the URL engine stores it (`message_urls` + `url_scan_results`). */
export interface UrlPlan {
  url: string;
  host: string;
  verdict: 'clean' | 'suspicious' | 'malicious';
}

/**
 * Engine rows written for the details sections (step 7.2 §1.4): `phish` (inbound phishing:
 * headers, auth, rspamd symbols with address options, BEC, URL, attachment, risk, policy,
 * lifecycle history), `outbound` (DLP findings, deliveries with SMTP texts and status events),
 * `basic` (headers, auth, rspamd, risk, policy and history only).
 */
export type DetailProfile = 'phish' | 'outbound' | 'basic';

export interface ScanPlan {
  status: ScanStatus;
  completedAfterMs: number | null;
}

export interface QuarantinePlan {
  state: QuarantineStatus;
  reason: QuarantineReason;
  /** `quarantined_at − received_at`. */
  afterMs: number;
}

export interface MessagePlan {
  key: string;
  receivedAt: Date;
  direction: MessageDirection;
  verdict: MessageVerdict;
  action: MessageAction;
  domain: DomainRef;
  riskScore: number;
  recipient: string;
  envelopeFrom: string;
  subject: string;
  deliveries: DeliveryPlan[];
  scan: ScanPlan | null;
  quarantine: QuarantinePlan | null;
  /** Special roles (approval flow, preview/download, beta isolation targets). */
  role?: 'approval' | 'preview' | 'beta-target';
  /**
   * `email_messages.header_from`: the address inside `<…>` of the first From header, as the
   * smtp-adapter stores it (default: the envelope sender).
   */
  headerFrom?: string;
  /** Message-ID header value as stored (default: a random id in angle brackets). */
  internetMessageId?: string;
  /** Every envelope recipient in `rcpt_seq` order (default `[recipient]`). */
  recipients?: string[];
  attachments?: AttachmentPlan[];
  urls?: UrlPlan[];
  /** Engine rows for the details sections (step 7.2); none by default. */
  details?: DetailProfile;
}

/** Every envelope recipient of a plan, in `rcpt_seq` order. */
export function recipientsOf(plan: MessagePlan): string[] {
  return plan.recipients ?? [plan.recipient];
}

const INBOUND_TABLE: Array<[MessageVerdict, MessageAction]> = [
  ['clean', 'deliver'],
  ['clean', 'deliver'],
  ['spam', 'quarantine'],
  ['bulk', 'discard'],
  ['phishing', 'quarantine'],
  ['malware', 'reject'],
  ['bec', 'quarantine'],
  ['suspicious', 'tag'],
  ['spam', 'tag'],
  ['clean', 'deliver'],
];
const DELIVERY_CYCLE: DeliveryStatus[] = [
  'delivered',
  'delivered',
  'delivered',
  'deferred',
  'bounced',
  'delivered',
  'failed',
  'expired',
];
const QUARANTINE_STATES: QuarantineStatus[] = ['held', 'held', 'released', 'rejected', 'expired'];
const REASON_OF: Partial<Record<MessageVerdict, QuarantineReason>> = {
  spam: 'spam',
  bulk: 'bulk',
  phishing: 'phishing',
  malware: 'malware',
  bec: 'bec',
  suspicious: 'suspicious',
};

export const ALPHA_GENERATED = 380;
export const BETA_GENERATED = 24;

function direction(i: number): MessageDirection {
  const k = i % 20;
  return k < 12 ? 'inbound' : k < 17 ? 'outbound' : 'internal';
}

/** Spread: the first 72 messages within the last 18 h, the rest between 1 and 6 days ago. */
function receivedAt(now: number, i: number, total: number): Date {
  if (i < 72) return new Date(now - 10 * MINUTE - i * 15 * MINUTE);
  const rest = Math.max(1, total - 72);
  return new Date(now - DAY - Math.floor(((i - 72) * 5 * DAY) / rest));
}

export function planMessages(
  org: 'alpha' | 'beta',
  domainName: string,
  now: number,
  mailbox: string,
): MessagePlan[] {
  const total = org === 'alpha' ? ALPHA_GENERATED : BETA_GENERATED;
  const plans: MessagePlan[] = [];
  let quarantined = 0;
  for (let i = 0; i < total; i++) {
    const dir = direction(i);
    const [verdict, action]: [MessageVerdict, MessageAction] =
      dir === 'inbound'
        ? INBOUND_TABLE[i % INBOUND_TABLE.length]!
        : i % 7 === 0
          ? ['spam', 'reject']
          : ['clean', 'deliver'];
    const domain: DomainRef =
      dir !== 'inbound' ? 'primary' : i % 9 === 0 ? null : i % 13 === 0 ? 'deleted' : 'primary';
    const at = receivedAt(now, i, total);
    const deliveries: DeliveryPlan[] =
      action === 'deliver' || action === 'tag'
        ? [
            {
              status: DELIVERY_CYCLE[i % DELIVERY_CYCLE.length]!,
              deliveredAfterMs: null,
            },
          ].map((d) => ({
            ...d,
            deliveredAfterMs: d.status === 'delivered' ? 2_000 + ((i * 1_373) % 600_000) : null,
          }))
        : [];
    const scan: ScanPlan =
      i % 15 === 14
        ? { status: 'failed', completedAfterMs: null }
        : i % 15 === 13
          ? { status: 'timed_out', completedAfterMs: null }
          : { status: 'completed', completedAfterMs: 300 + ((i * 997) % 12_000) };
    let quarantine: QuarantinePlan | null = null;
    let recipient = `user${i % 5}@${domainName}`;
    if (action === 'quarantine') {
      const state = QUARANTINE_STATES[quarantined % QUARANTINE_STATES.length]!;
      quarantine = { state, reason: REASON_OF[verdict] ?? 'policy', afterMs: 5_000 };
      // Every third quarantined message is addressed to the mailbox user (self-service).
      if (org === 'alpha' && quarantined % 3 === 0) recipient = mailbox;
      quarantined++;
    }
    plans.push({
      key: `${org}-${i}`,
      receivedAt: at,
      direction: dir,
      verdict,
      action,
      domain,
      riskScore: (i * 37) % 1000,
      recipient: dir === 'outbound' ? `partner${i % 4}@partner.e2e-portal.test` : recipient,
      envelopeFrom:
        dir === 'inbound'
          ? `sender${i % 7}@external.e2e-portal.test`
          : `staff${i % 6}@${domainName}`,
      subject:
        org === 'beta'
          ? `BETA-ONLY message ${i}`
          : `Alpha ${verdict} message ${i.toString().padStart(3, '0')}`,
      deliveries,
      scan,
      quarantine,
    });
  }
  return plans;
}

/** The two special alpha messages of the quarantine spec. */
export function planSpecialAlpha(now: number, domainName: string, mailbox: string): MessagePlan[] {
  return [
    {
      key: 'alpha-approval',
      role: 'approval',
      receivedAt: new Date(now - 40 * MINUTE),
      direction: 'inbound',
      verdict: 'spam',
      action: 'quarantine',
      domain: 'primary',
      riskScore: 640,
      recipient: `user1@${domainName}`,
      envelopeFrom: 'billing@external.e2e-portal.test',
      subject: 'E2E approval-required message',
      deliveries: [],
      // No completed scan round: the release pre-check answers `no_scan_round`, so a release
      // needs an approver (docs/plan/steps/17-quarantine.md §13.3).
      scan: null,
      quarantine: { state: 'held', reason: 'spam', afterMs: 5_000 },
    },
    {
      key: 'alpha-preview',
      role: 'preview',
      receivedAt: new Date(now - 50 * MINUTE),
      direction: 'inbound',
      verdict: 'spam',
      action: 'quarantine',
      domain: 'primary',
      riskScore: 420,
      recipient: mailbox,
      envelopeFrom: 'newsletter@external.e2e-portal.test',
      subject: 'E2E preview message',
      deliveries: [],
      scan: { status: 'completed', completedAfterMs: 1_800 },
      quarantine: { state: 'held', reason: 'spam', afterMs: 5_000 },
    },
  ];
}

/**
 * Step 7.2: the explorer's search targets and the details messages of alpha (design §9, WP5).
 * Distinct envelope senders, From header addresses, sender and recipient domains, subjects with
 * reply markers and a shared prefix ("Invoice 44"), Message-IDs in brackets, several delivery
 * and quarantine states, attachments and URLs. The six messages received in the explorer test
 * window `[now − 35 min, now − 11 min)` (search 1–4, details phish and outbound) plus generated
 * message 1 (25 min ago) are the exact expectations of the explorer filter tests; the approval
 * and rescan targets lie outside that window because details.spec changes their state.
 */
export const EXPLORER_WINDOW = { fromMinutesAgo: 35, toMinutesAgo: 11 } as const;

export function planExplorerAlpha(now: number, domainName: string): MessagePlan[] {
  const at = (minutesAgo: number) => new Date(now - minutesAgo * MINUTE);
  const completed = (ms: number): ScanPlan => ({ status: 'completed', completedAfterMs: ms });
  const local = (name: string) => `${name}@${domainName}`;
  return [
    {
      key: 'alpha-search-1',
      receivedAt: at(12),
      direction: 'inbound',
      verdict: 'clean',
      action: 'deliver',
      domain: 'primary',
      riskScore: 110,
      recipient: local('ap'),
      envelopeFrom: 'invoices@vendor-one.e2e-portal.test',
      headerFrom: 'billing@vendor-one.e2e-portal.test',
      subject: 'RE: Invoice 4471 for October',
      internetMessageId: '<inv-4471.e2e@vendor-one.e2e-portal.test>',
      deliveries: [{ status: 'delivered', deliveredAfterMs: 4_200 }],
      scan: completed(1_400),
      quarantine: null,
      attachments: [
        {
          filename: 'invoice-4471.pdf',
          contentType: 'application/pdf',
          sizeBytes: 48_213,
          verdict: 'clean',
        },
      ],
    },
    {
      key: 'alpha-search-2',
      receivedAt: at(14),
      direction: 'inbound',
      verdict: 'suspicious',
      action: 'tag',
      domain: null,
      riskScore: 480,
      recipient: local('finance'),
      envelopeFrom: 'invoices@vendor-one.e2e-portal.test',
      headerFrom: 'billing@vendor-one.e2e-portal.test',
      subject: 'Fwd: Invoice 4472 for November',
      internetMessageId: '<inv-4472.e2e@vendor-one.e2e-portal.test>',
      deliveries: [{ status: 'bounced', deliveredAfterMs: null }],
      scan: completed(1_900),
      quarantine: null,
    },
    {
      key: 'alpha-search-3',
      receivedAt: at(16),
      direction: 'inbound',
      verdict: 'phishing',
      action: 'quarantine',
      domain: 'primary',
      riskScore: 860,
      recipient: local('ap'),
      envelopeFrom: 'alerts@vendor-two.e2e-portal.test',
      headerFrom: 'security@vendor-two.e2e-portal.test',
      subject: 'Account notice 9931',
      internetMessageId: '<notice-9931.e2e@vendor-two.e2e-portal.test>',
      deliveries: [],
      scan: completed(2_300),
      quarantine: { state: 'held', reason: 'phishing', afterMs: 5_000 },
    },
    {
      key: 'alpha-search-4',
      receivedAt: at(18),
      direction: 'outbound',
      verdict: 'clean',
      action: 'deliver',
      domain: 'primary',
      riskScore: 30,
      recipient: 'buyer@customer-two.e2e-portal.test',
      recipients: ['buyer@customer-two.e2e-portal.test', 'cfo@customer-two.e2e-portal.test'],
      envelopeFrom: local('sales'),
      subject: 'Quote 5520 for Customer Two',
      internetMessageId: '<quote-5520.e2e@alpha.e2e-portal.test>',
      deliveries: [
        { status: 'delivered', deliveredAfterMs: 2_600, rcptSeq: 0 },
        { status: 'deferred', deliveredAfterMs: null, rcptSeq: 1 },
      ],
      scan: completed(900),
      quarantine: null,
    },
    {
      key: 'alpha-detail-phish',
      receivedAt: at(21),
      direction: 'inbound',
      verdict: 'phishing',
      action: 'quarantine',
      domain: 'primary',
      riskScore: 910,
      recipient: local('ap'),
      recipients: [local('ap'), local('finance'), local('ceo')],
      envelopeFrom: 'it-support@lookalike-alpha.e2e-portal.test',
      headerFrom: 'it-support@lookalike-alpha.e2e-portal.test',
      subject: 'Re: Password expiry notice',
      internetMessageId: '<pw-expiry.e2e@lookalike-alpha.e2e-portal.test>',
      deliveries: [],
      scan: completed(3_100),
      quarantine: { state: 'held', reason: 'phishing', afterMs: 5_000 },
      attachments: [
        {
          filename: 'password-reset.html',
          contentType: 'text/html',
          sizeBytes: 12_480,
          verdict: 'suspicious',
        },
      ],
      urls: [
        {
          url: 'https://login.lookalike-alpha.e2e-portal.test/reset?u=7',
          host: 'login.lookalike-alpha.e2e-portal.test',
          verdict: 'malicious',
        },
        {
          url: 'https://www.alpha.e2e-portal.test/help',
          host: 'www.alpha.e2e-portal.test',
          verdict: 'clean',
        },
      ],
      details: 'phish',
    },
    {
      key: 'alpha-detail-outbound',
      receivedAt: at(23),
      direction: 'outbound',
      verdict: 'suspicious',
      action: 'tag',
      domain: 'primary',
      riskScore: 520,
      recipient: 'payments@partner-three.e2e-portal.test',
      recipients: [
        'payments@partner-three.e2e-portal.test',
        'treasury@partner-three.e2e-portal.test',
      ],
      envelopeFrom: local('treasury'),
      subject: 'Card details for the October settlement',
      internetMessageId: '<settlement-oct.e2e@alpha.e2e-portal.test>',
      deliveries: [
        { status: 'delivered', deliveredAfterMs: 3_300, rcptSeq: 0 },
        { status: 'bounced', deliveredAfterMs: null, rcptSeq: 1 },
      ],
      scan: completed(2_700),
      quarantine: null,
      attachments: [
        {
          filename: 'settlement-october.xlsx',
          contentType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
          sizeBytes: 30_211,
          verdict: 'clean',
        },
      ],
      details: 'outbound',
    },
    {
      key: 'alpha-detail-approval',
      receivedAt: at(45),
      direction: 'inbound',
      verdict: 'spam',
      action: 'quarantine',
      domain: 'primary',
      riskScore: 640,
      recipient: local('finance'),
      envelopeFrom: 'offers@external.e2e-portal.test',
      subject: 'E2E details approval message',
      internetMessageId: '<details-approval.e2e@external.e2e-portal.test>',
      deliveries: [],
      // No scan round: a release needs an approver (`no_scan_round`, step 5.3 §13.3).
      scan: null,
      quarantine: { state: 'held', reason: 'spam', afterMs: 5_000 },
      details: 'basic',
    },
    {
      key: 'alpha-detail-rescan',
      receivedAt: at(47),
      direction: 'inbound',
      verdict: 'spam',
      action: 'quarantine',
      domain: 'primary',
      riskScore: 700,
      recipient: local('ap'),
      envelopeFrom: 'promo@external.e2e-portal.test',
      subject: 'E2E details rescan message',
      internetMessageId: '<details-rescan.e2e@external.e2e-portal.test>',
      deliveries: [],
      scan: completed(1_200),
      quarantine: { state: 'held', reason: 'spam', afterMs: 5_000 },
      details: 'basic',
    },
    {
      // Step 7.2 §13 closer: an entry created 80 days after receipt (a manual quarantine or a
      // rescan long after receipt), outside any 62-day window that starts at receipt; the
      // details page must still list it. Received 120 days ago and quarantined 40 days ago, so
      // no explorer, quarantine or dashboard range of the other specs (at most 31 days) sees
      // it; `expired` so the quarantine sweeper never acts on it.
      key: 'alpha-detail-late',
      receivedAt: new Date(now - LATE_MESSAGE_AGE_DAYS * DAY),
      direction: 'inbound',
      verdict: 'spam',
      action: 'quarantine',
      domain: 'primary',
      riskScore: 610,
      recipient: local('legal'),
      envelopeFrom: 'late@external.e2e-portal.test',
      subject: 'E2E details late quarantine message',
      internetMessageId: '<details-late.e2e@external.e2e-portal.test>',
      deliveries: [],
      scan: null,
      quarantine: { state: 'expired', reason: 'spam', afterMs: 80 * DAY },
    },
  ];
}

/**
 * Age of the oldest seeded message (`alpha-detail-late`, received 120 days ago). The cleanup's
 * partition cutoff must reach it (seed/cleanup.ts `PARTITION_CUTOFF_DAYS`).
 */
export const LATE_MESSAGE_AGE_DAYS = 120;

/** Beta's twin of alpha search message 1 (same sender and Message-ID; isolation target). */
export function planExplorerBeta(now: number): MessagePlan[] {
  return [
    {
      key: 'beta-search-twin',
      receivedAt: new Date(now - 13 * MINUTE),
      direction: 'inbound',
      verdict: 'clean',
      action: 'deliver',
      domain: 'primary',
      riskScore: 111,
      recipient: 'ap@beta.e2e-portal.test',
      envelopeFrom: 'invoices@vendor-one.e2e-portal.test',
      headerFrom: 'billing@vendor-one.e2e-portal.test',
      subject: 'BETA-ONLY RE: Invoice 4471 for October',
      internetMessageId: '<inv-4471.e2e@vendor-one.e2e-portal.test>',
      deliveries: [{ status: 'delivered', deliveredAfterMs: 2_000 }],
      scan: { status: 'completed', completedAfterMs: 1_000 },
      quarantine: null,
      details: 'basic',
    },
  ];
}

const PROCESSING_BOUNDS = [250, 500, 1000, 2000, 5000, 10000, 30000, 60000, 120000, 300000, 900000];
const THREAT_VERDICTS_TOP = ['spam', 'phishing', 'malware', 'bec', 'suspicious'];

/** Expected dashboard figures for messages received in [from, to). */
export function expectDashboard(
  plans: readonly MessagePlan[],
  domainNames: { primary: string; deleted: string },
  from: number,
  to: number,
): DashboardExpectation {
  const inRange = plans.filter(
    (p) => p.receivedAt.getTime() >= from && p.receivedAt.getTime() < to,
  );
  const count = (fn: (p: MessagePlan) => boolean) => inRange.filter(fn).length;
  const deliveries = inRange.flatMap((p) => p.deliveries);
  const status = (s: DeliveryStatus) => deliveries.filter((d) => d.status === s).length;
  const delivered = status('delivered');
  const denominator = delivered + status('bounced') + status('failed') + status('expired');
  const samples = inRange
    .map((p) => p.scan)
    .filter((s): s is ScanPlan => s !== null && s.status === 'completed')
    .map((s) => Math.max(0, s.completedAfterMs ?? 0));
  let p95: number | null = null;
  if (samples.length > 0) {
    const need = Math.ceil(samples.length * 0.95);
    for (const bound of PROCESSING_BOUNDS) {
      if (samples.filter((ms) => ms <= bound).length >= need) {
        p95 = bound;
        break;
      }
    }
  }
  const threatVerdicts: Record<string, number> = {};
  for (const p of inRange) threatVerdicts[p.verdict] = (threatVerdicts[p.verdict] ?? 0) + 1;
  const inbound = inRange.filter((p) => p.direction === 'inbound');
  const isThreat = (p: MessagePlan) => THREAT_VERDICTS_TOP.includes(p.verdict);
  const topDomains = (['primary', 'deleted'] as const)
    .map((ref) => {
      const rows = inbound.filter((p) => p.domain === ref);
      return {
        name: domainNames[ref],
        threats: rows.filter(isThreat).length,
        inbound: rows.length,
        deleted: ref === 'deleted',
      };
    })
    .filter((d) => d.threats > 0)
    .sort((a, b) => b.threats - a.threats || b.inbound - a.inbound);
  const unattributedRows = inbound.filter((p) => p.domain === null);
  return {
    total: inRange.length,
    inbound: count((p) => p.direction === 'inbound'),
    outbound: count((p) => p.direction === 'outbound'),
    internal: count((p) => p.direction === 'internal'),
    spamBlocked: count(
      (p) =>
        (p.verdict === 'spam' || p.verdict === 'bulk') &&
        (p.action === 'quarantine' || p.action === 'discard' || p.action === 'reject'),
    ),
    malware: count((p) => p.verdict === 'malware'),
    phishing: count((p) => p.verdict === 'phishing'),
    quarantinedMessages: count((p) => p.action === 'quarantine'),
    quarantineEntries: inRange.filter(
      (p) =>
        p.quarantine !== null &&
        p.receivedAt.getTime() + p.quarantine.afterMs >= from &&
        p.receivedAt.getTime() + p.quarantine.afterMs < to,
    ).length,
    delivered,
    deliveries: deliveries.length,
    successRate: denominator === 0 ? null : delivered / denominator,
    p95UpperBoundMs: p95,
    averageMs:
      samples.length === 0
        ? null
        : Math.round(samples.reduce((sum, ms) => sum + ms, 0) / samples.length),
    threatVerdicts,
    topDomains,
    unattributed: {
      inbound: unattributedRows.length,
      threats: unattributedRows.filter(isThreat).length,
    },
  };
}
