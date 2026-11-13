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
}

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
