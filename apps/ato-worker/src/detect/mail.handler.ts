import { NonRetryableError } from '@email-gateway/common';
import {
  atoMailKey,
  canonicalIp,
  hmacKey,
  ipPrefix,
  type ActivityDelta,
  type OutboundMessageObservation,
  type WindowSnapshot,
} from '@email-gateway/ato-detection';
import { messageScannedV1, type EventEnvelope } from '@email-gateway/event-contracts';
import { registrableDomainOf } from '@email-gateway/url-security';
import type { AtoEventResult } from '../metrics/ato-metrics';
import { atoEnabled, type OrgContext } from '../reads/org-context';
import { LEDGERS } from '../shared/db';
import { InconsistentReadError } from '../shared/errors';
import { detectLedgered, type DetectDeps } from './context';
import type { DetectionPipeline, DetectRequest } from './pipeline';

/** The scan round facts a mail detection needs (from `scanned.v1` or the catch-up reads). */
export interface ScannedFacts {
  messageId: bigint;
  receivedAt: Date;
  scanId: bigint;
  direction: 'inbound' | 'outbound' | 'internal';
  /** Aggregate scan verdict of the round. */
  verdict: string | null;
  /** Union of the round's final reason codes. */
  reasonCodes: readonly string[];
}

const PHISHING_CODES = new Set([
  'fuzzy.phish',
  'url.phishing_high_confidence',
  'url.dynamic_phishing',
  'url.credential_form',
  'url.credential_form_cross_origin',
  'url.dynamic_cross_origin_form',
  'url.feed_malicious',
  'url.dnsbl_phishing',
]);
const MALWARE_CODES = new Set(['attachment.malware', 'url.dnsbl_malware']);
const MALWARE_HARD_BLOCKS = new Set([
  'hb.malware_attachment',
  'hb.malware_url',
  'hb.malware_sandbox',
]);
const PHISHING_HARD_BLOCKS = new Set(['hb.known_phishing']);
const SPAM_CODES = new Set(['spam.score', 'spam.reject_action', 'spam.gtube']);
const FINANCIAL_DLP = new Set(['financial', 'bank_account', 'payment_card']);
/** Recipients and attachments read per message (D6 bounds). */
const MAX_RECIPIENTS = 1000;
const MAX_ATTACHMENTS = 100;
const REPLY_PARENT_DAYS = 180;
/** O5 threshold used for the `massSubject` content counter of the day row. */
const MASS_SUBJECT_MESSAGES = 30;

/** The parts of `bec_scan_results.outbound_observations` ATO reads (counts and flags only). */
interface ObservationsView {
  status?: unknown;
  categories?: Record<string, unknown>;
  financialIdentifiers?: Record<string, unknown>;
  links?: Record<string, unknown>;
}

function observationsView(value: unknown): ObservationsView | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

/** Classifies the round's findings (D6, P1–P5): codes and booleans only, never content. */
export function outboundFindings(input: {
  reasonCodes: readonly string[];
  verdict: string | null;
  hardBlocks: unknown;
  dlpCategories: unknown;
  observations: unknown;
}): OutboundMessageObservation['findings'] {
  const codes = input.reasonCodes;
  const blocks = Array.isArray(input.hardBlocks)
    ? input.hardBlocks
        .map((b) => (b && typeof b === 'object' ? (b as { id?: unknown }).id : null))
        .filter((id): id is string => typeof id === 'string')
    : [];
  const phishingCodes = codes.filter((c) => c.startsWith('phishing.') || PHISHING_CODES.has(c));
  phishingCodes.push(...blocks.filter((b) => PHISHING_HARD_BLOCKS.has(b)));
  const obs = observationsView(input.observations);
  if (obs?.links?.credentialHarvesting === true)
    phishingCodes.push('bec.link_credential_harvesting');
  if (obs?.links?.malicious === true) phishingCodes.push('bec.link_malicious');
  const becCategories =
    obs && obs.status !== 'unavailable' && obs.categories && typeof obs.categories === 'object'
      ? Object.entries(obs.categories)
          .filter(([, n]) => typeof n === 'number' && n > 0)
          .map(([k]) => k)
          .sort()
      : null;
  const ids: Record<string, unknown> = obs?.financialIdentifiers ?? {};
  const observedFinancial = ['iban', 'swift', 'ifsc_account'].some(
    (k) => typeof ids[k] === 'number' && ids[k] > 0,
  );
  const dlpFinancial = Array.isArray(input.dlpCategories)
    ? input.dlpCategories.some((c) => {
        const e = c as { category?: unknown; count?: unknown } | null;
        return (
          typeof e?.category === 'string' &&
          FINANCIAL_DLP.has(e.category) &&
          (typeof e.count !== 'number' || e.count > 0)
        );
      })
    : false;
  return {
    phishing: phishingCodes.length > 0,
    phishingCodes: [...new Set(phishingCodes)].sort(),
    malware:
      codes.some((c) => MALWARE_CODES.has(c)) || blocks.some((b) => MALWARE_HARD_BLOCKS.has(b)),
    spam: input.verdict === 'spam' || codes.some((c) => SPAM_CODES.has(c)),
    becCategories,
    financial: observedFinancial || dlpFinancial,
  };
}

/** The bare address of a From header value (`Name <a@b>` or `a@b`), lower-cased. */
export function bareAddress(value: string | null): string | null {
  if (!value) return null;
  const angle = /<([^<>\s]+@[^<>\s]+)>/.exec(value);
  const raw = (angle?.[1] ?? value).trim().toLowerCase();
  return raw.includes('@') ? raw : null;
}

/**
 * Outbound and internal mail (D6): `mail.message.scanned.v1` from the lossy `ato.mail` queue and
 * the catch-up job share this handler and its key `atoMailKey(messageId, scanId)` (D3). Reads on
 * the writer, echo-checked and partition-pruned by `received_at`; recipient addresses are never
 * stored (registrable domains and counts only). The mailbox account is the lower-cased envelope
 * sender; the attributed connector (submission telemetry, D4) is a second account.
 */
export class MailHandler {
  constructor(
    private readonly deps: DetectDeps,
    private readonly pipeline: DetectionPipeline,
  ) {}

  /** The live consumer's entry point (no-op fast paths without a ledger row, D3). */
  async handle(event: EventEnvelope<unknown>): Promise<AtoEventResult> {
    const parsed = messageScannedV1.safeParse(event.payload);
    if (!parsed.success) throw new NonRetryableError('payload_invalid');
    const p = parsed.data;
    if (p.direction === 'inbound') return 'skipped_direction';
    const org = await this.deps.orgs.get(BigInt(event.organizationId));
    if (!org.exists || !org.active) return 'skipped_org';
    if (!atoEnabled(org)) return 'skipped_feature';
    return this.process(org, {
      messageId: BigInt(p.messageId),
      receivedAt: new Date(p.receivedAt),
      scanId: BigInt(p.scanId),
      direction: p.direction,
      verdict: p.verdict,
      reasonCodes: p.reasonCodes,
    });
  }

  /** One message, once (shared by the live consumer and the catch-up). */
  async process(org: OrgContext, facts: ScannedFacts): Promise<AtoEventResult> {
    const prisma = this.deps.prisma;
    const orgId = org.id;
    const { messageId, receivedAt, scanId } = facts;
    const msg = await prisma.emailMessage.findUnique({
      where: { id_receivedAt: { id: messageId, receivedAt } },
      select: {
        id: true,
        receivedAt: true,
        organizationId: true,
        domainId: true,
        direction: true,
        envelopeFrom: true,
        headerFrom: true,
        clientIp: true,
        mtaQueueId: true,
        subjectKey: true,
        recipientCount: true,
        attachmentCount: true,
        ingestSource: true,
      },
    });
    if (!msg) return 'skipped_org';
    // Step 8.6 D4 (defence in depth): a journal intake message never writes `scanned.v1` and the
    // catch-up excludes it; one reaching here is still never an ATO signal.
    if (msg.ingestSource === 'journal_intake') return 'skipped_source';
    if (
      msg.organizationId !== orgId ||
      msg.id !== messageId ||
      msg.receivedAt.getTime() !== receivedAt.getTime() ||
      msg.direction !== facts.direction
    ) {
      throw new InconsistentReadError('email_message');
    }
    const sender = bareAddress(msg.envelopeFrom);
    // Null-sender (bounces) and malformed senders have no mailbox account (D6).
    if (!sender) return 'unattributed';

    const where = { messageId, receivedAt, organizationId: orgId };
    const [recipients, attachments, header, risk, dlp, bec] = await Promise.all([
      prisma.emailRecipient.findMany({
        where,
        select: { addressDomain: true, direction: true },
        take: MAX_RECIPIENTS,
      }),
      prisma.emailAttachment.findMany({
        where,
        select: { sha256: true, detectedContentType: true, declaredContentType: true },
        orderBy: { partIndex: 'asc' },
        take: MAX_ATTACHMENTS,
      }),
      prisma.emailHeader.findFirst({
        where: { ...where, name: 'In-Reply-To' },
        select: { value: true },
        orderBy: { seq: 'asc' },
      }),
      prisma.messageRiskScore.findFirst({
        where: { scanId, receivedAt, organizationId: orgId },
        select: { hardBlocks: true, messageId: true },
        orderBy: { revision: 'desc' },
      }),
      prisma.dlpScanResult.findFirst({
        where: { scanId, receivedAt, organizationId: orgId },
        select: { categories: true, messageId: true },
      }),
      prisma.becScanResult.findFirst({
        where: { scanId, receivedAt, organizationId: orgId },
        select: { outboundObservations: true, messageId: true },
      }),
    ]);
    for (const row of [risk, dlp, bec]) {
      if (row && row.messageId !== messageId) throw new InconsistentReadError('scan_result');
    }
    let replyWithoutParent = false;
    const parentKey = header ? /<([^<>\s]{1,253})>/.exec(header.value)?.[1] : undefined;
    if (parentKey) {
      const parent = await prisma.emailMessage.findFirst({
        where: {
          organizationId: orgId,
          messageIdKey: parentKey,
          ingestSource: 'gateway',
          receivedAt: { gte: new Date(receivedAt.getTime() - REPLY_PARENT_DAYS * 86_400_000) },
        },
        select: { id: true },
      });
      replyWithoutParent = parent === null;
    }
    const attribution = msg.mtaQueueId
      ? await this.deps.windows.submissionAttribution(orgId, msg.mtaQueueId)
      : null;
    let connectorId: bigint | null = null;
    if (attribution) {
      const connector = await prisma.smtpConnector.findUnique({
        where: { id: BigInt(attribution.connectorId) },
        select: { id: true, organizationId: true },
      });
      if (connector && connector.organizationId === orgId) connectorId = connector.id;
    }

    const findings = outboundFindings({
      reasonCodes: facts.reasonCodes,
      verdict: facts.verdict,
      hardBlocks: risk?.hardBlocks ?? null,
      dlpCategories: dlp?.categories ?? null,
      observations: bec?.outboundObservations ?? null,
    });
    const internalMessage = msg.direction === 'internal';
    const external = internalMessage
      ? []
      : recipients.filter((r) => r.direction === 'outbound' || r.direction === null);
    const internalCount = recipients.length - external.length;
    const externalDomains = [
      ...new Set(
        external
          .map((r) =>
            r.addressDomain ? (registrableDomainOf(r.addressDomain) ?? r.addressDomain) : null,
          )
          .filter((d): d is string => d !== null)
          .map((d) => d.toLowerCase()),
      ),
    ];
    const attachmentList = attachments.map((a) => ({
      sha256: a.sha256,
      type:
        (a.detectedContentType ?? a.declaredContentType ?? null)?.toLowerCase().slice(0, 64) ??
        null,
    }));
    const clientIp = msg.clientIp ? canonicalIp(msg.clientIp) : null;
    const clientIpPrefix = clientIp ? ipPrefix(clientIp) : null;
    const headerFrom = bareAddress(msg.headerFrom);
    const headerFromMatches = headerFrom === null || headerFrom === sender;
    const messageRef = { id: messageId, receivedAt };

    const observation = (
      key: string,
      connectorAttributed: boolean,
      newDomainRecipients: number,
      breachListed: boolean | null,
    ): OutboundMessageObservation => ({
      type: 'outbound_message',
      key,
      occurredAt: receivedAt,
      message: messageRef,
      clientIpPrefix,
      connectorAttributed,
      headerFromMatches,
      replyWithoutParent,
      externalRecipients: external.length,
      internalRecipients: internalCount,
      externalDomains,
      newDomainRecipients,
      attachments: attachmentList,
      subjectKey: msg.subjectKey,
      findings,
      breachListed,
    });
    const activity =
      (peer: string | null) =>
      (snapshot: WindowSnapshot): ActivityDelta => ({
        at: receivedAt,
        messages: 1,
        recipients: recipients.length,
        externalRecipients: external.length,
        internalRecipients: internalCount,
        attachments: attachmentList.length,
        findings: findings.phishing || findings.malware || findings.spam ? 1 : 0,
        recipientDomains: externalDomains,
        attachmentTypes: attachmentList.flatMap((a) => (a.type ? [a.type] : [])),
        peer,
        becCategories: findings.becCategories ?? [],
        financial: findings.financial,
        phishing: findings.phishing,
        spam: findings.spam,
        fromMismatch: !headerFromMatches,
        massSubject: snapshot.subjectMessages60m >= MASS_SUBJECT_MESSAGES,
        clientPrefix: clientIpPrefix,
        hourExternalDomains: snapshot.distinctExternalDomains60m,
      });
    const key = atoMailKey(messageId, scanId);
    let newDomains: string[] = [];
    const requests: DetectRequest[] = [
      {
        org,
        subject: { kind: 'mailbox', address: sender },
        domainId: msg.domainId,
        breachAddress: sender,
        messages: [messageRef],
        observation: ({ baseline, seen, breachListed }) => {
          newDomains = externalDomains.filter(
            (d) => !baseline.externalDomains.has(d) && !seen.domains.has(d),
          );
          const fresh = new Set(newDomains);
          const count = external.filter((r) => {
            const d = r.addressDomain
              ? (registrableDomainOf(r.addressDomain) ?? r.addressDomain).toLowerCase()
              : null;
            return d !== null && fresh.has(d);
          }).length;
          return observation(key, false, count, breachListed);
        },
        activity: activity(connectorId?.toString() ?? null),
      },
    ];
    if (connectorId !== null) {
      // The attributed connector (D4): attribution is evidence, never enforcement alone.
      const senderHash = hmacKey(this.deps.hmacKey, 'sender', sender);
      requests.push({
        org,
        subject: { kind: 'smtp_connector', connectorId },
        messages: [messageRef],
        observation: () => observation(key, true, 0, null),
        activity: activity(senderHash.slice(0, 16)),
      });
    } else if (msg.mtaQueueId) {
      this.deps.metrics?.events.inc({ source: 'outbound_message', result: 'unattributed' });
    }
    return detectLedgered(
      this.deps,
      { consumer: LEDGERS.mail, eventId: key, source: 'outbound_message', occurredAt: receivedAt },
      requests,
      (outcomes, after) => {
        const mailbox = outcomes[0]!;
        const wa = { organizationId: orgId, accountId: mailbox.account.id };
        const domains = newDomains.slice(0, 200);
        after.push(async () => {
          for (const d of domains) await this.deps.windows.rememberSeen(wa, 'domains', d);
        });
      },
    );
  }
}
