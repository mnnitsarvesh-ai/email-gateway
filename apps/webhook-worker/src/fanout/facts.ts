import type { Prisma } from '@email-gateway/database';
import {
  assertWebhookPayloadSafe,
  domainNameSchema,
  INTERNET_MESSAGE_ID_MAX_LENGTH,
  MAX_RECIPIENT_DOMAINS,
  type WebhookDirection,
} from '@email-gateway/webhooks';
import { idOf, type InconsistencySink, wrongRead } from '../shared/errors';

/**
 * The fanout's writer reads (step 6.2 W3): every read is on the writer inside the fanout
 * transaction, scoped by the envelope organization, echo-checked (organization and key, 6.1 D15)
 * and partition-pruned (`received_at`). A required row that is missing or echoes another key is
 * an `InconsistentReadError` (retried); an optional row missing means "no event". Only metadata
 * leaves this module: domains (never local parts), public ids, codes and counts.
 */

export interface MessageKey {
  organizationId: bigint;
  messageId: bigint;
  receivedAt: Date;
}

/** `message` of §5.1 plus the internal keys the stored event row needs. */
export interface MessageFacts {
  key: MessageKey;
  publicId: string;
  direction: WebhookDirection;
  domainId: bigint | null;
  domainPublicId: string | null;
  internetMessageId: string | null;
  senderDomain: string | null;
  headerFromDomain: string | null;
  recipientCount: number;
  recipientDomains: string[];
  sizeBytes: number;
  attachmentCount: number;
  lifecycleRound: number;
  /**
   * `email_messages.ingest_source` (step 8.6, API-1): a copy (`journal_intake`, `mailbox_api`)
   * is never a gateway message — its sandbox verdict yields `mailbox.threat.detected` (API-4 A9.1).
   */
  ingestSource: 'gateway' | 'journal_intake' | 'mailbox_api';
}

/**
 * The counted copies of a copy message (step API-4 A9.1, sandbox stage): copies with copy verdict
 * authority (hybrid inline-authority copies never count, P-I3) of in-scope mailboxes (B6).
 */
export interface CopyDetectionFacts {
  /** `api` when any counted copy's mailbox domain is effective `api`, else `hybrid` (A8.2). */
  protectionMode: 'api' | 'hybrid';
  direction: WebhookDirection;
  copySource: 'journal' | 'graph' | 'gmail';
  /** The strongest stored policy disposition of the counted copies, or null. */
  policyDisposition: PolicyDispositionCode | null;
  mailboxCount: number;
  /** Public ids of the counted copies (first 20 by id). */
  detectionIds: string[];
}

/** `PolicyDisposition` values, weakest first (the order of strength A4 uses). */
export const POLICY_DISPOSITION_ORDER = [
  'allow',
  'require_approval',
  'quarantine',
  'reject',
] as const;
export type PolicyDispositionCode = (typeof POLICY_DISPOSITION_ORDER)[number];
/** Most copy public ids a detection names (`MAILBOX_MAX_DETECTION_IDS`). */
const MAX_DETECTION_IDS = 20;

export interface QuarantineEntryFacts {
  publicId: string;
  kind: 'quarantine' | 'review';
  reason: string;
  expiresAt: Date;
}

export interface ReleaseFacts {
  releaseId: string;
  mode: 'operator' | 'self' | 'approved';
  entryIds: string[];
}

export interface RecipientOutcomeCounts {
  delivered: number;
  failed: number;
  bounced: number;
  expired: number;
  suppressed: number;
  quarantined: number;
  discarded: number;
  other: number;
}

export interface MatchedRuleFacts {
  policyId: string;
  versionNo: number;
  ruleId: string;
}

export interface ExecutionLogFacts {
  matchedRules: MatchedRuleFacts[];
  /** Unique action types of the round (TAG, WARN, …), ≤ 16. */
  actions: string[];
}

/** `ato_accounts.kind` (step 8.4). */
export type AtoAccountKind = 'mailbox' | 'gateway_user' | 'smtp_connector';

export interface DomainFacts {
  id: bigint;
  publicId: string;
  name: string;
  status: string;
}

// eslint-disable-next-line no-control-regex -- control characters are exactly what is stripped
const CONTROL = /[\x00-\x1f\x7f]/g;
const DOTTED_CODE = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/;
const SNAKE = /^[a-z][a-z0-9_]*$/;
const RULE_ID = /^[a-z0-9][a-z0-9_-]{0,47}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ACTION_TYPE = /^[A-Z][A-Z_]{0,31}$/;

/** The lower-case domain of an address (`local@domain`, `Name <local@domain>`), else null. */
export function domainOf(address: string | null | undefined): string | null {
  if (!address) return null;
  const at = address.lastIndexOf('@');
  if (at < 0) return null;
  const match = /^[A-Za-z0-9._-]+/.exec(address.slice(at + 1));
  if (!match) return null;
  const domain = match[0].toLowerCase().replace(/\.+$/, '');
  return domainNameSchema.safeParse(domain).success ? domain : null;
}

/**
 * `internetMessageId` of §5.1: control characters stripped, trimmed, ≤ 255 characters; a value
 * the payload guard would refuse (a URL, an object key, MIME content) is dropped (null) so a
 * sender-controlled header can never dead-letter the source event.
 */
export function safeInternetMessageId(value: string | null | undefined): string | null {
  if (!value) return null;
  const text = value.replace(CONTROL, '').trim();
  if (text.length === 0 || text.length > INTERNET_MESSAGE_ID_MAX_LENGTH) return null;
  try {
    assertWebhookPayloadSafe({ internetMessageId: text });
  } catch {
    return null;
  }
  return text;
}

/** Dotted lower-case reason codes (§5.2), unique, at most `max`. */
export function reasonCodes(value: unknown, max = 32): string[] {
  if (!Array.isArray(value)) return [];
  const out: string[] = [];
  for (const item of value) {
    if (typeof item !== 'string' || item.length > 64 || !DOTTED_CODE.test(item)) continue;
    if (!out.includes(item)) out.push(item);
    if (out.length >= max) break;
  }
  return out;
}

/** `policy_execution_logs.matched_rules` (step 5.2 result) → `{ policyId, versionNo, ruleId }`. */
export function matchedRulesOf(value: unknown): MatchedRuleFacts[] {
  if (!Array.isArray(value)) return [];
  const out: MatchedRuleFacts[] = [];
  for (const item of value) {
    if (typeof item !== 'object' || item === null) continue;
    const { policyPublicId, versionNo, ruleId } = item as Record<string, unknown>;
    if (
      typeof policyPublicId === 'string' &&
      UUID.test(policyPublicId) &&
      typeof versionNo === 'number' &&
      Number.isInteger(versionNo) &&
      versionNo >= 1 &&
      typeof ruleId === 'string' &&
      RULE_ID.test(ruleId)
    ) {
      out.push({ policyId: policyPublicId, versionNo, ruleId });
    }
  }
  return out;
}

/** `policy_execution_logs.actions` → unique action types (≤ 16). */
export function actionTypesOf(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const out: string[] = [];
  for (const item of value) {
    const type = (item as { type?: unknown } | null)?.type;
    if (typeof type === 'string' && ACTION_TYPE.test(type) && !out.includes(type)) out.push(type);
    if (out.length >= 16) break;
  }
  return out;
}

/** A snake_case code (≤ 64) or null (domain status reasons, sandbox detected types). */
export function snakeCodeOrNull(value: string | null | undefined): string | null {
  if (!value || value.length > 64 || !SNAKE.test(value)) return null;
  return value;
}

const num = (value: bigint | number | null | undefined): number => Number(value ?? 0);

export class FanoutReads {
  constructor(private readonly sink: InconsistencySink) {}

  /** The message of §5.1 (required: registry row, message row; recipients may be none). */
  async message(tx: Prisma.TransactionClient, key: MessageKey): Promise<MessageFacts> {
    const [identity, message] = await Promise.all([
      tx.messageIdentity.findUnique({
        where: { id: key.messageId },
        select: { id: true, organizationId: true, publicId: true },
      }),
      tx.emailMessage.findUnique({
        where: { id_receivedAt: { id: key.messageId, receivedAt: key.receivedAt } },
        select: {
          id: true,
          receivedAt: true,
          organizationId: true,
          domainId: true,
          direction: true,
          lifecycleRound: true,
          internetMessageId: true,
          envelopeFrom: true,
          headerFrom: true,
          sizeBytes: true,
          recipientCount: true,
          attachmentCount: true,
          ingestSource: true,
        },
      }),
    ]);
    if (identity === null) wrongRead(this.sink, 'message_identity', 'missing');
    if (identity.id !== key.messageId || identity.organizationId !== key.organizationId) {
      wrongRead(this.sink, 'message_identity', 'id or organization');
    }
    if (message === null) wrongRead(this.sink, 'message', 'missing');
    if (
      message.id !== key.messageId ||
      message.organizationId !== key.organizationId ||
      message.receivedAt.getTime() !== key.receivedAt.getTime()
    ) {
      wrongRead(this.sink, 'message', 'key or organization');
    }
    const rows = await tx.$queryRaw<
      Array<{ organization_id: bigint; message_id: bigint; domain: string | null }>
    >`
      SELECT organization_id, message_id, LOWER(SUBSTRING_INDEX(address, '@', -1)) AS domain
      FROM email_recipients
      WHERE message_id = ${key.messageId} AND received_at = ${key.receivedAt}
      GROUP BY organization_id, message_id, domain
      ORDER BY domain
      LIMIT 64`;
    const recipientDomains: string[] = [];
    for (const row of rows) {
      if (
        idOf(row.organization_id) !== key.organizationId ||
        idOf(row.message_id) !== key.messageId
      ) {
        wrongRead(this.sink, 'recipients', 'organization or message');
      }
      const domain = row.domain === null ? null : domainOf(`x@${row.domain}`);
      if (domain !== null && !recipientDomains.includes(domain)) recipientDomains.push(domain);
      if (recipientDomains.length >= MAX_RECIPIENT_DOMAINS) break;
    }
    let domainPublicId: string | null = null;
    if (message.domainId !== null) {
      const domain = await tx.domain.findUnique({
        where: { id: message.domainId },
        select: { id: true, organizationId: true, publicId: true },
      });
      if (domain === null) wrongRead(this.sink, 'domain', 'missing');
      if (domain.id !== message.domainId || domain.organizationId !== key.organizationId) {
        wrongRead(this.sink, 'domain', 'id or organization');
      }
      domainPublicId = domain.publicId;
    }
    return {
      key,
      publicId: identity.publicId,
      direction: message.direction,
      domainId: message.domainId,
      domainPublicId,
      internetMessageId: safeInternetMessageId(message.internetMessageId),
      senderDomain: domainOf(message.envelopeFrom),
      headerFromDomain: domainOf(message.headerFrom),
      recipientCount: message.recipientCount,
      recipientDomains,
      sizeBytes: message.sizeBytes,
      attachmentCount: message.attachmentCount,
      lifecycleRound: message.lifecycleRound,
      ingestSource: message.ingestSource,
    };
  }

  /**
   * Step API-4 A9.1: the reason codes of a copy's detect scan — the latest risk row of lifecycle
   * round 0 (`message_risk_scores`, highest revision). Optional: no row → no codes.
   */
  async riskReasonCodes(tx: Prisma.TransactionClient, key: MessageKey): Promise<string[]> {
    const row = await tx.messageRiskScore.findFirst({
      where: {
        messageId: key.messageId,
        receivedAt: key.receivedAt,
        organizationId: key.organizationId,
        lifecycleRound: 0,
      },
      select: { messageId: true, organizationId: true, receivedAt: true, reasonCodes: true },
      orderBy: [{ revision: 'desc' }, { id: 'desc' }],
    });
    if (row === null) return [];
    if (
      row.messageId !== key.messageId ||
      row.organizationId !== key.organizationId ||
      row.receivedAt.getTime() !== key.receivedAt.getTime()
    ) {
      wrongRead(this.sink, 'risk_score', 'key or organization');
    }
    return reasonCodes(row.reasonCodes);
  }

  /**
   * Step API-4 A9.1 (sandbox of a copy message): the counted copies of the message — copy
   * verdict authority, in-scope mailbox — with the effective protection mode of each mailbox's
   * domain (`COALESCE(domains.protection_mode, organizations.protection_mode)`). Optional: none
   * counted → null (no detection event). Echo-checked: every row of the envelope organization
   * and the message key.
   */
  async copyDetections(
    tx: Prisma.TransactionClient,
    key: MessageKey,
  ): Promise<CopyDetectionFacts | null> {
    const rows = await tx.$queryRaw<
      Array<{
        organization_id: bigint;
        message_id: bigint;
        public_id: string;
        direction: WebhookDirection;
        source: 'journal' | 'graph' | 'gmail';
        policy_disposition: PolicyDispositionCode | null;
        mode: string | null;
      }>
    >`
      SELECT c.organization_id, c.message_id, c.public_id, c.direction, c.source,
             c.policy_disposition, COALESCE(d.protection_mode, o.protection_mode) AS mode
      FROM api_message_copies c
      JOIN api_mailboxes m ON m.id = c.mailbox_id AND m.organization_id = c.organization_id
      JOIN organizations o ON o.id = c.organization_id
      LEFT JOIN domains d ON d.id = m.domain_id AND d.organization_id = c.organization_id
      WHERE c.organization_id = ${key.organizationId}
        AND c.message_id = ${key.messageId}
        AND c.received_at = ${key.receivedAt}
        AND c.verdict_authority = 'copy'
        AND m.scope_state = 'in_scope'
      ORDER BY c.id
      LIMIT 1000`;
    if (rows.length === 0) return null;
    for (const r of rows) {
      if (idOf(r.organization_id) !== key.organizationId || idOf(r.message_id) !== key.messageId) {
        wrongRead(this.sink, 'api_message_copies', 'organization or message');
      }
    }
    const first = rows[0]!;
    let disposition: PolicyDispositionCode | null = null;
    for (const r of rows) {
      const d = r.policy_disposition;
      if (
        d !== null &&
        (disposition === null ||
          POLICY_DISPOSITION_ORDER.indexOf(d) > POLICY_DISPOSITION_ORDER.indexOf(disposition))
      ) {
        disposition = d;
      }
    }
    return {
      protectionMode: rows.some((r) => r.mode === 'api') ? 'api' : 'hybrid',
      direction: first.direction,
      copySource: first.source,
      policyDisposition: disposition,
      mailboxCount: rows.length,
      detectionIds: rows.slice(0, MAX_DETECTION_IDS).map((r) => r.public_id),
    };
  }

  /** The reason codes of a scan round (`email_scans.reason_codes`; required). */
  async scanReasonCodes(
    tx: Prisma.TransactionClient,
    key: MessageKey,
    scanId: bigint,
  ): Promise<string[]> {
    const scan = await tx.emailScan.findUnique({
      where: { id_receivedAt: { id: scanId, receivedAt: key.receivedAt } },
      select: { id: true, messageId: true, organizationId: true, reasonCodes: true },
    });
    if (scan === null) wrongRead(this.sink, 'scan', 'missing');
    if (
      scan.id !== scanId ||
      scan.messageId !== key.messageId ||
      scan.organizationId !== key.organizationId
    ) {
      wrongRead(this.sink, 'scan', 'key or organization');
    }
    return reasonCodes(scan.reasonCodes);
  }

  /** The execution log of a decided round (required: written in the decision transaction). */
  async executionLog(
    tx: Prisma.TransactionClient,
    key: MessageKey,
    round: number,
  ): Promise<ExecutionLogFacts> {
    const row = await tx.policyExecutionLog.findUnique({
      where: {
        messageId_evaluationSeq_receivedAt: {
          messageId: key.messageId,
          evaluationSeq: round,
          receivedAt: key.receivedAt,
        },
      },
      select: {
        messageId: true,
        organizationId: true,
        evaluationSeq: true,
        matchedRules: true,
        actions: true,
      },
    });
    if (row === null) wrongRead(this.sink, 'execution_log', 'missing');
    if (
      row.messageId !== key.messageId ||
      row.organizationId !== key.organizationId ||
      row.evaluationSeq !== round
    ) {
      wrongRead(this.sink, 'execution_log', 'key or organization');
    }
    return { matchedRules: matchedRulesOf(row.matchedRules), actions: actionTypesOf(row.actions) };
  }

  /** The quarantine entries of one round and origin (optional: none → no event). */
  async quarantineEntries(
    tx: Prisma.TransactionClient,
    key: MessageKey,
    round: number,
    origin: 'policy' | 'manual',
  ): Promise<QuarantineEntryFacts[]> {
    const rows = await tx.quarantineMessage.findMany({
      where: {
        organizationId: key.organizationId,
        messageId: key.messageId,
        messageReceivedAt: key.receivedAt,
        lifecycleRound: round,
        origin,
      },
      select: {
        publicId: true,
        organizationId: true,
        messageId: true,
        lifecycleRound: true,
        origin: true,
        kind: true,
        reason: true,
        expiresAt: true,
      },
      orderBy: { id: 'asc' },
      take: 1000,
    });
    for (const r of rows) {
      if (
        r.organizationId !== key.organizationId ||
        r.messageId !== key.messageId ||
        r.lifecycleRound !== round ||
        r.origin !== origin
      ) {
        wrongRead(this.sink, 'quarantine_entries', 'key or organization');
      }
    }
    return rows.map((r) => ({
      publicId: r.publicId,
      kind: r.kind,
      reason: r.reason,
      expiresAt: r.expiresAt,
    }));
  }

  /** The release log rows of one released delivery (optional: none → no event). */
  async release(
    tx: Prisma.TransactionClient,
    key: MessageKey,
    deliverySeq: number,
  ): Promise<ReleaseFacts | null> {
    const rows = await tx.$queryRaw<
      Array<{
        organization_id: bigint;
        message_id: bigint;
        delivery_seq: number | bigint | null;
        release_public_id: string;
        mode: 'operator' | 'self' | 'approved';
        entry_public_id: string;
      }>
    >`
      SELECT rl.organization_id, qm.message_id, rl.delivery_seq, rl.release_public_id, rl.mode,
             qm.public_id AS entry_public_id
      FROM quarantine_release_logs rl
      JOIN quarantine_messages qm ON qm.id = rl.quarantine_message_id
      WHERE qm.organization_id = ${key.organizationId}
        AND qm.message_id = ${key.messageId}
        AND qm.message_received_at = ${key.receivedAt}
        AND rl.organization_id = ${key.organizationId}
        AND rl.delivery_seq = ${deliverySeq}
      ORDER BY rl.id
      LIMIT 1000`;
    if (rows.length === 0) return null;
    for (const r of rows) {
      if (
        idOf(r.organization_id) !== key.organizationId ||
        idOf(r.message_id) !== key.messageId ||
        num(r.delivery_seq) !== deliverySeq
      ) {
        wrongRead(this.sink, 'release_logs', 'key or organization');
      }
    }
    const first = rows[0]!;
    const entryIds: string[] = [];
    for (const r of rows) {
      if (r.release_public_id !== first.release_public_id) continue;
      if (!entryIds.includes(r.entry_public_id)) entryIds.push(r.entry_public_id);
      if (entryIds.length >= 50) break;
    }
    return { releaseId: first.release_public_id, mode: first.mode, entryIds };
  }

  /** Recipient outcomes of a delivered message (one grouped read + expired/suppressed split). */
  async recipientOutcomes(
    tx: Prisma.TransactionClient,
    key: MessageKey,
  ): Promise<RecipientOutcomeCounts> {
    const groups = await tx.$queryRaw<
      Array<{ status: string; n: bigint; org_min: bigint; org_max: bigint }>
    >`
      SELECT status, COUNT(*) AS n, MIN(organization_id) AS org_min, MAX(organization_id) AS org_max
      FROM email_recipients
      WHERE message_id = ${key.messageId} AND received_at = ${key.receivedAt}
      GROUP BY status`;
    const failedKinds = await tx.$queryRaw<
      Array<{ status: string; n: bigint; org_min: bigint; org_max: bigint }>
    >`
      SELECT d.status, COUNT(DISTINCT d.recipient_id) AS n,
             MIN(d.organization_id) AS org_min, MAX(d.organization_id) AS org_max
      FROM email_deliveries d
      JOIN email_recipients r ON r.id = d.recipient_id AND r.received_at = d.received_at
      WHERE d.message_id = ${key.messageId} AND d.received_at = ${key.receivedAt}
        AND r.status = 'failed' AND d.status IN ('expired', 'suppressed')
      GROUP BY d.status`;
    for (const g of [...groups, ...failedKinds]) {
      if (idOf(g.org_min) !== key.organizationId || idOf(g.org_max) !== key.organizationId) {
        wrongRead(this.sink, 'recipients', 'organization');
      }
    }
    const counts: RecipientOutcomeCounts = {
      delivered: 0,
      failed: 0,
      bounced: 0,
      expired: 0,
      suppressed: 0,
      quarantined: 0,
      discarded: 0,
      other: 0,
    };
    for (const g of groups) {
      const n = num(g.n);
      switch (g.status) {
        case 'delivered':
        case 'failed':
        case 'bounced':
        case 'quarantined':
        case 'discarded':
          counts[g.status] += n;
          break;
        default:
          counts.other += n;
      }
    }
    for (const f of failedKinds) {
      const n = Math.min(num(f.n), counts.failed);
      if (f.status === 'expired' || f.status === 'suppressed') {
        counts[f.status] += n;
        counts.failed -= n;
      }
    }
    return counts;
  }

  /** The submission of a sandbox completion (required). */
  async sandboxSubmission(
    tx: Prisma.TransactionClient,
    key: MessageKey,
    submissionId: bigint,
  ): Promise<{ partIndex: number; sha256: string; detectedType: string }> {
    const row = await tx.sandboxSubmission.findUnique({
      where: { id_receivedAt: { id: submissionId, receivedAt: key.receivedAt } },
      select: {
        id: true,
        organizationId: true,
        messageId: true,
        partIndex: true,
        sha256: true,
        detectedType: true,
      },
    });
    if (row === null) wrongRead(this.sink, 'sandbox_submission', 'missing');
    if (
      row.id !== submissionId ||
      row.organizationId !== key.organizationId ||
      row.messageId !== key.messageId
    ) {
      wrongRead(this.sink, 'sandbox_submission', 'key or organization');
    }
    return {
      partIndex: row.partIndex,
      sha256: row.sha256.toLowerCase(),
      detectedType: snakeCodeOrNull(row.detectedType.toLowerCase()) ?? 'unknown',
    };
  }

  /** A domain of the organization (required; its public id must echo the event's). */
  async domain(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    domainId: bigint,
    expectedPublicId: string,
  ): Promise<DomainFacts> {
    const row = await tx.domain.findUnique({
      where: { id: domainId },
      select: { id: true, organizationId: true, publicId: true, name: true, status: true },
    });
    if (row === null) wrongRead(this.sink, 'domain', 'missing');
    if (
      row.id !== domainId ||
      row.organizationId !== organizationId ||
      row.publicId !== expectedPublicId
    ) {
      wrongRead(this.sink, 'domain', 'id, organization or public id');
    }
    return { id: row.id, publicId: row.publicId, name: row.name, status: row.status };
  }

  /**
   * Step 8.4: the kind of a monitored account of the organization by public id (required: the
   * account exists while its response actions exist; echo-checked like every fanout read).
   */
  async atoAccountKind(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    accountPublicId: string,
  ): Promise<AtoAccountKind> {
    const row = await tx.atoAccount.findUnique({
      where: { publicId: accountPublicId },
      select: { organizationId: true, publicId: true, kind: true },
    });
    if (row === null) wrongRead(this.sink, 'ato_account', 'missing');
    if (row.organizationId !== organizationId || row.publicId !== accountPublicId) {
      wrongRead(this.sink, 'ato_account', 'organization or public id');
    }
    return row.kind;
  }
}
