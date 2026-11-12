import { Injectable } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import type { MessageRef } from '@email-gateway/message-lifecycle';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import type { FactsScanRow } from '../../policies/repositories/policy-facts.repository';
import { hardBlockIds, stringList } from '../domain/entry';
import { InconsistentQuarantineReadError } from '../quarantine.errors';

/** A writer transaction or the replica client: both expose the model delegates read here. */
type Db = Prisma.TransactionClient;

const OPEN_SCAN = ['pending', 'running'] as const;
const LIST_BOUND = 1000;

/** Latest-round facts of the malware gating (Q12.4) and the preview (Q11). */
export interface ContentFacts {
  scan: FactsScanRow | null;
  /** Hard blocks of any round's risk scores of the message (sorted, unique). */
  messageHardBlocks: string[];
  /** The latest round's verdict (highest risk revision), else the message's final verdict. */
  latestVerdict: string | null;
  attachments: Array<{
    partIndex: number;
    filename: string | null;
    declaredType: string | null;
    detectedType: string | null;
    typeFamily: string | null;
    sizeBytes: number;
    sha256: string;
    objectKey: string | null;
    /** The latest round's `attachment_scan_results.verdict`; null when not scanned. */
    verdict: string | null;
    reasonCodes: string[];
  }>;
  urls: Array<{ urlSha256: string; verdict: string | null }>;
}

/** Q13.4 staleness facts of the latest round. */
export interface StalenessFactRows {
  hasUrls: boolean;
  hasScannedAttachments: boolean;
  newestClamavDbFirstSeenAt: Date | null;
}

/** Q11 sources besides the content facts. */
export interface PreviewSourceRows {
  parse: {
    status: string;
    textKey: string | null;
    htmlKey: string | null;
    textSize: number | null;
    htmlSize: number | null;
  } | null;
  headers: Array<{ name: string; value: string }>;
  subject: string | null;
}

/**
 * Tenant-scoped reads of the message facts the quarantine decides on (step 5.3 Q11, Q12.4,
 * Q13.3, Q13.4): the latest completed scan round, its risk, attachment and URL verdicts, the
 * staleness facts and the preview sources. Every method takes the client to read with: a writer
 * transaction for deciding reads (echo-checked, §6) or the replica for views and the advisory
 * pre-check. Partitioned tables are addressed with the message's `received_at`.
 */
@Injectable()
export class QuarantineFactsRepository {
  /** The greatest completed round of the message (`completed_at` set, status not open). */
  async latestScan(db: Db, scope: TenantScope, message: MessageRef): Promise<FactsScanRow | null> {
    const scan = await db.emailScan.findFirst({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        completedAt: { not: null },
        status: { notIn: [...OPEN_SCAN] },
      }),
      select: {
        id: true,
        messageId: true,
        receivedAt: true,
        organizationId: true,
        lifecycleRound: true,
        scanKind: true,
        status: true,
        scanVerdict: true,
        reasonCodes: true,
        requiredEngines: true,
        completedAt: true,
      },
      orderBy: { lifecycleRound: 'desc' },
    });
    if (
      scan !== null &&
      (scan.messageId !== message.id ||
        scan.organizationId !== scope.organizationId ||
        scan.receivedAt.getTime() !== message.receivedAt.getTime())
    ) {
      throw new InconsistentQuarantineReadError('scan_round');
    }
    return scan;
  }

  async contentFacts(db: Db, scope: TenantScope, message: MessageRef): Promise<ContentFacts> {
    const byMessage = { messageId: message.id, receivedAt: message.receivedAt };
    const scan = await this.latestScan(db, scope, message);
    const [risks, msg, attachments, results, urls, urlResults] = await Promise.all([
      db.messageRiskScore.findMany({
        where: tenantWhere(scope, byMessage),
        select: {
          scanId: true,
          revision: true,
          verdict: true,
          hardBlocks: true,
          organizationId: true,
        },
        orderBy: [{ lifecycleRound: 'asc' }, { revision: 'asc' }],
        take: 400,
      }),
      db.emailMessage.findFirst({
        where: tenantWhere(scope, { id: message.id, receivedAt: message.receivedAt }),
        select: { finalVerdict: true },
      }),
      db.emailAttachment.findMany({
        where: tenantWhere(scope, byMessage),
        select: {
          partIndex: true,
          filename: true,
          declaredContentType: true,
          detectedContentType: true,
          sizeBytes: true,
          sha256: true,
          objectKey: true,
          organizationId: true,
        },
        orderBy: { partIndex: 'asc' },
        take: LIST_BOUND,
      }),
      scan === null
        ? Promise.resolve([])
        : db.attachmentScanResult.findMany({
            where: tenantWhere(scope, { ...byMessage, scanId: scan.id }),
            select: {
              partIndex: true,
              verdict: true,
              reasonCodes: true,
              typeFamily: true,
              detectedType: true,
            },
            take: LIST_BOUND,
          }),
      db.messageUrl.findMany({
        where: tenantWhere(scope, byMessage),
        select: { urlSeq: true, urlSha256: true },
        orderBy: { urlSeq: 'asc' },
        take: LIST_BOUND,
      }),
      scan === null
        ? Promise.resolve([])
        : db.urlScanResult.findMany({
            where: tenantWhere(scope, { ...byMessage, scanId: scan.id }),
            select: { urlSeq: true, verdict: true },
            take: LIST_BOUND,
          }),
    ]);
    if ([...risks, ...attachments].some((r) => r.organizationId !== scope.organizationId)) {
      throw new InconsistentQuarantineReadError('content_facts');
    }
    const hardBlocks = new Set<string>();
    for (const r of risks) for (const hb of hardBlockIds(r.hardBlocks, 32)) hardBlocks.add(hb);
    const latest = scan === null ? [] : risks.filter((r) => r.scanId === scan.id);
    const latestVerdict =
      latest.length > 0 ? latest[latest.length - 1]!.verdict : (msg?.finalVerdict ?? null);
    const byPart = new Map(results.map((r) => [r.partIndex, r]));
    const urlVerdicts = new Map(urlResults.map((u) => [u.urlSeq, u.verdict]));
    return {
      scan,
      messageHardBlocks: [...hardBlocks].sort(),
      latestVerdict,
      attachments: attachments.map((a) => {
        const r = byPart.get(a.partIndex);
        return {
          partIndex: a.partIndex,
          filename: a.filename,
          declaredType: a.declaredContentType,
          detectedType: r?.detectedType ?? a.detectedContentType,
          typeFamily: r?.typeFamily ?? null,
          sizeBytes: a.sizeBytes,
          sha256: a.sha256,
          objectKey: a.objectKey,
          verdict: r?.verdict ?? null,
          reasonCodes: stringList(r?.reasonCodes, 64),
        };
      }),
      urls: urls.map((u) => ({
        urlSha256: u.urlSha256,
        verdict: urlVerdicts.get(u.urlSeq) ?? null,
      })),
    };
  }

  async stalenessFacts(
    db: Db,
    scope: TenantScope,
    message: MessageRef,
    scanId: bigint | null,
  ): Promise<StalenessFactRows> {
    const byMessage = { messageId: message.id, receivedAt: message.receivedAt };
    const [urls, scanned, clamav] = await Promise.all([
      db.messageUrl.count({ where: tenantWhere(scope, byMessage) }),
      scanId === null
        ? Promise.resolve(0)
        : db.attachmentScanResult.count({ where: tenantWhere(scope, { ...byMessage, scanId }) }),
      db.scanSignatureVersion.findFirst({
        where: { engine: 'attachment', component: 'clamav_db' },
        select: { firstSeenAt: true },
        orderBy: { firstSeenAt: 'desc' },
      }),
    ]);
    return {
      hasUrls: urls > 0,
      hasScannedAttachments: scanned > 0,
      newestClamavDbFirstSeenAt: clamav?.firstSeenAt ?? null,
    };
  }

  async previewSources(
    db: Db,
    scope: TenantScope,
    message: MessageRef,
  ): Promise<PreviewSourceRows> {
    const byMessage = { messageId: message.id, receivedAt: message.receivedAt };
    const [parse, headers, msg] = await Promise.all([
      db.emailMessageParse.findFirst({
        where: tenantWhere(scope, byMessage),
        select: {
          status: true,
          textBodyObjectKey: true,
          htmlBodyObjectKey: true,
          textBodySizeBytes: true,
          htmlBodySizeBytes: true,
        },
      }),
      db.emailHeader.findMany({
        where: tenantWhere(scope, byMessage),
        select: { name: true, value: true },
        orderBy: { seq: 'asc' },
        take: 64,
      }),
      db.emailMessage.findFirst({
        where: tenantWhere(scope, { id: message.id, receivedAt: message.receivedAt }),
        select: { subject: true },
      }),
    ]);
    return {
      parse:
        parse === null
          ? null
          : {
              status: parse.status,
              textKey: parse.textBodyObjectKey,
              htmlKey: parse.htmlBodyObjectKey,
              textSize: parse.textBodySizeBytes,
              htmlSize: parse.htmlBodySizeBytes,
            },
      headers,
      subject: msg?.subject ?? null,
    };
  }
}
