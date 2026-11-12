import type { Prisma } from '@email-gateway/database';
import type { StalenessFacts } from '@email-gateway/quarantine';
import { type QuarantineInconsistencySink, quarantineWrongRead } from './errors';
import type { MessageKey } from './store-writer';

/** The latest completed scan round of a message (Q13.3). */
export interface LatestScanRound {
  scanId: bigint;
  round: number;
  status: 'completed' | 'failed' | 'timed_out';
  completedAt: Date;
}

const FINAL_SCAN_STATUSES = ['completed', 'failed', 'timed_out'] as const;

/**
 * Writer reads of the release re-validation (step 5.3 Q13.3, Q13.4, §6), each echo-checked:
 * the latest completed scan round (`email_scans` with `completed_at`, greatest
 * `lifecycle_round`), the staleness facts of that round (attachments and URLs present, ClamAV
 * scanned attachments) and the newest ClamAV database (`scan_signature_versions`
 * `attachment/clamav_db`, by `first_seen_at`).
 */
export class ReleaseFactsReader {
  constructor(private readonly sink: QuarantineInconsistencySink) {}

  async latestScanRound(
    tx: Prisma.TransactionClient,
    message: MessageKey,
  ): Promise<LatestScanRound | null> {
    const row = await tx.emailScan.findFirst({
      where: {
        messageId: message.messageId,
        receivedAt: message.receivedAt,
        organizationId: message.organizationId,
        status: { in: [...FINAL_SCAN_STATUSES] },
        completedAt: { not: null },
        scanKind: { in: ['initial', 'rescan'] },
      },
      orderBy: [{ lifecycleRound: 'desc' }, { id: 'desc' }],
      select: {
        id: true,
        messageId: true,
        receivedAt: true,
        organizationId: true,
        lifecycleRound: true,
        status: true,
        completedAt: true,
      },
    });
    if (row === null) return null;
    if (
      row.messageId !== message.messageId ||
      row.organizationId !== message.organizationId ||
      row.receivedAt.getTime() !== message.receivedAt.getTime() ||
      row.completedAt === null ||
      !(FINAL_SCAN_STATUSES as readonly string[]).includes(row.status)
    ) {
      quarantineWrongRead(this.sink, 'scan_round', 'scan echo');
    }
    return {
      scanId: row.id,
      round: row.lifecycleRound,
      status: row.status as LatestScanRound['status'],
      completedAt: row.completedAt,
    };
  }

  /** Q13.4 facts of a scan round. */
  async staleness(
    tx: Prisma.TransactionClient,
    message: MessageKey,
    scan: LatestScanRound | null,
  ): Promise<StalenessFacts> {
    const where = {
      messageId: message.messageId,
      receivedAt: message.receivedAt,
      organizationId: message.organizationId,
    };
    const attachments = await tx.emailAttachment.count({ where });
    const urls = await tx.messageUrl.count({ where });
    let scanned = 0;
    if (scan !== null) {
      scanned = await tx.attachmentScanResult.count({
        where: { ...where, scanId: scan.scanId, clamavDbVersion: { not: null } },
      });
    }
    const newest = await tx.scanSignatureVersion.findFirst({
      where: { engine: 'attachment', component: 'clamav_db' },
      orderBy: { firstSeenAt: 'desc' },
      select: { engine: true, component: true, firstSeenAt: true },
    });
    if (newest !== null && (newest.engine !== 'attachment' || newest.component !== 'clamav_db')) {
      quarantineWrongRead(this.sink, 'signature_versions', 'signature echo');
    }
    return {
      hasAttachments: attachments > 0,
      hasUrls: urls > 0,
      hasScannedAttachments: scanned > 0,
      newestClamavDbFirstSeenAt: newest?.firstSeenAt ?? null,
    };
  }
}
