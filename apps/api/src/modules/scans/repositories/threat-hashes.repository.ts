import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { Prisma, Severity } from '@email-gateway/database';

type Client = Prisma.TransactionClient;

const threatHashSelect = {
  id: true,
  sha256: true,
  md5: true,
  severity: true,
  family: true,
  source: true,
  reason: true,
  expiresAt: true,
  firstSeenAt: true,
  lastSeenAt: true,
  createdAt: true,
  updatedAt: true,
  addedBy: { select: { publicId: true } },
} satisfies Prisma.MalwareSignatureSelect;

export type ThreatHashRow = Prisma.MalwareSignatureGetPayload<{
  select: typeof threatHashSelect;
}>;

export interface NewThreatHash {
  sha256: string;
  md5: string | null;
  severity: Severity;
  family: string | null;
  reason: string;
  expiresAt: Date | null;
  addedByUserId: bigint;
  now: Date;
}

/**
 * The platform known-threat hash catalog `malware_signatures` (step 4.2 A17). Platform-wide, not
 * tenant-scoped: only platform users with `platform:threat_intel_manage` reach these queries.
 * Lists read the replica (`PrismaReadService`, writer fallback above the lag threshold); every
 * change and its read-before-write runs on the writer transaction the service passes.
 */
@Injectable()
export class ThreatHashesRepository {
  constructor(private readonly reader: PrismaReadService) {}

  /** Newest first (id descending), below `beforeId`, optionally one source or one hash. */
  list(page: {
    take: number;
    beforeId?: bigint;
    source?: string;
    sha256?: string;
  }): Promise<ThreatHashRow[]> {
    return this.reader.client.malwareSignature.findMany({
      where: {
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
        ...(page.source !== undefined && { source: page.source }),
        ...(page.sha256 !== undefined && { sha256: page.sha256 }),
      },
      select: threatHashSelect,
      orderBy: { id: 'desc' },
      take: page.take,
    });
  }

  /** The row of a hash on the writer, locked for the rest of the transaction. */
  async findForUpdate(tx: Client, sha256: string): Promise<ThreatHashRow | null> {
    await tx.$queryRaw`SELECT id FROM malware_signatures WHERE sha256 = ${sha256} FOR UPDATE`;
    return tx.malwareSignature.findUnique({ where: { sha256 }, select: threatHashSelect });
  }

  /** An analyst hash: `source = analyst`, first and last seen now. */
  create(tx: Client, input: NewThreatHash): Promise<ThreatHashRow> {
    return tx.malwareSignature.create({
      data: {
        sha256: input.sha256,
        md5: input.md5,
        severity: input.severity,
        family: input.family,
        source: 'analyst',
        reason: input.reason,
        expiresAt: input.expiresAt,
        addedByUserId: input.addedByUserId,
        firstSeenAt: input.now,
        lastSeenAt: input.now,
      },
      select: threatHashSelect,
    });
  }

  /** Hard delete (the audit row keeps the before-image, A17). */
  async remove(tx: Client, id: bigint): Promise<void> {
    await tx.malwareSignature.delete({ where: { id }, select: { id: true } });
  }
}
