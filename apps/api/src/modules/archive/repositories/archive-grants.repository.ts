import { Injectable } from '@nestjs/common';
import type { ArchiveDownloadKind, EdiscoveryExportStatus, Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { assertEcho } from '../../../http/listing/echo-check';

type Tx = Prisma.TransactionClient;

export interface NewGrant {
  jti: string;
  userId: bigint;
  kind: ArchiveDownloadKind;
  messageId: bigint | null;
  messageReceivedAt: Date | null;
  exportId: bigint | null;
  expiresAt: Date;
  sourceIp: string | null;
}

export interface GrantRow {
  jti: string;
  userId: bigint;
  kind: ArchiveDownloadKind;
  messageId: bigint | null;
  messageReceivedAt: Date | null;
  exportId: bigint | null;
  expiresAt: Date;
  consumedAt: Date | null;
}

/** The export columns a download grant and a download read (writer). */
export interface ExportDownloadRow {
  id: bigint;
  publicId: string;
  casePublicId: string;
  status: EdiscoveryExportStatus;
  objectKey: string | null;
  objectVersionId: string | null;
  keyVersion: number | null;
  wrappedDek: string | null;
  packageSha256: string | null;
  packageBytes: bigint | null;
  expiresAt: Date | null;
}

/**
 * `archive_download_grants` (step 8.1 A19): single-use download grants of archived messages and
 * eDiscovery exports, on the writer inside the caller's transaction. The consume is one atomic
 * `UPDATE … WHERE consumed_at IS NULL AND expires_at > now` bound to the organization and the
 * user, so a token is served at most once even under concurrent requests.
 */
@Injectable()
export class ArchiveGrantsRepository {
  async insert(tx: Tx, scope: TenantScope, grant: NewGrant): Promise<void> {
    await tx.archiveDownloadGrant.create({
      data: { organizationId: scope.organizationId, ...grant },
      select: { id: true },
    });
  }

  /** `ok` when this request consumed the grant; `used` / `invalid` otherwise. */
  async consume(
    tx: Tx,
    scope: TenantScope,
    jti: string,
    userId: bigint,
    now: Date,
  ): Promise<'ok' | 'used' | 'invalid'> {
    const result = await tx.archiveDownloadGrant.updateMany({
      where: tenantWhere(scope, { jti, userId, consumedAt: null, expiresAt: { gt: now } }),
      data: { consumedAt: now },
    });
    if (result.count === 1) return 'ok';
    const row = await this.byJti(tx, scope, jti);
    if (row !== null && row.userId === userId && row.consumedAt !== null) return 'used';
    return 'invalid';
  }

  async byJti(tx: Tx, scope: TenantScope, jti: string): Promise<GrantRow | null> {
    const row = await tx.archiveDownloadGrant.findFirst({
      where: tenantWhere(scope, { jti }),
      select: {
        organizationId: true,
        jti: true,
        userId: true,
        kind: true,
        messageId: true,
        messageReceivedAt: true,
        exportId: true,
        expiresAt: true,
        consumedAt: true,
      },
    });
    if (row === null) return null;
    assertEcho('archive.grants.jti', [row], { organizationId: scope.organizationId, jti });
    const { organizationId: _o, ...rest } = row;
    return rest;
  }

  /** An export of the organization by public id (writer), with its case public id. */
  async exportForDownload(
    tx: Tx,
    scope: TenantScope,
    publicId: string,
  ): Promise<ExportDownloadRow | null> {
    const row = await tx.ediscoveryExport.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: {
        id: true,
        publicId: true,
        organizationId: true,
        status: true,
        objectKey: true,
        objectVersionId: true,
        keyVersion: true,
        wrappedDek: true,
        packageSha256: true,
        packageBytes: true,
        expiresAt: true,
        case: { select: { publicId: true } },
      },
    });
    if (row === null) return null;
    assertEcho('archive.grants.export', [row], { organizationId: scope.organizationId, publicId });
    const { organizationId: _o, case: c, ...rest } = row;
    return { ...rest, casePublicId: c.publicId };
  }
}
