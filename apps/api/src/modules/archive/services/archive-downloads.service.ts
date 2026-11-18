import type { Readable } from 'node:stream';
import { ForbiddenException, Inject, Injectable } from '@nestjs/common';
import {
  type ArchiveDownloadKind,
  parseDownloadTokenKey,
  signArchiveDownloadToken,
  verifyArchiveDownloadToken,
} from '@email-gateway/archive';
import { uuidv7 } from '@email-gateway/common';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal, UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { TransactionRunner } from '../../../database/transaction-runner';
import type { ClientContext } from '../../auth/services/session.service';
import { ReauthenticationService } from '../../auth/services/reauthentication.service';
import {
  ARCHIVE_AUDIT,
  ARCHIVE_PERMISSIONS as P,
  ARCHIVE_RESOURCE,
  type ArchiveConfig,
} from '../archive.constants';
import {
  archiveContentUnavailable,
  archiveDownloadBlocked,
  archiveDownloadDisabled,
  archiveDownloadTokenInvalid,
  archiveDownloadTokenUsed,
  exportExpired,
  exportNotFound,
  exportNotReady,
  reauthFailed,
} from '../archive.errors';
import type { DownloadGrantBody, DownloadGrantView } from '../dto/archive.schemas';
import { ArchiveConfigRepository } from '../repositories/archive-config.repository';
import {
  type ExportDownloadRow,
  ArchiveGrantsRepository,
} from '../repositories/archive-grants.repository';
import {
  ArchiveRecordsRepository,
  type RecordRow,
} from '../repositories/archive-records.repository';
import { asUser, refuseOverride } from './archive-common';
import { ArchiveContentService } from './archive-content.service';
import { ArchiveMessagesService } from './archive-messages.service';
import { effectiveSettings } from './archive-settings.service';

type Config = Pick<
  ArchiveConfig,
  'ARCHIVE_DOWNLOAD_TOKEN_KEY' | 'ARCHIVE_DOWNLOAD_TOKEN_TTL_SECONDS'
>;

/** Audit actions of the eDiscovery export downloads (A21). */
export const EXPORT_DOWNLOAD_AUDIT = {
  granted: 'ediscovery.download_granted',
  downloaded: 'ediscovery.downloaded',
} as const;

/** What a grant targets: one archived message or one completed export (writer facts). */
export type GrantTarget =
  | { kind: 'message'; record: RecordRow }
  | { kind: 'export'; row: ExportDownloadRow; casePublicId: string };

/** The streamed download (`Content-Disposition: attachment`). */
export interface ArchiveDownload {
  body: Readable;
  sizeBytes: number;
  filename: string;
}

const messageFilename = (publicId: string) => `message-${publicId}.eml`;
const exportFilename = (publicId: string) => `ediscovery-export-${publicId}.zip`;

/**
 * The archive download door (step 8.1 §4.4 #21, #22, #41; A18, A19; the 5.3 ADR-0048 model):
 * grants are customer-only (`403 archive_override_forbidden`), need an MFA session and a fresh
 * password (+ TOTP) re-entry through `ReauthenticationService` (`401 quarantine_reauth_failed`,
 * reused, counted toward the login lockout), and create a single-use
 * `archive_download_grants` row plus an HMAC token (`ARCHIVE_DOWNLOAD_TOKEN_KEY`, TTL
 * `ARCHIVE_DOWNLOAD_TOKEN_TTL_SECONDS`) bound to the organization, the user, the kind and the
 * target. Message grants need `access.downloadEnabled` and are refused for malicious records
 * (`409 archive_download_blocked`: use an eDiscovery export). The download verifies the token,
 * consumes the grant atomically, re-checks the target on the writer, commits the audit row and
 * only then streams the decrypted bytes (plaintext SHA-256 verified while streaming).
 */
@Injectable()
export class ArchiveDownloadsService {
  private readonly key: Buffer;

  constructor(
    @Inject(API_CONFIG) private readonly config: Config,
    private readonly grants: ArchiveGrantsRepository,
    private readonly records: ArchiveRecordsRepository,
    private readonly configs: ArchiveConfigRepository,
    private readonly messages: ArchiveMessagesService,
    private readonly content: ArchiveContentService,
    private readonly reauth: ReauthenticationService,
    private readonly runner: TransactionRunner,
    private readonly audit: AuditService,
  ) {
    this.key = parseDownloadTokenKey(config.ARCHIVE_DOWNLOAD_TOKEN_KEY);
  }

  now(): Date {
    return new Date();
  }

  /** `POST /archive/messages/{messageId}/download-grants` (#21). */
  async grantMessage(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    body: DownloadGrantBody,
    client: ClientContext,
  ): Promise<DownloadGrantView> {
    refuseOverride(principal);
    const user = asUser(principal);
    const settings = await this.configs.settingsOnWriter(scope);
    if (!effectiveSettings(settings?.settings ?? null).access.downloadEnabled) {
      this.content.count('download_grant', 'disabled');
      throw archiveDownloadDisabled();
    }
    // The record exists in the scope before the password is checked (no oracle for ids).
    const record = await this.messages.writerRecord(scope, rawId);
    if (record.malicious) {
      this.content.count('download_grant', 'blocked');
      throw archiveDownloadBlocked('malicious');
    }
    return this.issue(user, scope, { kind: 'message', record }, body, client);
  }

  /** Export grants (#41): the ediscovery service resolves and checks the export first. */
  async grantExport(
    principal: Principal,
    scope: TenantScope,
    target: { row: ExportDownloadRow; casePublicId: string },
    body: DownloadGrantBody,
    client: ClientContext,
  ): Promise<DownloadGrantView> {
    refuseOverride(principal);
    const user = asUser(principal);
    this.checkExport(target.row, this.now());
    return this.issue(user, scope, { kind: 'export', ...target }, body, client);
  }

  private async issue(
    user: UserPrincipal,
    scope: TenantScope,
    target: GrantTarget,
    body: DownloadGrantBody,
    client: ClientContext,
  ): Promise<DownloadGrantView> {
    const verified = await this.reauth.verify(user, {
      password: body.password,
      ...(body.totpCode !== undefined && { totpCode: body.totpCode }),
    });
    if (!verified.ok) {
      this.content.count('download_grant', 'reauth_failed');
      throw reauthFailed();
    }
    const now = this.now();
    const expiresAt = new Date(
      now.getTime() + this.config.ARCHIVE_DOWNLOAD_TOKEN_TTL_SECONDS * 1000,
    );
    const jti = uuidv7(now.getTime());
    const t = this.describe(target);
    await this.runner.run(async (tx) => {
      await this.grants.insert(tx, scope, {
        jti,
        userId: user.userId,
        kind: target.kind,
        messageId: target.kind === 'message' ? target.record.messageId : null,
        messageReceivedAt: target.kind === 'message' ? target.record.receivedAt : null,
        exportId: target.kind === 'export' ? target.row.id : null,
        expiresAt,
        sourceIp: client.ip,
      });
      await this.audit.record(
        {
          organizationId: scope.organizationId,
          actor: this.audit.actorFrom(user),
          action:
            target.kind === 'message'
              ? ARCHIVE_AUDIT.downloadGranted
              : EXPORT_DOWNLOAD_AUDIT.granted,
          resourceType: t.resourceType,
          resourceId: t.publicId,
          sourceIp: client.ip,
          metadata: { ...t.ids, jti, expiresAt: expiresAt.toISOString() },
        },
        tx,
      );
    });
    this.content.count('download_grant', 'granted');
    const token = signArchiveDownloadToken(
      {
        jti,
        org: user.organizationPublicId,
        usr: user.userPublicId,
        kind: target.kind,
        tgt: t.publicId,
        exp: Math.floor(expiresAt.getTime() / 1000),
      },
      this.key,
    );
    return {
      token,
      expiresAt: expiresAt.toISOString(),
      filename: t.filename,
      sizeBytes: t.sizeBytes,
      sha256: t.sha256,
    };
  }

  /** `GET /archive/downloads/{token}` (#22): consume, re-check, audit, then stream. */
  async download(
    principal: Principal,
    scope: TenantScope,
    token: string,
    client: ClientContext,
  ): Promise<ArchiveDownload> {
    refuseOverride(principal);
    const user = asUser(principal);
    const now = this.now();
    const verified = verifyArchiveDownloadToken(token, this.key, {
      now,
      expected: { org: user.organizationPublicId, usr: user.userPublicId },
    });
    if (!verified.ok) {
      this.content.count('download', 'token_invalid');
      throw archiveDownloadTokenInvalid();
    }
    const p = verified.payload;
    const needed: string[] = p.kind === 'message' ? [P.retrieve] : [P.export, P.ediscovery];
    if (!needed.every((perm) => user.permissions.has(perm))) {
      throw new ForbiddenException('Missing permission for this download');
    }
    const target = await this.runner.run(async (tx): Promise<GrantTarget> => {
      const consumed = await this.grants.consume(tx, scope, p.jti, user.userId, now);
      if (consumed === 'used') throw archiveDownloadTokenUsed();
      if (consumed === 'invalid') throw archiveDownloadTokenInvalid();
      const grant = await this.grants.byJti(tx, scope, p.jti);
      if (grant === null || grant.kind !== p.kind) throw archiveDownloadTokenInvalid();
      const resolved = await this.resolve(tx, scope, p.kind, p.tgt, grant);
      const t = this.describe(resolved);
      await this.audit.record(
        {
          organizationId: scope.organizationId,
          actor: this.audit.actorFrom(user),
          action:
            p.kind === 'message' ? ARCHIVE_AUDIT.downloaded : EXPORT_DOWNLOAD_AUDIT.downloaded,
          resourceType: t.resourceType,
          resourceId: t.publicId,
          sourceIp: client.ip,
          metadata: { ...t.ids, jti: p.jti, sizeBytes: t.sizeBytes, sha256: t.sha256 },
        },
        tx,
      );
      return resolved;
    });
    const t = this.describe(target);
    const body =
      target.kind === 'message'
        ? await this.content.openEml(scope, target.record)
        : await this.content.openExport(scope, target.row);
    this.content.count('download', target.kind);
    return { body, sizeBytes: t.sizeBytes, filename: t.filename };
  }

  /** The grant's target re-read on the writer, bound to the token's public id. */
  private async resolve(
    tx: Parameters<Parameters<TransactionRunner['run']>[0]>[0],
    scope: TenantScope,
    kind: ArchiveDownloadKind,
    targetPublicId: string,
    grant: { messageId: bigint | null; messageReceivedAt: Date | null; exportId: bigint | null },
  ): Promise<GrantTarget> {
    if (kind === 'message') {
      const key = await this.records.messageKey(scope, targetPublicId, tx);
      if (
        key === null ||
        grant.messageId === null ||
        key.id !== grant.messageId ||
        grant.messageReceivedAt === null ||
        key.receivedAt.getTime() !== grant.messageReceivedAt.getTime()
      ) {
        throw archiveDownloadTokenInvalid();
      }
      const record = await this.records.record(scope, key, tx);
      if (record === null || record.status === 'disposing' || record.wrappedDek === null) {
        throw archiveContentUnavailable();
      }
      if (record.malicious) throw archiveDownloadBlocked('malicious');
      return { kind: 'message', record };
    }
    const row = await this.grants.exportForDownload(tx, scope, targetPublicId);
    if (row === null || grant.exportId === null || row.id !== grant.exportId) {
      throw archiveDownloadTokenInvalid();
    }
    this.checkExport(row, this.now());
    return { kind: 'export', row, casePublicId: row.casePublicId };
  }

  /** A completed, unexpired export with a package (`409` not ready, `410` expired). */
  private checkExport(row: ExportDownloadRow, now: Date): void {
    if (
      row.status === 'expired' ||
      (row.expiresAt !== null && row.expiresAt.getTime() <= now.getTime())
    ) {
      throw exportExpired();
    }
    if (row.status !== 'completed' || row.objectKey === null || row.packageBytes === null) {
      throw exportNotReady(row.status);
    }
  }

  private describe(target: GrantTarget): {
    publicId: string;
    resourceType: string;
    filename: string;
    sizeBytes: number;
    sha256: string;
    ids: Record<string, string>;
  } {
    if (target.kind === 'message') {
      const r = target.record;
      return {
        publicId: r.messagePublicId,
        resourceType: ARCHIVE_RESOURCE.message,
        filename: messageFilename(r.messagePublicId),
        sizeBytes: r.sizeBytes,
        sha256: r.sha256,
        ids: { messageId: r.messagePublicId },
      };
    }
    const e = target.row;
    if (e === undefined) throw exportNotFound();
    return {
      publicId: e.publicId,
      resourceType: 'ediscovery_export',
      filename: exportFilename(e.publicId),
      sizeBytes: Number(e.packageBytes ?? 0n),
      sha256: e.packageSha256 ?? '0'.repeat(64),
      ids: { exportId: e.publicId, caseId: target.casePublicId },
    };
  }
}
