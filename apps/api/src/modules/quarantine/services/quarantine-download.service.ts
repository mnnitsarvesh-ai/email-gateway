import type { Readable } from 'node:stream';
import { Inject, Injectable, Logger } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import {
  checkDownloadable,
  type DownloadableCheck,
  sanitizeDisplayText,
  signDownloadToken,
  verifyDownloadToken,
} from '@email-gateway/quarantine';
import { API_CONFIG } from '../../../api-config.token';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ClientContext } from '../../auth/services/session.service';
import { ReauthenticationService } from '../../auth/services/reauthentication.service';
import type { EntryRow } from '../domain/entry';
import type { DownloadGrantBody, DownloadGrantResponse } from '../dto/quarantine.schemas';
import {
  type QuarantineConfig,
  QUARANTINE_AUDIT,
  QUARANTINE_RESOURCE,
} from '../quarantine.constants';
import {
  AuditedRefusal,
  contentPurged,
  downloadBlocked,
  downloadDisabled,
  downloadTokenInvalid,
  downloadTokenUsed,
  entryNotFound,
  reauthFailed,
} from '../quarantine.errors';
import type { CodedHttpException } from '../../../http/coded-exception';
import {
  type ContentFacts,
  QuarantineFactsRepository,
} from '../repositories/quarantine-facts.repository';
import { QuarantineWriteRepository } from '../repositories/quarantine-write.repository';
import { QuarantineContext } from './quarantine-context';
import { QuarantineEntryOps } from './quarantine-entry-ops';
import { QuarantineMetrics } from './quarantine-metrics';
import { QuarantineObjectError, QuarantineObjectStore } from './quarantine-object-store';
import { QuarantineWriter } from './quarantine-writer';

type Tx = Prisma.TransactionClient;

type Config = Pick<
  QuarantineConfig,
  | 'QUARANTINE_DOWNLOAD_TOKEN_KEY'
  | 'QUARANTINE_DOWNLOAD_TOKEN_TTL_SECONDS'
  | 'QUARANTINE_DOWNLOAD_MAX_BYTES'
>;

/** What the download route streams, with the exact Q12.3 headers. */
export interface DownloadStream {
  body: Readable;
  sizeBytes: number;
  filename: string;
}

/** `<sanitized>.eml.bin` / `<sanitized>.bin` (ASCII, no quotes or path separators, ≤ 120). */
export function downloadFilename(name: string | null, object: 'eml' | 'attachment'): string {
  const cleaned = sanitizeDisplayText(name ?? '', { maxChars: 200 })
    .text.normalize('NFKD')
    .replace(/[^A-Za-z0-9._-]+/g, '_')
    .replace(/^[._]+/, '')
    .slice(0, 100);
  const base = cleaned === '' ? (object === 'eml' ? 'message' : 'attachment') : cleaned;
  return object === 'eml' ? `${base}.eml.bin` : `${base}.bin`;
}

interface Target {
  entry: EntryRow;
  object: 'eml' | 'attachment';
  partIndex: number | null;
  key: string | null;
  prefix: '' | 'part/';
  sizeBytes: number;
  sha256: string;
  name: string | null;
}

/**
 * The download door (step 5.3 Q12; ADR-0048). Grants: tenant `download.enabled`, fresh password
 * (+ TOTP when enrolled) re-authorization through the auth module with lockout accounting
 * (`401 quarantine_reauth_failed`), malware gating (`checkDownloadable`, `409`), then a
 * single-use `quarantine_download_grants` row and an HMAC token bound to the organization, the
 * user and the entry, valid `QUARANTINE_DOWNLOAD_TOKEN_TTL_SECONDS`. Download: MAC and expiry,
 * binding to the caller, the atomic consume, the gating again on writer facts, the audit row
 * committed, then the object streamed (organization prefix, size bound). Never an S3 URL.
 */
@Injectable()
export class QuarantineDownloadService {
  private readonly logger = new Logger(QuarantineDownloadService.name);
  private readonly key: Buffer;

  constructor(
    @Inject(API_CONFIG) private readonly config: Config,
    private readonly writer: QuarantineWriter,
    private readonly ops: QuarantineEntryOps,
    private readonly writes: QuarantineWriteRepository,
    private readonly facts: QuarantineFactsRepository,
    private readonly objects: QuarantineObjectStore,
    private readonly context: QuarantineContext,
    private readonly reauth: ReauthenticationService,
    private readonly metrics: QuarantineMetrics,
  ) {
    this.key = Buffer.from(config.QUARANTINE_DOWNLOAD_TOKEN_KEY, 'hex');
  }

  async grant(
    principal: UserPrincipal,
    scope: TenantScope,
    entryId: string,
    body: DownloadGrantBody,
    client: ClientContext,
  ): Promise<DownloadGrantResponse> {
    // A deciding read (Q26: writer): a tenant that has just switched downloads off must not
    // be granted one for the replication lag.
    const gate = await this.writer.run(async (tx) => {
      const settings = await this.context.settingsTx(tx, scope);
      if (!settings.download.enabled) return 'disabled' as const;
      // The entry exists in the scope before the password is checked (no oracle for ids).
      return (await this.writes.findEntryRef(tx, scope, entryId)) === null ? 'missing' : 'ok';
    });
    if (gate === 'disabled') {
      this.metrics.downloads.inc({ stage: 'grant', result: 'disabled' });
      throw downloadDisabled();
    }
    if (gate === 'missing') throw entryNotFound();
    const verified = await this.reauth.verify(principal, {
      password: body.password,
      ...(body.totpCode !== undefined && { totpCode: body.totpCode }),
    });
    if (!verified.ok) {
      this.metrics.downloads.inc({ stage: 'grant', result: 'reauth_failed' });
      await this.refused(
        principal,
        scope,
        client,
        entryId,
        'reauth_failed',
        reauthFailed(),
        verified.reason,
      );
    }
    const now = new Date();
    const expiresAt = new Date(
      now.getTime() + this.config.QUARANTINE_DOWNLOAD_TOKEN_TTL_SECONDS * 1000,
    );
    const jti = uuidv7(now.getTime());
    try {
      const target = await this.writer.run(async (tx) => {
        const locked = await this.ops.lock(tx, scope, entryId);
        const t = await this.target(tx, scope, locked.entry, body.object, body.partIndex ?? null);
        this.gate(t);
        await this.writes.insertGrant(tx, {
          jti,
          organizationId: scope.organizationId,
          userId: principal.userId,
          quarantineMessageId: t.entry.id,
          object: t.object,
          partIndex: t.partIndex,
          expiresAt,
          sourceIp: client.ip,
        });
        await this.ops.action(tx, scope, principal, t.entry, 'download_grant', {
          result: 'granted',
          details: { object: t.object, partIndex: t.partIndex },
        });
        await this.writer.record(tx, {
          principal,
          scope,
          client,
          action: QUARANTINE_AUDIT.downloadGranted,
          resourceType: QUARANTINE_RESOURCE.entry,
          resourceId: t.entry.publicId,
          metadata: { entryId: t.entry.publicId, object: t.object, partIndex: t.partIndex, jti },
        });
        return t;
      });
      this.metrics.downloads.inc({ stage: 'grant', result: 'granted' });
      const token = signDownloadToken(
        {
          v: 1,
          jti,
          org: scope.organizationId.toString(),
          usr: principal.userPublicId,
          ent: target.entry.publicId,
          obj: target.object,
          part: target.partIndex,
          exp: Math.floor(expiresAt.getTime() / 1000),
        },
        this.key,
      );
      return {
        token,
        expiresAt: expiresAt.toISOString(),
        filename: downloadFilename(target.name, target.object),
        sizeBytes: target.sizeBytes,
        sha256: target.sha256,
      };
    } catch (error) {
      if (!(error instanceof AuditedRefusal)) throw error;
      this.metrics.downloads.inc({ stage: 'grant', result: 'blocked' });
      await this.writer.recordRefusal(principal, scope, client, error);
      throw error.error;
    }
  }

  async download(
    principal: UserPrincipal,
    scope: TenantScope,
    token: string,
    client: ClientContext,
  ): Promise<DownloadStream> {
    const now = new Date();
    const verified = verifyDownloadToken(token, this.key, {
      now,
      expected: { org: scope.organizationId.toString(), usr: principal.userPublicId },
    });
    if (!verified.ok) {
      this.metrics.downloads.inc({ stage: 'download', result: 'token_invalid' });
      throw downloadTokenInvalid();
    }
    const p = verified.payload;
    let target: Target;
    try {
      target = await this.writer.run(async (tx) => {
        const consumed = await this.writes.consumeGrant(tx, scope, p.jti, principal.userId, now);
        if (consumed === 'used') throw downloadTokenUsed();
        if (consumed === 'invalid') throw downloadTokenInvalid();
        const grant = await this.writes.grantByJti(tx, scope, p.jti);
        const ref = await this.writes.findEntryRef(tx, scope, p.ent);
        if (
          grant === null ||
          ref === null ||
          grant.quarantineMessageId !== ref.id ||
          grant.object !== p.obj ||
          grant.partIndex !== p.part
        ) {
          throw downloadTokenInvalid();
        }
        const locked = await this.ops.lockRef(tx, scope, ref);
        const t = await this.target(tx, scope, locked.entry, p.obj, p.part);
        this.gate(t);
        await this.ops.action(tx, scope, principal, t.entry, 'download', {
          result: 'served',
          details: { object: t.object, partIndex: t.partIndex },
        });
        await this.writer.record(tx, {
          principal,
          scope,
          client,
          action: QUARANTINE_AUDIT.downloaded,
          resourceType: QUARANTINE_RESOURCE.entry,
          resourceId: t.entry.publicId,
          metadata: {
            entryId: t.entry.publicId,
            object: t.object,
            partIndex: t.partIndex,
            jti: p.jti,
            sizeBytes: t.sizeBytes,
          },
        });
        return t;
      });
    } catch (error) {
      const code = (error as { code?: unknown }).code;
      if (error instanceof AuditedRefusal) {
        this.metrics.downloads.inc({ stage: 'download', result: 'blocked' });
        // The grant stays consumed: the refusal rolled back the consume, so consume it again.
        await this.writer.run((tx) =>
          this.writes.consumeGrant(tx, scope, p.jti, principal.userId, now),
        );
        await this.writer.recordRefusal(principal, scope, client, error);
        throw error.error;
      }
      this.metrics.downloads.inc({
        stage: 'download',
        result:
          code === 'quarantine_download_token_used'
            ? 'token_used'
            : code === 'quarantine_download_token_invalid'
              ? 'token_invalid'
              : 'error',
      });
      throw error;
    }
    try {
      const opened = await this.objects.open(
        scope.organizationId,
        target.key!,
        target.prefix,
        this.config.QUARANTINE_DOWNLOAD_MAX_BYTES,
      );
      this.metrics.downloads.inc({ stage: 'download', result: 'served' });
      return {
        body: opened.body,
        sizeBytes: opened.sizeBytes,
        filename: downloadFilename(target.name, target.object),
      };
    } catch (error) {
      const reason = error instanceof QuarantineObjectError ? error.why : 'storage_error';
      this.metrics.downloads.inc({ stage: 'download', result: 'unavailable' });
      this.logger.warn({ message: 'quarantine download object unavailable', reason });
      await this.writer.run((tx) =>
        this.writer.record(tx, {
          principal,
          scope,
          client,
          action: QUARANTINE_AUDIT.downloadRefused,
          resourceType: QUARANTINE_RESOURCE.entry,
          resourceId: target.entry.publicId,
          metadata: { entryId: target.entry.publicId, reason },
        }),
      );
      if (error instanceof QuarantineObjectError) {
        throw error.why === 'not_found' ? contentPurged() : downloadBlocked(reason);
      }
      throw error;
    }
  }

  /** The object of the grant (writer facts). */
  private async target(
    tx: Tx,
    scope: TenantScope,
    entry: EntryRow,
    object: 'eml' | 'attachment',
    partIndex: number | null,
  ): Promise<Target & { facts: ContentFacts }> {
    const ref = {
      id: entry.messageId,
      receivedAt: entry.messageReceivedAt,
      organizationId: scope.organizationId,
    };
    const facts = await this.facts.contentFacts(tx, scope, ref);
    if (object === 'eml') {
      const message = await this.writes.messageById(tx, scope, ref);
      if (message === null) throw entryNotFound();
      return {
        entry,
        object,
        partIndex: null,
        key: message.emlObjectKey,
        prefix: '',
        sizeBytes: message.sizeBytes,
        sha256: message.emlSha256,
        name: `message-${entry.publicId}`,
        facts,
      };
    }
    const a = facts.attachments.find((x) => x.partIndex === partIndex);
    return {
      entry,
      object,
      partIndex,
      key: a?.objectKey ?? null,
      prefix: 'part/',
      sizeBytes: a?.sizeBytes ?? 0,
      sha256: a?.sha256 ?? '0'.repeat(64),
      name: a?.filename ?? null,
      facts,
    };
  }

  /** Q12.4 malware gating + content presence + size bound; refusals are audited. */
  private gate(t: Target & { facts: ContentFacts }): void {
    if (t.entry.state === 'deleted' || t.entry.objectPurgedAt !== null) {
      throw this.refusal(t, 'content_purged', contentPurged());
    }
    const check: DownloadableCheck = checkDownloadable({
      object: t.object,
      partIndex: t.partIndex,
      entryHardBlocks: t.entry.hardBlocks,
      messageHardBlocks: t.facts.messageHardBlocks,
      latestVerdict: t.facts.latestVerdict,
      attachments: t.facts.attachments,
      urls: t.facts.urls,
    });
    if (!check.ok) throw this.refusal(t, check.reason, downloadBlocked(check.reason));
    if (t.key === null) throw this.refusal(t, 'object_missing', downloadBlocked('object_missing'));
    if (t.sizeBytes > this.config.QUARANTINE_DOWNLOAD_MAX_BYTES) {
      throw this.refusal(t, 'too_large', downloadBlocked('too_large'));
    }
  }

  private refusal(t: Target, reason: string, error: CodedHttpException): AuditedRefusal {
    return new AuditedRefusal(error, {
      action: QUARANTINE_AUDIT.downloadRefused,
      resourceId: t.entry.publicId,
      metadata: { entryId: t.entry.publicId, object: t.object, partIndex: t.partIndex, reason },
    });
  }

  private async refused(
    principal: UserPrincipal,
    scope: TenantScope,
    client: ClientContext,
    entryId: string,
    reason: string,
    error: CodedHttpException,
    cause: string,
  ): Promise<never> {
    await this.writer.recordRefusal(
      principal,
      scope,
      client,
      new AuditedRefusal(error, {
        action: QUARANTINE_AUDIT.downloadRefused,
        resourceId: entryId,
        metadata: { entryId, reason, cause },
      }),
    );
    throw error;
  }
}
