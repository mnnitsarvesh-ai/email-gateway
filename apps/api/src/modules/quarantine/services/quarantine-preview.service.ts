import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  type BodyUnavailableReason,
  type QuarantinePreview,
  renderPreview,
} from '@email-gateway/mail-safety';
import {
  checkDownloadable,
  checkSelfService,
  QUARANTINE_PERMISSIONS,
} from '@email-gateway/quarantine';
import { API_CONFIG } from '../../../api-config.token';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ClientContext } from '../../auth/services/session.service';
import type { EntryRow } from '../domain/entry';
import {
  type QuarantineConfig,
  QUARANTINE_AUDIT,
  QUARANTINE_RESOURCE,
} from '../quarantine.constants';
import {
  contentPurged,
  entryNotFound,
  previewNotAllowed,
  quarantineError,
} from '../quarantine.errors';
import { QuarantineFactsRepository } from '../repositories/quarantine-facts.repository';
import { QuarantineReadRepository } from '../repositories/quarantine-read.repository';
import { QuarantineWriteRepository } from '../repositories/quarantine-write.repository';
import { QuarantineContext, permissionsOf } from './quarantine-context';
import { actorOf } from './quarantine-entry-ops';
import { QuarantineMetrics } from './quarantine-metrics';
import { QuarantineObjectError, QuarantineObjectStore } from './quarantine-object-store';
import { QuarantineWriter } from './quarantine-writer';

type Config = Pick<
  QuarantineConfig,
  'QUARANTINE_PREVIEW_MAX_BODY_BYTES' | 'QUARANTINE_PREVIEW_MAX_TEXT_CHARS'
>;

/** Which part the preview reads, decided before the audit row (Q11). */
export function plannedBody(
  entry: Pick<EntryRow, 'objectPurgedAt'>,
  parse: { status: string; textKey: string | null; htmlKey: string | null } | null,
): { source: 'text' | 'html'; key: string } | { source: null; unavailable: BodyUnavailableReason } {
  if (entry.objectPurgedAt !== null) return { source: null, unavailable: 'purged' };
  if (parse === null || parse.status !== 'parsed')
    return { source: null, unavailable: 'not_parsed' };
  if (parse.textKey !== null) return { source: 'text', key: parse.textKey };
  if (parse.htmlKey !== null) return { source: 'html', key: parse.htmlKey };
  return { source: null, unavailable: 'no_text_part' };
}

/**
 * The sanitized, DLP-masked preview (step 5.3 Q11; ADR-0048): headers from `email_headers`, the
 * decoded text (else HTML) part read with a bounded Range GET under `org/<org>/part/` (never the
 * raw EML), attachments with their latest-round verdicts and URL verdicts, rendered by
 * `@email-gateway/mail-safety` `renderPreview` (JSON text only, active content dropped, links
 * defanged and not clickable, DLP values masked). The `preview` action and the
 * `quarantine.previewed` audit row are committed **before** any part is read; a failure
 * afterwards adds `quarantine.preview_failed` (reason code only).
 */
@Injectable()
export class QuarantinePreviewService {
  private readonly logger = new Logger(QuarantinePreviewService.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: Config,
    private readonly reads: QuarantineReadRepository,
    private readonly writes: QuarantineWriteRepository,
    private readonly facts: QuarantineFactsRepository,
    private readonly objects: QuarantineObjectStore,
    private readonly context: QuarantineContext,
    private readonly writer: QuarantineWriter,
    private readonly metrics: QuarantineMetrics,
  ) {}

  async preview(
    principal: Principal,
    scope: TenantScope,
    entryId: string,
    client: ClientContext,
  ): Promise<QuarantinePreview> {
    const entry = await this.reads.entry(scope, entryId);
    if (entry === null) throw entryNotFound();
    return this.render(principal, scope, entry, client, false);
  }

  async selfPreview(
    principal: Principal,
    scope: TenantScope,
    entryId: string,
    client: ClientContext,
  ): Promise<QuarantinePreview> {
    const caller = await this.context.selfCaller(principal, scope);
    const entry = await this.reads.entry(scope, entryId, caller.address);
    if (entry === null) throw entryNotFound();
    const settings = await this.context.settings(scope);
    const check = checkSelfService({
      action: 'preview',
      settings,
      caller: {
        type: 'user',
        verifiedEmail: caller.address,
        permissions: permissionsOf(principal),
      },
      entry: {
        recipientAddress: entry.recipientAddress,
        state: entry.state,
        reason: entry.reason,
        riskLevel: entry.riskLevel,
        hasHardBlock: entry.hasHardBlock,
      },
    });
    if (!check.allowed) {
      if (check.code === 'quarantine_preview_not_allowed') throw previewNotAllowed(check.cause);
      throw entryNotFound();
    }
    return this.render(principal, scope, entry, client, true);
  }

  private async render(
    principal: Principal,
    scope: TenantScope,
    entry: EntryRow,
    client: ClientContext,
    self: boolean,
  ): Promise<QuarantinePreview> {
    if (entry.state === 'deleted' && entry.objectPurgedAt !== null) {
      this.metrics.previews.inc({ result: 'purged' });
      throw contentPurged();
    }
    const ref = {
      id: entry.messageId,
      receivedAt: entry.messageReceivedAt,
      organizationId: scope.organizationId,
    };
    const db = this.reads.client;
    const [sources, content, settings] = await Promise.all([
      this.facts.previewSources(db, scope, ref),
      this.facts.contentFacts(db, scope, ref),
      this.context.settings(scope),
    ]);
    const plan = plannedBody(entry, sources.parse);

    // (1) The audit row and the action, committed before anything is read from storage.
    await this.writer.run(async (tx) => {
      await this.writes.insertAction(tx, {
        organizationId: scope.organizationId,
        quarantineMessageId: entry.id,
        action: 'preview',
        ...actorOf(principal),
        reason: null,
        result: plan.source ?? 'unavailable',
        details: { self },
        idempotencyKey: null,
      });
      await this.writer.record(tx, {
        principal,
        scope,
        client,
        action: QUARANTINE_AUDIT.previewed,
        resourceType: QUARANTINE_RESOURCE.entry,
        resourceId: entry.publicId,
        metadata: { entryId: entry.publicId, bodySource: plan.source, self },
      });
    });

    // (2) The bounded part read and the pure rendering.
    let textPart: string | null = null;
    let htmlPart: string | null = null;
    let partsTruncated = false;
    let unavailable: BodyUnavailableReason | null = plan.source === null ? plan.unavailable : null;
    try {
      if (plan.source !== null) {
        const read = await this.objects.readPart(
          scope.organizationId,
          plan.key,
          this.config.QUARANTINE_PREVIEW_MAX_BODY_BYTES,
        );
        const text = read.bytes.toString('utf8');
        partsTruncated = read.truncated;
        if (plan.source === 'text') textPart = text;
        else htmlPart = text;
      }
    } catch (error) {
      if (error instanceof QuarantineObjectError && error.why === 'not_found') {
        unavailable = 'purged';
      } else {
        const reason = error instanceof QuarantineObjectError ? error.why : 'storage_error';
        await this.failed(principal, scope, client, entry, reason);
        throw error instanceof QuarantineObjectError
          ? quarantineError('quarantine_preview_unavailable', 'The preview cannot be produced', {
              reason,
            })
          : error;
      }
    }
    const canDownload =
      !self &&
      settings.download.enabled &&
      principal.permissions.has(QUARANTINE_PERMISSIONS.download);
    try {
      const preview = renderPreview({
        subject: sources.subject,
        headers: sources.headers,
        textPart,
        htmlPart,
        partsTruncated,
        unavailableReason: unavailable,
        attachments: content.attachments.map((a) => ({
          partIndex: a.partIndex,
          filename: a.filename,
          declaredType: a.declaredType,
          detectedType: a.detectedType,
          typeFamily: a.typeFamily,
          sizeBytes: a.sizeBytes,
          sha256: a.sha256,
          verdict: a.verdict,
          reasonCodes: a.reasonCodes,
          downloadable:
            canDownload &&
            checkDownloadable({
              object: 'attachment',
              partIndex: a.partIndex,
              entryHardBlocks: entry.hardBlocks,
              messageHardBlocks: content.messageHardBlocks,
              latestVerdict: content.latestVerdict,
              attachments: content.attachments,
              urls: content.urls,
            }).ok,
        })),
        urlVerdicts: content.urls,
        now: new Date(),
        limits: { maxTextChars: this.config.QUARANTINE_PREVIEW_MAX_TEXT_CHARS },
      });
      this.metrics.previews.inc({ result: unavailable === null ? 'ok' : 'unavailable' });
      return preview;
    } catch (error) {
      await this.failed(principal, scope, client, entry, 'render_error');
      throw error;
    }
  }

  private async failed(
    principal: Principal,
    scope: TenantScope,
    client: ClientContext,
    entry: EntryRow,
    reason: string,
  ): Promise<void> {
    this.metrics.previews.inc({ result: 'failed' });
    this.logger.warn({ message: 'quarantine preview failed after its audit row', reason });
    try {
      await this.writer.run((tx) =>
        this.writer.record(tx, {
          principal,
          scope,
          client,
          action: QUARANTINE_AUDIT.previewFailed,
          resourceType: QUARANTINE_RESOURCE.entry,
          resourceId: entry.publicId,
          metadata: { entryId: entry.publicId, reason },
        }),
      );
    } catch (error) {
      this.logger.error({ message: 'preview_failed audit row not written', err: error });
    }
  }
}
