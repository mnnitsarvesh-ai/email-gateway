import type { Prisma } from '@email-gateway/database';
import { POLICY_LIMITS, PolicyInputError, type PolicyRoundRows } from '@email-gateway/policy-dsl';
import { type InconsistencySink, wrongRead } from './errors';

/** The round being evaluated; organization from the trusted envelope, matched on every read. */
export interface RoundRef {
  messageId: bigint;
  receivedAt: Date;
  organizationId: bigint;
  round: number;
  trigger: PolicyRoundRows['trigger'];
  /** `email_scans.id` of the round; null for a parse failure. */
  scanId: bigint | null;
  /**
   * Step 5.3 Q13.3 (release re-validation): the round read is the latest completed scan round,
   * which may be older than the message's current round (after an earlier release or E28). The
   * message row's round is then checked to be at least the scan's (default: equal).
   */
  olderRoundAllowed?: boolean;
}

/** P8 rows without the directory (resolved after the snapshot is known). */
export type RoundFacts = Omit<PolicyRoundRows, 'directory'>;

type Keyed = { messageId: bigint; organizationId: bigint; receivedAt: Date };
type ScanKeyed = Keyed & { scanId: bigint };

const sameTime = (a: Date, b: Date): boolean => a.getTime() === b.getTime();

/**
 * The writer reads of one evaluation (P8, §6), inside the evaluation transaction after the first
 * lifecycle edge locked the message row. Every deciding read selects and verifies its identifying
 * columns (message, organization, `received_at`, scan, round, revision); a shifted read throws
 * `InconsistentPolicyReadError` (retryable). Lists by message are capped at the P4 limit + 1
 * (lowest sequence first) so the input builder can set its truncation flags without reading an
 * unbounded number of rows. Consistent (non-locking) reads: they see the snapshot taken after the
 * message lock, which includes every row of the round (committed with `scanned.v1`).
 */
export class FactsRepository {
  constructor(private readonly sink: InconsistencySink) {}

  async read(tx: Prisma.TransactionClient, ref: RoundRef): Promise<RoundFacts> {
    const message = await this.message(tx, ref);
    const recipients = await this.recipients(tx, ref);
    const attachments = await this.attachments(tx, ref);
    const urls = await this.urls(tx, ref);
    if (ref.scanId === null) {
      return {
        trigger: ref.trigger,
        message,
        recipients,
        scan: null,
        parseFailedAt: await this.parseFailedAt(tx, ref),
        finals: [],
        auth: null,
        bec: null,
        dlp: null,
        risk: [],
        attachments,
        attachmentResults: [],
        urls,
        urlResults: [],
        urlRewrite: null,
      };
    }
    const scanRef = { ...ref, scanId: ref.scanId };
    return {
      trigger: ref.trigger,
      message,
      recipients,
      scan: await this.scan(tx, scanRef),
      parseFailedAt: null,
      finals: await this.finals(tx, scanRef),
      auth: await this.auth(tx, scanRef),
      bec: await this.bec(tx, scanRef),
      dlp: await this.dlp(tx, scanRef),
      risk: await this.risk(tx, scanRef),
      attachments,
      attachmentResults: await this.attachmentResults(tx, scanRef),
      urls,
      urlResults: await this.urlResults(
        tx,
        scanRef,
        urls.map((u) => u.urlSeq),
      ),
      urlRewrite: await this.urlRewrite(tx, scanRef),
    };
  }

  private echo(read: Parameters<InconsistencySink>[0], row: Keyed, ref: RoundRef): void {
    if (row.messageId !== ref.messageId) wrongRead(this.sink, read, 'message echo');
    if (row.organizationId !== ref.organizationId) wrongRead(this.sink, read, 'organization echo');
    if (!sameTime(row.receivedAt, ref.receivedAt)) wrongRead(this.sink, read, 'received_at echo');
  }

  private echoScan(
    read: Parameters<InconsistencySink>[0],
    row: ScanKeyed,
    ref: RoundRef & { scanId: bigint },
  ): void {
    this.echo(read, row, ref);
    if (row.scanId !== ref.scanId) wrongRead(this.sink, read, 'scan echo');
  }

  private async message(
    tx: Prisma.TransactionClient,
    ref: RoundRef,
  ): Promise<RoundFacts['message']> {
    const row = await tx.emailMessage.findFirst({
      where: { id: ref.messageId, receivedAt: ref.receivedAt, organizationId: ref.organizationId },
      select: {
        id: true,
        receivedAt: true,
        organizationId: true,
        direction: true,
        envelopeFrom: true,
        headerFrom: true,
        clientIp: true,
        clientName: true,
        sizeBytes: true,
        recipientCount: true,
        attachmentCount: true,
        lifecycleRound: true,
      },
    });
    // The first edge locked this row in the same transaction: absence is a wrong read.
    if (row === null) return wrongRead(this.sink, 'message', 'row missing');
    this.echo('message', { ...row, messageId: row.id }, ref);
    if (
      ref.olderRoundAllowed === true
        ? row.lifecycleRound < ref.round
        : row.lifecycleRound !== ref.round
    ) {
      wrongRead(this.sink, 'message', 'round echo');
    }
    return {
      direction: row.direction,
      envelopeFrom: row.envelopeFrom,
      headerFrom: row.headerFrom,
      clientIp: row.clientIp,
      clientName: row.clientName,
      sizeBytes: row.sizeBytes,
      recipientCount: row.recipientCount,
      attachmentCount: row.attachmentCount,
      // The round evaluated (the scan's): equal to the row's unless an older round is read.
      lifecycleRound: ref.round,
    };
  }

  private async recipients(
    tx: Prisma.TransactionClient,
    ref: RoundRef,
  ): Promise<RoundFacts['recipients']> {
    const rows = await tx.emailRecipient.findMany({
      where: {
        messageId: ref.messageId,
        receivedAt: ref.receivedAt,
        organizationId: ref.organizationId,
      },
      select: {
        messageId: true,
        receivedAt: true,
        organizationId: true,
        rcptSeq: true,
        address: true,
      },
      orderBy: { rcptSeq: 'asc' },
      take: POLICY_LIMITS.recipients + 1,
    });
    for (const row of rows) this.echo('recipients', row, ref);
    return rows.map((r) => ({ rcptSeq: r.rcptSeq, address: r.address }));
  }

  private async attachments(
    tx: Prisma.TransactionClient,
    ref: RoundRef,
  ): Promise<RoundFacts['attachments']> {
    const rows = await tx.emailAttachment.findMany({
      where: {
        messageId: ref.messageId,
        receivedAt: ref.receivedAt,
        organizationId: ref.organizationId,
      },
      select: {
        messageId: true,
        receivedAt: true,
        organizationId: true,
        partIndex: true,
        filename: true,
        declaredContentType: true,
        detectedContentType: true,
        sizeBytes: true,
        sha256: true,
        archiveInfo: true,
      },
      orderBy: { partIndex: 'asc' },
      take: POLICY_LIMITS.attachments + 1,
    });
    for (const row of rows) this.echo('attachments', row, ref);
    return rows.map((r) => ({
      partIndex: r.partIndex,
      filename: r.filename,
      declaredContentType: r.declaredContentType,
      detectedContentType: r.detectedContentType,
      sizeBytes: r.sizeBytes,
      sha256: r.sha256,
      archiveInfo: r.archiveInfo,
    }));
  }

  private async urls(tx: Prisma.TransactionClient, ref: RoundRef): Promise<RoundFacts['urls']> {
    const rows = await tx.messageUrl.findMany({
      where: {
        messageId: ref.messageId,
        receivedAt: ref.receivedAt,
        organizationId: ref.organizationId,
      },
      select: {
        messageId: true,
        receivedAt: true,
        organizationId: true,
        urlSeq: true,
        host: true,
        registrableDomain: true,
        scheme: true,
        hostKind: true,
        truncated: true,
      },
      orderBy: { urlSeq: 'asc' },
      take: POLICY_LIMITS.urls + 1,
    });
    for (const row of rows) this.echo('urls', row, ref);
    return rows.map((r) => ({
      urlSeq: r.urlSeq,
      host: r.host,
      registrableDomain: r.registrableDomain,
      scheme: r.scheme,
      hostKind: r.hostKind,
      truncated: r.truncated,
    }));
  }

  private async parseFailedAt(tx: Prisma.TransactionClient, ref: RoundRef): Promise<Date> {
    const row = await tx.emailMessageParse.findFirst({
      where: {
        messageId: ref.messageId,
        receivedAt: ref.receivedAt,
        organizationId: ref.organizationId,
      },
      select: {
        messageId: true,
        receivedAt: true,
        organizationId: true,
        status: true,
        completedAt: true,
      },
    });
    // parse_failed.v1 is written with the final parse row: absent or unfinished is a defect.
    if (row === null) throw new PolicyInputError('parse row missing for a parse failure');
    this.echo('parse', row, ref);
    if (row.completedAt === null) throw new PolicyInputError('parse row without completion time');
    return row.completedAt;
  }

  private async scan(
    tx: Prisma.TransactionClient,
    ref: RoundRef & { scanId: bigint },
  ): Promise<RoundFacts['scan']> {
    const row = await tx.emailScan.findFirst({
      where: { id: ref.scanId, receivedAt: ref.receivedAt },
      select: {
        id: true,
        receivedAt: true,
        messageId: true,
        organizationId: true,
        lifecycleRound: true,
        scanKind: true,
        status: true,
        scanVerdict: true,
        reasonCodes: true,
        requiredEngines: true,
        completedAt: true,
      },
    });
    if (row === null) return wrongRead(this.sink, 'scan', 'row missing');
    this.echoScan('scan', { ...row, scanId: row.id }, ref);
    if (row.lifecycleRound !== ref.round) wrongRead(this.sink, 'scan', 'round echo');
    if (row.status !== 'completed' && row.status !== 'failed' && row.status !== 'timed_out') {
      throw new PolicyInputError('scan round is not final');
    }
    if (row.completedAt === null) throw new PolicyInputError('scan round without completion time');
    // `release_revalidation` (reserved for 5.3) never produces scanned.v1 (its schema refuses it).
    if (row.scanKind !== 'initial' && row.scanKind !== 'rescan') {
      throw new PolicyInputError('scan kind not evaluated by policy-input/1');
    }
    return {
      scanId: row.id,
      lifecycleRound: row.lifecycleRound,
      scanKind: row.scanKind,
      status: row.status,
      scanVerdict: row.scanVerdict,
      reasonCodes: row.reasonCodes,
      requiredEngines: row.requiredEngines,
      completedAt: row.completedAt,
    };
  }

  private async finals(
    tx: Prisma.TransactionClient,
    ref: RoundRef & { scanId: bigint },
  ): Promise<RoundFacts['finals']> {
    const rows = await tx.scanEngineResult.findMany({
      where: { scanId: ref.scanId, receivedAt: ref.receivedAt, isFinal: true },
      select: {
        scanId: true,
        receivedAt: true,
        messageId: true,
        organizationId: true,
        isFinal: true,
        engine: true,
        outcome: true,
        reasonCodes: true,
      },
      orderBy: { engine: 'asc' },
    });
    for (const row of rows) {
      this.echoScan('finals', row, ref);
      if (!row.isFinal) wrongRead(this.sink, 'finals', 'final echo');
    }
    return rows.map((r) => ({ engine: r.engine, outcome: r.outcome, reasonCodes: r.reasonCodes }));
  }

  private async auth(
    tx: Prisma.TransactionClient,
    ref: RoundRef & { scanId: bigint },
  ): Promise<RoundFacts['auth']> {
    const rows = await tx.emailAuthResult.findMany({
      where: { scanId: ref.scanId, receivedAt: ref.receivedAt, engine: 'rspamd' },
      select: {
        scanId: true,
        receivedAt: true,
        messageId: true,
        organizationId: true,
        engine: true,
        spf: true,
        dkim: true,
        dmarc: true,
        dmarcPolicy: true,
        arc: true,
      },
    });
    const row = rows[0];
    if (row === undefined) return null;
    if (rows.length !== 1 || row.engine !== 'rspamd') wrongRead(this.sink, 'auth', 'unique row');
    this.echoScan('auth', row, ref);
    return {
      spf: row.spf,
      dkim: row.dkim,
      dmarc: row.dmarc,
      dmarcPolicy: row.dmarcPolicy,
      arc: row.arc,
    };
  }

  private async bec(
    tx: Prisma.TransactionClient,
    ref: RoundRef & { scanId: bigint },
  ): Promise<RoundFacts['bec']> {
    const rows = await tx.becScanResult.findMany({
      where: { scanId: ref.scanId, receivedAt: ref.receivedAt },
      select: {
        scanId: true,
        receivedAt: true,
        messageId: true,
        organizationId: true,
        lifecycleRound: true,
        deterministicVerdict: true,
        verdict: true,
        rules: true,
      },
    });
    const row = rows[0];
    if (row === undefined) return null;
    if (rows.length !== 1) wrongRead(this.sink, 'bec', 'unique row');
    this.echoScan('bec', row, ref);
    if (row.lifecycleRound !== ref.round) wrongRead(this.sink, 'bec', 'round echo');
    return {
      deterministicVerdict: row.deterministicVerdict,
      verdict: row.verdict,
      rules: row.rules,
    };
  }

  private async dlp(
    tx: Prisma.TransactionClient,
    ref: RoundRef & { scanId: bigint },
  ): Promise<RoundFacts['dlp']> {
    const rows = await tx.dlpScanResult.findMany({
      where: { scanId: ref.scanId, receivedAt: ref.receivedAt },
      select: {
        scanId: true,
        receivedAt: true,
        messageId: true,
        organizationId: true,
        lifecycleRound: true,
        action: true,
        verdict: true,
        coverage: true,
        categories: true,
      },
    });
    const row = rows[0];
    if (row === undefined) return null;
    if (rows.length !== 1) wrongRead(this.sink, 'dlp', 'unique row');
    this.echoScan('dlp', row, ref);
    if (row.lifecycleRound !== ref.round) wrongRead(this.sink, 'dlp', 'round echo');
    return {
      action: row.action,
      verdict: row.verdict,
      coverage: row.coverage,
      categories: row.categories,
    };
  }

  private async risk(
    tx: Prisma.TransactionClient,
    ref: RoundRef & { scanId: bigint },
  ): Promise<RoundFacts['risk']> {
    const rows = await tx.messageRiskScore.findMany({
      where: { scanId: ref.scanId, receivedAt: ref.receivedAt },
      select: {
        scanId: true,
        receivedAt: true,
        messageId: true,
        organizationId: true,
        lifecycleRound: true,
        revision: true,
        status: true,
        score: true,
        level: true,
        verdict: true,
        recommendedAction: true,
        hardBlocks: true,
        reasonCodes: true,
        failures: true,
        engines: true,
        evidence: true,
      },
      orderBy: { revision: 'asc' },
    });
    const seen = new Set<number>();
    for (const row of rows) {
      this.echoScan('risk', row, ref);
      if (row.lifecycleRound !== ref.round) wrongRead(this.sink, 'risk', 'round echo');
      if ((row.revision !== 0 && row.revision !== 1) || seen.has(row.revision)) {
        wrongRead(this.sink, 'risk', 'revision echo');
      }
      seen.add(row.revision);
    }
    return rows.map((r) => ({
      revision: r.revision,
      status: r.status,
      score: r.score,
      level: r.level,
      verdict: r.verdict,
      recommendedAction: r.recommendedAction,
      hardBlocks: r.hardBlocks,
      reasonCodes: r.reasonCodes,
      failures: r.failures,
      engines: r.engines,
      evidence: r.evidence,
    }));
  }

  private async attachmentResults(
    tx: Prisma.TransactionClient,
    ref: RoundRef & { scanId: bigint },
  ): Promise<RoundFacts['attachmentResults']> {
    const rows = await tx.attachmentScanResult.findMany({
      where: { scanId: ref.scanId, receivedAt: ref.receivedAt },
      select: {
        scanId: true,
        receivedAt: true,
        messageId: true,
        organizationId: true,
        partIndex: true,
        detectedType: true,
        typeFamily: true,
        typeMismatch: true,
        verdict: true,
        reasonCodes: true,
        archive: true,
      },
      orderBy: { partIndex: 'asc' },
    });
    for (const row of rows) this.echoScan('attachment_results', row, ref);
    return rows.map((r) => ({
      partIndex: r.partIndex,
      detectedType: r.detectedType,
      typeFamily: r.typeFamily,
      typeMismatch: r.typeMismatch,
      verdict: r.verdict,
      reasonCodes: r.reasonCodes,
      archive: r.archive,
    }));
  }

  private async urlResults(
    tx: Prisma.TransactionClient,
    ref: RoundRef & { scanId: bigint },
    urlSeqs: number[],
  ): Promise<RoundFacts['urlResults']> {
    if (urlSeqs.length === 0) return [];
    const rows = await tx.urlScanResult.findMany({
      where: { scanId: ref.scanId, receivedAt: ref.receivedAt, urlSeq: { in: urlSeqs } },
      select: {
        scanId: true,
        receivedAt: true,
        messageId: true,
        organizationId: true,
        urlSeq: true,
        verdict: true,
        reasonCodes: true,
        rewritten: true,
      },
      orderBy: { urlSeq: 'asc' },
    });
    for (const row of rows) this.echoScan('url_results', row, ref);
    return rows.map((r) => ({
      urlSeq: r.urlSeq,
      verdict: r.verdict,
      reasonCodes: r.reasonCodes,
      rewritten: r.rewritten,
    }));
  }

  private async urlRewrite(
    tx: Prisma.TransactionClient,
    ref: RoundRef & { scanId: bigint },
  ): Promise<RoundFacts['urlRewrite']> {
    const rows = await tx.urlRewrite.findMany({
      where: { scanId: ref.scanId, receivedAt: ref.receivedAt },
      select: {
        scanId: true,
        receivedAt: true,
        messageId: true,
        organizationId: true,
        lifecycleRound: true,
        status: true,
        skipReason: true,
      },
    });
    const row = rows[0];
    if (row === undefined) return null;
    if (rows.length !== 1) wrongRead(this.sink, 'url_rewrite', 'unique row');
    this.echoScan('url_rewrite', row, ref);
    if (row.lifecycleRound !== ref.round) wrongRead(this.sink, 'url_rewrite', 'round echo');
    return { status: row.status, skipReason: row.skipReason };
  }
}
