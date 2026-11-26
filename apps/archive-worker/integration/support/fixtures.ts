import { createHash, randomBytes, randomUUID } from 'node:crypto';
import {
  DeleteObjectCommand,
  ListObjectVersionsCommand,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import {
  indexTemplateName,
  JOURNAL_INTAKE_PROOF_EXAMPLE,
  type IntakeRecipientField,
} from '@email-gateway/archive';
import { OpenSearchService } from '@email-gateway/common';
import {
  type MessageDirection,
  type MessageStatus,
  Prisma,
  PrismaClient,
  type RecipientStatus,
} from '@email-gateway/database';
import { requireEnv } from './broker';

export interface SeededMessage {
  id: bigint;
  receivedAt: Date;
  organizationId: bigint;
  publicId: string;
  emlKey: string;
  eml: Buffer;
  emlSha256: string;
  scanId: bigint | null;
}

export interface OrgOptions {
  entitled?: boolean;
  enabled?: boolean;
  settings?: Prisma.InputJsonValue | null;
  lockMode?: 'none' | 'governance' | 'compliance';
  retentionDays?: number;
  onExpiry?: 'delete' | 'review';
  journalEnabledAt?: Date | null;
}

export interface MessageOptions {
  direction?: MessageDirection;
  status?: MessageStatus;
  statusReason?: string | null;
  recipients?: Array<{ address: string; direction?: MessageDirection; status?: RecipientStatus }>;
  envelopeFrom?: string;
  subject?: string;
  bodyBytes?: number;
  round?: boolean;
  maliciousUrl?: boolean;
  /** A stored evaluation whose actions hold `{ type: 'ARCHIVE', status: 'requested' }`. */
  archivePolicy?: boolean;
  /** Seconds before now (received_at); created_at is 60 s later than received_at. */
  ageSeconds?: number;
  /** Overrides the stored eml_sha256 (integrity mismatch test). */
  wrongSha?: boolean;
  /** Skips the EML object (mail-bucket lifecycle test: `lost`). */
  noEml?: boolean;
}

const sha256 = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex');

/** One copy of a message for the step 8.6 dedupe suites (gateway or journal intake). */
export interface CopySpec {
  /** `mailbox_api` (step API-1): a mailbox API copy, `journaled` like an intake copy, no intake row. */
  ingestSource: 'gateway' | 'journal_intake' | 'mailbox_api';
  /** The Message-ID header value without angle brackets. */
  messageId: string;
  /** The Date header (RFC 5322). */
  date: string;
  from: string;
  to: string[];
  cc?: string[];
  body: string;
  attachment: Buffer;
  /** Header lines prepended to the copy (a provider stamp, a gateway Received line). */
  extraHeaders?: string[];
  /** Registry recipients; default: To + Cc. */
  recipients?: Array<{
    address: string;
    direction: MessageDirection | null;
    field?: IntakeRecipientField;
  }>;
  /** Journal envelope recipients beyond the registry ones (intake: BCC custodians). */
  bcc?: string[];
  direction?: MessageDirection;
  status?: MessageStatus;
  /** Gateway facts (an intake copy has none). */
  finalVerdict?: 'clean' | 'phishing' | 'spam';
  riskScore?: number;
  /** Journal intake source of an intake copy (internal id). */
  sourceId?: bigint;
  scanRequested?: boolean;
  ageSeconds?: number;
}

/** A synthetic copy: the given headers, a text body and one base64 attachment. */
export function copyEml(spec: CopySpec): Buffer {
  const attachment = spec.attachment.toString('base64').replace(/(.{76})/g, '$1\r\n');
  return Buffer.from(
    [
      ...(spec.extraHeaders ?? []),
      `From: Sender <${spec.from}>`,
      `To: ${spec.to.join(', ')}`,
      ...(spec.cc && spec.cc.length > 0 ? [`Cc: ${spec.cc.join(', ')}`] : []),
      'Subject: Dedupe test',
      `Date: ${spec.date}`,
      `Message-ID: <${spec.messageId}>`,
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="b1"',
      '',
      '--b1',
      'Content-Type: text/plain; charset=utf-8',
      '',
      spec.body,
      '--b1',
      'Content-Type: application/octet-stream; name="report.bin"',
      'Content-Disposition: attachment; filename="report.bin"',
      'Content-Transfer-Encoding: base64',
      '',
      attachment,
      '--b1--',
      '',
    ].join('\r\n'),
    'utf8',
  );
}
const pad = (n: number, w = 2): string => String(n).padStart(w, '0');

/** A synthetic RFC 5322 message with a text body and one attachment (no real content). */
export function syntheticEml(input: {
  from: string;
  to: string[];
  subject: string;
  messageId: string;
  bodyBytes?: number;
}): Buffer {
  const body = 'Synthetic archive test body.\r\n'.repeat(
    Math.max(1, Math.ceil((input.bodyBytes ?? 512) / 30)),
  );
  const attachment = randomBytes(256)
    .toString('base64')
    .replace(/(.{76})/g, '$1\r\n');
  return Buffer.from(
    [
      `From: Sender <${input.from}>`,
      `To: ${input.to.join(', ')}`,
      `Subject: ${input.subject}`,
      `Message-ID: <${input.messageId}>`,
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="b1"',
      '',
      '--b1',
      'Content-Type: text/plain; charset=utf-8',
      '',
      body,
      '--b1',
      'Content-Type: application/octet-stream; name="report.bin"',
      'Content-Disposition: attachment; filename="report.bin"',
      'Content-Transfer-Encoding: base64',
      '',
      attachment,
      '--b1--',
      '',
    ].join('\r\n'),
    'utf8',
  );
}

/**
 * Per-run fixtures of the archive-worker suite: `it-arch-<suffix>-*` organizations on the seeded
 * `enterprise` plan with the `archiving` feature, archive settings and a default retention
 * policy, realistic messages (registry, message, recipients, parse, headers, attachment, decoded
 * parts and the original EML in the mail bucket, a completed scan round with engine, auth,
 * attachment, URL, risk and evaluation rows), and the cleanup of everything the worker writes:
 * rows, mail/archive/replica objects (every version), OpenSearch indices, aliases and templates of
 * the run's index prefix, cursors and ledger rows.
 */
export class Fixtures {
  readonly prisma: PrismaClient = new PrismaClient({ datasourceUrl: requireEnv('DATABASE_URL') });
  readonly suffix = randomUUID().slice(0, 8);
  readonly prefix = `eg-archive-wp3-${this.suffix}`;
  readonly organizationIds: bigint[] = [];
  readonly eventIds = new Set<string>();
  readonly mailBucket = requireEnv('S3_BUCKET_MAIL');
  readonly archiveBucket = requireEnv('S3_BUCKET_ARCHIVE');
  readonly replicaBucket = process.env.ARCHIVE_TEST_REPLICA_BUCKET || 'gateway-archive-replica';
  readonly s3 = new S3Client({
    region: requireEnv('S3_REGION'),
    endpoint: process.env.S3_ENDPOINT,
    forcePathStyle: process.env.S3_FORCE_PATH_STYLE !== 'false',
    credentials: {
      accessKeyId: requireEnv('S3_ACCESS_KEY_ID'),
      secretAccessKey: requireEnv('S3_SECRET_ACCESS_KEY'),
    },
  });
  readonly search = new OpenSearchService({
    url: requireEnv('ARCHIVE_SEARCH_URL'),
    username: process.env.ARCHIVE_SEARCH_USERNAME || undefined,
    password: process.env.ARCHIVE_SEARCH_PASSWORD || undefined,
    timeoutMs: 15_000,
  });
  private planId: bigint | undefined;
  private counter = 0;

  track(eventId: string): string {
    this.eventIds.add(eventId);
    return eventId;
  }

  async organization(
    label: string,
    options: OrgOptions = {},
  ): Promise<{ id: bigint; publicId: string; defaultPolicyId: bigint }> {
    if (this.planId === undefined) {
      const plan = await this.prisma.organizationPlan.findFirstOrThrow({
        where: { code: 'enterprise' },
        select: { id: true },
      });
      this.planId = plan.id;
    }
    const org = await this.prisma.organization.create({
      data: {
        slug: `it-arch-${this.suffix}-${label}`,
        name: `Archive ${label}`,
        planId: this.planId,
        dataRegion: 'ap-south-1',
        status: 'active',
      },
      select: { id: true, publicId: true },
    });
    this.organizationIds.push(org.id);
    await this.prisma.organizationFeature.create({
      data: { organizationId: org.id, featureKey: 'archiving', enabled: options.entitled ?? true },
    });
    const policy = await this.prisma.archiveRetentionPolicy.create({
      data: {
        organizationId: org.id,
        name: 'default',
        retentionDays: options.retentionDays ?? 2_555,
        priority: 1_000,
        onExpiry: options.onExpiry ?? 'delete',
      },
      select: { id: true },
    });
    await this.prisma.archiveSetting.create({
      data: {
        organizationId: org.id,
        enabled: options.enabled ?? true,
        settings:
          options.settings === undefined || options.settings === null
            ? Prisma.DbNull
            : options.settings,
        generation: 1n,
        journalEnabledAt:
          options.journalEnabledAt === undefined
            ? new Date(Date.now() - 86_400_000)
            : options.journalEnabledAt,
        objectLockMode: options.lockMode ?? 'none',
        defaultRetentionPolicyId: policy.id,
      },
    });
    return { ...org, defaultPolicyId: policy.id };
  }

  async put(bucket: string, key: string, body: Buffer): Promise<void> {
    await this.s3.send(new PutObjectCommand({ Bucket: bucket, Key: key, Body: body }));
  }

  async message(organizationId: bigint, options: MessageOptions = {}): Promise<SeededMessage> {
    this.counter += 1;
    const now = Date.now();
    const receivedAt = new Date(
      Math.floor((now - (options.ageSeconds ?? 300) * 1000) / 1000) * 1000,
    );
    const createdAt = new Date(receivedAt.getTime() + 1_000);
    const direction = options.direction ?? 'inbound';
    const recipients = options.recipients ?? [
      {
        address: `user${this.counter}@corp-${this.suffix}.example`,
        direction,
        status: 'delivered',
      },
    ];
    const from = options.envelopeFrom ?? `sender${this.counter}@partner-${this.suffix}.example`;
    const internetMessageId = `it-${this.suffix}-${this.counter}@partner.example`;
    const eml = syntheticEml({
      from,
      to: recipients.map((r) => r.address),
      subject: options.subject ?? `Archive test ${this.counter}`,
      messageId: internetMessageId,
      bodyBytes: options.bodyBytes ?? 512,
    });
    const emlSha256 = sha256(eml);
    const identity = await this.prisma.messageIdentity.create({
      data: { organizationId, ingestKey: `it-arch-${randomUUID()}`, receivedAt },
      select: { id: true, publicId: true },
    });
    const day = `${receivedAt.getUTCFullYear()}/${pad(receivedAt.getUTCMonth() + 1)}/${pad(receivedAt.getUTCDate())}`;
    const emlKey = `org/${organizationId}/eml/${day}/${identity.id}.eml`;
    if (!options.noEml) await this.put(this.mailBucket, emlKey, eml);
    const status = options.status ?? 'delivered';
    await this.prisma.emailMessage.create({
      data: {
        id: identity.id,
        receivedAt,
        organizationId,
        direction,
        status,
        statusReason: options.statusReason ?? (status === 'delivered' ? 'delivery_complete' : null),
        statusChangedAt: createdAt,
        lifecycleRound: 0,
        internetMessageId: `<${internetMessageId}>`,
        envelopeFrom: from,
        headerFrom: `Sender <${from}>`,
        subject: options.subject ?? `Archive test ${this.counter}`,
        sizeBytes: eml.length,
        recipientCount: recipients.length,
        attachmentCount: 1,
        emlObjectKey: emlKey,
        emlSha256: options.wrongSha ? sha256('not the original') : emlSha256,
        clientIp: '192.0.2.10',
        clientHelo: 'mail.partner.example',
        finalVerdict: options.maliciousUrl ? 'phishing' : 'clean',
        finalAction:
          status === 'quarantined' ? 'quarantine' : status === 'rejected' ? 'reject' : 'deliver',
        riskScore: options.maliciousUrl ? 900 : 120,
        createdAt,
      },
    });
    for (const [seq, r] of recipients.entries()) {
      await this.prisma.emailRecipient.create({
        data: {
          receivedAt,
          messageId: identity.id,
          organizationId,
          rcptSeq: seq,
          address: r.address,
          direction: r.direction ?? direction,
          status: r.status ?? (status === 'delivered' ? 'delivered' : 'pending'),
          finalAction: status === 'delivered' ? 'deliver' : null,
        },
      });
    }
    const base = { receivedAt, messageId: identity.id, organizationId };
    const textKey = `org/${organizationId}/part/${day}/${identity.id}/1.text`;
    const htmlKey = `org/${organizationId}/part/${day}/${identity.id}/1.html`;
    await this.put(this.mailBucket, textKey, Buffer.from('Synthetic archive test body.', 'utf8'));
    await this.put(
      this.mailBucket,
      htmlKey,
      Buffer.from('<p>Synthetic archive test body.</p>', 'utf8'),
    );
    await this.prisma.emailMessageParse.create({
      data: {
        ...base,
        status: 'parsed',
        attempts: 1,
        parserVersion: 'it/1',
        partCount: 3,
        attachmentCount: 1,
        textBodyObjectKey: textKey,
        htmlBodyObjectKey: htmlKey,
        startedAt: createdAt,
        completedAt: createdAt,
      },
    });
    await this.prisma.emailHeader.createMany({
      data: [
        { ...base, seq: 0, name: 'From', value: `Sender <${from}>` },
        {
          ...base,
          seq: 1,
          name: 'Subject',
          value: options.subject ?? `Archive test ${this.counter}`,
        },
      ],
    });
    const attachmentSha = sha256(`att-${identity.id}`);
    const attachment = await this.prisma.emailAttachment.create({
      data: {
        ...base,
        partIndex: 2,
        filename: 'report.bin',
        declaredContentType: 'application/octet-stream',
        detectedContentType: 'application/octet-stream',
        sizeBytes: 256,
        sha256: attachmentSha,
      },
      select: { id: true },
    });
    let scanId: bigint | null = null;
    if (options.round !== false) {
      const scan = await this.prisma.emailScan.create({
        data: {
          ...base,
          scanKind: 'initial',
          status: 'completed',
          lifecycleRound: 0,
          scanVerdict: options.maliciousUrl ? 'malicious' : 'clean',
          requiredEngines: ['rspamd'],
          reasonCodes: [],
          startedAt: createdAt,
          completedAt: createdAt,
          deadlineAt: new Date(createdAt.getTime() + 1_800_000),
        },
        select: { id: true },
      });
      scanId = scan.id;
      await this.prisma.scanEngineResult.create({
        data: {
          ...base,
          scanId,
          engine: 'rspamd',
          engineVersion: '3.13.2',
          outcome: 'clean',
          score: 1.5,
          requiredScore: 15,
          durationMs: 120,
          attempt: 1,
          isFinal: true,
          reasonCodes: [],
          settingsVersion: 'rspamd-map/2',
          evidence: { signals: [] },
          completedAt: createdAt,
        },
      });
      await this.prisma.emailAuthResult.create({
        data: { ...base, scanId, engine: 'rspamd', spf: 'pass', dkim: 'pass', dmarc: 'pass' },
      });
      await this.prisma.attachmentScanResult.create({
        data: {
          ...base,
          scanId,
          attachmentId: attachment.id,
          partIndex: 2,
          sha256: attachmentSha,
          sizeBytes: 256,
          detectedType: 'bin',
          typeFamily: 'binary',
          typeMismatch: false,
          verdict: 'clean',
          reasonCodes: [],
          cacheResult: 'miss',
          durationMs: 10,
        },
      });
      const url = `https://link-${this.suffix}.example/path`;
      await this.prisma.messageUrl.create({
        data: {
          ...base,
          urlSeq: 0,
          url,
          urlSha256: sha256(url),
          scheme: 'https',
          host: `link-${this.suffix}.example`,
          hostKind: 'domain',
          sources: ['text'],
          occurrences: 1,
          firstLifecycleRound: 0,
          extractorVersion: 'it/1',
        },
      });
      await this.prisma.urlScanResult.create({
        data: {
          ...base,
          scanId,
          urlSeq: 0,
          urlSha256: sha256(url),
          verdict: options.maliciousUrl ? 'malicious' : 'clean',
          reasonCodes: [],
          reputation: {},
          fetchStatus: 'not_attempted',
          rewritten: false,
          dynamicRequested: false,
          fetchCache: 'none',
          durationMs: 5,
        },
      });
      await this.riskRevision(base, scanId, 0, direction);
      await this.prisma.policyExecutionLog.create({
        data: {
          ...base,
          evaluationSeq: 0,
          scanId,
          trigger: 'scanned',
          direction,
          disposition:
            status === 'quarantined' ? 'quarantine' : status === 'rejected' ? 'reject' : 'allow',
          decisionSource: options.archivePolicy ? 'tenant_rule' : 'platform_default',
          action:
            status === 'quarantined' ? 'quarantine' : status === 'rejected' ? 'reject' : 'deliver',
          finalVerdict: options.maliciousUrl ? 'phishing' : 'clean',
          riskScore: 120,
          matchedPolicyVersionIds: [],
          actions: options.archivePolicy
            ? [
                {
                  type: 'ARCHIVE',
                  params: {},
                  origin: 'tenant_rule',
                  ruleRefs: [`${randomUUID()}#1/archive-legal`],
                  applicability: 'applies',
                  status: 'requested',
                },
              ]
            : [],
          matchedRules: [],
          floor: {},
          recommendation: {},
          clamps: [],
          reasonCodes: [],
          deliveredObject: 'original',
          explanation: [],
          explanationText: 'synthetic evaluation',
          policyGeneration: 1n,
          snapshotSha256: 'a'.repeat(64),
          policyVersions: [],
          platformDefaultId: 'pol-default/1',
          dslVersion: 'policy-dsl/1',
          evaluatorVersion: 'it/1',
          inputVersion: 'it/1',
          inputSha256: 'b'.repeat(64),
          tzdataVersion: '2026a',
          durationUs: 100,
          evaluatedAt: createdAt,
          createdAt,
        },
      });
    }
    return {
      id: identity.id,
      receivedAt,
      organizationId,
      publicId: identity.publicId,
      emlKey,
      eml,
      emlSha256,
      scanId,
    };
  }

  /** A risk revision of a round (a late sandbox revision is revision 1, A7). */
  async riskRevision(
    base: { receivedAt: Date; messageId: bigint; organizationId: bigint },
    scanId: bigint,
    revision: number,
    direction: MessageDirection = 'inbound',
  ): Promise<void> {
    await this.prisma.messageRiskScore.create({
      data: {
        ...base,
        scanId,
        lifecycleRound: 0,
        revision,
        direction,
        status: 'scored',
        score: 120 + revision,
        level: 'low',
        verdict: 'clean',
        recommendedAction: 'deliver',
        hardBlocks: [],
        reasonCodes: [],
        contributions: [],
        groups: {},
        engines: {},
        failures: [],
        floors: [],
        trust: {},
        evidence: {},
        explanation: [],
        explanationText: 'synthetic risk',
        profileSource: 'platform',
        profileIdText: 'rsk-default/1',
        profileSha256: 'c'.repeat(64),
        inputSha256: 'd'.repeat(64),
        scorerVersion: 'it/1',
        signalMapVersion: 'it/1',
        inputVersion: 'it/1',
        durationUs: 100,
      },
    });
  }

  /** A journal intake source of the organization (step 8.6), as the api creates it. */
  async intakeSource(
    organizationId: bigint,
    options: {
      kind?:
        'microsoft_365_journal' | 'google_workspace_copy' | 'exchange_onprem_journal' | 'smtp_bcc';
      status?: 'pending_verification' | 'active' | 'paused';
      silenceAlertMinutes?: number | null;
      verifiedAt?: Date | null;
      lastAcceptedAt?: Date | null;
      lastRefusedAt?: Date | null;
      healthStatus?: 'unknown' | 'healthy' | 'silent' | 'failing' | 'paused';
    } = {},
  ): Promise<{ id: bigint; publicId: string }> {
    this.counter += 1;
    return this.prisma.journalIntakeSource.create({
      data: {
        organizationId,
        kind: options.kind ?? 'smtp_bcc',
        displayName: `it-source-${this.suffix}-${this.counter}`,
        status: options.status ?? 'active',
        networks: { v: 1, cidrs: ['198.51.100.0/24'] },
        silenceAlertMinutes:
          options.silenceAlertMinutes === undefined ? 240 : options.silenceAlertMinutes,
        addressHash: sha256(`it-address-${randomUUID()}`),
        verifiedAt:
          options.verifiedAt === undefined ? new Date(Date.now() - 86_400_000) : options.verifiedAt,
        lastAcceptedAt: options.lastAcceptedAt === undefined ? new Date() : options.lastAcceptedAt,
        lastRefusedAt: options.lastRefusedAt ?? null,
        healthStatus: options.healthStatus ?? 'unknown',
      },
      select: { id: true, publicId: true },
    });
  }

  /**
   * One copy of a message as the gateway (smtp-adapter + MIME + delivery) or the journal intake
   * LMTP (step 8.6 `JournalIntakeRepository`: `ingest_source = journal_intake`, recipients
   * `journaled`, a `journal_intake_messages` row) and the MIME stage would have written it: the
   * EML in the mail bucket, the registry row, message, recipients, parse row, headers and the
   * attachment row with the attachment's real SHA-256.
   */
  async copy(organizationId: bigint, spec: CopySpec): Promise<SeededMessage> {
    this.counter += 1;
    const intake = spec.ingestSource !== 'gateway';
    const journalIntake = spec.ingestSource === 'journal_intake';
    const now = Date.now();
    const receivedAt = new Date(
      Math.floor((now - (spec.ageSeconds ?? 300) * 1000) / 1000) * 1000 + (this.counter % 1000),
    );
    const createdAt = new Date(receivedAt.getTime() + 1_000);
    const eml = copyEml(spec);
    const emlSha256 = sha256(eml);
    const direction = spec.direction ?? 'inbound';
    const recipients: NonNullable<CopySpec['recipients']> =
      spec.recipients ??
      [...spec.to, ...(spec.cc ?? [])].map((address) => ({
        address,
        direction: intake ? null : direction,
      }));
    const status = spec.status ?? (intake ? 'journaled' : 'delivered');
    const identity = await this.prisma.messageIdentity.create({
      data: { organizationId, ingestKey: `it-arch-${randomUUID()}`, receivedAt },
      select: { id: true, publicId: true },
    });
    const day = `${receivedAt.getUTCFullYear()}/${pad(receivedAt.getUTCMonth() + 1)}/${pad(receivedAt.getUTCDate())}`;
    const emlKey = `org/${organizationId}/eml/${day}/${identity.id}.eml`;
    await this.put(this.mailBucket, emlKey, eml);
    await this.prisma.emailMessage.create({
      data: {
        id: identity.id,
        receivedAt,
        organizationId,
        direction,
        status,
        statusReason: intake ? 'intake_unscanned' : 'delivery_complete',
        statusChangedAt: createdAt,
        lifecycleRound: 0,
        internetMessageId: `<${spec.messageId}>`,
        envelopeFrom: spec.from,
        headerFrom: `Sender <${spec.from}>`,
        subject: 'Dedupe test',
        sizeBytes: eml.length,
        recipientCount: recipients.length,
        attachmentCount: 1,
        emlObjectKey: emlKey,
        emlSha256,
        clientIp: '192.0.2.10',
        clientHelo: 'mail.partner.example',
        finalVerdict: intake ? null : (spec.finalVerdict ?? 'clean'),
        finalAction: intake ? null : 'deliver',
        riskScore: intake ? null : (spec.riskScore ?? 120),
        ingestSource: spec.ingestSource,
        createdAt,
      },
    });
    for (const [seq, r] of recipients.entries()) {
      await this.prisma.emailRecipient.create({
        data: {
          receivedAt,
          messageId: identity.id,
          organizationId,
          rcptSeq: seq,
          address: r.address,
          direction: r.direction,
          status: intake ? 'journaled' : 'delivered',
          finalAction: intake ? null : 'deliver',
        },
      });
    }
    const base = { receivedAt, messageId: identity.id, organizationId };
    const textKey = `org/${organizationId}/part/${day}/${identity.id}/1.text`;
    await this.put(this.mailBucket, textKey, Buffer.from(spec.body, 'utf8'));
    await this.prisma.emailMessageParse.create({
      data: {
        ...base,
        status: 'parsed',
        attempts: 1,
        parserVersion: 'it/1',
        partCount: 3,
        attachmentCount: 1,
        textBodyObjectKey: textKey,
        startedAt: createdAt,
        completedAt: createdAt,
      },
    });
    await this.prisma.emailHeader.createMany({
      data: [
        { ...base, seq: 0, name: 'From', value: `Sender <${spec.from}>` },
        { ...base, seq: 1, name: 'Subject', value: 'Dedupe test' },
      ],
    });
    await this.prisma.emailAttachment.create({
      data: {
        ...base,
        partIndex: 2,
        filename: 'report.bin',
        declaredContentType: 'application/octet-stream',
        detectedContentType: 'application/octet-stream',
        sizeBytes: spec.attachment.length,
        sha256: sha256(spec.attachment),
      },
    });
    if (journalIntake) {
      const fields = recipients.map((r) => ({
        address: r.address,
        field: r.field ?? (spec.cc?.includes(r.address) ? 'cc' : 'to'),
      }));
      await this.prisma.journalIntakeMessage.create({
        data: {
          ...base,
          sourceId: spec.sourceId ?? 0n,
          kind: 'microsoft_365_journal',
          format: 'journal_report',
          envelope: {
            v: 1,
            sender: spec.from,
            onBehalfOf: null,
            messageId: `<${spec.messageId}>`,
            recipients: [
              ...fields,
              ...(spec.bcc ?? []).map((address) => ({ address, field: 'bcc' })),
            ],
            truncated: false,
            envelopeMismatch: false,
          },
          proof: JOURNAL_INTAKE_PROOF_EXAMPLE,
          reportSha256: sha256(`report-${identity.id}`),
          reportSizeBytes: eml.length + 512,
          scanRequested: spec.scanRequested ?? false,
          createdAt,
        },
      });
      // The BCC custodians are registry recipients too (D3: the journal envelope recipients).
      for (const [i, address] of (spec.bcc ?? []).entries()) {
        await this.prisma.emailRecipient.create({
          data: {
            receivedAt,
            messageId: identity.id,
            organizationId,
            rcptSeq: recipients.length + i,
            address,
            direction: null,
            status: 'journaled',
          },
        });
      }
    }
    return {
      id: identity.id,
      receivedAt,
      organizationId,
      publicId: identity.publicId,
      emlKey,
      eml,
      emlSha256,
      scanId: null,
    };
  }

  /** Every version (and delete marker) under a prefix of a bucket, removed with governance bypass. */
  async purgeBucketPrefix(bucket: string, prefix: string): Promise<{ left: number }> {
    let left = 0;
    let keyMarker: string | undefined;
    let versionMarker: string | undefined;
    do {
      const page = await this.s3.send(
        new ListObjectVersionsCommand({
          Bucket: bucket,
          Prefix: prefix,
          KeyMarker: keyMarker,
          VersionIdMarker: versionMarker,
        }),
      );
      for (const v of [...(page.Versions ?? []), ...(page.DeleteMarkers ?? [])]) {
        try {
          await this.s3.send(
            new DeleteObjectCommand({
              Bucket: bucket,
              Key: v.Key,
              VersionId: v.VersionId,
              BypassGovernanceRetention: true,
            }),
          );
        } catch {
          left += 1;
        }
      }
      keyMarker = page.IsTruncated ? page.NextKeyMarker : undefined;
      versionMarker = page.IsTruncated ? page.NextVersionIdMarker : undefined;
    } while (keyMarker !== undefined);
    return { left };
  }

  async countVersions(bucket: string, prefix: string): Promise<number> {
    let n = 0;
    let keyMarker: string | undefined;
    let versionMarker: string | undefined;
    do {
      const page = await this.s3.send(
        new ListObjectVersionsCommand({
          Bucket: bucket,
          Prefix: prefix,
          KeyMarker: keyMarker,
          VersionIdMarker: versionMarker,
        }),
      );
      n += (page.Versions ?? []).length;
      keyMarker = page.IsTruncated ? page.NextKeyMarker : undefined;
      versionMarker = page.IsTruncated ? page.NextVersionIdMarker : undefined;
    } while (keyMarker !== undefined);
    return n;
  }

  /** Deletes everything of the run; reports objects that are still locked (compliance). */
  async cleanup(): Promise<{ lockedObjects: number }> {
    let lockedObjects = 0;
    const ids = this.organizationIds;
    if (ids.length > 0) {
      const where = { organizationId: { in: ids } };
      const p = this.prisma;
      await p.ediscoverySearchHit.deleteMany({ where });
      await p.archiveDownloadGrant.deleteMany({ where });
      await p.ediscoveryExport.deleteMany({ where });
      await p.ediscoverySearch.deleteMany({ where });
      await p.archiveLegalHold.deleteMany({ where });
      await p.ediscoveryCustodian.deleteMany({ where });
      await p.ediscoveryCase.deleteMany({ where });
      await p.archiveIndexQueue.deleteMany({ where });
      // Step 8.6 tables (the worker writes them; the suites seed sources and intake messages).
      await p.archiveRecordSource.deleteMany({ where });
      await p.archiveDedupeKey.deleteMany({ where });
      await p.journalIntakeMessage.deleteMany({ where });
      await p.journalIntakeCounter.deleteMany({ where });
      await p.journalIntakeSource.deleteMany({ where });
      await p.notificationAlertWindow.deleteMany({ where });
      await p.messageOutbox.deleteMany({ where });
      await p.archiveIndexCheck.deleteMany({ where });
      await p.archiveDisposal.deleteMany({ where });
      await p.emailArchive.deleteMany({ where });
      await p.archiveCaptureIntent.deleteMany({ where });
      await p.archiveSetting.deleteMany({ where });
      await p.archiveRetentionPolicy.deleteMany({ where });
      await p.archiveEncryptionKey.deleteMany({ where });
      await p.auditLog.deleteMany({ where });
      await p.policyExecutionLog.deleteMany({ where });
      await p.messageRiskScore.deleteMany({ where });
      await p.urlScanResult.deleteMany({ where });
      await p.messageUrl.deleteMany({ where });
      await p.attachmentScanResult.deleteMany({ where });
      await p.emailAuthResult.deleteMany({ where });
      await p.scanEngineResult.deleteMany({ where });
      await p.emailScan.deleteMany({ where });
      await p.emailDelivery.deleteMany({ where });
      await p.emailAttachment.deleteMany({ where });
      await p.emailHeader.deleteMany({ where });
      await p.emailMessageParse.deleteMany({ where });
      await p.emailRecipient.deleteMany({ where });
      await p.emailMessage.deleteMany({ where });
      await p.messageIdentity.deleteMany({ where });
      await p.tenantDepartmentMember.deleteMany({ where });
      await p.tenantDepartment.deleteMany({ where });
      await p.user.deleteMany({ where });
      await p.domain.deleteMany({ where });
      await p.organizationFeature.deleteMany({ where });
      await p.streamCursor.deleteMany({
        where: {
          OR: [
            { name: { endsWith: this.suffix } },
            ...ids.map((id) => ({ name: { endsWith: `:${id.toString()}` } })),
            ...ids.map((id) => ({ name: { contains: `:${id.toString()}:` } })),
          ],
        },
      });
      await p.organization.deleteMany({ where: { id: { in: ids } } });
      for (const id of ids) {
        await this.purgeBucketPrefix(this.mailBucket, `org/${id}/`);
        lockedObjects += (await this.purgeBucketPrefix(this.archiveBucket, `org/${id}/`)).left;
        lockedObjects += (await this.purgeBucketPrefix(this.replicaBucket, `org/${id}/`)).left;
      }
    }
    if (this.eventIds.size > 0) {
      const eventId = { in: [...this.eventIds] };
      await this.prisma.messageIdempotency.deleteMany({ where: { eventId } });
      await this.prisma.messageConsumerProgress.deleteMany({ where: { eventId } });
    }
    await this.search
      .request('DELETE', `/${this.prefix}-*`, { allowStatuses: [404] })
      .catch(() => undefined);
    for (let v = 1; v <= 3; v += 1) {
      await this.search
        .request('DELETE', `/_index_template/${indexTemplateName(this.prefix, v)}`, {
          allowStatuses: [404],
        })
        .catch(() => undefined);
    }
    await this.prisma.$disconnect();
    this.s3.destroy();
    return { lockedObjects };
  }
}
