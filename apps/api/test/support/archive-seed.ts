/**
 * Archive records built with the real `@email-gateway/archive` crypto and documents (step 8.1
 * §9.3): what the archive-worker would write for one captured message — the encrypted EML,
 * journal report and scan snapshot objects (`archive-object/1` under the record's DEK, wrapped
 * under a tenant key version wrapped under the root key) and the `email_archives` row values.
 * Shared by the stubbed e2e world (objects kept in memory) and the integration suites (objects
 * put into the archive bucket, rows inserted on the writer). Test-only.
 */
import { createHash, randomUUID } from 'node:crypto';
import {
  ARCHIVE_OBJECT_FORMAT,
  ARCHIVE_TENANT_KEY_ALGORITHM,
  type ArchiveJournal,
  type ArchiveRecordObjects,
  archiveObjectKey,
  buildScanSnapshot,
  encryptArchiveObject,
  generateDataKey,
  LocalRootKeyProvider,
  wrapRecordKey,
  wrapTenantKey,
} from '@email-gateway/archive';
import { uuidv7 } from '@email-gateway/common';

export interface SeedTenantKey {
  version: number;
  key: Buffer;
  wrappedKey: string;
  rootKeyId: string;
  algorithm: string;
}

/** A fresh tenant key version wrapped under the configured root key. */
export async function seedTenantKey(
  rootKey: { ARCHIVE_ROOT_KEY: string; ARCHIVE_ROOT_KEY_ID?: string | undefined },
  organizationId: bigint,
  version: number,
): Promise<SeedTenantKey> {
  const provider = LocalRootKeyProvider.fromConfig({
    ARCHIVE_ROOT_KEY: rootKey.ARCHIVE_ROOT_KEY,
    ARCHIVE_ROOT_KEY_ID: rootKey.ARCHIVE_ROOT_KEY_ID,
  });
  const key = generateDataKey();
  const wrappedKey = await wrapTenantKey(provider, { organizationId, version }, key);
  return {
    version,
    key,
    wrappedKey,
    rootKeyId: provider.currentKeyId,
    algorithm: ARCHIVE_TENANT_KEY_ALGORITHM,
  };
}

export interface SeedRecordInput {
  organizationId: bigint;
  messageId: bigint;
  messagePublicId?: string;
  receivedAt?: Date;
  direction?: 'inbound' | 'outbound' | 'internal';
  category?: 'delivered' | 'rejected' | 'quarantined' | 'failed';
  status?: 'active' | 'expiry_review' | 'disposing';
  envelopeFrom?: string;
  headerFrom?: string | null;
  subject?: string;
  recipients?: string[];
  eml?: Buffer;
  bodyText?: string | null;
  malicious?: boolean;
  verdict?: 'clean' | 'spam' | 'phishing' | 'malware' | null;
  retainUntil?: Date;
  retentionPolicyId?: bigint | null;
  expiryAction?: 'delete' | 'review';
  lockMode?: 'none' | 'governance' | 'compliance';
  attachments?: Array<{ partIndex: number; fileName: string; sha256: string; sizeBytes: number }>;
  urlSha256?: string;
  /** Step 8.6: copy sources of the record (default: a gateway capture). */
  sourceGateway?: boolean;
  sourceJournalIntake?: boolean;
  intakeSourceId?: bigint | null;
  /** Step 8.6 D6: the intake block of the journal object (a journal intake capture). */
  intake?: ArchiveJournal['intake'];
  /** Step 8.6 D7: merged copies (`eml` null: same body, no content variant). */
  mergedCopies?: Array<{
    messagePublicId: string;
    receivedAt: Date;
    source: 'gateway' | 'journal_intake';
    eml: Buffer | null;
  }>;
}

/** The `email_archives` values of a seeded record (create input). */
export interface SeedRecordRow {
  receivedAt: Date;
  messageId: bigint;
  organizationId: bigint;
  messagePublicId: string;
  direction: 'inbound' | 'outbound' | 'internal';
  capturedByJournal: boolean;
  capturedByPolicy: boolean;
  policyRuleRef: string | null;
  category: 'delivered' | 'rejected' | 'quarantined' | 'failed';
  status: 'active' | 'expiry_review' | 'disposing';
  messageState: 'delivered' | 'quarantined' | 'rejected';
  messageStateReason: string | null;
  envelopeFrom: string;
  headerFrom: string | null;
  subject: string | null;
  internetMessageId: string | null;
  parties: Record<string, unknown>;
  recipientCount: number;
  attachmentCount: number;
  archiveObjectKey: string;
  sha256: string;
  sizeBytes: number;
  objects: ArchiveRecordObjects;
  storedBytes: bigint;
  encryptionFormat: string;
  keyVersion: number;
  wrappedDek: string | null;
  lockMode: 'none' | 'governance' | 'compliance';
  lockUntil: Date | null;
  retentionPolicyId: bigint | null;
  retainUntil: Date;
  expiryAction: 'delete' | 'review';
  legalHold: boolean;
  finalVerdict: 'clean' | 'spam' | 'phishing' | 'malware' | null;
  finalAction: 'deliver' | 'quarantine' | null;
  riskScore: number | null;
  malicious: boolean;
  scanRounds: Array<{ round: number; revision: number; frozenAt: string }>;
  settingsGeneration: bigint;
  archivedAt: Date;
  deletedAt: Date | null;
  sourceGateway: boolean;
  sourceJournalIntake: boolean;
  intakeSourceId: bigint | null;
  mergedCount: number;
}

export interface SeededRecord {
  row: SeedRecordRow;
  /** Encrypted objects by key (all under `org/<org>/archive/`). */
  objects: Map<string, Buffer>;
  eml: Buffer;
  journal: ArchiveJournal;
  /** Step 8.6: the merged copies as `archive_record_sources` describes them. */
  merged: Array<{
    messagePublicId: string;
    receivedAt: Date;
    source: 'gateway' | 'journal_intake';
    emlSha256: string;
    sizeBytes: number;
    contentVariant: boolean;
  }>;
}

const DAY_MS = 86_400_000;

/** One captured message as the archive-worker writes it (objects + row values). */
export function seedRecord(tenantKey: SeedTenantKey, input: SeedRecordInput): SeededRecord {
  const org = input.organizationId;
  const messagePublicId = input.messagePublicId ?? uuidv7();
  const receivedAt = input.receivedAt ?? new Date(Date.now() - 3_600_000);
  const captureId = randomUUID();
  const capturedAt = new Date(receivedAt.getTime() + 60_000);
  const direction = input.direction ?? 'inbound';
  const recipients = input.recipients ?? ['alice.recipient@corp.example'];
  const envelopeFrom = input.envelopeFrom ?? 'sender@external.example';
  const subject = input.subject ?? 'Quarterly report';
  const eml =
    input.eml ??
    Buffer.from(
      `From: ${envelopeFrom}\r\nTo: ${recipients.join(', ')}\r\nSubject: ${subject}\r\n` +
        `Message-ID: <${messagePublicId}@external.example>\r\n\r\n` +
        `${input.bodyText ?? 'Hello, the report is attached.'}\r\n`,
      'utf8',
    );
  const emlSha256 = createHash('sha256').update(eml).digest('hex');
  const dek = generateDataKey();
  const wrappedDek = wrapRecordKey(
    tenantKey.key,
    { organizationId: org, messagePublicId, captureId, keyVersion: tenantKey.version },
    dek,
  );
  const ctx = (kind: 'eml' | 'journal' | 'scan') => ({
    dek,
    kind,
    organizationId: org,
    subjectId: messagePublicId,
  });
  const attachments = input.attachments ?? [];
  const journal: ArchiveJournal = {
    version: 'archive-journal/1',
    organizationId: org.toString(),
    messageId: messagePublicId,
    receivedAt: receivedAt.toISOString(),
    capturedAt: capturedAt.toISOString(),
    captureId,
    direction,
    category: input.category ?? 'delivered',
    sources: { journal: true, policy: false, policyRuleRef: null },
    settingsGeneration: 1,
    message: {
      internetMessageId: `<${messagePublicId}@external.example>`,
      envelopeFrom,
      headerFrom: input.headerFrom === undefined ? `Sender <${envelopeFrom}>` : input.headerFrom,
      subject,
      sizeBytes: eml.length,
      emlSha256,
      clientIp: '192.0.2.10',
      clientHelo: 'mail.external.example',
      clientName: null,
    },
    envelope: {
      recipients: recipients.map((address, seq) => ({
        seq,
        address,
        direction,
        status: 'delivered',
      })),
    },
    headers: [
      { name: 'From', value: `Sender <${envelopeFrom}>` },
      { name: 'To', value: recipients.join(', ') },
      { name: 'Subject', value: subject },
      { name: 'Message-ID', value: `<${messagePublicId}@external.example>` },
    ],
    parse: { status: 'parsed', codes: [] },
    body: {
      text:
        input.bodyText === null
          ? null
          : (input.bodyText ?? 'Hello, the report is attached. See https://phish.example/login'),
      html: null,
      truncated: false,
      unavailableReason: null,
    },
    attachments: attachments.map((a) => ({
      partIndex: a.partIndex,
      fileName: a.fileName,
      contentType: 'application/pdf',
      detectedType: 'application/pdf',
      sizeBytes: a.sizeBytes,
      sha256: a.sha256,
    })),
    deliveries: recipients.map((_, seq) => ({
      seq,
      status: 'delivered',
      finalAt: capturedAt.toISOString(),
    })),
    ...(input.intake !== undefined && { intake: input.intake }),
  };
  const now = capturedAt;
  const snapshot = buildScanSnapshot({
    organizationId: org.toString(),
    messageId: messagePublicId,
    round: 1,
    revision: 1,
    frozenAt: now,
    rows: {
      scan: {
        id: 9001n,
        lifecycleRound: 1,
        scanKind: 'initial',
        status: 'completed',
        scanVerdict: input.verdict ?? 'clean',
        reasonCodes: [],
        requiredEngines: ['rspamd'],
        startedAt: receivedAt,
        completedAt: now,
        deadlineAt: null,
      },
      engines: [
        {
          scanId: 9001n,
          engine: 'rspamd',
          engineVersion: '3.10',
          outcome: 'clean',
          // Frozen as decimal strings, as the archive-worker writes them (WP3 D2).
          score: '1.500',
          requiredScore: '15.000',
          action: 'no action',
          reasonCodes: [],
          errorCode: null,
          settingsVersion: null,
          durationMs: 12,
          evidence: null,
          attempt: 1,
          isFinal: true,
          completedAt: now,
        },
      ],
      auth: [],
      attachments: attachments.map((a) => ({
        scanId: 9001n,
        attachmentId: BigInt(a.partIndex + 1),
        partIndex: a.partIndex,
        sha256: a.sha256,
        sizeBytes: a.sizeBytes,
        detectedType: 'application/pdf',
        typeFamily: 'document',
        typeMismatch: false,
        verdict: input.malicious ? 'malicious' : 'clean',
        reasonCodes: [],
        clamavSignature: null,
        clamavEngineVersion: null,
        clamavDbVersion: null,
        yaraBundleId: null,
        yaraMatches: null,
        archive: null,
        knownHashSeverity: null,
      })),
      attachmentParts: [],
      sandboxSubmissions: [],
      sandboxAnalyses: [],
      sandboxArtifacts: [],
      urls: [],
      urlResults: input.urlSha256
        ? [
            {
              scanId: 9001n,
              urlSeq: 0,
              urlSha256: input.urlSha256,
              verdict: 'malicious',
              reasonCodes: [],
              reputation: null,
              lookalike: null,
              fetchStatus: null,
              fetchError: null,
              hopCount: 0,
              redirectChain: null,
              finalUrl: null,
              finalStatus: null,
              landing: null,
              rewritten: false,
            },
          ]
        : [],
      urlRewrites: [],
      urlInspections: [],
      bec: [],
      dlp: [],
      risk: [],
      policy: null,
    },
  });
  const emlObject = encryptArchiveObject(eml, ctx('eml'));
  const journalObject = encryptArchiveObject(
    Buffer.from(JSON.stringify(journal), 'utf8'),
    ctx('journal'),
  );
  const scanObject = encryptArchiveObject(snapshot.bytes, ctx('scan'));
  const keyOf = (kind: 'eml' | 'journal' | 'scan') =>
    archiveObjectKey({
      organizationId: org,
      receivedAt,
      messagePublicId,
      captureId,
      kind,
      ...(kind === 'scan' && { round: 1, revision: 1 }),
    });
  const ref = (kind: 'eml' | 'journal' | 'scan', object: Buffer, sha: string) => ({
    key: keyOf(kind),
    versionId: null,
    sha256: sha,
    bytes: object.length,
  });
  const objects: ArchiveRecordObjects = {
    captureId,
    eml: ref('eml', emlObject.object, emlObject.summary.ciphertextSha256),
    journal: ref('journal', journalObject.object, journalObject.summary.ciphertextSha256),
    scans: [
      {
        ...ref('scan', scanObject.object, scanObject.summary.ciphertextSha256),
        round: 1,
        revision: 1,
      },
    ],
  };
  // Step 8.6 D7: merged copies under the record's DEK, subject = the copy's public id.
  const mergedOut: SeededRecord['merged'] = [];
  const mergedObjects = new Map<string, Buffer>();
  if (input.mergedCopies !== undefined && input.mergedCopies.length > 0) {
    objects.merged = input.mergedCopies.map((m) => {
      const sub = (kind: 'eml' | 'journal') => ({
        dek,
        kind,
        organizationId: org,
        subjectId: m.messagePublicId,
      });
      const copyKey = (kind: 'eml' | 'journal') =>
        archiveObjectKey({
          organizationId: org,
          receivedAt,
          messagePublicId: m.messagePublicId,
          captureId,
          kind,
        });
      const copyJournal = encryptArchiveObject(
        Buffer.from(JSON.stringify({ mergedFrom: messagePublicId }), 'utf8'),
        sub('journal'),
      );
      mergedObjects.set(copyKey('journal'), copyJournal.object);
      const copyEml = m.eml === null ? null : encryptArchiveObject(m.eml, sub('eml'));
      if (copyEml !== null) mergedObjects.set(copyKey('eml'), copyEml.object);
      const body = m.eml ?? eml;
      mergedOut.push({
        messagePublicId: m.messagePublicId,
        receivedAt: m.receivedAt,
        source: m.source,
        emlSha256: createHash('sha256').update(body).digest('hex'),
        sizeBytes: body.length,
        contentVariant: m.eml !== null,
      });
      return {
        messageId: m.messagePublicId,
        receivedAt: m.receivedAt.toISOString(),
        source: m.source,
        journal: {
          key: copyKey('journal'),
          versionId: null,
          sha256: copyJournal.summary.ciphertextSha256,
          bytes: copyJournal.object.length,
        },
        eml:
          copyEml === null
            ? null
            : {
                key: copyKey('eml'),
                versionId: null,
                sha256: copyEml.summary.ciphertextSha256,
                bytes: copyEml.object.length,
              },
      };
    });
  }
  dek.fill(0);
  const row: SeedRecordRow = {
    receivedAt,
    messageId: input.messageId,
    organizationId: org,
    messagePublicId,
    direction,
    capturedByJournal: true,
    capturedByPolicy: false,
    policyRuleRef: null,
    category: input.category ?? 'delivered',
    status: input.status ?? 'active',
    messageState: 'delivered',
    messageStateReason: 'delivery_complete',
    envelopeFrom,
    headerFrom: input.headerFrom === undefined ? envelopeFrom : input.headerFrom,
    subject,
    internetMessageId: `<${messagePublicId}@external.example>`,
    parties: {
      v: 1,
      from: envelopeFrom,
      headerFrom: input.headerFrom === undefined ? `Sender <${envelopeFrom}>` : input.headerFrom,
      recipients: recipients.map((address, seq) => ({
        seq,
        address,
        direction,
        status: 'delivered',
        finalAction: 'deliver',
      })),
    },
    recipientCount: recipients.length,
    attachmentCount: attachments.length,
    archiveObjectKey: keyOf('eml'),
    sha256: emlSha256,
    sizeBytes: eml.length,
    objects,
    storedBytes: BigInt(
      emlObject.object.length + journalObject.object.length + scanObject.object.length,
    ),
    encryptionFormat: ARCHIVE_OBJECT_FORMAT,
    keyVersion: tenantKey.version,
    wrappedDek,
    lockMode: input.lockMode ?? 'none',
    lockUntil: null,
    retentionPolicyId: input.retentionPolicyId ?? null,
    retainUntil: input.retainUntil ?? new Date(receivedAt.getTime() + 365 * DAY_MS),
    expiryAction: input.expiryAction ?? 'delete',
    legalHold: false,
    finalVerdict: input.verdict === undefined ? 'clean' : input.verdict,
    finalAction: 'deliver',
    riskScore: input.malicious ? 95 : 10,
    malicious: input.malicious ?? false,
    scanRounds: [{ round: 1, revision: 1, frozenAt: now.toISOString() }],
    settingsGeneration: 1n,
    archivedAt: capturedAt,
    deletedAt: null,
    sourceGateway: input.sourceGateway ?? true,
    sourceJournalIntake: input.sourceJournalIntake ?? false,
    intakeSourceId: input.intakeSourceId ?? null,
    mergedCount: mergedOut.length,
  };
  return {
    row,
    objects: new Map([
      [objects.eml.key, emlObject.object],
      [objects.journal.key, journalObject.object],
      [objects.scans[0]!.key, scanObject.object],
      ...mergedObjects,
    ]),
    eml,
    journal,
    merged: mergedOut,
  };
}

/** The OpenSearch `_source` of a seeded record (the fields the api reads). */
export function searchSourceOf(row: SeedRecordRow): Record<string, unknown> {
  const parties = row.parties as { recipients: Array<{ address: string }> };
  return {
    org_id: row.organizationId.toString(),
    message_id: row.messagePublicId,
    received_at: row.receivedAt.toISOString(),
    captured_at: row.archivedAt.toISOString(),
    direction: row.direction,
    category: row.category,
    sources: ['journal'],
    status: row.status,
    envelope_from: row.envelopeFrom.toLowerCase(),
    header_from: row.headerFrom?.toLowerCase() ?? null,
    recipients: parties.recipients.map((r) => r.address.toLowerCase()),
    subject: row.subject,
    size_bytes: row.sizeBytes,
    attachment_count: row.attachmentCount,
    attachment_names: [],
    verdict: row.finalVerdict,
    final_action: row.finalAction,
    risk_score: row.riskScore,
    malicious: row.malicious,
    retain_until: row.retainUntil.toISOString(),
    legal_hold: row.legalHold,
    lock_mode: row.lockMode,
    ingest_sources: [
      ...(row.sourceGateway ? ['gateway'] : []),
      ...(row.sourceJournalIntake ? ['journal_intake'] : []),
    ],
  };
}
