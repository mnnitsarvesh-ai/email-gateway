/**
 * Step 8.1 additions of the portal end-to-end seed (docs/plan/steps/23-journaling-archiving.md
 * §9.5): archive tenants and messages the **real archive-worker** captures.
 *
 * - `prepareArchive` (seed time): alpha gets a default retention policy (through the api, as the
 *   alpha administrator) and archive settings **disabled** with a journal scope of the e2e
 *   custodian mailbox (through the api, as the MFA approver: `PUT /archive/settings` is an MFA
 *   route) — the archive spec enables archiving through the Settings page. Beta gets the same
 *   written on the writer (its administrator has no MFA) but **enabled**, plus one message after
 *   the enable instant, so beta has a captured record for the isolation checks.
 * - `insertArchiveMessages` writes messages exactly like the archive-worker's integration
 *   fixtures (apps/archive-worker/integration/support/fixtures.ts): registry row, message,
 *   recipients, the original EML and the decoded parts in the mail bucket, parse, headers, an
 *   attachment and one completed scan round (engine, authentication, attachment and risk rows).
 *   Received after the enable instant and inside the journal scope, they are captured by the
 *   worker's journal sweep, encrypted into the archive bucket and indexed into OpenSearch.
 * - `cleanupArchive` removes every archive and eDiscovery row of the e2e organizations, every
 *   object version under their prefix in the archive bucket, their documents in the shared
 *   OpenSearch indices and their tenant alias, and their worker cursors.
 *
 * Reserved `.test` domains and `EXAMPLE`-free synthetic text only; no real content.
 */
import { createHash, randomUUID } from 'node:crypto';
import {
  DeleteObjectCommand,
  ListObjectVersionsCommand,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { tenantAliasName } from '@email-gateway/archive';
import type { MessageDirection, PrismaClient } from '@email-gateway/database';
import { optionalEnv, requireEnv } from '../support/env';
import type { ApiSession } from './api';
import type { MessagePlan } from './plan';

const sha256 = (data: string | Buffer) => createHash('sha256').update(data).digest('hex');
const pad = (n: number) => String(n).padStart(2, '0');
const dayPath = (d: Date) =>
  `${d.getUTCFullYear()}/${pad(d.getUTCMonth() + 1)}/${pad(d.getUTCDate())}`;

/** The alpha mailbox the journal scope includes (every e2e archive message involves it). */
export const ARCHIVE_CUSTODIAN = 'archive-custodian@alpha.e2e-portal.test';
export const ARCHIVE_POLICY_NAME = 'E2E default seven years';
/** Subjects of the alpha archive messages (masked in every list; revealed in the spec). */
export const ARCHIVE_SUBJECTS = {
  invoice: 'E2E archive invoice 9031',
  outbound: 'E2E archive outbound proposal',
  phish: 'E2E archive suspicious login',
  beta: 'BETA-ONLY archive message',
} as const;
/** A marker inside the body of the invoice message (the sanitized preview shows it). */
export const ARCHIVE_BODY_MARKER = 'E2E-ARCHIVE-BODY-MARKER payment schedule';
export const ARCHIVE_SENDER = 'billing@vendor.e2e-portal.test';

export interface ArchiveMessagePlan {
  key: keyof typeof ARCHIVE_SUBJECTS;
  direction: MessageDirection;
  from: string;
  to: string[];
  verdict: 'clean' | 'phishing';
}

export function alphaArchivePlans(): ArchiveMessagePlan[] {
  return [
    {
      key: 'invoice',
      direction: 'inbound',
      from: ARCHIVE_SENDER,
      to: [ARCHIVE_CUSTODIAN],
      verdict: 'clean',
    },
    {
      key: 'outbound',
      direction: 'outbound',
      from: ARCHIVE_CUSTODIAN,
      to: ['partner@external.e2e-portal.test'],
      verdict: 'clean',
    },
    {
      key: 'phish',
      direction: 'inbound',
      from: 'alerts@login-check.e2e-portal.test',
      to: [ARCHIVE_CUSTODIAN],
      verdict: 'phishing',
    },
  ];
}

export function betaArchivePlans(): ArchiveMessagePlan[] {
  return [
    {
      key: 'beta',
      direction: 'inbound',
      from: ARCHIVE_SENDER,
      to: ['user0@beta.e2e-portal.test'],
      verdict: 'clean',
    },
  ];
}

function s3(): S3Client {
  return new S3Client({
    region: optionalEnv('S3_REGION', 'us-east-1'),
    endpoint: requireEnv('S3_ENDPOINT'),
    forcePathStyle: optionalEnv('S3_FORCE_PATH_STYLE', 'true') === 'true',
    credentials: {
      accessKeyId: requireEnv('S3_ACCESS_KEY_ID'),
      secretAccessKey: requireEnv('S3_SECRET_ACCESS_KEY'),
    },
  });
}

function syntheticEml(plan: ArchiveMessagePlan, messageId: string): Buffer {
  const subject = ARCHIVE_SUBJECTS[plan.key];
  const body =
    plan.key === 'invoice'
      ? `${ARCHIVE_BODY_MARKER}\r\nSynthetic e2e archive message; no real content.\r\n`
      : 'Synthetic e2e archive message; no real content.\r\n';
  return Buffer.from(
    [
      `From: Sender <${plan.from}>`,
      `To: ${plan.to.join(', ')}`,
      `Subject: ${subject}`,
      `Message-ID: <${messageId}>`,
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="e2e"',
      '',
      '--e2e',
      'Content-Type: text/plain; charset=utf-8',
      '',
      body,
      '--e2e',
      'Content-Type: application/octet-stream; name="statement.bin"',
      'Content-Disposition: attachment; filename="statement.bin"',
      'Content-Transfer-Encoding: base64',
      '',
      Buffer.from('synthetic e2e attachment').toString('base64'),
      '--e2e--',
      '',
    ].join('\r\n'),
    'utf8',
  );
}

export interface InsertedArchiveMessage {
  key: ArchiveMessagePlan['key'];
  id: bigint;
  publicId: string;
  receivedAt: Date;
  internetMessageId: string;
}

/** Messages the archive-worker captures (the worker's integration fixture, A2–A5). */
export async function insertArchiveMessages(
  p: PrismaClient,
  organizationId: bigint,
  plans: readonly ArchiveMessagePlan[],
): Promise<InsertedArchiveMessage[]> {
  const client = s3();
  const bucket = requireEnv('S3_BUCKET_MAIL');
  const out: InsertedArchiveMessage[] = [];
  try {
    for (const [index, plan] of plans.entries()) {
      // Strictly after the journal enable instant (millisecond precision, DATETIME(3)).
      const receivedAt = new Date(Date.now() + 5 + index);
      const createdAt = new Date(receivedAt.getTime() + 500);
      const internetMessageId = `e2e-archive-${randomUUID()}@vendor.e2e-portal.test`;
      const eml = syntheticEml(plan, internetMessageId);
      const identity = await p.messageIdentity.create({
        data: { organizationId, ingestKey: `e2e-archive-${randomUUID()}`, receivedAt },
        select: { id: true, publicId: true },
      });
      const day = dayPath(receivedAt);
      const emlKey = `org/${organizationId}/eml/${day}/${identity.id}.eml`;
      await client.send(
        new PutObjectCommand({
          Bucket: bucket,
          Key: emlKey,
          Body: eml,
          ContentType: 'message/rfc822',
        }),
      );
      const malicious = plan.verdict === 'phishing';
      await p.emailMessage.create({
        data: {
          id: identity.id,
          receivedAt,
          organizationId,
          direction: plan.direction,
          status: 'delivered',
          statusReason: 'delivery_complete',
          statusChangedAt: createdAt,
          lifecycleRound: 0,
          internetMessageId: `<${internetMessageId}>`,
          envelopeFrom: plan.from,
          headerFrom: plan.from,
          subject: ARCHIVE_SUBJECTS[plan.key],
          sizeBytes: eml.length,
          recipientCount: plan.to.length,
          attachmentCount: 1,
          emlObjectKey: emlKey,
          emlSha256: sha256(eml),
          clientIp: '198.51.100.7',
          clientHelo: 'mx.vendor.e2e-portal.test',
          finalVerdict: plan.verdict,
          finalAction: 'deliver',
          riskScore: malicious ? 880 : 110,
          createdAt,
        },
      });
      for (const [seq, address] of plan.to.entries()) {
        await p.emailRecipient.create({
          data: {
            receivedAt,
            messageId: identity.id,
            organizationId,
            rcptSeq: seq,
            address,
            direction: plan.direction,
            status: 'delivered',
            finalAction: 'deliver',
          },
        });
      }
      const base = { receivedAt, messageId: identity.id, organizationId };
      const textKey = `org/${organizationId}/part/${day}/${identity.id}/1.text`;
      const text =
        plan.key === 'invoice'
          ? `${ARCHIVE_BODY_MARKER}\nSynthetic e2e archive message; no real content.`
          : 'Synthetic e2e archive message; no real content.';
      await client.send(
        new PutObjectCommand({
          Bucket: bucket,
          Key: textKey,
          Body: text,
          ContentType: 'text/plain',
        }),
      );
      await p.emailMessageParse.create({
        data: {
          ...base,
          status: 'parsed',
          attempts: 1,
          parserVersion: 'e2e/1',
          partCount: 2,
          attachmentCount: 1,
          textBodyObjectKey: textKey,
          startedAt: createdAt,
          completedAt: createdAt,
        },
      });
      await p.emailHeader.createMany({
        data: [
          { ...base, seq: 0, name: 'From', value: `Sender <${plan.from}>` },
          { ...base, seq: 1, name: 'To', value: plan.to.join(', ') },
          { ...base, seq: 2, name: 'Subject', value: ARCHIVE_SUBJECTS[plan.key] },
          { ...base, seq: 3, name: 'Message-ID', value: `<${internetMessageId}>` },
        ],
      });
      const attachmentSha = sha256(`e2e-archive-att-${identity.id}`);
      const attachment = await p.emailAttachment.create({
        data: {
          ...base,
          partIndex: 2,
          filename: 'statement.bin',
          declaredContentType: 'application/octet-stream',
          detectedContentType: 'application/octet-stream',
          sizeBytes: 24,
          sha256: attachmentSha,
        },
        select: { id: true },
      });
      const scan = await p.emailScan.create({
        data: {
          ...base,
          scanKind: 'initial',
          status: 'completed',
          lifecycleRound: 0,
          scanVerdict: malicious ? 'malicious' : 'clean',
          requiredEngines: ['rspamd'],
          reasonCodes: [],
          startedAt: createdAt,
          completedAt: createdAt,
          deadlineAt: new Date(createdAt.getTime() + 1_800_000),
        },
        select: { id: true },
      });
      await p.scanEngineResult.create({
        data: {
          ...base,
          scanId: scan.id,
          engine: 'rspamd',
          engineVersion: '3.12',
          outcome: malicious ? 'malicious' : 'clean',
          score: malicious ? 14.5 : 1.5,
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
      await p.emailAuthResult.create({
        data: {
          ...base,
          scanId: scan.id,
          engine: 'rspamd',
          spf: 'pass',
          dkim: 'pass',
          dmarc: 'pass',
        },
      });
      await p.attachmentScanResult.create({
        data: {
          ...base,
          scanId: scan.id,
          attachmentId: attachment.id,
          partIndex: 2,
          sha256: attachmentSha,
          sizeBytes: 24,
          detectedType: 'bin',
          typeFamily: 'binary',
          typeMismatch: false,
          verdict: 'clean',
          reasonCodes: [],
          cacheResult: 'miss',
          durationMs: 10,
        },
      });
      await p.messageRiskScore.create({
        data: {
          ...base,
          scanId: scan.id,
          lifecycleRound: 0,
          revision: 0,
          direction: plan.direction,
          status: 'scored',
          score: malicious ? 880 : 110,
          level: malicious ? 'critical' : 'low',
          verdict: malicious ? 'phishing' : 'clean',
          recommendedAction: malicious ? 'quarantine' : 'deliver',
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
          explanationText: 'synthetic e2e risk',
          profileSource: 'platform',
          profileIdText: 'rsk-default/1',
          profileSha256: 'c'.repeat(64),
          inputSha256: 'd'.repeat(64),
          scorerVersion: 'e2e/1',
          signalMapVersion: 'e2e/1',
          inputVersion: 'e2e/1',
          durationUs: 100,
        },
      });
      out.push({
        key: plan.key,
        id: identity.id,
        publicId: identity.publicId,
        receivedAt,
        internetMessageId,
      });
    }
  } finally {
    client.destroy();
  }
  return out;
}

/** The journal scope and access settings of the e2e tenants (`archive-settings/1`). */
export function archiveSettingsDocument(addresses: string[]) {
  return {
    directions: { inbound: true, outbound: true, internal: true },
    include: { rejected: false, quarantined: false, failed: false },
    scope: { mode: 'include' as const, domainIds: [], departmentIds: [], userIds: [], addresses },
    policyArchive: { enabled: true },
    access: { previewEnabled: true, downloadEnabled: true },
  };
}

/**
 * Alpha: retention policy and disabled settings with the custodian scope (api, MFA approver: an
 * organization admin with the migrated compliance_officer grant since step 8.6, because retention
 * needs `archive:manage`, which new organization admins no longer hold). Beta: the same rows on
 * the writer, enabled, plus one captured-to-be message.
 */
export async function prepareArchive(
  p: PrismaClient,
  input: {
    alphaApprover: ApiSession;
    betaOrg: bigint;
  },
): Promise<{ alphaPolicyId: string; betaMessages: InsertedArchiveMessage[] }> {
  const policy = await input.alphaApprover.call<{ id: string }>(
    'POST',
    '/archive/retention-policies',
    { name: ARCHIVE_POLICY_NAME, retentionDays: 2555, onExpiry: 'delete', priority: 1000 },
    { idempotent: true, expect: 201 },
  );
  const current = await input.alphaApprover.call<{ rowVersion: number }>(
    'GET',
    '/archive/settings',
    undefined,
    {
      expect: 200,
    },
  );
  await input.alphaApprover.call(
    'PUT',
    '/archive/settings',
    {
      expectedRowVersion: current.body.rowVersion,
      enabled: false,
      immutability: 'none',
      defaultRetentionPolicyId: policy.body.id,
      settings: archiveSettingsDocument([ARCHIVE_CUSTODIAN]),
    },
    { idempotent: true, expect: 200 },
  );
  const betaPolicy = await p.archiveRetentionPolicy.create({
    data: {
      organizationId: input.betaOrg,
      name: ARCHIVE_POLICY_NAME,
      retentionDays: 2555,
      priority: 1000,
    },
    select: { id: true },
  });
  const enabledAt = new Date(Date.now() - 1_000);
  await p.archiveSetting.create({
    data: {
      organizationId: input.betaOrg,
      enabled: true,
      settings: archiveSettingsDocument(['user0@beta.e2e-portal.test']),
      generation: 1n,
      journalEnabledAt: enabledAt,
      objectLockMode: 'none',
      defaultRetentionPolicyId: betaPolicy.id,
    },
  });
  const betaMessages = await insertArchiveMessages(p, input.betaOrg, betaArchivePlans());
  return { alphaPolicyId: policy.body.id, betaMessages };
}

async function purgeVersions(client: S3Client, bucket: string, prefix: string): Promise<number> {
  let deleted = 0;
  let keyMarker: string | undefined;
  let versionMarker: string | undefined;
  do {
    const page = await client.send(
      new ListObjectVersionsCommand({
        Bucket: bucket,
        Prefix: prefix,
        KeyMarker: keyMarker,
        VersionIdMarker: versionMarker,
      }),
    );
    for (const v of [...(page.Versions ?? []), ...(page.DeleteMarkers ?? [])]) {
      await client.send(
        new DeleteObjectCommand({
          Bucket: bucket,
          Key: v.Key,
          VersionId: v.VersionId,
          BypassGovernanceRetention: true,
        }),
      );
      deleted += 1;
    }
    keyMarker = page.IsTruncated ? page.NextKeyMarker : undefined;
    versionMarker = page.IsTruncated ? page.NextVersionIdMarker : undefined;
  } while (keyMarker !== undefined);
  return deleted;
}

/** Archive and eDiscovery tables in a RESTRICT-safe delete order (WP3/WP4 cleanup order). */
export const ARCHIVE_TABLES = [
  'ediscovery_search_hits',
  'archive_download_grants',
  'ediscovery_exports',
  'ediscovery_searches',
  'archive_legal_holds',
  'ediscovery_custodians',
  'ediscovery_cases',
  'archive_index_queue',
  'archive_index_checks',
  'archive_disposals',
  // Step 8.6: cross-source dedupe rows and merged copies (deleted with their records).
  'archive_record_sources',
  'archive_dedupe_keys',
  'email_archives',
  'archive_capture_intents',
  'archive_settings',
  'archive_retention_policies',
  'archive_encryption_keys',
] as const;

/**
 * Archive objects, index documents, the tenant alias and the worker cursors of the e2e
 * organizations (rows are deleted by the main cleanup with `ARCHIVE_TABLES`).
 */
export async function cleanupArchiveStores(
  p: PrismaClient,
  orgIds: readonly bigint[],
): Promise<number> {
  if (orgIds.length === 0) return 0;
  let objects = 0;
  const client = s3();
  try {
    const archive = requireEnv('S3_BUCKET_ARCHIVE');
    for (const id of orgIds) objects += await purgeVersions(client, archive, `org/${id}/`);
    const replica = optionalEnv('ARCHIVE_TEST_REPLICA_BUCKET', '');
    if (replica) {
      for (const id of orgIds) {
        objects += await purgeVersions(client, replica, `org/${id}/`).catch(() => 0);
      }
    }
  } finally {
    client.destroy();
  }
  const url = optionalEnv('ARCHIVE_SEARCH_URL', '');
  if (url) {
    const prefix = optionalEnv('ARCHIVE_SEARCH_INDEX_PREFIX', 'eg-archive');
    for (const id of orgIds) {
      const alias = tenantAliasName(prefix, id.toString());
      // Documents first (through the filtered alias: only this tenant's), then the alias itself.
      await fetch(`${url}/${alias}/_delete_by_query?refresh=true&conflicts=proceed`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ query: { match_all: {} } }),
      }).catch(() => undefined);
      await fetch(`${url}/_all/_alias/${alias}`, { method: 'DELETE' }).catch(() => undefined);
    }
  }
  await p.streamCursor.deleteMany({
    where: {
      OR: orgIds.flatMap((id) => [
        { name: { endsWith: `:${id.toString()}` } },
        { name: { contains: `:${id.toString()}:` } },
      ]),
    },
  });
  return objects;
}

/** Captured records of the given messages (writer). */
export async function capturedCount(
  p: PrismaClient,
  messageIds: readonly bigint[],
): Promise<number> {
  return p.emailArchive.count({ where: { messageId: { in: [...messageIds] } } });
}

/**
 * The alpha archive messages as dashboard plans (`seed/plan.ts` `expectDashboard`): they are
 * inserted during the run (archive spec) at "now", inside the dashboard's default 7-day range,
 * delivered without delivery rows, no tenant domain (unattributed), scanned 500 ms after receipt.
 */
export function alphaArchiveDashboardPlans(now: number): MessagePlan[] {
  return alphaArchivePlans().map((plan) => ({
    key: `alpha-archive-${plan.key}`,
    receivedAt: new Date(now),
    direction: plan.direction,
    verdict: plan.verdict,
    action: 'deliver',
    domain: null,
    riskScore: plan.verdict === 'phishing' ? 880 : 110,
    recipient: plan.to[0]!,
    envelopeFrom: plan.from,
    subject: ARCHIVE_SUBJECTS[plan.key],
    deliveries: [],
    scan: { status: 'completed', completedAfterMs: 500 },
    quarantine: null,
  }));
}
