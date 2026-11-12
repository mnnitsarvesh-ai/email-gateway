/**
 * Test hygiene for the SmtpEmailSender probe of `common.test.ts` (step 3.3 L16): the probe mail
 * goes through the real mail plane (Postfix → smtp-adapter → delivery-worker → postfix-outbound)
 * and used to stay deferred in postfix-outbound with its S3 objects. `cleanupProbeMessages`
 * finds the message(s) of this run by their unique Message-ID and removes their outbound queue
 * files, their S3 objects (EML, parts, rewritten copies, policy copies, DLP evidence) and their
 * rows, including the policy evaluations (the run
 * marker proves the test owns them).
 */
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import type { PrismaService } from '@email-gateway/common';
import { s3ConfigSchema } from '@email-gateway/config';

/** Repository root: `docker compose` reads docker-compose.yml and .env from here. */
const REPO_ROOT = resolve(__dirname, '../../../..');
const QUEUE_ID = /^[A-Za-z0-9]{6,32}$/;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export interface ProbeMessage {
  id: bigint;
  receivedAt: Date;
  organizationId: bigint;
  emlObjectKey: string;
}

export interface ProbeCleanupResult {
  messages: number;
  queueFiles: number;
  objects: number;
}

/** `docker compose exec -T <service> <args…>` with an argument array (no shell). */
function composeExec(service: string, args: readonly string[]): Promise<number> {
  return new Promise((resolvePromise) => {
    execFile(
      'docker',
      ['compose', 'exec', '-T', service, ...args],
      { cwd: REPO_ROOT, timeout: 30_000, killSignal: 'SIGKILL' },
      (error) => resolvePromise(error ? (typeof error.code === 'number' ? error.code : 1) : 0),
    );
  });
}

/**
 * The S3 client commands come from `@aws-sdk/client-s3`, a dependency of `@email-gateway/common`
 * (not of the api package), resolved from there.
 */
interface S3Commands {
  S3Client: new (config: Record<string, unknown>) => {
    send(command: unknown): Promise<{
      Contents?: Array<{ Key?: string }>;
      IsTruncated?: boolean;
      NextContinuationToken?: string;
    }>;
    destroy(): void;
  };
  DeleteObjectCommand: new (input: { Bucket: string; Key: string }) => unknown;
  PutObjectCommand: new (input: { Bucket: string; Key: string; Body: string }) => unknown;
  ListObjectsV2Command: new (input: {
    Bucket: string;
    Prefix: string;
    ContinuationToken?: string;
  }) => unknown;
}

export function s3Commands(): S3Commands {
  const fromCommon = createRequire(require.resolve('@email-gateway/common'));
  return fromCommon('@aws-sdk/client-s3') as S3Commands;
}

/** An S3 client of the mail bucket from the local `.env` (MinIO). */
export function mailBucketClient(): { s3: InstanceType<S3Commands['S3Client']>; bucket: string } {
  const config = s3ConfigSchema.parse(process.env);
  const { S3Client } = s3Commands();
  return {
    bucket: config.S3_BUCKET_MAIL,
    s3: new S3Client({
      region: config.S3_REGION,
      endpoint: config.S3_ENDPOINT,
      forcePathStyle: config.S3_FORCE_PATH_STYLE,
      credentials:
        config.S3_ACCESS_KEY_ID && config.S3_SECRET_ACCESS_KEY
          ? { accessKeyId: config.S3_ACCESS_KEY_ID, secretAccessKey: config.S3_SECRET_ACCESS_KEY }
          : undefined,
    }),
  };
}

const pad = (n: number, width = 2) => String(n).padStart(width, '0');

/** `org/{organizationId}/part/{yyyy}/{mm}/{dd}/{messageId}/` (step 3.1 M11 part keys). */
export function partPrefix(
  message: ProbeMessage,
  kind: 'part' | 'rewrite' | 'policy' = 'part',
): string {
  const at = message.receivedAt;
  return (
    `org/${message.organizationId.toString()}/${kind}/${pad(at.getUTCFullYear(), 4)}/` +
    `${pad(at.getUTCMonth() + 1)}/${pad(at.getUTCDate())}/${message.id.toString()}/`
  );
}

/** The probe's messages: the relay domain's organization, created since the run started. */
export async function findProbeMessages(
  prisma: PrismaService,
  options: { relayDomain: string; since: Date; messageIds: readonly string[] },
): Promise<ProbeMessage[]> {
  const ids = options.messageIds.flatMap((id) => [id, id.replace(/^<|>$/g, '')]);
  if (ids.length === 0) return [];
  const domains = await prisma.domain.findMany({
    where: { name: options.relayDomain.toLowerCase() },
    select: { organizationId: true },
  });
  if (domains.length === 0) return [];
  return prisma.emailMessage.findMany({
    where: {
      organizationId: { in: [...new Set(domains.map((d) => d.organizationId))] },
      createdAt: { gte: options.since },
      internetMessageId: { in: [...new Set(ids)] },
    },
    select: { id: true, receivedAt: true, organizationId: true, emlObjectKey: true },
  });
}

/**
 * Waits up to `waitMs` for the probe's message(s) to appear and for their deliveries to reach
 * postfix-outbound (an outbound queue id) or a terminal status, then deletes: the outbound queue
 * files (`postsuper -d <queue id>`, one id at a time, unknown ids ignored; never `ALL`), the EML
 * and the part objects in the mail bucket, and the rows of the message graph.
 */
export async function cleanupProbeMessages(
  prisma: PrismaService,
  options: { relayDomain: string; since: Date; messageIds: readonly string[]; waitMs?: number },
): Promise<ProbeCleanupResult> {
  const deadline = Date.now() + (options.waitMs ?? 20_000);
  let messages = await findProbeMessages(prisma, options);
  while (messages.length === 0 && Date.now() < deadline) {
    await sleep(500);
    messages = await findProbeMessages(prisma, options);
  }
  if (messages.length === 0) return { messages: 0, queueFiles: 0, objects: 0 };

  const ids = messages.map((m) => m.id);
  const settled = async () => {
    const deliveries = await prisma.emailDelivery.findMany({
      where: { messageId: { in: ids } },
      select: { outboundQueueId: true, status: true },
    });
    return (
      deliveries.length > 0 &&
      deliveries.every(
        (d) =>
          d.outboundQueueId !== null ||
          ['delivered', 'bounced', 'expired', 'failed', 'suppressed'].includes(d.status),
      )
    );
  };
  while (!(await settled()) && Date.now() < deadline) await sleep(500);

  // 1. Queue files of postfix-outbound (deferred mail of the probe), by queue id only.
  const queueIds = [
    ...new Set(
      (
        await prisma.emailDelivery.findMany({
          where: { messageId: { in: ids }, outboundQueueId: { not: null } },
          select: { outboundQueueId: true },
        })
      ).flatMap((d) =>
        d.outboundQueueId && QUEUE_ID.test(d.outboundQueueId) ? [d.outboundQueueId] : [],
      ),
    ),
  ];
  let queueFiles = 0;
  for (const queueId of queueIds) {
    if ((await composeExec('postfix-outbound', ['postsuper', '-d', queueId])) === 0) {
      queueFiles += 1;
    }
  }

  // 2. S3 objects: the EML, every part object of the message and (step 4.5) the DLP evidence
  // objects of its rounds (their keys are recorded in dlp_evidence, under org/<org>/dlp-evidence/).
  const evidence = await prisma.dlpEvidence.findMany({
    where: { messageId: { in: ids } },
    select: { organizationId: true, objectKey: true },
  });
  const { DeleteObjectCommand, ListObjectsV2Command } = s3Commands();
  const { s3, bucket } = mailBucketClient();
  let objects = 0;
  try {
    for (const message of messages) {
      const keys = new Set<string>();
      if (message.emlObjectKey.startsWith(`org/${message.organizationId.toString()}/`)) {
        keys.add(message.emlObjectKey);
      }
      // Part objects (3.1), rewritten copies of the URL engine (4.3) and policy copies of the
      // policy-engine (5.2 P21: TAG/WARN header edits), all on the same date/message path.
      for (const kind of ['part', 'rewrite', 'policy'] as const) {
        let token: string | undefined;
        do {
          const page = await s3.send(
            new ListObjectsV2Command({
              Bucket: bucket,
              Prefix: partPrefix(message, kind),
              ...(token !== undefined && { ContinuationToken: token }),
            }),
          );
          for (const item of page.Contents ?? []) if (item.Key) keys.add(item.Key);
          token = page.IsTruncated ? page.NextContinuationToken : undefined;
        } while (token !== undefined);
      }
      for (const key of keys) {
        await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
        objects += 1;
      }
    }
    for (const row of evidence) {
      if (row.objectKey?.startsWith(`org/${row.organizationId.toString()}/dlp-evidence/`)) {
        await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: row.objectKey }));
        objects += 1;
      }
    }
  } finally {
    s3.destroy();
  }

  // 3. Rows of the message graph (partitioned tables, no foreign keys).
  const byMessage = { messageId: { in: ids } };
  // Scan rows of the live scan role (steps 4.1–4.3): the probe is scanned like any message.
  // Step 4.4: the BEC result rows and any analyst feedback of the probe messages.
  // Step 4.5: the DLP result and evidence rows (objects deleted above).
  await prisma.dlpEvidence.deleteMany({ where: byMessage });
  await prisma.dlpScanResult.deleteMany({ where: byMessage });
  await prisma.becFeedback.deleteMany({ where: { messageId: { in: ids } } });
  await prisma.becScanResult.deleteMany({ where: byMessage });
  await prisma.urlClickEvent.deleteMany({ where: byMessage });
  await prisma.urlDynamicInspection.deleteMany({ where: byMessage });
  await prisma.urlRewrite.deleteMany({ where: byMessage });
  await prisma.urlScanResult.deleteMany({ where: byMessage });
  await prisma.messageUrl.deleteMany({ where: byMessage });
  await prisma.sandboxSubmission.deleteMany({ where: byMessage });
  await prisma.attachmentScanResult.deleteMany({ where: byMessage });
  // Step 5.1: the round's risk scores (no foreign keys; written with the round's completion).
  await prisma.messageRiskScore.deleteMany({ where: byMessage });
  // Step 5.2: the policy-engine's evaluation of each round (no foreign keys).
  await prisma.policyExecutionLog.deleteMany({ where: byMessage });
  await prisma.emailAuthResult.deleteMany({ where: byMessage });
  await prisma.scanEngineResult.deleteMany({ where: byMessage });
  await prisma.emailScan.deleteMany({ where: byMessage });
  await prisma.deliveryStatusEvent.deleteMany({ where: byMessage });
  await prisma.deliveryAttempt.deleteMany({ where: byMessage });
  await prisma.emailDelivery.deleteMany({ where: byMessage });
  await prisma.deliveryReinjection.deleteMany({ where: byMessage });
  await prisma.emailHeader.deleteMany({ where: byMessage });
  await prisma.emailAttachment.deleteMany({ where: byMessage });
  await prisma.emailMessageParse.deleteMany({ where: byMessage });
  await prisma.emailEvent.deleteMany({ where: byMessage });
  await prisma.emailMessageStatusHistory.deleteMany({ where: byMessage });
  await prisma.emailRecipient.deleteMany({ where: byMessage });
  await prisma.messageOutbox.deleteMany({
    where: { aggregateType: 'message', aggregateId: { in: ids.map((id) => id.toString()) } },
  });
  await prisma.emailMessage.deleteMany({ where: { id: { in: ids } } });
  await prisma.messageIdentity.deleteMany({ where: { id: { in: ids } } });
  // Step 5.3: the probe is a demo-domain message that the policy-engine may quarantine (BEC,
  // platform default), so its quarantine entries are deleted too, after the message (no
  // adoption can follow) and scoped to the probe's messages only (never tenant-wide: the
  // relay domain's organization is the demo tenant). RESTRICT keys: release logs before actions.
  await deleteProbeQuarantineRows(prisma, ids);
  return { messages: messages.length, queueFiles, objects };
}

/** The quarantine rows of the given messages (entries and their dependants), RESTRICT-safe. */
export async function deleteProbeQuarantineRows(
  prisma: PrismaService,
  messageIds: readonly bigint[],
): Promise<number> {
  const entries = await prisma.quarantineMessage.findMany({
    where: { messageId: { in: [...messageIds] } },
    select: { id: true },
  });
  const entryIds = entries.map((e) => e.id);
  if (entryIds.length > 0) {
    const byEntry = { quarantineMessageId: { in: entryIds } };
    await prisma.quarantineDownloadGrant.deleteMany({ where: byEntry });
    await prisma.quarantineApprovalRequest.deleteMany({ where: byEntry });
    await prisma.quarantineReleaseLog.deleteMany({ where: byEntry });
    await prisma.quarantineAction.deleteMany({ where: byEntry });
  }
  await prisma.quarantineObjectPurge.deleteMany({ where: { messageId: { in: [...messageIds] } } });
  if (entryIds.length > 0) {
    await prisma.quarantineMessage.deleteMany({ where: { id: { in: entryIds } } });
  }
  return entryIds.length;
}
