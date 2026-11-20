import {
  DeleteObjectCommand,
  HeadObjectCommand,
  ListObjectVersionsCommand,
  type S3Client,
} from '@aws-sdk/client-s3';
import {
  EMPTY_JOURNAL_SCOPE,
  type ResolvedArchiveSettings,
  type ResolvedJournalScope,
  resolveArchiveSettings,
} from '@email-gateway/archive';
import type { Prisma } from '@email-gateway/database';
import {
  archivePendingOf,
  type ObjectDisposalInput,
  type QuarantineState,
} from '@email-gateway/quarantine';
import { type QuarantineInconsistencySink, quarantineWrongRead } from './errors';
import type { MessageKey } from './store-writer';
import { gatewayRecipientState } from './gateway-states';

/**
 * Object disposal of quarantined mail (step 5.3 Q17, Q19 step 3): the writer facts
 * `decideObjectDisposal` needs, and the S3 purge of a message's objects after organization
 * prefix checks.
 */

const two = (n: number) => String(n).padStart(2, '0');

/** True when `key` is an object key of `organizationId` (`org/<org>/…`, clean segments). */
export function isOrganizationKey(key: string, organizationId: bigint): boolean {
  return (
    key.startsWith(`org/${organizationId.toString()}/`) &&
    !key.split('/').some((segment) => segment === '..' || segment === '.' || segment === '')
  );
}

/**
 * The prefixes of a message's derived objects (Q17): decoded parts (3.1), rewritten copies
 * (4.3) and policy/release copies (5.2, 5.3), all keyed by the UTC date of `received_at`.
 */
export function messageObjectPrefixes(message: MessageKey): string[] {
  const d = message.receivedAt;
  const date = `${String(d.getUTCFullYear())}/${two(d.getUTCMonth() + 1)}/${two(d.getUTCDate())}`;
  const org = `org/${message.organizationId.toString()}`;
  const id = message.messageId.toString();
  return ['part', 'rewrite', 'policy'].map((kind) => `${org}/${kind}/${date}/${id}/`);
}

/** The objects of the mail bucket the quarantine purges and checks. */
export interface QuarantineObjects {
  exists(key: string, signal?: AbortSignal): Promise<boolean>;
  /** Deletes every version of `key` (exact). Returns the versions deleted. */
  purgeKey(key: string): Promise<number>;
  /** Deletes every version of every key under `prefix`. Returns the versions deleted. */
  purgePrefix(prefix: string): Promise<number>;
}

/**
 * S3 implementation over the (versioned) mail bucket: purges remove every version and delete
 * marker, so a purged message leaves nothing behind (the bucket lifecycle would otherwise keep
 * noncurrent versions).
 */
export class S3QuarantineObjects implements QuarantineObjects {
  constructor(
    private readonly client: S3Client,
    private readonly bucket: string,
  ) {}

  async exists(key: string, signal?: AbortSignal): Promise<boolean> {
    try {
      await this.client.send(
        new HeadObjectCommand({ Bucket: this.bucket, Key: key }),
        signal ? { abortSignal: signal } : {},
      );
      return true;
    } catch (error) {
      const status = (error as { $metadata?: { httpStatusCode?: number } }).$metadata
        ?.httpStatusCode;
      const name = (error as { name?: string }).name;
      if (status === 404 || name === 'NotFound' || name === 'NoSuchKey') return false;
      throw error;
    }
  }

  purgeKey(key: string): Promise<number> {
    return this.purge(key, (k) => k === key);
  }

  purgePrefix(prefix: string): Promise<number> {
    return this.purge(prefix, (k) => k.startsWith(prefix));
  }

  private async purge(prefix: string, match: (key: string) => boolean): Promise<number> {
    let deleted = 0;
    let keyMarker: string | undefined;
    let versionMarker: string | undefined;
    do {
      const page = await this.client.send(
        new ListObjectVersionsCommand({
          Bucket: this.bucket,
          Prefix: prefix,
          KeyMarker: keyMarker,
          VersionIdMarker: versionMarker,
        }),
      );
      for (const v of [...(page.Versions ?? []), ...(page.DeleteMarkers ?? [])]) {
        if (v.Key === undefined || !match(v.Key)) continue;
        await this.client.send(
          new DeleteObjectCommand({ Bucket: this.bucket, Key: v.Key, VersionId: v.VersionId }),
        );
        deleted += 1;
      }
      keyMarker = page.IsTruncated ? page.NextKeyMarker : undefined;
      versionMarker = page.IsTruncated ? page.NextVersionIdMarker : undefined;
    } while (keyMarker !== undefined);
    return deleted;
  }
}

/** Plan feature of archiving (step 8.1 A20): journaling only applies to entitled tenants. */
const ARCHIVING_FEATURE = 'archiving';
/** Most department member rows read per scope resolution. */
const MAX_DEPARTMENT_MEMBERS = 50_000;

/** The writer facts of `decideObjectDisposal` for one message (Q17 under 8.1, A23). */
export interface DisposalFacts extends Omit<ObjectDisposalInput, 'now' | 'entries'> {
  /** Every entry of the message (state as stored). */
  entries: Array<{ id: bigint; state: QuarantineState; emlObjectKey: string }>;
}

/**
 * The journal scope of `archive-settings/1` resolved inside the organization (A4): verified
 * domains by name, users by e-mail, department member addresses and member users' e-mails.
 * Every query filters by the organization, so another organization's id never resolves.
 */
async function resolveScope(
  tx: Prisma.TransactionClient,
  org: bigint,
  scope: ResolvedArchiveSettings['scope'],
): Promise<ResolvedJournalScope> {
  if (scope.mode === 'all') return EMPTY_JOURNAL_SCOPE;
  const [domains, users, departments] = await Promise.all([
    scope.domainIds.length === 0
      ? []
      : tx.domain.findMany({
          where: {
            organizationId: org,
            publicId: { in: scope.domainIds },
            deletedAt: null,
            verifiedAt: { not: null },
          },
          select: { name: true, organizationId: true },
        }),
    scope.userIds.length === 0
      ? []
      : tx.user.findMany({
          where: { organizationId: org, publicId: { in: scope.userIds }, deletedAt: null },
          select: { email: true, organizationId: true },
        }),
    scope.departmentIds.length === 0
      ? []
      : tx.tenantDepartmentMember.findMany({
          where: { organizationId: org, department: { publicId: { in: scope.departmentIds } } },
          select: {
            address: true,
            organizationId: true,
            user: { select: { email: true, deletedAt: true } },
          },
          take: MAX_DEPARTMENT_MEMBERS,
        }),
  ]);
  const own = <R extends { organizationId: bigint }>(rows: readonly R[]) =>
    rows.filter((r) => r.organizationId === org);
  return {
    addresses: [...scope.addresses],
    userEmails: own(users).map((u) => u.email),
    departmentAddresses: own(departments).flatMap((m) => [
      ...(m.address !== null ? [m.address] : []),
      ...(m.user !== null && m.user.deletedAt === null ? [m.user.email] : []),
    ]),
    domains: own(domains).map((d) => d.name),
  };
}

/**
 * Reads the Q17 facts of a message on the writer (echo-checked on the organization), as bound
 * to step 8.1 (A23): the active legal holds of the organization with their criteria version,
 * whether a live `email_archives` row exists, and whether a capture is still expected
 * (`archivePendingOf`: the message's capture intent, an ARCHIVE request of an evaluation, or
 * journal eligibility under the current settings with the resolved scope), every entry and every
 * recipient status. When the message row is gone (its partition was dropped), the entries carry
 * the facts (received time, direction, addresses).
 */
export class DisposalFactsReader {
  constructor(private readonly sink: QuarantineInconsistencySink) {}

  async read(tx: Prisma.TransactionClient, message: MessageKey): Promise<DisposalFacts> {
    const org = message.organizationId;
    const holds = await tx.archiveLegalHold.findMany({
      where: { organizationId: org, status: 'active' },
      select: {
        id: true,
        organizationId: true,
        status: true,
        criteria: true,
        criteriaVersion: true,
      },
      orderBy: { id: 'asc' },
    });
    for (const h of holds) {
      if (h.organizationId !== org || h.status !== 'active') {
        quarantineWrongRead(this.sink, 'legal_holds', 'hold echo');
      }
    }
    const settings = await tx.archiveSetting.findFirst({
      where: { organizationId: org },
      select: { organizationId: true, enabled: true, settings: true, journalEnabledAt: true },
    });
    if (settings !== null && settings.organizationId !== org) {
      quarantineWrongRead(this.sink, 'archive', 'archive settings echo');
    }
    const feature = await tx.organizationFeature.findUnique({
      where: { organizationId_featureKey: { organizationId: org, featureKey: ARCHIVING_FEATURE } },
      select: { organizationId: true, enabled: true },
    });
    if (feature !== null && feature.organizationId !== org) {
      quarantineWrongRead(this.sink, 'archive', 'archiving feature echo');
    }
    const archives = await tx.emailArchive.findMany({
      where: {
        messageId: message.messageId,
        receivedAt: message.receivedAt,
        organizationId: org,
        deletedAt: null,
      },
      select: { messageId: true, organizationId: true },
      take: 1,
    });
    if (archives.some((a) => a.messageId !== message.messageId || a.organizationId !== org)) {
      quarantineWrongRead(this.sink, 'archive', 'email archive echo');
    }
    const intents = await tx.archiveCaptureIntent.findMany({
      where: { messageId: message.messageId, receivedAt: message.receivedAt, organizationId: org },
      select: { messageId: true, organizationId: true, status: true },
      take: 1,
    });
    if (intents.some((i) => i.messageId !== message.messageId || i.organizationId !== org)) {
      quarantineWrongRead(this.sink, 'archive', 'capture intent echo');
    }
    const evaluations = await tx.policyExecutionLog.findMany({
      where: { messageId: message.messageId, receivedAt: message.receivedAt, organizationId: org },
      select: { messageId: true, organizationId: true, actions: true },
    });
    if (evaluations.some((e) => e.messageId !== message.messageId || e.organizationId !== org)) {
      quarantineWrongRead(this.sink, 'evaluation', 'evaluation echo');
    }
    const archiveRequested = evaluations.some(
      (e) =>
        Array.isArray(e.actions) &&
        (e.actions as Array<{ type?: unknown; status?: unknown }>).some(
          (a) => a.type === 'ARCHIVE' && a.status === 'requested',
        ),
    );
    const entries = await tx.quarantineMessage.findMany({
      where: { messageId: message.messageId, messageReceivedAt: message.receivedAt },
      select: {
        id: true,
        organizationId: true,
        messageId: true,
        status: true,
        emlObjectKey: true,
        direction: true,
        envelopeFrom: true,
        headerFrom: true,
        recipientAddress: true,
      },
      orderBy: { id: 'asc' },
    });
    if (entries.some((e) => e.organizationId !== org || e.messageId !== message.messageId)) {
      quarantineWrongRead(this.sink, 'entries', 'disposal entry echo');
    }
    const recipients = await tx.emailRecipient.findMany({
      where: { messageId: message.messageId, receivedAt: message.receivedAt, organizationId: org },
      select: {
        messageId: true,
        organizationId: true,
        address: true,
        status: true,
        direction: true,
      },
    });
    if (recipients.some((r) => r.messageId !== message.messageId || r.organizationId !== org)) {
      quarantineWrongRead(this.sink, 'recipients', 'disposal recipient echo');
    }
    const first = entries[0];
    const direction = first?.direction ?? 'inbound';
    const senders = new Set<string>();
    for (const e of entries) {
      senders.add(e.envelopeFrom.toLowerCase());
      if (e.headerFrom !== null) senders.add(e.headerFrom.toLowerCase());
    }
    const recipientFacts = [
      ...recipients.map((r) => ({ address: r.address, direction: r.direction ?? direction })),
      ...entries
        .filter(
          (e) =>
            !recipients.some((r) => r.address.toLowerCase() === e.recipientAddress.toLowerCase()),
        )
        .map((e) => ({ address: e.recipientAddress, direction: e.direction })),
    ];
    let journal: Parameters<typeof archivePendingOf>[0]['journal'] = null;
    if (settings !== null) {
      let scope: ResolvedJournalScope = EMPTY_JOURNAL_SCOPE;
      try {
        scope = await resolveScope(tx, org, resolveArchiveSettings(settings.settings).scope);
      } catch {
        // Unparsable settings: archivePendingOf treats them as eligible (fail-safe).
      }
      journal = {
        entitled: feature?.enabled ?? false,
        enabled: settings.enabled,
        settings: settings.settings,
        journalEnabledAt: settings.journalEnabledAt,
        scope,
        message: {
          receivedAt: message.receivedAt,
          direction,
          envelopeFrom: first?.envelopeFrom ?? null,
          headerFrom: first?.headerFrom ?? null,
          recipients: recipientFacts,
        },
      };
    }
    return {
      message: {
        receivedAt: message.receivedAt,
        direction,
        recipientDirections: [...new Set(recipientFacts.map((r) => r.direction))],
        senderAddresses: [...senders],
        recipientAddresses: [...new Set(recipientFacts.map((r) => r.address.toLowerCase()))],
      },
      legalHolds: holds.map((h) => ({
        id: h.id.toString(),
        criteria: h.criteria,
        criteriaVersion: h.criteriaVersion,
      })),
      archived: archives.length > 0,
      archivePending: archivePendingOf({
        intentStatus: intents[0]?.status ?? null,
        archiveRequested,
        journal,
      }),
      entries: entries.map((e) => ({
        id: e.id,
        state: e.status,
        emlObjectKey: e.emlObjectKey,
      })),
      recipientStatuses: recipients.map((r) => gatewayRecipientState(r.status)),
    };
  }
}
