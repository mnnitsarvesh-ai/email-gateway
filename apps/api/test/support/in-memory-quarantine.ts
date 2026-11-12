/**
 * An in-memory quarantine world for the e2e suite (step 5.3 WP4): fakes of the quarantine
 * repositories, the facts reader, the object store, the lifecycle gateway, the idempotency
 * store, the audit service and the transaction runner, with the same contracts (tenant scoping,
 * CAS on `row_version`, single-use grants). Transactions are not rolled back here: the suite
 * asserts on HTTP behaviour (RBAC, validation, scoping, idempotency, rate limits, audit rows);
 * the transactional behaviour is covered by integration/quarantine.test.ts on MySQL.
 */
import { Readable } from 'node:stream';
import type {
  LifecycleSnapshot,
  MessageRef,
  TransitionRequest,
} from '@email-gateway/message-lifecycle';
import type { AuditEntry } from '../../src/audit/audit.service';
import type { TenantScope } from '../../src/auth-contracts/tenant-scope';
import type {
  IdempotencyRecord,
  NewIdempotencyRecord,
} from '../../src/http/idempotency/idempotency.repository';
import type { ApprovalRow, EntryRow, ReleaseRow } from '../../src/modules/quarantine/domain/entry';

export const ORG = 1n;
export const OTHER_ORG = 2n;

let seq = 0;
const uuid = (n: number) => `0190a5b2-7c3d-7e4f-8a1b-${n.toString(16).padStart(12, '0')}`;
const nextId = () => {
  seq += 1;
  return seq;
};

interface MessageFake {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  receivedAt: Date;
  state: LifecycleSnapshot['state'];
  statusReason: string | null;
  version: number;
  round: number;
  emlObjectKey: string;
  recipients: Array<{ id: bigint; rcptSeq: number; address: string; status: string }>;
}

export class QuarantineWorld {
  messages: MessageFake[] = [];
  entries: EntryRow[] = [];
  approvals: ApprovalRow[] = [];
  releases: ReleaseRow[] = [];
  actions: Array<{
    id: bigint;
    quarantineMessageId: bigint;
    action: string;
    actorType: string;
    actorId: string | null;
    reason: string | null;
    result: string | null;
    details: unknown;
    createdAt: Date;
    idempotencyKey: string | null;
    organizationId: bigint;
  }> = [];
  grants: Array<{
    jti: string;
    organizationId: bigint;
    userId: bigint;
    quarantineMessageId: bigint;
    object: 'eml' | 'attachment';
    partIndex: number | null;
    expiresAt: Date;
    consumedAt: Date | null;
  }> = [];
  settings = new Map<bigint, { settings: unknown; rowVersion: number }>();
  prefs = new Map<bigint, boolean>();
  outbox: Array<{ eventType: string; aggregateType: string; payload: unknown }> = [];
  audits: AuditEntry[] = [];
  idempotency = new Map<string, IdempotencyRecord & { organizationId: bigint }>();
  transitions: TransitionRequest[] = [];
  identities = new Map<bigint, { email: string; verified: boolean }>();
  /** `api_keys.created_by_user_id` by API key id (Q14 key-creator rule). */
  apiKeyCreators = new Map<bigint, bigint | null>();
  purges: Array<{ messageId: bigint; status: string }> = [];

  reset(): void {
    this.messages = [];
    this.entries = [];
    this.approvals = [];
    this.releases = [];
    this.actions = [];
    this.grants = [];
    this.settings.clear();
    this.prefs.clear();
    this.outbox = [];
    this.audits = [];
    this.idempotency.clear();
    this.transitions = [];
    this.purges = [];
    this.apiKeyCreators.clear();
  }

  /** A quarantined message with one held entry for `address`. */
  addEntry(
    o: Partial<EntryRow> & {
      organizationId?: bigint;
      address?: string;
      messageState?: LifecycleSnapshot['state'];
    } = {},
  ): EntryRow {
    const n = nextId();
    const organizationId = o.organizationId ?? ORG;
    const receivedAt = new Date(Date.now() - 3_600_000);
    const address = (o.address ?? `rcpt${n}@acme.example`).toLowerCase();
    const message: MessageFake = {
      id: BigInt(1000 + n),
      publicId: uuid(1000 + n),
      organizationId,
      receivedAt,
      state: o.messageState ?? 'quarantined',
      statusReason: 'policy_quarantine',
      version: 3,
      round: 0,
      emlObjectKey: `org/${organizationId.toString()}/eml/${n}.eml`,
      recipients: [{ id: BigInt(5000 + n), rcptSeq: 0, address, status: 'quarantined' }],
    };
    this.messages.push(message);
    const entry: EntryRow = {
      id: BigInt(n),
      publicId: uuid(n),
      organizationId,
      messageId: message.id,
      messageReceivedAt: receivedAt,
      lifecycleRound: 0,
      scanId: null,
      recipientId: message.recipients[0]!.id,
      rcptSeq: 0,
      recipientAddress: address,
      userId: null,
      direction: 'inbound',
      kind: 'quarantine',
      origin: 'policy',
      reason: 'spam',
      state: 'held',
      envelopeFrom: 'sender@outside.example',
      headerFrom: null,
      hasAttachments: false,
      attachmentCount: 0,
      sizeBytes: 100,
      riskScore: 100,
      riskLevel: 'low',
      recommendedAction: 'tag',
      riskVerdict: 'spam',
      hasHardBlock: false,
      hardBlocks: [],
      reasonCodes: [],
      floorReasons: [],
      primaryEngine: 'rspamd',
      decisionSource: 'platform_default',
      decisivePolicyPublicId: null,
      decisivePolicyVersionNo: null,
      decisiveRuleId: null,
      explanation: [],
      explanationText: 'fixture',
      emlObjectKey: message.emlObjectKey,
      quarantinedAt: new Date(Date.now() - 60_000 + n),
      expiresAt: new Date(Date.now() + 86_400_000),
      stateChangedAt: new Date(),
      releasedAt: null,
      approvalRequestId: null,
      objectPurgedAt: null,
      rowVersion: 1,
      ...o,
    };
    this.entries.push(entry);
    return entry;
  }

  messageOf(entry: Pick<EntryRow, 'messageId'>): MessageFake {
    return this.messages.find((m) => m.id === entry.messageId)!;
  }

  // ------------------------------------------------------------------ writer repository

  writer() {
    const inScope = <T extends { organizationId: bigint }>(scope: TenantScope, rows: T[]) =>
      rows.filter((r) => r.organizationId === scope.organizationId);
    return {
      findEntryRef: (
        _tx: unknown,
        scope: TenantScope,
        publicId: string,
        self: string | null = null,
      ) => {
        const e = inScope(scope, this.entries).find(
          (x) => x.publicId === publicId && (self === null || x.recipientAddress === self),
        );
        return Promise.resolve(
          e
            ? {
                id: e.id,
                publicId: e.publicId,
                messageId: e.messageId,
                messageReceivedAt: e.messageReceivedAt,
              }
            : null,
        );
      },
      entryRefById: (_tx: unknown, scope: TenantScope, id: bigint) => {
        const e = inScope(scope, this.entries).find((x) => x.id === id);
        return Promise.resolve(
          e
            ? {
                id: e.id,
                publicId: e.publicId,
                messageId: e.messageId,
                messageReceivedAt: e.messageReceivedAt,
              }
            : null,
        );
      },
      lockEntry: (_tx: unknown, _scope: TenantScope, ref: { id: bigint }) =>
        Promise.resolve({ ...this.entries.find((x) => x.id === ref.id)! }),
      updateEntry: (
        _tx: unknown,
        _scope: TenantScope,
        entry: { id: bigint; rowVersion: number },
        u: Record<string, unknown>,
      ) => {
        const row = this.entries.find((x) => x.id === entry.id);
        if (!row || row.rowVersion !== entry.rowVersion) return Promise.resolve(false);
        Object.assign(row, { ...u, state: u.state, rowVersion: row.rowVersion + 1 });
        return Promise.resolve(true);
      },
      entriesOfMessage: (_tx: unknown, scope: TenantScope, m: MessageRef) =>
        Promise.resolve(
          inScope(scope, this.entries)
            .filter((e) => e.messageId === m.id)
            .map((e) => ({
              id: e.id,
              state: e.state,
              kind: e.kind,
              lifecycleRound: e.lifecycleRound,
              rcptSeq: e.rcptSeq,
            })),
        ),
      lockReviewEntries: (_tx: unknown, scope: TenantScope, m: MessageRef) =>
        Promise.resolve(
          inScope(scope, this.entries)
            .filter(
              (e) => e.messageId === m.id && e.kind === 'review' && e.state === 'pending_approval',
            )
            .map((e) => ({ ...e })),
        ),
      createEntries: () => Promise.resolve([]),
      insertAction: (
        _tx: unknown,
        row: {
          organizationId: bigint;
          quarantineMessageId: bigint;
          action: string;
          actorType: string;
          actorId: string | null;
          reason: string | null;
          result: string | null;
          details: unknown;
          idempotencyKey: string | null;
        },
      ) => {
        const id = BigInt(nextId());
        this.actions.push({ ...row, id, createdAt: new Date() });
        return Promise.resolve(id);
      },
      insertReleaseLog: (
        _tx: unknown,
        row: {
          quarantineMessageId: bigint;
          releasePublicId: string;
          mode: ReleaseRow['mode'];
          requestedByType: ReleaseRow['requestedByType'];
          requestedById: string | null;
          precheck: unknown;
        },
      ) => {
        const entry = this.entries.find((e) => e.id === row.quarantineMessageId)!;
        this.releases.push({
          id: BigInt(nextId()),
          quarantineMessageId: row.quarantineMessageId,
          entryPublicId: entry.publicId,
          releasePublicId: row.releasePublicId,
          mode: row.mode,
          status: 'pending',
          requestedByType: row.requestedByType,
          requestedById: row.requestedById,
          revalidation: row.precheck,
          deliveredObject: null,
          approvalRequestPublicId: null,
          createdAt: new Date(),
          completedAt: null,
        });
        return Promise.resolve(BigInt(1));
      },
      createApproval: (
        _tx: unknown,
        row: {
          organizationId: bigint;
          quarantineMessageId: bigint;
          kind: ApprovalRow['kind'];
          approvalReasons: string[];
          requestedByType: ApprovalRow['requestedByType'];
          requestedByUserId: bigint | null;
          requestedByApiKeyId: bigint | null;
          requestReason: string | null;
          expiresAt: Date;
        },
      ) => {
        const n = nextId();
        const entry = this.entries.find((e) => e.id === row.quarantineMessageId)!;
        const approval: ApprovalRow = {
          id: BigInt(n),
          publicId: uuid(90_000 + n),
          organizationId: row.organizationId,
          quarantineMessageId: row.quarantineMessageId,
          entryPublicId: entry.publicId,
          kind: row.kind,
          status: 'pending',
          approvalReasons: row.approvalReasons as ApprovalRow['approvalReasons'],
          approvedReasons: null,
          requestedByType: row.requestedByType,
          requestedByUserId: row.requestedByUserId,
          requestedByApiKeyId: row.requestedByApiKeyId,
          requestedByPublicId: null,
          requestReason: row.requestReason,
          decidedByUserId: null,
          decidedByPublicId: null,
          decisionReason: null,
          expiresAt: row.expiresAt,
          decidedAt: null,
          rowVersion: 1,
          createdAt: new Date(),
        };
        this.approvals.push(approval);
        return Promise.resolve({ id: approval.id, publicId: approval.publicId });
      },
      findApprovalRef: (_tx: unknown, scope: TenantScope, publicId: string) => {
        const a = inScope(scope, this.approvals).find((x) => x.publicId === publicId);
        return Promise.resolve(a ? { id: a.id, quarantineMessageId: a.quarantineMessageId } : null);
      },
      lockApproval: (_tx: unknown, _scope: TenantScope, id: bigint) =>
        Promise.resolve({ ...this.approvals.find((a) => a.id === id)! }),
      apiKeyCreator: (_tx: unknown, _scope: TenantScope, apiKeyId: bigint) =>
        Promise.resolve(this.apiKeyCreators.get(apiKeyId) ?? null),
      updateApproval: (
        _tx: unknown,
        _scope: TenantScope,
        a: { id: bigint; rowVersion: number },
        u: Record<string, unknown>,
      ) => {
        const row = this.approvals.find((x) => x.id === a.id);
        if (!row || row.rowVersion !== a.rowVersion) return Promise.resolve(false);
        Object.assign(row, u, { rowVersion: row.rowVersion + 1 });
        return Promise.resolve(true);
      },
      cancelPendingApprovals: (_tx: unknown, _scope: TenantScope, entryId: bigint) => {
        const pending = this.approvals.filter(
          (a) => a.quarantineMessageId === entryId && a.status === 'pending',
        );
        for (const a of pending) a.status = 'cancelled';
        return Promise.resolve(pending.map((a) => a.publicId));
      },
      setRecipientStatus: (
        _tx: unknown,
        _scope: TenantScope,
        m: MessageRef,
        rcptSeq: number,
        from: string[],
        to: string,
      ) => {
        const msg = this.messages.find((x) => x.id === m.id)!;
        const r = msg.recipients.find((x) => x.rcptSeq === rcptSeq && from.includes(x.status));
        if (r) r.status = to;
        return Promise.resolve(r ? 1 : 0);
      },
      recipients: (_tx: unknown, _scope: TenantScope, m: MessageRef) =>
        Promise.resolve(
          this.messages.find((x) => x.id === m.id)!.recipients.map((r) => ({ ...r })),
        ),
      disposalFacts: () =>
        Promise.resolve({
          legalHolds: [],
          archive: null,
          retentionPolicyDays: [],
          emailArchives: [],
          evaluationActions: [],
        }),
      upsertPurge: (_tx: unknown, _scope: TenantScope, m: MessageRef, p: { status: string }) => {
        this.purges.push({ messageId: m.id, status: p.status });
        return Promise.resolve();
      },
      insertOutbox: (
        _tx: unknown,
        row: { eventType: string; aggregateType: string; payload: unknown },
      ) => {
        this.outbox.push(row);
        return Promise.resolve();
      },
      message: (_tx: unknown, scope: TenantScope, publicId: string) => {
        const m = inScope(scope, this.messages).find((x) => x.publicId === publicId);
        return Promise.resolve(m ? this.messageRow(m) : null);
      },
      messageById: (_tx: unknown, _scope: TenantScope, ref: MessageRef) => {
        const m = this.messages.find((x) => x.id === ref.id);
        return Promise.resolve(m ? this.messageRow(m) : null);
      },
      roundFacts: () => Promise.resolve({ scanId: null, evaluation: null, risk: [] }),
      userIdByEmail: () => Promise.resolve(null),
      orgSettings: () => Promise.resolve(null),
      lockSettings: (_tx: unknown, scope: TenantScope) => {
        const s = this.settings.get(scope.organizationId);
        return Promise.resolve(
          s ? { id: 1n, settings: s.settings, rowVersion: s.rowVersion } : null,
        );
      },
      settingsDocument: (_tx: unknown, scope: TenantScope) =>
        Promise.resolve(this.settings.get(scope.organizationId)?.settings ?? null),
      insertSettings: (_tx: unknown, scope: TenantScope, d: { settings: unknown }) => {
        this.settings.set(scope.organizationId, { settings: d.settings, rowVersion: 1 });
        return Promise.resolve(1);
      },
      updateSettings: (
        _tx: unknown,
        scope: TenantScope,
        rowVersion: number,
        d: { settings: unknown },
      ) => {
        const s = this.settings.get(scope.organizationId);
        if (!s || s.rowVersion !== rowVersion) return Promise.resolve(false);
        this.settings.set(scope.organizationId, {
          settings: d.settings,
          rowVersion: rowVersion + 1,
        });
        return Promise.resolve(true);
      },
      upsertPreferences: (_tx: unknown, _scope: TenantScope, userId: bigint, optOut: boolean) => {
        this.prefs.set(userId, optOut);
        return Promise.resolve();
      },
      insertGrant: (_tx: unknown, row: QuarantineWorld['grants'][number]) => {
        this.grants.push({ ...row, consumedAt: null });
        return Promise.resolve();
      },
      consumeGrant: (_tx: unknown, scope: TenantScope, jti: string, userId: bigint, now: Date) => {
        const g = this.grants.find(
          (x) => x.jti === jti && x.organizationId === scope.organizationId && x.userId === userId,
        );
        if (g && g.consumedAt === null && g.expiresAt > now) {
          g.consumedAt = now;
          return Promise.resolve('consumed' as const);
        }
        return Promise.resolve(
          g && g.consumedAt !== null ? ('used' as const) : ('invalid' as const),
        );
      },
      grantByJti: (_tx: unknown, scope: TenantScope, jti: string) => {
        const g = this.grants.find(
          (x) => x.jti === jti && x.organizationId === scope.organizationId,
        );
        return Promise.resolve(
          g
            ? {
                quarantineMessageId: g.quarantineMessageId,
                object: g.object,
                partIndex: g.partIndex,
                userId: g.userId,
              }
            : null,
        );
      },
    };
  }

  messageRow(m: MessageFake) {
    return {
      id: m.id,
      publicId: m.publicId,
      receivedAt: m.receivedAt,
      organizationId: m.organizationId,
      direction: 'inbound' as const,
      status: m.state,
      statusReason: m.statusReason,
      lifecycleRound: m.round,
      envelopeFrom: 'sender@outside.example',
      headerFrom: null,
      sizeBytes: 100,
      attachmentCount: 0,
      emlObjectKey: m.emlObjectKey,
      emlSha256: 'a'.repeat(64),
      finalVerdict: null,
      riskScore: null,
    };
  }

  // ------------------------------------------------------------------ replica repository

  reader() {
    const inScope = <T extends { organizationId: bigint }>(scope: TenantScope, rows: T[]) =>
      rows.filter((r) => r.organizationId === scope.organizationId);
    return {
      client: {},
      search: (
        scope: TenantScope,
        f: { from: Date; to: Date; states?: string[]; recipient?: string; take: number },
      ) =>
        Promise.resolve(
          inScope(scope, this.entries)
            .filter((e) => e.quarantinedAt >= f.from && e.quarantinedAt < f.to)
            .filter((e) => f.states === undefined || f.states.includes(e.state))
            .filter((e) => f.recipient === undefined || e.recipientAddress === f.recipient)
            .sort((a, b) => b.quarantinedAt.getTime() - a.quarantinedAt.getTime())
            .slice(0, f.take),
        ),
      entry: (scope: TenantScope, publicId: string, self: string | null = null) =>
        Promise.resolve(
          inScope(scope, this.entries).find(
            (e) => e.publicId === publicId && (self === null || e.recipientAddress === self),
          ) ?? null,
        ),
      messagePublicIds: (_scope: TenantScope, ids: bigint[]) =>
        Promise.resolve(
          new Map(this.messages.filter((m) => ids.includes(m.id)).map((m) => [m.id, m.publicId])),
        ),
      messageIdByPublicId: (scope: TenantScope, publicId: string) =>
        Promise.resolve(
          inScope(scope, this.messages).find((m) => m.publicId === publicId)?.id ?? null,
        ),
      subjects: () => Promise.resolve(new Map<bigint, string | null>()),
      approvalPublicIds: (_scope: TenantScope, ids: bigint[]) =>
        Promise.resolve(
          new Map(this.approvals.filter((a) => ids.includes(a.id)).map((a) => [a.id, a.publicId])),
        ),
      actions: (_scope: TenantScope, entryId: bigint) =>
        Promise.resolve(this.actions.filter((a) => a.quarantineMessageId === entryId)),
      releasesOfEntry: (_scope: TenantScope, entryId: bigint) =>
        Promise.resolve(this.releases.filter((r) => r.quarantineMessageId === entryId)),
      release: (scope: TenantScope, id: string) =>
        Promise.resolve(
          this.releases.filter(
            (r) =>
              r.releasePublicId === id &&
              inScope(scope, this.entries).some((e) => e.id === r.quarantineMessageId),
          ),
        ),
      approvals: (scope: TenantScope) => Promise.resolve(inScope(scope, this.approvals)),
      approval: (scope: TenantScope, publicId: string) =>
        Promise.resolve(
          inScope(scope, this.approvals).find((a) => a.publicId === publicId) ?? null,
        ),
      countsByState: () => Promise.resolve(new Map([['held', 1]])),
      pendingApprovals: () => Promise.resolve(0),
      settings: (scope: TenantScope) =>
        Promise.resolve(this.settings.get(scope.organizationId) ?? null),
      orgSettings: () => Promise.resolve(null),
      preferences: (_scope: TenantScope, userId: bigint) =>
        Promise.resolve(this.prefs.get(userId) ?? false),
      identity: (userId: bigint) => {
        const i = this.identities.get(userId);
        return Promise.resolve(
          i ? { id: userId, email: i.email, emailVerified: i.verified, active: true } : null,
        );
      },
    };
  }

  facts() {
    return {
      latestScan: () => Promise.resolve(null),
      contentFacts: () =>
        Promise.resolve({
          scan: null,
          messageHardBlocks: [],
          latestVerdict: null,
          attachments: [],
          urls: [],
        }),
      stalenessFacts: () =>
        Promise.resolve({
          hasUrls: false,
          hasScannedAttachments: false,
          newestClamavDbFirstSeenAt: null,
        }),
      previewSources: () =>
        Promise.resolve({
          parse: {
            status: 'parsed',
            textKey: null,
            htmlKey: 'org/1/part/2026/11/12/1/1.html',
            textSize: null,
            htmlSize: 40,
          },
          headers: [{ name: 'From', value: 'sender@outside.example' }],
          subject: 'Hello',
        }),
    };
  }

  objects() {
    return {
      readPart: () =>
        Promise.resolve({
          bytes: Buffer.from('Hello <script>alert(1)</script>'),
          truncated: false,
        }),
      exists: () => Promise.resolve(true),
      open: () => Promise.resolve({ body: Readable.from([Buffer.from('EML')]), sizeBytes: 3 }),
    };
  }

  lifecycle() {
    return {
      lock: (_tx: unknown, ref: MessageRef) => {
        const m = this.messages.find(
          (x) => x.id === ref.id && x.organizationId === ref.organizationId,
        );
        return Promise.resolve(
          m
            ? {
                state: m.state,
                version: m.version,
                round: m.round,
                statusChangedAt: new Date(),
                statusReason: m.statusReason,
                direction: 'inbound' as const,
                emlObjectKey: m.emlObjectKey,
              }
            : null,
        );
      },
      transition: (_tx: unknown, request: TransitionRequest) => {
        this.transitions.push(request);
        const m = this.messages.find((x) => x.id === request.message.id)!;
        const from = m.state;
        m.state = request.to;
        m.version += 1;
        return Promise.resolve({
          result: 'applied' as const,
          from,
          to: request.to,
          version: m.version,
          round: m.round,
          historyId: 1n,
          stateEventId: 'e',
          snapshot: {} as LifecycleSnapshot,
        });
      },
    };
  }

  idempotencyRepository() {
    const k = (org: bigint, key: string) => `${org.toString()}:${key}`;
    return {
      lock: (_tx: unknown, org: bigint, key: string) =>
        Promise.resolve(this.idempotency.get(k(org, key)) ?? null),
      delete: (_tx: unknown, id: bigint) => {
        for (const [key, value] of this.idempotency)
          if (value.id === id) this.idempotency.delete(key);
        return Promise.resolve();
      },
      insert: (_tx: unknown, r: NewIdempotencyRecord) => {
        this.idempotency.set(k(r.organizationId, r.idempotencyKey), {
          id: BigInt(nextId()),
          organizationId: r.organizationId,
          operation: r.operation,
          principal: r.principal,
          requestSha256: r.requestSha256,
          resourceId: r.resourceId,
          statusCode: r.statusCode,
          response: JSON.parse(JSON.stringify(r.response)),
          expiresAt: r.expiresAt,
        });
        return Promise.resolve();
      },
    };
  }

  auditService() {
    return {
      actorFrom: (p: { kind: string; userPublicId?: string; apiKeyPublicId?: string }) => ({
        type: p.kind === 'api_key' ? 'api_key' : 'user',
        id: p.kind === 'api_key' ? p.apiKeyPublicId : p.userPublicId,
      }),
      record: (entry: AuditEntry) => {
        this.audits.push(entry);
        return Promise.resolve();
      },
    };
  }

  /** Audit actions written so far (in order). */
  auditActions(): string[] {
    return this.audits.map((a) => a.action);
  }
}
