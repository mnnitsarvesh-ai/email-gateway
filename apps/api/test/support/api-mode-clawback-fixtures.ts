/**
 * In-memory double of the step API-3 `ApiClawbackRepository` for the e2e suites
 * (docs/plan/steps/37-api-mode-clawback-reporting.md §9.4): clawbacks with their frozen targets,
 * user reports with their groups and triage history (read from the recorded audit rows), the
 * organization's settings with CAS, report-mailbox designation over the `ApiModeWorld`'s
 * mailboxes and domains, the outbox rows and the purge-approval alert windows, and the overview's
 * live counts. The mailbox-worker's work (materialization, execution) is simulated by the tests
 * through the `seed*` helpers. Nothing here is used by production code.
 */

import type { AuditEntry } from '../../src/audit/audit.service';
import type { TenantScope } from '../../src/auth-contracts/tenant-scope';
import { API_MODE_AUDIT, API_MODE_RESOURCES } from '../../src/modules/api-mode/api-mode.constants';
import {
  type ApiClawbackRepository,
  type ClawbackFilter,
  type ClawbackRow,
  type ClawbackUpdate,
  copyKey,
  type CreateClawbackRow,
  type OrgSettingsRow,
  type OrgSettingsWrite,
  type OutboxRow,
  type ReportFilter,
  type ReportMailboxRow,
  type ReportRow,
  type ReportUpdate,
  type TargetFilter,
  type TargetRow,
} from '../../src/modules/api-mode/repositories/api-clawback.repository';
import type { ApiModeWorld, StoredCopy, StoredMailbox } from './api-mode-fixtures';

const clone = <T>(value: T): T => structuredClone(value);

export interface StoredClawback extends ClawbackRow {
  organizationId: bigint;
}

export interface StoredTarget extends TargetRow {
  organizationId: bigint;
  clawbackId: bigint;
  copyId: bigint;
  mailboxId: bigint;
}

export interface StoredReport extends ReportRow {
  organizationId: bigint;
  reportMailboxId: bigint;
  triagedByUserId: bigint | null;
}

/** The API-3 state of the e2e world. */
export class ClawbackStore {
  clawbacks: StoredClawback[] = [];
  targets: StoredTarget[] = [];
  reports: StoredReport[] = [];
  settings = new Map<bigint, OrgSettingsRow>();
  outbox: OutboxRow[] = [];
  /** `notification_alert_windows` keys (`org:kind:scope:windowStart`) → event count. */
  alertWindows = new Map<string, number>();
  /** Report mailbox designation per mailbox id. */
  reportMailboxes = new Map<bigint, Date>();
  resolvedCounters: Array<{ apiConnectionId: bigint; n: number }> = [];
  counters: Array<{
    organizationId: bigint;
    apiConnectionId: bigint;
    hour: Date;
    internalCopies: number;
    clawbackTargetsQueued: number;
    clawbackTargetsSucceeded: number;
    clawbackTargetsFailed: number;
    reportsReceived: number;
    reportsResolved: number;
  }> = [];
  /** The recorded audit rows (the triage history reads them). */
  audit: AuditEntry[] = [];

  reset(): void {
    this.clawbacks = [];
    this.targets = [];
    this.reports = [];
    this.settings.clear();
    this.outbox = [];
    this.alertWindows.clear();
    this.reportMailboxes.clear();
    this.resolvedCounters = [];
    this.counters = [];
  }
}

/** A clawback as the mailbox-worker leaves it after materialization (default: `ready`). */
export function seedClawback(
  world: ApiModeWorld,
  organizationId: bigint,
  patch: Partial<StoredClawback> = {},
): StoredClawback {
  const now = new Date();
  const row: StoredClawback = {
    id: world.id(),
    publicId: crypto.randomUUID(),
    organizationId,
    trigger: 'admin',
    status: 'ready',
    signal: { v: 1, kind: 'admin', refs: {}, facts: null, signalAt: now.toISOString() },
    criteria: {
      v: 1,
      window: { from: new Date(now.getTime() - 86_400_000).toISOString(), to: now.toISOString() },
      keys: { messageIdHashes: ['ab'.repeat(32)] },
      directions: ['inbound', 'internal'],
      includeReportMailboxes: false,
    },
    decisionMode: null,
    action: null,
    signalVerdict: null,
    signalLevel: null,
    signalHardBlocks: null,
    cancelRequestedAt: null,
    restoreStatus: 'none',
    targetsTotal: 3,
    mailboxesTotal: 3,
    targetsEligible: 3,
    mailboxesEligible: 3,
    targetsSkipped: 0,
    targetsSimulated: 0,
    targetsQueued: 0,
    targetsSucceeded: 0,
    targetsFailed: 0,
    targetsCancelled: 0,
    restoresQueued: 0,
    restoresSucceeded: 0,
    restoresFailed: 0,
    restoresSkipped: 0,
    requiresApproval: false,
    approvalReasons: null,
    approvalStatus: null,
    approvalRequestedAt: null,
    approvalExpiresAt: null,
    approvalDecidedAt: null,
    approvedByUserId: null,
    approvalDecisionReason: null,
    requestedByType: 'user',
    requestedByUserId: null,
    submittedByUserId: null,
    requestReason: 'Seeded by the test',
    submittedAt: null,
    reportId: null,
    seedCopyId: null,
    seedCopyReceivedAt: null,
    signalAt: now,
    lastErrorCode: null,
    rowVersion: 2,
    startedAt: null,
    completedAt: null,
    createdAt: new Date(now.getTime() - 60_000),
    updatedAt: now,
    reportPublicId: null,
    requestedByUserPublicId: null,
    submittedByUserPublicId: null,
    approvedByUserPublicId: null,
    seedCopyPublicId: null,
    ...patch,
  };
  world.claw.clawbacks.push(row);
  return row;
}

/** A target of a clawback for a copy of the world (default: `matched`). */
export function seedTarget(
  world: ApiModeWorld,
  clawback: StoredClawback,
  c: StoredCopy,
  patch: Partial<StoredTarget> = {},
): StoredTarget {
  const mailbox = world.mailboxes.find((m) => m.id === c.mailboxId)!;
  const row: StoredTarget = {
    id: world.id(),
    organizationId: clawback.organizationId,
    clawbackId: clawback.id,
    copyId: c.id,
    mailboxId: mailbox.id,
    mailboxPublicId: mailbox.publicId,
    mailboxAddress: mailbox.primaryAddress,
    connectionPublicId: mailbox.connectionPublicId,
    detectionPublicId: c.publicId,
    receivedAt: c.receivedAt,
    headerFrom: c.headerFrom,
    subject: c.subject,
    matchKeys: ['message_id'],
    copyRemediationState: c.remediationState,
    status: 'matched',
    plannedAction: null,
    reasonCode: null,
    remediationPublicId: null,
    restoreStatus: 'none',
    restoreReasonCode: null,
    ...patch,
  };
  world.claw.targets.push(row);
  return row;
}

/** A user report received in a report mailbox (default: `pending_triage`, an identified original). */
export function seedReport(
  world: ApiModeWorld,
  reportMailbox: StoredMailbox,
  patch: Partial<StoredReport> = {},
): StoredReport {
  const now = new Date();
  const row: StoredReport = {
    id: world.id(),
    publicId: crypto.randomUUID(),
    organizationId: reportMailbox.organizationId,
    apiConnectionId: reportMailbox.apiConnectionId,
    reportMailboxId: reportMailbox.id,
    status: 'pending_triage',
    reporterAddress: 'sam@contoso.example',
    reportedAt: new Date(now.getTime() - 120_000),
    identification: 'attachment',
    original: {
      v: 1,
      messageIdHash: 'cd'.repeat(32),
      sender: 'billing@fabrikam.example',
      subjectKey: 'Invoice overdue',
      date: new Date(now.getTime() - 3_600_000).toISOString(),
      attachmentSha256: ['ef'.repeat(32)],
      urlSha256: ['12'.repeat(32)],
      extraOriginals: 0,
    },
    groupKey: 'cd'.repeat(32),
    originalIngested: false,
    scanVerdict: 'phishing',
    scanRiskScore: 910,
    scanLevel: 'critical',
    assessment: 'malicious',
    analystVerdict: null,
    analystNote: null,
    triagedAt: null,
    clawbackId: null,
    ackFeedback: 'queued',
    resultFeedback: 'none',
    rejectReason: null,
    rowVersion: 3,
    updatedAt: now,
    clawbackPublicId: null,
    reportMailboxPublicId: reportMailbox.publicId,
    reportMailboxAddress: reportMailbox.primaryAddress,
    reporterMailboxPublicId: null,
    reporterUserPublicId: null,
    triagedByUserPublicId: null,
    originalCopyPublicId: null,
    triagedByUserId: null,
    ...patch,
  };
  world.claw.reports.push(row);
  return row;
}

/** The `ApiClawbackRepository` double over the world and its store. */
export function clawbackRepositoryDouble(
  world: ApiModeWorld,
): Partial<Record<keyof ApiClawbackRepository, unknown>> {
  const s = world.claw;
  const mine = <T extends { organizationId: bigint }>(rows: T[], scope: TenantScope) =>
    rows.filter((r) => r.organizationId === scope.organizationId);
  const strip = <T extends { organizationId: bigint }>(r: T) => {
    const { organizationId: _o, ...rest } = r;
    return clone(rest);
  };
  const clawbackView = (k: StoredClawback): ClawbackRow => {
    const report = s.reports.find((r) => r.id === k.reportId);
    const seed = world.copies.find((c) => c.id === k.seedCopyId);
    const user = (id: bigint | null) =>
      id === null ? null : (world.userPublicIds.get(id) ?? null);
    return strip({
      ...k,
      reportPublicId: report?.publicId ?? null,
      seedCopyPublicId: seed?.publicId ?? null,
      requestedByUserPublicId: k.requestedByUserPublicId ?? user(k.requestedByUserId),
      submittedByUserPublicId: k.submittedByUserPublicId ?? user(k.submittedByUserId),
      approvedByUserPublicId: k.approvedByUserPublicId ?? user(k.approvedByUserId),
    });
  };
  const reportView = (r: StoredReport): ReportRow => {
    const { reportMailboxId: _m, triagedByUserId: _t, ...rest } = strip(r);
    const clawback = s.clawbacks.find((k) => k.id === r.clawbackId);
    return { ...rest, clawbackPublicId: clawback?.publicId ?? null };
  };
  const apiSide = (domainPublicId: string | undefined, organizationId: bigint): boolean => {
    const d = world.domains.find(
      (x) => x.organizationId === organizationId && x.publicId === domainPublicId,
    );
    if (d === undefined) return false;
    const orgMode =
      world.organizations.find((o) => o.id === organizationId)?.protectionMode ?? 'inline';
    return (d.configured ?? orgMode) !== 'inline';
  };
  const mailboxView = (m: StoredMailbox): ReportMailboxRow => {
    const connection = world.connections.find((c) => c.api?.id === m.apiConnectionId);
    const domain = world.domains.find(
      (d) => d.organizationId === m.organizationId && d.publicId === m.domain?.publicId,
    );
    const lastReport = s.reports
      .filter((r) => r.reportMailboxId === m.id)
      .reduce<Date | null>(
        (max, r) => (max === null || r.reportedAt > max ? r.reportedAt : max),
        null,
      );
    return {
      id: m.id,
      publicId: m.publicId,
      primaryAddress: m.primaryAddress,
      apiConnectionId: m.apiConnectionId,
      connectionPublicId: m.connectionPublicId,
      provider: connection?.provider ?? 'microsoft_365',
      status: m.status,
      coverageState: m.coverageState,
      domain:
        domain === undefined
          ? null
          : {
              id: domain.id,
              publicId: domain.publicId,
              name: domain.name,
              apiSide: apiSide(domain.publicId, m.organizationId),
            },
      reportMailbox: s.reportMailboxes.has(m.id),
      reportMailboxAt: s.reportMailboxes.get(m.id) ?? null,
      lastReportAt: lastReport,
    };
  };
  const findClawback = (scope: TenantScope, publicId: string) =>
    mine(s.clawbacks, scope).find((k) => k.publicId === publicId);
  const findReport = (scope: TenantScope, publicId: string) =>
    mine(s.reports, scope).find((r) => r.publicId === publicId);
  const findMailbox = (scope: TenantScope, publicId: string) =>
    world.mailboxes.find(
      (m) => m.organizationId === scope.organizationId && m.publicId === publicId,
    );

  return {
    // ---- settings
    orgSettings: (scope: TenantScope) =>
      Promise.resolve(clone(s.settings.get(scope.organizationId) ?? null)),
    lockOrganization: (_tx: unknown, scope: TenantScope) =>
      Promise.resolve(world.organizations.some((o) => o.id === scope.organizationId)),
    lockOrgSettings: (_tx: unknown, scope: TenantScope) =>
      Promise.resolve(clone(s.settings.get(scope.organizationId) ?? null)),
    createOrgSettings: (_tx: unknown, scope: TenantScope, write: OrgSettingsWrite) => {
      const { updatedByUserId: _u, ...values } = write;
      s.settings.set(scope.organizationId, { ...values, rowVersion: 1, updatedAt: new Date() });
      return Promise.resolve();
    },
    updateOrgSettings: (
      _tx: unknown,
      scope: TenantScope,
      rowVersion: number,
      write: OrgSettingsWrite,
    ) => {
      const current = s.settings.get(scope.organizationId);
      if (current === undefined || current.rowVersion !== rowVersion) return Promise.resolve(false);
      const { updatedByUserId: _u, ...values } = write;
      s.settings.set(scope.organizationId, {
        ...values,
        rowVersion: rowVersion + 1,
        updatedAt: new Date(),
      });
      return Promise.resolve(true);
    },

    // ---- seed detection
    seedCopy: (_tx: unknown, scope: TenantScope, publicId: string) => {
      const c = world.copies.find(
        (x) => x.organizationId === scope.organizationId && x.publicId === publicId,
      );
      if (c === undefined) return Promise.resolve(null);
      return Promise.resolve({
        id: c.id,
        publicId: c.publicId,
        receivedAt: c.receivedAt,
        messageId: c.messageId,
        messageIdHash: 'ab'.repeat(32),
        sender: c.headerFrom?.toLowerCase() ?? null,
        subjectKey: c.subject,
        attachmentSha256: ['ef'.repeat(32)],
        urlSha256: ['12'.repeat(32)],
      });
    },

    // ---- clawbacks
    createClawback: (_tx: unknown, scope: TenantScope, row: CreateClawbackRow) => {
      const k = seedClawback(world, scope.organizationId, {
        publicId: row.publicId,
        trigger: row.trigger,
        status: 'searching',
        signal: clone(row.signal),
        criteria: clone(row.criteria),
        requestedByType: row.requestedByType,
        requestedByUserId: row.requestedByUserId,
        requestReason: row.requestReason,
        reportId: row.reportId,
        seedCopyId: row.seedCopyId,
        seedCopyReceivedAt: row.seedCopyReceivedAt,
        targetsTotal: 0,
        mailboxesTotal: 0,
        targetsEligible: 0,
        mailboxesEligible: 0,
        rowVersion: 1,
        createdAt: row.now,
        signalAt: row.now,
      });
      return Promise.resolve({ id: k.id, publicId: k.publicId, rowVersion: k.rowVersion });
    },
    clawbacks: (
      scope: TenantScope,
      filter: ClawbackFilter,
      range: { from: Date; to: Date },
      page: { take: number; before?: { at: Date; id: bigint } },
    ) =>
      Promise.resolve(
        mine(s.clawbacks, scope)
          .filter(
            (k) =>
              k.createdAt >= range.from &&
              k.createdAt < range.to &&
              (!filter.status || filter.status.includes(k.status)) &&
              (!filter.trigger || filter.trigger.includes(k.trigger)) &&
              (!filter.approvalStatus ||
                (k.approvalStatus !== null && filter.approvalStatus.includes(k.approvalStatus))) &&
              (page.before === undefined ||
                k.createdAt < page.before.at ||
                (k.createdAt.getTime() === page.before.at.getTime() && k.id < page.before.id)),
          )
          .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime() || (a.id < b.id ? 1 : -1))
          .slice(0, page.take)
          .map(clawbackView),
      ),
    clawback: (scope: TenantScope, publicId: string) => {
      const k = findClawback(scope, publicId);
      return Promise.resolve(k ? clawbackView(k) : null);
    },
    lockClawback: (_tx: unknown, scope: TenantScope, publicId: string) => {
      const k = findClawback(scope, publicId);
      return Promise.resolve(k ? clawbackView(k) : null);
    },
    updateClawback: (
      _tx: unknown,
      scope: TenantScope,
      id: bigint,
      rowVersion: number,
      update: ClawbackUpdate,
    ) => {
      const k = mine(s.clawbacks, scope).find((x) => x.id === id);
      if (k === undefined || k.rowVersion !== rowVersion) return Promise.resolve(false);
      const users = world.userPublicIds;
      Object.assign(k, update, { rowVersion: rowVersion + 1, updatedAt: new Date() });
      if ('approvalReasons' in update) {
        k.approvalReasons = Array.isArray(update.approvalReasons) ? update.approvalReasons : null;
      }
      if (update.submittedByUserId !== undefined) {
        k.submittedByUserPublicId =
          update.submittedByUserId === null ? null : (users.get(update.submittedByUserId) ?? null);
      }
      if (update.approvedByUserId !== undefined) {
        k.approvedByUserPublicId =
          update.approvedByUserId === null ? null : (users.get(update.approvedByUserId) ?? null);
      }
      return Promise.resolve(true);
    },
    targets: (
      scope: TenantScope,
      clawbackId: bigint,
      filter: TargetFilter,
      page: { take: number; afterId?: bigint },
    ) =>
      Promise.resolve(
        mine(s.targets, scope)
          .filter(
            (t) =>
              t.clawbackId === clawbackId &&
              (!filter.status || filter.status.includes(t.status)) &&
              (!filter.restoreStatus || filter.restoreStatus.includes(t.restoreStatus)) &&
              (filter.mailboxPublicId === undefined ||
                t.mailboxPublicId === filter.mailboxPublicId) &&
              (page.afterId === undefined || t.id > page.afterId),
          )
          .sort((a, b) => (a.id < b.id ? -1 : 1))
          .slice(0, page.take)
          .map((t) => {
            const { clawbackId: _c, copyId: _p, mailboxId: _m, ...row } = strip(t);
            return row;
          }),
      ),
    clawbacksOfCopies: (
      scope: TenantScope,
      copies: ReadonlyArray<{ id: bigint; receivedAt: Date }>,
      max: number,
    ) => {
      const out = new Map<string, string[]>();
      for (const c of copies) {
        const ids = mine(s.targets, scope)
          .filter((t) => t.copyId === c.id)
          .map((t) => s.clawbacks.find((k) => k.id === t.clawbackId)!)
          .sort((a, b) => (a.id < b.id ? 1 : -1))
          .map((k) => k.publicId);
        if (ids.length > 0) out.set(copyKey(c.id, c.receivedAt), [...new Set(ids)].slice(0, max));
      }
      return Promise.resolve(out);
    },

    // ---- outbox and alerts
    insertOutbox: (_tx: unknown, row: OutboxRow) => {
      s.outbox.push(clone(row));
      return Promise.resolve();
    },
    requestAlert: (
      _tx: unknown,
      input: {
        organizationId: bigint;
        kind: string;
        scopeKey: string;
        window: { from: Date; to: Date };
        windowMinutes: number;
        sourceEventId: string;
        outbox: (suppressedBefore: number) => OutboxRow;
      },
    ) => {
      const key = `${input.organizationId}:${input.kind}:${input.scopeKey}:${input.window.from.getTime()}`;
      const count = s.alertWindows.get(key) ?? 0;
      s.alertWindows.set(key, count + 1);
      if (count > 0) return Promise.resolve(false);
      s.outbox.push(clone(input.outbox(0)));
      return Promise.resolve(true);
    },

    // ---- reports
    reports: (
      scope: TenantScope,
      filter: ReportFilter,
      range: { from: Date; to: Date },
      page: { take: number; before?: { at: Date; id: bigint } },
    ) =>
      Promise.resolve(
        mine(s.reports, scope)
          .filter(
            (r) =>
              r.reportedAt >= range.from &&
              r.reportedAt < range.to &&
              (!filter.status || filter.status.includes(r.status)) &&
              (!filter.assessment ||
                (r.assessment !== null && filter.assessment.includes(r.assessment))) &&
              (!filter.analystVerdict ||
                (r.analystVerdict !== null && filter.analystVerdict.includes(r.analystVerdict))) &&
              (filter.reporter === undefined || r.reporterAddress === filter.reporter) &&
              (page.before === undefined ||
                r.reportedAt < page.before.at ||
                (r.reportedAt.getTime() === page.before.at.getTime() && r.id < page.before.id)),
          )
          .sort((a, b) => b.reportedAt.getTime() - a.reportedAt.getTime() || (a.id < b.id ? 1 : -1))
          .slice(0, page.take)
          .map(reportView),
      ),
    report: (scope: TenantScope, publicId: string) => {
      const r = findReport(scope, publicId);
      return Promise.resolve(r ? reportView(r) : null);
    },
    lockReport: (_tx: unknown, scope: TenantScope, publicId: string) => {
      const r = findReport(scope, publicId);
      return Promise.resolve(r ? reportView(r) : null);
    },
    groupSizes: (scope: TenantScope, keys: readonly string[]) => {
      const out = new Map<string, number>();
      for (const key of new Set(keys)) {
        out.set(key, mine(s.reports, scope).filter((r) => r.groupKey === key).length);
      }
      return Promise.resolve(out);
    },
    groupMembers: (scope: TenantScope, groupKey: string, exceptId: bigint, limit: number) =>
      Promise.resolve(
        mine(s.reports, scope)
          .filter((r) => r.groupKey === groupKey && r.id !== exceptId)
          .sort((a, b) => b.reportedAt.getTime() - a.reportedAt.getTime())
          .slice(0, limit)
          .map((r) => ({
            publicId: r.publicId,
            status: r.status,
            reporterAddress: r.reporterAddress,
            reportedAt: r.reportedAt,
          })),
      ),
    lockOpenGroupReports: (_tx: unknown, scope: TenantScope, groupKey: string, exceptId: bigint) =>
      Promise.resolve(
        mine(s.reports, scope)
          .filter(
            (r) =>
              r.groupKey === groupKey &&
              r.id !== exceptId &&
              (r.status === 'pending_triage' || r.status === 'in_review'),
          )
          .map((r) => ({
            id: r.id,
            publicId: r.publicId,
            status: r.status,
            apiConnectionId: r.apiConnectionId,
            rowVersion: r.rowVersion,
          })),
      ),
    updateReport: (
      _tx: unknown,
      scope: TenantScope,
      id: bigint,
      rowVersion: number,
      update: ReportUpdate,
    ) => {
      const r = mine(s.reports, scope).find((x) => x.id === id);
      if (r === undefined || r.rowVersion !== rowVersion) return Promise.resolve(false);
      Object.assign(r, update, { rowVersion: rowVersion + 1, updatedAt: new Date() });
      if (update.triagedByUserId !== undefined) {
        r.triagedByUserPublicId =
          update.triagedByUserId === null
            ? null
            : (world.userPublicIds.get(update.triagedByUserId) ?? null);
      }
      return Promise.resolve(true);
    },
    reportHistory: (scope: TenantScope, reportPublicId: string, limit: number) =>
      Promise.resolve(
        s.audit
          .filter(
            (e) =>
              e.organizationId === scope.organizationId &&
              e.action === API_MODE_AUDIT.reportTriaged &&
              e.resourceType === API_MODE_RESOURCES.report &&
              e.resourceId === reportPublicId,
          )
          .reverse()
          .slice(0, limit)
          .map((e) => ({
            at: new Date(),
            actorType: e.actor.type,
            actorId: e.actor.type === 'system' ? null : e.actor.id,
            metadata: clone(e.metadata ?? null),
          })),
      ),
    addReportsResolved: (_tx: unknown, _scope: TenantScope, apiConnectionId: bigint, n: number) => {
      s.resolvedCounters.push({ apiConnectionId, n });
      return Promise.resolve();
    },

    // ---- report mailboxes
    reportMailboxes: (scope: TenantScope) =>
      Promise.resolve(
        world.mailboxes
          .filter((m) => m.organizationId === scope.organizationId && s.reportMailboxes.has(m.id))
          .map(mailboxView),
      ),
    countReportMailboxes: (_tx: unknown, scope: TenantScope) =>
      Promise.resolve(
        world.mailboxes.filter(
          (m) => m.organizationId === scope.organizationId && s.reportMailboxes.has(m.id),
        ).length,
      ),
    lockMailbox: (_tx: unknown, scope: TenantScope, publicId: string) => {
      const m = findMailbox(scope, publicId);
      return Promise.resolve(m ? mailboxView(m) : null);
    },
    lockMailboxByAddress: (_tx: unknown, scope: TenantScope, address: string) => {
      const m = world.mailboxes.find(
        (x) =>
          x.organizationId === scope.organizationId &&
          (x.primaryAddress === address || x.aliases.includes(address)),
      );
      return Promise.resolve(m ? mailboxView(m) : null);
    },
    domainForReportAddress: (_tx: unknown, scope: TenantScope, name: string) => {
      const d = world.domains.find(
        (x) => x.organizationId === scope.organizationId && x.name === name,
      );
      if (d === undefined) return Promise.resolve(null);
      const connection = world.connections.find((c) => c.id === d.connectionId);
      return Promise.resolve({
        id: d.id,
        apiSide: apiSide(d.publicId, scope.organizationId),
        apiConnectionId: connection?.api?.id ?? null,
      });
    },
    createDiscoveredMailbox: (
      _tx: unknown,
      scope: TenantScope,
      input: { apiConnectionId: bigint; address: string; domainId: bigint; now: Date },
    ) => {
      const connection = world.connections.find(
        (c) => c.organizationId === scope.organizationId && c.api?.id === input.apiConnectionId,
      )!;
      const m = world.addMailbox(connection, input.address, {
        status: 'discovered',
        providerUserId: null,
        coverageState: 'out_of_scope',
      });
      return Promise.resolve(m.publicId);
    },
    setReportMailbox: (
      _tx: unknown,
      _scope: TenantScope,
      id: bigint,
      enabled: boolean,
      now: Date,
    ) => {
      if (enabled) s.reportMailboxes.set(id, now);
      else s.reportMailboxes.delete(id);
      return Promise.resolve();
    },

    // ---- overview
    clawbackOverview: (scope: TenantScope, now: Date, cap: number) => {
      const rows = mine(s.clawbacks, scope);
      const active = rows.filter((k) =>
        ['searching', 'ready', 'review_required', 'pending_approval', 'queued', 'running'].includes(
          k.status,
        ),
      );
      const oldest = active.reduce<Date | null>(
        (min, k) => (min === null || k.createdAt < min ? k.createdAt : min),
        null,
      );
      return Promise.resolve({
        active: Math.min(active.length, cap),
        reviewRequired: active.filter((k) => k.status === 'review_required').length,
        pendingApproval: active.filter((k) => k.status === 'pending_approval').length,
        completed24h: rows.filter(
          (k) =>
            (k.status === 'completed' || k.status === 'completed_with_errors') &&
            k.completedAt !== null &&
            k.completedAt.getTime() >= now.getTime() - 86_400_000,
        ).length,
        oldestActiveCreatedAt: oldest,
      });
    },
    reportOverview: (scope: TenantScope, apiConnectionIds: readonly bigint[]) => {
      const out = new Map<bigint, unknown>();
      for (const id of apiConnectionIds) {
        const rows = mine(s.reports, scope).filter((r) => r.apiConnectionId === id);
        const pending = rows.filter((r) => r.status === 'pending_triage');
        out.set(id, {
          pendingTriage: pending.length,
          inReview: rows.filter((r) => r.status === 'in_review').length,
          oldestPendingReportedAt: pending.reduce<Date | null>(
            (min, r) => (min === null || r.reportedAt < min ? r.reportedAt : min),
            null,
          ),
          reportMailboxes: world.mailboxes.filter(
            (m) => m.apiConnectionId === id && s.reportMailboxes.has(m.id),
          ).length,
        });
      }
      return Promise.resolve(out);
    },
    clawbackCounters: (scope: TenantScope, apiConnectionIds: readonly bigint[], from: Date) =>
      Promise.resolve(
        mine(s.counters, scope)
          .filter((c) => apiConnectionIds.includes(c.apiConnectionId) && c.hour >= from)
          .map((c) => strip(c)),
      ),
  };
}
