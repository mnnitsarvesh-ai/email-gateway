import { Prisma, type PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import {
  API_MAILBOX_SCOPE_STATES,
  mailboxInScope,
  type ApiMailboxScopeState,
  type ApiModeScopeKind,
} from '@email-gateway/mailbox-api';
import type { MailboxMetrics } from '../metrics/mailbox-metrics';
import { errorFields, InconsistentReadError } from '../shared/errors';

/** Mailboxes evaluated per batch (B6 "bounded batches of 1 000"). */
export const SCOPE_BATCH = 1_000;
const DOMAIN_PAGE = 500;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface ScopeEvaluatorDeps {
  prisma: PrismaClient;
  metrics: MailboxMetrics | null;
  logger: Logger;
  now: () => Date;
  config: {
    /** `API_MODE_SCOPE_REFRESH_MINUTES`: `departments` domains are re-evaluated this often. */
    refreshMinutes: number;
    /** `API_MODE_SCOPE_MAX_DEPARTMENTS`: departments of one scope read. */
    maxDepartments: number;
  };
  organizationIds?: readonly bigint[];
}

export interface ScopeReport {
  domains: number;
  mailboxes: number;
  changed: number;
  failed: number;
}

/** The facts one `departments` scope resolves against (P5: member address or active user). */
export interface DepartmentMembers {
  addresses: ReadonlySet<string>;
  userEmails: ReadonlySet<string>;
}

/**
 * B6: the scope state of one mailbox — `all` → in scope; `mailboxes` → `scope_selected`;
 * `departments` → in scope when the primary or an alias address is a member address of a listed
 * department or the e-mail of an active member user (P5 resolution). Pure.
 */
export function evaluateMailboxScope(
  kind: ApiModeScopeKind,
  mailbox: { scopeSelected: boolean; addresses: readonly string[] },
  members: DepartmentMembers | null,
): ApiMailboxScopeState {
  if (kind !== 'departments') {
    return mailboxInScope(kind, { scopeSelected: mailbox.scopeSelected, scopeState: 'in_scope' })
      ? 'in_scope'
      : 'excluded';
  }
  if (members === null) return 'excluded';
  for (const raw of mailbox.addresses) {
    const address = raw.trim().toLowerCase();
    if (members.addresses.has(address) || members.userEmails.has(address)) return 'in_scope';
  }
  return 'excluded';
}

/** The department public ids of `scope_department_ids` (JSON list), bounded. */
export function scopeDepartmentIds(raw: unknown, max: number): string[] {
  const value = typeof raw === 'string' ? safeJson(raw) : raw;
  if (!Array.isArray(value)) return [];
  const ids = new Set<string>();
  for (const id of value) {
    if (typeof id === 'string' && UUID.test(id)) ids.add(id.toLowerCase());
  }
  return [...ids].slice(0, max);
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

interface DomainScopeRow {
  id: bigint;
  organizationId: bigint;
  domainId: bigint;
  scopeKind: ApiModeScopeKind;
  scopeDepartmentIds: unknown;
  scopeRecomputeRequestedAt: Date | null;
}

/**
 * Mailbox scope evaluation of the health leader (step API-4 B6, ADR-0107): each tick, domains
 * whose scope the api changed (`scope_recompute_requested_at` set) and, every
 * `API_MODE_SCOPE_REFRESH_MINUTES`, every `departments` domain (directory membership changes) are
 * evaluated in batches of 1 000 mailboxes: `scope_state` and `scope_evaluated_at` are written for
 * every mailbox of the domain, the request is cleared (compare-and-set on the requested time, so a
 * newer request is evaluated again). A mailbox newly excluded with a running feed gets a sync
 * request, so the feeds role stops it promptly (cursor cleared, subscription removed); a mailbox
 * back in scope is restarted by the maintenance feed sweep without backfill. Organization
 * echo-checked; logs carry ids and counts only.
 */
export class ScopeEvaluator {
  /** When each `departments` domain was last evaluated by this process (ms). */
  private readonly lastEvaluated = new Map<string, number>();

  constructor(private readonly deps: ScopeEvaluatorDeps) {}

  async runOnce(): Promise<ScopeReport> {
    const now = this.deps.now();
    const report: ScopeReport = { domains: 0, mailboxes: 0, changed: 0, failed: 0 };
    const refreshMs = this.deps.config.refreshMinutes * 60_000;
    let after = 0n;
    for (;;) {
      const rows: DomainScopeRow[] = await this.deps.prisma.apiModeDomainSetting.findMany({
        where: {
          id: { gt: after },
          OR: [{ scopeRecomputeRequestedAt: { not: null } }, { scopeKind: 'departments' }],
          ...(this.deps.organizationIds
            ? { organizationId: { in: [...this.deps.organizationIds] } }
            : {}),
        },
        orderBy: { id: 'asc' },
        take: DOMAIN_PAGE,
        select: {
          id: true,
          organizationId: true,
          domainId: true,
          scopeKind: true,
          scopeDepartmentIds: true,
          scopeRecomputeRequestedAt: true,
        },
      });
      for (const row of rows) {
        const last = this.lastEvaluated.get(row.domainId.toString());
        const due =
          row.scopeRecomputeRequestedAt !== null ||
          (row.scopeKind === 'departments' &&
            (last === undefined || now.getTime() - last >= refreshMs));
        if (!due) continue;
        try {
          const result = await this.evaluateDomain(row, now);
          report.domains += 1;
          report.mailboxes += result.mailboxes;
          report.changed += result.changed;
          this.lastEvaluated.set(row.domainId.toString(), now.getTime());
        } catch (error) {
          report.failed += 1;
          this.deps.logger.warn(
            { domainId: row.domainId.toString(), ...errorFields(error) },
            'api-mode mailbox scope not evaluated; retried next run',
          );
        }
      }
      if (rows.length < DOMAIN_PAGE) break;
      after = rows[rows.length - 1]!.id;
    }
    if (this.lastEvaluated.size > 100_000) this.lastEvaluated.clear();
    if (report.domains > 0) {
      this.deps.logger.info(
        { domains: report.domains, mailboxes: report.mailboxes, changed: report.changed },
        'api-mode mailbox scope evaluated',
      );
    }
    return report;
  }

  /** One domain's scope (also called directly by tests). */
  async evaluateDomain(
    row: DomainScopeRow,
    now: Date,
  ): Promise<{ mailboxes: number; changed: number }> {
    const prisma = this.deps.prisma;
    const organizationId = row.organizationId;
    const domain = await prisma.domain.findUnique({
      where: { id: row.domainId },
      select: { organizationId: true, deletedAt: true },
    });
    if (domain && domain.organizationId !== organizationId) {
      throw new InconsistentReadError('domains');
    }
    let mailboxes = 0;
    let changed = 0;
    if (domain && domain.deletedAt === null) {
      const members =
        row.scopeKind === 'departments' ? await this.members(organizationId, row) : null;
      let after = 0n;
      for (;;) {
        const page = await prisma.apiMailbox.findMany({
          where: { domainId: row.domainId, organizationId, id: { gt: after } },
          orderBy: { id: 'asc' },
          take: SCOPE_BATCH,
          select: {
            id: true,
            organizationId: true,
            primaryAddress: true,
            scopeSelected: true,
            scopeState: true,
            feedStatus: true,
          },
        });
        if (page.length === 0) break;
        const ids = page.map((m) => m.id);
        const aliases =
          row.scopeKind === 'departments'
            ? await prisma.apiMailboxAddress.findMany({
                where: { mailboxId: { in: ids }, organizationId },
                select: { mailboxId: true, address: true, organizationId: true },
              })
            : [];
        const byMailbox = new Map<bigint, string[]>();
        for (const a of aliases) {
          if (a.organizationId !== organizationId) {
            throw new InconsistentReadError('api_mailbox_addresses');
          }
          const list = byMailbox.get(a.mailboxId) ?? [];
          list.push(a.address);
          byMailbox.set(a.mailboxId, list);
        }
        const groups = new Map<ApiMailboxScopeState, bigint[]>(
          API_MAILBOX_SCOPE_STATES.map((s) => [s, []]),
        );
        const stopFeeds: bigint[] = [];
        for (const m of page) {
          if (m.organizationId !== organizationId) throw new InconsistentReadError('api_mailboxes');
          const state = evaluateMailboxScope(
            row.scopeKind,
            {
              scopeSelected: m.scopeSelected,
              addresses: [m.primaryAddress, ...(byMailbox.get(m.id) ?? [])],
            },
            members,
          );
          groups.get(state)!.push(m.id);
          if (state !== m.scopeState) {
            changed += 1;
            if (state === 'excluded' && m.feedStatus !== 'off') stopFeeds.push(m.id);
          }
        }
        for (const [state, list] of groups) {
          if (list.length === 0) continue;
          await prisma.$executeRaw`
            UPDATE api_mailboxes SET scope_state = ${state}, scope_evaluated_at = ${now}
            WHERE id IN (${Prisma.join(list)}) AND organization_id = ${organizationId}`;
        }
        if (stopFeeds.length > 0) {
          await prisma.$executeRaw`
            UPDATE api_mailboxes SET sync_requested_at = ${now}
            WHERE id IN (${Prisma.join(stopFeeds)}) AND organization_id = ${organizationId}
              AND feed_status <> 'off'`;
        }
        mailboxes += page.length;
        if (page.length < SCOPE_BATCH) break;
        after = page[page.length - 1]!.id;
      }
    }
    if (row.scopeRecomputeRequestedAt !== null) {
      await prisma.apiModeDomainSetting.updateMany({
        where: {
          id: row.id,
          organizationId,
          scopeRecomputeRequestedAt: row.scopeRecomputeRequestedAt,
        },
        data: { scopeRecomputeRequestedAt: null },
      });
    }
    return { mailboxes, changed };
  }

  /** P5: the member addresses and active member users' e-mails of the scope's departments. */
  private async members(organizationId: bigint, row: DomainScopeRow): Promise<DepartmentMembers> {
    const prisma = this.deps.prisma;
    const publicIds = scopeDepartmentIds(row.scopeDepartmentIds, this.deps.config.maxDepartments);
    if (publicIds.length === 0) return { addresses: new Set(), userEmails: new Set() };
    const departments = await prisma.tenantDepartment.findMany({
      where: { organizationId, publicId: { in: publicIds } },
      select: { id: true, organizationId: true },
    });
    for (const d of departments) {
      if (d.organizationId !== organizationId)
        throw new InconsistentReadError('tenant_departments');
    }
    if (departments.length === 0) return { addresses: new Set(), userEmails: new Set() };
    const members = await prisma.tenantDepartmentMember.findMany({
      where: { organizationId, departmentId: { in: departments.map((d) => d.id) } },
      select: { organizationId: true, address: true, userId: true },
    });
    const addresses = new Set<string>();
    const userIds = new Set<bigint>();
    for (const m of members) {
      if (m.organizationId !== organizationId) {
        throw new InconsistentReadError('tenant_department_members');
      }
      if (m.address !== null) addresses.add(m.address.trim().toLowerCase());
      if (m.userId !== null) userIds.add(m.userId);
    }
    const userEmails = new Set<string>();
    if (userIds.size > 0) {
      const users = await prisma.user.findMany({
        where: { id: { in: [...userIds] }, organizationId, status: 'active', deletedAt: null },
        select: { organizationId: true, email: true },
      });
      for (const u of users) {
        if (u.organizationId !== organizationId) throw new InconsistentReadError('users');
        userEmails.add(u.email.trim().toLowerCase());
      }
    }
    return { addresses, userEmails };
  }

  /** `api_mode_scope_mailboxes{state}` (no organization label; deleted mailboxes not counted). */
  async gauge(): Promise<void> {
    const m = this.deps.metrics;
    if (!m) return;
    const orgs = this.deps.organizationIds;
    const rows = await this.deps.prisma.$queryRaw<
      Array<{ scope_state: string; n: bigint | number }>
    >`
      SELECT scope_state, COUNT(*) AS n FROM api_mailboxes
      WHERE status <> 'deleted'
        ${orgs ? Prisma.sql`AND organization_id IN (${Prisma.join(orgs)})` : Prisma.empty}
      GROUP BY scope_state`;
    const counts = new Map<string, number>(API_MAILBOX_SCOPE_STATES.map((s) => [s, 0]));
    for (const r of rows) counts.set(r.scope_state, Number(r.n));
    for (const [state, n] of counts) m.scopeMailboxes.set({ state }, n);
  }
}
