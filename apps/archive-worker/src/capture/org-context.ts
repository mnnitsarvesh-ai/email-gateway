import {
  ARCHIVE_SETTINGS_DEFAULTS,
  createScopeMatcher,
  type ObjectLockMode,
  resolveArchiveSettings,
  type ResolvedArchiveSettings,
  type ResolvedJournalScope,
} from '@email-gateway/archive';
import type { Logger } from '@email-gateway/logger';
import type { Db } from '../shared/db';
import { InconsistentReadError } from '../shared/errors';

/** The plan feature that entitles an organization to archiving (A20; seed: enterprise, dedicated). */
export const ARCHIVING_FEATURE = 'archiving';

/**
 * Most department members a journal scope resolves: the settings name ≤ 50 departments and the
 * api bounds a department by `DEPARTMENT_MAX_MEMBERS` (default 5 000), so the default maximum
 * (250 000) is read completely, in keyset pages of MEMBER_PAGE. Beyond it the scope is reported
 * truncated (warn log, `archive_scope_truncated_total`), never cut silently.
 */
export const SCOPE_MAX_DEPARTMENT_MEMBERS = 250_000;
const MEMBER_PAGE = 10_000;

/** Everything capture needs to know about an organization, cached per settings generation. */
export interface OrgArchiveContext {
  organizationId: bigint;
  entitled: boolean;
  /** `archive_settings.enabled` (no row = false). */
  enabled: boolean;
  settings: ResolvedArchiveSettings;
  /** False when the stored document is not `archive-settings/1` (journaling then stops). */
  settingsValid: boolean;
  generation: bigint;
  journalEnabledAt: Date | null;
  objectLockMode: ObjectLockMode;
  defaultRetentionPolicyId: bigint | null;
  /** The scope matcher (addresses, users, departments, verified domains resolved once). */
  matcher: (address: string) => boolean;
  /** Scope ids that no longer resolve inside the organization. */
  unresolved: number;
  /** The department members exceeded SCOPE_MAX_DEPARTMENT_MEMBERS (the rest is not in scope). */
  scopeTruncated: boolean;
}

interface CacheEntry {
  value: OrgArchiveContext;
  at: number;
}

const disabledSettings = (): ResolvedArchiveSettings => resolveArchiveSettings(null);

/**
 * Organization context of the capture role (A3, A4, A22): entitlement (`organization_features`
 * `archiving`), `archive_settings` (typed columns + the `archive-settings/1` document with the
 * defaults applied) and the resolved scope. Cached for `ARCHIVE_SETTINGS_CACHE_TTL_MS`; the scope
 * is resolved again only when the settings generation changes. Unresolved scope ids are ignored
 * and counted (`archive_scope_unresolved_total`).
 */
export class OrgContextCache {
  private readonly cache = new Map<string, CacheEntry>();
  private readonly scopes = new Map<
    string,
    {
      generation: bigint;
      matcher: (a: string) => boolean;
      unresolved: number;
      truncated: boolean;
    }
  >();

  constructor(
    private readonly db: Db,
    private readonly options: {
      ttlMs: number;
      logger: Logger;
      onUnresolved?: (count: number) => void;
      onTruncated?: () => void;
      now?: () => number;
    },
  ) {}

  private now(): number {
    return this.options.now?.() ?? Date.now();
  }

  invalidate(organizationId?: bigint): void {
    if (organizationId === undefined) {
      this.cache.clear();
      this.scopes.clear();
    } else {
      this.cache.delete(organizationId.toString());
    }
  }

  async get(organizationId: bigint): Promise<OrgArchiveContext> {
    const key = organizationId.toString();
    const hit = this.cache.get(key);
    if (hit !== undefined && this.now() - hit.at < this.options.ttlMs) return hit.value;
    const value = await this.load(organizationId);
    this.cache.set(key, { value, at: this.now() });
    return value;
  }

  private async load(organizationId: bigint): Promise<OrgArchiveContext> {
    const [feature, row] = await Promise.all([
      this.db.organizationFeature.findUnique({
        where: { organizationId_featureKey: { organizationId, featureKey: ARCHIVING_FEATURE } },
        select: { organizationId: true, featureKey: true, enabled: true },
      }),
      this.db.archiveSetting.findUnique({
        where: { organizationId },
        select: {
          organizationId: true,
          enabled: true,
          settings: true,
          generation: true,
          journalEnabledAt: true,
          objectLockMode: true,
          defaultRetentionPolicyId: true,
        },
      }),
    ]);
    if (feature !== null && feature.organizationId !== organizationId) {
      throw new InconsistentReadError('organization_feature');
    }
    if (row !== null && row.organizationId !== organizationId) {
      throw new InconsistentReadError('archive_settings');
    }
    let settings: ResolvedArchiveSettings;
    let settingsValid = true;
    try {
      settings = resolveArchiveSettings(row?.settings ?? null);
    } catch {
      settingsValid = false;
      settings = disabledSettings();
      this.options.logger.warn(
        { organizationId: organizationId.toString() },
        'archive settings document invalid; journaling paused for the organization',
      );
    }
    const generation = row?.generation ?? 0n;
    const scope =
      settings.scope.mode === 'all' || !settingsValid
        ? { matcher: () => false, unresolved: 0, truncated: false }
        : await this.scopeMatcher(organizationId, generation, settings);
    return {
      organizationId,
      entitled: feature?.enabled === true,
      enabled: row?.enabled === true && settingsValid,
      settings,
      settingsValid,
      generation,
      journalEnabledAt: row?.journalEnabledAt ?? null,
      objectLockMode: row?.objectLockMode ?? 'none',
      defaultRetentionPolicyId: row?.defaultRetentionPolicyId ?? null,
      matcher: scope.matcher,
      unresolved: scope.unresolved,
      scopeTruncated: scope.truncated,
    };
  }

  private async scopeMatcher(
    organizationId: bigint,
    generation: bigint,
    settings: ResolvedArchiveSettings,
  ): Promise<{ matcher: (a: string) => boolean; unresolved: number; truncated: boolean }> {
    const key = organizationId.toString();
    const cached = this.scopes.get(key);
    if (cached !== undefined && cached.generation === generation) return cached;
    const { scope, unresolved, truncated } = await resolveScope(this.db, organizationId, settings);
    const entry = { generation, matcher: createScopeMatcher(scope), unresolved, truncated };
    this.scopes.set(key, entry);
    if (unresolved > 0) this.options.onUnresolved?.(unresolved);
    if (truncated) {
      this.options.onTruncated?.();
      this.options.logger.warn(
        {
          organizationId: organizationId.toString(),
          maxMembers: SCOPE_MAX_DEPARTMENT_MEMBERS,
          mode: settings.scope.mode,
        },
        'archive journal scope truncated: department members beyond the bound are not in scope',
      );
    }
    return entry;
  }
}

/**
 * Resolves the public ids of a scope inside the organization (A4): users' emails, department
 * members (addresses and member users' emails) and verified domain names. Ids that do not
 * resolve are counted, never guessed.
 */
export async function resolveScope(
  db: Db,
  organizationId: bigint,
  settings: Pick<ResolvedArchiveSettings, 'scope'>,
): Promise<{ scope: ResolvedJournalScope; unresolved: number; truncated: boolean }> {
  const s = settings.scope;
  let unresolved = 0;
  const users =
    s.userIds.length === 0
      ? []
      : await db.user.findMany({
          where: { organizationId, publicId: { in: s.userIds }, deletedAt: null },
          select: { organizationId: true, publicId: true, email: true },
        });
  unresolved += s.userIds.length - users.filter((u) => u.organizationId === organizationId).length;
  const departments =
    s.departmentIds.length === 0
      ? []
      : await db.tenantDepartment.findMany({
          where: { organizationId, publicId: { in: s.departmentIds } },
          select: { id: true, organizationId: true },
        });
  const deptIds = departments.filter((d) => d.organizationId === organizationId).map((d) => d.id);
  unresolved += s.departmentIds.length - deptIds.length;
  // Every member, in keyset pages, up to the bound; one row more tells a truncation.
  const members: Array<{
    organizationId: bigint;
    address: string | null;
    user: { email: string } | null;
  }> = [];
  let truncated = false;
  let after = 0n;
  while (deptIds.length > 0) {
    const page = await db.tenantDepartmentMember.findMany({
      where: { organizationId, departmentId: { in: deptIds }, id: { gt: after } },
      select: {
        id: true,
        organizationId: true,
        address: true,
        user: { select: { email: true } },
      },
      orderBy: { id: 'asc' },
      take: MEMBER_PAGE,
    });
    for (const m of page) {
      if (members.length === SCOPE_MAX_DEPARTMENT_MEMBERS) {
        truncated = true;
        break;
      }
      members.push(m);
    }
    if (truncated || page.length < MEMBER_PAGE) break;
    after = page[page.length - 1]!.id;
  }
  const domains =
    s.domainIds.length === 0
      ? []
      : await db.domain.findMany({
          where: {
            organizationId,
            publicId: { in: s.domainIds },
            status: { in: ['verified', 'active'] },
            deletedAt: null,
          },
          select: { organizationId: true, name: true },
        });
  const ownDomains = domains.filter((d) => d.organizationId === organizationId);
  unresolved += s.domainIds.length - ownDomains.length;
  return {
    scope: {
      addresses: s.addresses,
      userEmails: users.filter((u) => u.organizationId === organizationId).map((u) => u.email),
      departmentAddresses: members
        .filter((m) => m.organizationId === organizationId)
        .flatMap((m) => [m.address, m.user?.email].filter((a): a is string => !!a)),
      domains: ownDomains.map((d) => d.name),
    },
    unresolved,
    truncated,
  };
}

/** Exposed for tests: the defaults applied when no settings row exists. */
export const DEFAULT_SETTINGS = ARCHIVE_SETTINGS_DEFAULTS;
