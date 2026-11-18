import { decimalIdOrNull, type NumericId } from '../ids';

/**
 * OpenSearch names (A16, ADR-0068). No user input ever names an index: every name is derived
 * from `ARCHIVE_SEARCH_INDEX_PREFIX`, the index version and the organization id of the
 * authenticated principal or of the row being processed.
 *
 * - composable template `<prefix>-v<version>` for `<prefix>-v<version>-*`;
 * - yearly indices `<prefix>-v<version>-<yyyy>` by the UTC year of `received_at`;
 * - one filtered alias per tenant `<prefix>-t<organizationId>` (term `org_id`, routing).
 */

export const INDEX_PREFIX_PATTERN = /^[a-z][a-z0-9-]{2,40}$/;
export const DEFAULT_INDEX_PREFIX = 'eg-archive';

export class ArchiveSearchNameError extends Error {
  constructor(what: string) {
    super(`Invalid archive search ${what}`);
    this.name = 'ArchiveSearchNameError';
  }
}

function prefixOf(prefix: string): string {
  if (!INDEX_PREFIX_PATTERN.test(prefix)) throw new ArchiveSearchNameError('index prefix');
  return prefix;
}

function versionOf(version: number): number {
  if (!Number.isInteger(version) || version < 1 || version > 999) {
    throw new ArchiveSearchNameError('index version');
  }
  return version;
}

export function organizationTerm(organizationId: NumericId): string {
  const id = decimalIdOrNull(organizationId);
  if (id === null) throw new ArchiveSearchNameError('organization id');
  return id;
}

export function indexTemplateName(prefix: string, version = 1): string {
  return `${prefixOf(prefix)}-v${versionOf(version)}`;
}

export function indexPattern(prefix: string, version = 1): string {
  return `${indexTemplateName(prefix, version)}-*`;
}

export function yearlyIndexName(prefix: string, receivedAt: Date, version = 1): string {
  const year = receivedAt.getUTCFullYear();
  if (!Number.isInteger(year) || year < 1970 || year > 9999) {
    throw new ArchiveSearchNameError('received_at');
  }
  return `${indexTemplateName(prefix, version)}-${String(year).padStart(4, '0')}`;
}

export function tenantAliasName(prefix: string, organizationId: NumericId): string {
  return `${prefixOf(prefix)}-t${organizationTerm(organizationId)}`;
}

/** The yearly indices covering a `received_at` range (inclusive), oldest first. */
export function yearlyIndicesBetween(prefix: string, from: Date, to: Date, version = 1): string[] {
  const a = from.getUTCFullYear();
  const b = to.getUTCFullYear();
  const out: string[] = [];
  for (let y = a; y <= b; y += 1)
    out.push(yearlyIndexName(prefix, new Date(Date.UTC(y, 0, 1)), version));
  return out;
}

export interface AliasAction {
  add?: { index: string; alias: string; filter: { term: { org_id: string } }; routing: string };
  remove?: { index: string; alias: string };
}

/** `_aliases` body adding a tenant's filtered alias to indices (before its first document). */
export function tenantAliasActions(
  prefix: string,
  organizationId: NumericId,
  indices: readonly string[],
): { actions: AliasAction[] } {
  const org = organizationTerm(organizationId);
  const alias = tenantAliasName(prefix, org);
  return {
    actions: indices.map((index) => ({
      add: { index, alias, filter: { term: { org_id: org } }, routing: org },
    })),
  };
}

/** `_aliases` body for a new yearly index: every known tenant alias added to it at once. */
export function newIndexAliasActions(
  prefix: string,
  index: string,
  organizationIds: readonly NumericId[],
): { actions: AliasAction[] } {
  const orgs = [...new Set(organizationIds.map((o) => organizationTerm(o)))];
  return {
    actions: orgs.map((org) => ({
      add: {
        index,
        alias: tenantAliasName(prefix, org),
        filter: { term: { org_id: org } },
        routing: org,
      },
    })),
  };
}

/** `_aliases` body removing a tenant alias from indices (organization purge, rebuild swap). */
export function removeTenantAliasActions(
  prefix: string,
  organizationId: NumericId,
  indices: readonly string[],
): { actions: AliasAction[] } {
  const alias = tenantAliasName(prefix, organizationId);
  return { actions: indices.map((index) => ({ remove: { index, alias } })) };
}

/** `index.aliases` of `PUT /<index>` creating a yearly index with tenant aliases. */
export function aliasesForIndexCreation(
  prefix: string,
  organizationIds: readonly NumericId[],
): Record<string, { filter: { term: { org_id: string } }; routing: string }> {
  const out: Record<string, { filter: { term: { org_id: string } }; routing: string }> = {};
  for (const o of organizationIds) {
    const org = organizationTerm(o);
    out[tenantAliasName(prefix, org)] = { filter: { term: { org_id: org } }, routing: org };
  }
  return out;
}
