import {
  aliasesForIndexCreation,
  buildIndexMappingUpdate,
  buildIndexTemplate,
  indexPattern,
  indexTemplateName,
  newIndexAliasActions,
  organizationTerm,
  removeTenantAliasActions,
  tenantAliasActions,
  tenantAliasName,
} from '@email-gateway/archive';
import type { OpenSearchService } from '@email-gateway/common';
import type { Db } from '../shared/db';
import { archiveOrganizations } from '../shared/db';

/** How often the index role re-reads the active index version. */
export const VERSION_CHECK_MS = 60_000;

/** Every `<prefix>-v<n>` template with its rebuild state (`_meta.state = 'building'`). */
export async function listTemplateVersions(
  search: OpenSearchService,
  prefix: string,
): Promise<Array<{ version: number; building: boolean }>> {
  const res = await search.request<{
    index_templates?: Array<{ name?: string; index_template?: { _meta?: { state?: unknown } } }>;
  }>('GET', `/_index_template/${prefix}-v*`, { allowStatuses: [404] });
  if (res.status === 404) return [];
  const out: Array<{ version: number; building: boolean }> = [];
  for (const t of res.body?.index_templates ?? []) {
    const m =
      typeof t.name === 'string' ? new RegExp(`^${prefix}-v([1-9][0-9]{0,2})$`).exec(t.name) : null;
    if (!m) continue;
    out.push({ version: Number(m[1]), building: t.index_template?._meta?.state === 'building' });
  }
  return out.sort((a, b) => a.version - b.version);
}

/**
 * Physical layout of the archive search index (A16, ADR-0068, §4.3): the composable template
 * `<prefix>-v<n>`, yearly indices `<prefix>-v<n>-<yyyy>` created on demand, and one filtered
 * alias per tenant `<prefix>-t<organizationId>` (term `org_id`, routing). A new yearly index is
 * created with every known tenant alias in the same request, and a tenant's alias is added to
 * every existing index before its first document, so a tenant alias always spans every index of
 * the current version. Names never come from user input.
 */
export class IndexManager {
  private templateReady = false;
  private readonly knownIndices = new Set<string>();
  private readonly knownAliases = new Set<string>();
  private activeVersion: number;
  private versionCheckedAt = 0;

  constructor(
    private readonly search: OpenSearchService,
    private readonly db: Db,
    readonly options: {
      prefix: string;
      shards: number;
      replicas: number;
      /** Fixed version (the rebuild CLI); otherwise the active one is detected (A16 rebuild). */
      version?: number;
      now?: () => number;
    },
  ) {
    this.activeVersion = options.version ?? 1;
  }

  get version(): number {
    return this.activeVersion;
  }

  /** Forgets cached state (after a rebuild swap or in tests). */
  reset(): void {
    this.templateReady = false;
    this.knownIndices.clear();
    this.knownAliases.clear();
    this.versionCheckedAt = 0;
  }

  /**
   * The active index version (A16 rebuild): the highest `<prefix>-v<n>` template whose `_meta`
   * is not marked `building` (the rebuild CLI marks its target until the alias swap). Re-read at
   * most every `VERSION_CHECK_MS`; a version change resets the cached indices and aliases.
   */
  async refreshVersion(): Promise<number> {
    if (this.options.version !== undefined) return this.activeVersion;
    const now = this.options.now?.() ?? Date.now();
    if (now - this.versionCheckedAt < VERSION_CHECK_MS) return this.activeVersion;
    const versions = await listTemplateVersions(this.search, this.options.prefix);
    const active = versions.filter((v) => !v.building).map((v) => v.version);
    const next = active.length === 0 ? 1 : Math.max(...active);
    if (next !== this.activeVersion) {
      this.activeVersion = next;
      this.templateReady = false;
      this.knownIndices.clear();
      this.knownAliases.clear();
    }
    this.versionCheckedAt = now;
    return this.activeVersion;
  }

  /**
   * The template of the active version, then the additive mapping update of the current mapping
   * revision on every existing index of the version (step 8.6: the keyword field `ingest_sources`,
   * `buildIndexMappingUpdate`), so documents with the new field never meet an index without it.
   * New yearly indices get the field from the template.
   */
  async ensureTemplate(): Promise<void> {
    if (this.templateReady) return;
    await this.search.putIndexTemplate(
      indexTemplateName(this.options.prefix, this.version),
      buildIndexTemplate({
        prefix: this.options.prefix,
        version: this.version,
        shards: this.options.shards,
        replicas: this.options.replicas,
      }),
    );
    await this.ensureMappingRevision();
    this.templateReady = true;
  }

  /** The additive mapping update on every index of the version (no index yet: nothing to do). */
  async ensureMappingRevision(): Promise<void> {
    const indices = await this.indices();
    if (indices.length === 0) return;
    await this.search.request(
      'PUT',
      `/${indexPattern(this.options.prefix, this.version)}/_mapping`,
      {
        body: buildIndexMappingUpdate(),
      },
    );
  }

  /** Indices of the current version (`<prefix>-v<n>-*`). */
  async indices(): Promise<string[]> {
    const res = await this.search.request<Array<{ index?: string }>>(
      'GET',
      `/_cat/indices/${indexPattern(this.options.prefix, this.version)}`,
      { query: { format: 'json', h: 'index' }, allowStatuses: [404] },
    );
    if (res.status === 404 || !Array.isArray(res.body)) return [];
    return res.body
      .map((r) => r.index)
      .filter((i): i is string => typeof i === 'string')
      .sort();
  }

  /** Indices that carry a tenant's alias. */
  async aliasIndices(organizationId: bigint): Promise<string[]> {
    const alias = tenantAliasName(this.options.prefix, organizationId);
    const res = await this.search.request<Record<string, unknown>>('GET', `/_alias/${alias}`, {
      allowStatuses: [404],
    });
    if (res.status === 404 || res.body === null || typeof res.body !== 'object') return [];
    return Object.keys(res.body).sort();
  }

  /**
   * Creates the yearly index (with every known tenant alias) if it does not exist yet; when
   * another replica created it first, the aliases are added in one `_aliases` call.
   */
  async ensureIndex(index: string, extraOrganizations: readonly bigint[] = []): Promise<void> {
    if (this.knownIndices.has(index)) return;
    await this.ensureTemplate();
    if (!(await this.search.indexExists(index))) {
      const tenants = [
        ...new Set([...(await archiveOrganizations(this.db, undefined)), ...extraOrganizations]),
      ];
      const created = await this.search.createIndex(index, {
        aliases: aliasesForIndexCreation(this.options.prefix, tenants),
      });
      if (!created.created) {
        await this.search.updateAliases(newIndexAliasActions(this.options.prefix, index, tenants));
      }
    }
    this.knownIndices.add(index);
  }

  /** Adds the tenant's alias to every current index that lacks it (before its first document). */
  async ensureTenantAlias(organizationId: bigint): Promise<void> {
    const key = organizationTerm(organizationId);
    if (this.knownAliases.has(key)) return;
    const [all, have] = await Promise.all([this.indices(), this.aliasIndices(organizationId)]);
    const missing = all.filter((i) => !have.includes(i));
    if (missing.length > 0) {
      await this.search.updateAliases(
        tenantAliasActions(this.options.prefix, organizationId, missing),
      );
    }
    this.knownAliases.add(key);
  }

  /** Removes a tenant alias from every index (organization purge). */
  async removeTenantAlias(organizationId: bigint): Promise<void> {
    const have = await this.aliasIndices(organizationId);
    if (have.length > 0) {
      await this.search.updateAliases(
        removeTenantAliasActions(this.options.prefix, organizationId, have),
      );
    }
    this.knownAliases.delete(organizationTerm(organizationId));
  }
}
