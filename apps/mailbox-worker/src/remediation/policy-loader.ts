import type { Logger } from '@email-gateway/logger';
import {
  parseRemediationPolicy,
  resolveEffectivePolicy,
  type EffectiveRemediationPolicy,
  type RemediationPolicyDocument,
  type StoredRemediationPolicy,
} from '@email-gateway/mailbox-api';
import type { Db } from '../shared/db';
import { InconsistentReadError } from '../shared/errors';

/** How long an organization's policy rows are reused in process (R2.6). */
export const POLICY_CACHE_TTL_MS = 30_000;
/** Parsed documents kept per process (by policy public id and row version). */
const PARSED_MAX = 10_000;
const ORGS_MAX = 10_000;

/** An invalid stored document decides nothing (no rule): never more than the tenant asked for. */
const NO_RULES: RemediationPolicyDocument = Object.freeze({ v: 1, rules: [] });

export interface OrganizationPolicies {
  organization: StoredRemediationPolicy | null;
  domains: StoredRemediationPolicy[];
}

interface CacheEntry {
  loadedAt: number;
  rows: OrganizationPolicies;
}

/**
 * The remediation policies of an organization (`api_remediation_policies`, R2.6), read on the
 * writer and kept in process for 30 s per organization. Parsed documents are memoized by
 * `(public_id, row_version)`, so a changed row is re-validated on the next load and an unchanged
 * one never is. A stored document that fails the strict schema (written by an older api, or
 * edited by hand) acts as a policy without rules — nothing is remediated by it — and is logged
 * once per row version (public id only).
 */
export class RemediationPolicyLoader {
  private readonly byOrg = new Map<string, CacheEntry>();
  private readonly parsed = new Map<string, RemediationPolicyDocument>();

  constructor(private readonly deps: { now: () => Date; logger: Logger; ttlMs?: number }) {}

  /** Forgets the cached rows (one organization, or all). */
  invalidate(organizationId?: bigint): void {
    if (organizationId === undefined) this.byOrg.clear();
    else this.byOrg.delete(organizationId.toString());
  }

  async rows(db: Db, organizationId: bigint): Promise<OrganizationPolicies> {
    const key = organizationId.toString();
    const nowMs = this.deps.now().getTime();
    const ttl = this.deps.ttlMs ?? POLICY_CACHE_TTL_MS;
    const cached = this.byOrg.get(key);
    if (cached && nowMs - cached.loadedAt >= 0 && nowMs - cached.loadedAt < ttl) {
      return cached.rows;
    }
    const stored = await db.apiRemediationPolicy.findMany({
      where: { organizationId },
      select: {
        publicId: true,
        organizationId: true,
        domainId: true,
        mode: true,
        document: true,
        rowVersion: true,
      },
      orderBy: { id: 'asc' },
    });
    const rows: OrganizationPolicies = { organization: null, domains: [] };
    for (const row of stored) {
      if (row.organizationId !== organizationId) {
        throw new InconsistentReadError('api_remediation_policies');
      }
      const policy: StoredRemediationPolicy = {
        publicId: row.publicId,
        domainId: row.domainId,
        mode: row.mode,
        document: this.document(row.publicId, row.rowVersion, row.document),
        rowVersion: row.rowVersion,
      };
      if (row.domainId === null) rows.organization = policy;
      else rows.domains.push(policy);
    }
    if (this.byOrg.size >= ORGS_MAX) this.byOrg.clear();
    this.byOrg.set(key, { loadedAt: nowMs, rows });
    return rows;
  }

  /** R2.6: the domain row, else the organization row, else the platform default P1. */
  async effective(
    db: Db,
    organizationId: bigint,
    domainId: bigint | null,
  ): Promise<EffectiveRemediationPolicy> {
    return resolveEffectivePolicy(await this.rows(db, organizationId), domainId);
  }

  private document(publicId: string, rowVersion: number, raw: unknown): RemediationPolicyDocument {
    const key = `${publicId}:${String(rowVersion)}`;
    const known = this.parsed.get(key);
    if (known) return known;
    const result = parseRemediationPolicy(raw);
    const document = result.ok ? result.document : NO_RULES;
    if (!result.ok) {
      this.deps.logger.warn(
        { policyId: publicId, rowVersion, issues: result.issues.length },
        'stored remediation policy is invalid; it decides no action until it is saved again',
      );
    }
    if (this.parsed.size >= PARSED_MAX) this.parsed.clear();
    this.parsed.set(key, document);
    return document;
  }
}
