import { Inject, Injectable, Logger } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { checkDictionaryTerms } from '@email-gateway/dlp';
import { API_CONFIG } from '../../../api-config.token';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { pageWindow, toPage } from '../../../http/pagination';
import type { ClientContext } from '../../auth/services/session.service';
import { isUniqueViolation } from '../../domains/repositories/domains.repository';
import {
  dlpDictionaryInvalid,
  dlpExists,
  dlpInUse,
  dlpLimitReached,
  dlpNotFound,
  dlpVersionConflict,
} from '../dlp.errors';
import { twoDecimals } from '../domain/dlp-inputs';
import type {
  DlpDictionaryCreate,
  DlpDictionaryDetail,
  DlpDictionaryPage,
  DlpDictionaryUpdate,
  DlpListQuery,
} from '../dto/dlp.schemas';
import { DlpConfigRepository, type DictionaryData } from '../repositories/dlp-config.repository';
import {
  conditionsOf,
  DlpAuditor,
  dictionaryDetail,
  dictionaryImage,
  dictionaryView,
} from './dlp-views';
import { DLP_AUDIT, DLP_RESOURCE, DlpWriter, userIdOf } from './dlp-writer';

type Limits = { DLP_DICTIONARIES_MAX_PER_TENANT: number; DLP_DICTIONARY_MAX_TERMS: number };

const strings = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];

/**
 * Tenant keyword dictionaries (step 4.5 D8, D21). Terms are validated with
 * `checkDictionaryTerms` (1..DLP_DICTIONARY_MAX_TERMS, 1–64 characters, 1–8 tokens after the
 * bec normalization, unique after normalization; `400 dictionary_terms_count` /
 * `dictionary_term_invalid` with the index, never the term). Terms may be confidential project
 * names: they are shown to `dlp:read` holders only, **never logged and never in audit metadata
 * (term counts only)**, and never in the scans read API. At most DLP_DICTIONARIES_MAX_PER_TENANT
 * per organization; deleting a dictionary a rule selects is `409 dlp_dictionary_in_use`.
 */
@Injectable()
export class DlpDictionariesService {
  private readonly logger = new Logger(DlpDictionariesService.name);

  constructor(
    @Inject(API_CONFIG) private readonly limits: Limits,
    private readonly repository: DlpConfigRepository,
    private readonly writer: DlpWriter,
    private readonly auditor: DlpAuditor,
  ) {}

  async list(scope: TenantScope, query: DlpListQuery): Promise<DlpDictionaryPage> {
    const rows = await this.repository.listDictionaries(scope, {
      ...pageWindow(query),
      ...(query.enabled !== undefined && { enabled: query.enabled }),
    });
    return toPage(rows, query.limit, dictionaryView);
  }

  async get(scope: TenantScope, id: string): Promise<DlpDictionaryDetail> {
    const row = await this.repository.findDictionary(scope, id);
    if (!row) throw dlpNotFound('dictionary');
    return dictionaryDetail(row);
  }

  async create(
    principal: Principal,
    scope: TenantScope,
    body: DlpDictionaryCreate,
    client: ClientContext,
  ): Promise<DlpDictionaryDetail> {
    const data: DictionaryData = {
      name: body.name,
      category: body.category,
      terms: this.checkTerms(body.terms),
      severity: body.severity,
      baseConfidence: twoDecimals(body.baseConfidence),
      minMatches: body.minMatches,
      enabled: body.enabled,
    };
    try {
      const view = await this.writer.run(async (tx) => {
        await this.repository.lockOrganization(tx, scope);
        const existing = await this.repository.dictionaryByName(tx, scope, body.name);
        if (existing) throw dlpExists('dictionary', existing.publicId);
        const count = await this.repository.countDictionaries(tx, scope);
        if (count >= this.limits.DLP_DICTIONARIES_MAX_PER_TENANT) {
          throw dlpLimitReached('dictionaries', this.limits.DLP_DICTIONARIES_MAX_PER_TENANT);
        }
        const row = await this.repository.createDictionary(
          tx,
          scope,
          uuidv7(),
          data,
          userIdOf(principal),
        );
        await this.record(tx, principal, scope, client, DLP_AUDIT.dictionaryCreated, row.publicId, {
          after: dictionaryImage(row),
        });
        return dictionaryDetail(row);
      });
      this.logChange('created', scope, view.id, view.termCount);
      return view;
    } catch (error) {
      if (isUniqueViolation(error)) throw dlpExists('dictionary', null);
      throw error;
    }
  }

  async update(
    principal: Principal,
    scope: TenantScope,
    id: string,
    body: DlpDictionaryUpdate,
    client: ClientContext,
  ): Promise<DlpDictionaryDetail> {
    const terms = body.terms === undefined ? undefined : this.checkTerms(body.terms);
    try {
      const view = await this.writer.run(async (tx) => {
        await this.repository.lockOrganization(tx, scope);
        const current = await this.repository.findDictionaryForUpdate(tx, scope, id);
        if (!current) throw dlpNotFound('dictionary');
        if (current.version !== body.version) throw dlpVersionConflict(current.version);
        if (body.name !== undefined && body.name !== current.name) {
          const other = await this.repository.dictionaryByName(tx, scope, body.name);
          if (other && other.id !== current.id) throw dlpExists('dictionary', other.publicId);
        }
        const data: DictionaryData = {
          name: body.name ?? current.name,
          category: body.category ?? current.category,
          terms: terms ?? strings(current.terms),
          severity: body.severity ?? current.severity,
          baseConfidence: twoDecimals(body.baseConfidence ?? current.baseConfidence),
          minMatches: body.minMatches ?? current.minMatches,
          enabled: body.enabled ?? current.enabled,
        };
        const updated = await this.repository.updateDictionary(
          tx,
          scope,
          current.id,
          body.version,
          data,
          userIdOf(principal),
        );
        if (!updated) throw dlpVersionConflict(current.version);
        const row = await this.repository.dictionaryById(tx, scope, current.id);
        await this.record(tx, principal, scope, client, DLP_AUDIT.dictionaryUpdated, row.publicId, {
          before: dictionaryImage(current),
          after: dictionaryImage(row),
          termsChanged: terms !== undefined,
        });
        return dictionaryDetail(row);
      });
      this.logChange('updated', scope, view.id, view.termCount);
      return view;
    } catch (error) {
      if (isUniqueViolation(error)) throw dlpExists('dictionary', null);
      throw error;
    }
  }

  async remove(
    principal: Principal,
    scope: TenantScope,
    id: string,
    version: number | undefined,
    client: ClientContext,
  ): Promise<void> {
    await this.writer.run(async (tx) => {
      await this.repository.lockOrganization(tx, scope);
      const current = await this.repository.findDictionaryForUpdate(tx, scope, id);
      if (!current) throw dlpNotFound('dictionary');
      if (version !== undefined && current.version !== version) {
        throw dlpVersionConflict(current.version);
      }
      const rules = await this.repository.allRuleConditions(tx, scope);
      const references = rules.filter((rule) =>
        (conditionsOf(rule.conditions).selectors.dictionaryIds ?? []).includes(current.publicId),
      ).length;
      if (references > 0) throw dlpInUse('dictionary', references);
      await this.repository.deleteDictionary(tx, scope, current.id);
      await this.record(
        tx,
        principal,
        scope,
        client,
        DLP_AUDIT.dictionaryDeleted,
        current.publicId,
        {
          before: dictionaryImage(current),
        },
      );
    });
    this.logChange('deleted', scope, id, null);
  }

  /** D8 term validation against the configured cap; terms are stored as entered (trimmed). */
  private checkTerms(raw: readonly string[]): string[] {
    const terms = raw.map((term) => term.trim());
    const check = checkDictionaryTerms(terms, this.limits.DLP_DICTIONARY_MAX_TERMS);
    if (!check.ok) throw dlpDictionaryInvalid(check.code, check.index);
    return terms;
  }

  private record(
    tx: Prisma.TransactionClient,
    principal: Principal,
    scope: TenantScope,
    client: ClientContext,
    action: string,
    resourceId: string,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    return this.auditor.record(tx, {
      principal,
      scope,
      client,
      action,
      resourceType: DLP_RESOURCE.dictionary,
      resourceId,
      metadata,
    });
  }

  /** Ids and the term count only: names and terms are never logged. */
  private logChange(change: string, scope: TenantScope, id: string, terms: number | null): void {
    this.logger.log({
      message: `dlp keyword dictionary ${change}`,
      organizationId: scope.organizationId.toString(),
      id,
      ...(terms !== null && { termCount: terms }),
    });
  }
}
