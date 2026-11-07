import { Inject, Injectable, InternalServerErrorException, Logger } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { compileCustomPattern, testCustomPattern } from '@email-gateway/dlp';
import { API_CONFIG } from '../../../api-config.token';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { pageWindow, toPage } from '../../../http/pagination';
import type { ClientContext } from '../../auth/services/session.service';
import { isUniqueViolation } from '../../domains/repositories/domains.repository';
import {
  DLP_PATTERN_CODES,
  dlpExists,
  dlpInUse,
  dlpLimitReached,
  dlpNotFound,
  dlpPatternInvalid,
  dlpVersionConflict,
} from '../dlp.errors';
import { twoDecimals } from '../domain/dlp-inputs';
import type {
  DlpListQuery,
  DlpPatternCreate,
  DlpPatternPage,
  DlpPatternTest,
  DlpPatternTestResult,
  DlpPatternUpdate,
  DlpPatternView,
} from '../dto/dlp.schemas';
import { DlpConfigRepository, type PatternData } from '../repositories/dlp-config.repository';
import { conditionsOf, DlpAuditor, patternImage, patternView } from './dlp-views';
import { DLP_AUDIT, DLP_RESOURCE, DlpMetrics, DlpWriter, userIdOf } from './dlp-writer';

type Limits = {
  DLP_CUSTOM_PATTERNS_MAX_PER_TENANT: number;
  DLP_CUSTOM_PATTERN_MAX_LENGTH: number;
  DLP_CUSTOM_PATTERN_PROBE_MAX_MS: number;
};

const isPatternCode = (code: string): code is (typeof DLP_PATTERN_CODES)[number] =>
  (DLP_PATTERN_CODES as readonly string[]).includes(code);

/**
 * Tenant custom patterns (step 4.5 D9, D21) and the pattern test endpoint. Every create and
 * update runs `compileCustomPattern` (re2js: RE2 semantics, no backtracking; length,
 * unsupported constructs, repetition bounds, empty match, breadth and cost probes): a refusal is
 * a `400` with the D9 code and the measured complexity, never the pattern. At most
 * DLP_CUSTOM_PATTERNS_MAX_PER_TENANT per organization; deleting a pattern a rule selects is
 * `409 dlp_pattern_in_use`.
 *
 * **The test endpoint persists nothing and never logs, audits or echoes the sample or the
 * pattern:** the response carries masked matches only, an unexpected failure is a generic `500`
 * without the cause (whose message could hold the pattern), and the only trace is
 * `dlp_pattern_tests_total{result}`.
 */
@Injectable()
export class DlpPatternsService {
  private readonly logger = new Logger(DlpPatternsService.name);

  constructor(
    @Inject(API_CONFIG) private readonly limits: Limits,
    private readonly repository: DlpConfigRepository,
    private readonly writer: DlpWriter,
    private readonly auditor: DlpAuditor,
    private readonly metrics: DlpMetrics,
  ) {}

  private get compileLimits() {
    return {
      maxLength: this.limits.DLP_CUSTOM_PATTERN_MAX_LENGTH,
      probeMaxMs: this.limits.DLP_CUSTOM_PATTERN_PROBE_MAX_MS,
    };
  }

  async list(scope: TenantScope, query: DlpListQuery): Promise<DlpPatternPage> {
    const rows = await this.repository.listPatterns(scope, {
      ...pageWindow(query),
      ...(query.enabled !== undefined && { enabled: query.enabled }),
    });
    return toPage(rows, query.limit, patternView);
  }

  async get(scope: TenantScope, id: string): Promise<DlpPatternView> {
    const row = await this.repository.findPattern(scope, id);
    if (!row) throw dlpNotFound('pattern');
    return patternView(row);
  }

  async create(
    principal: Principal,
    scope: TenantScope,
    body: DlpPatternCreate,
    client: ClientContext,
  ): Promise<DlpPatternView> {
    const data: PatternData = {
      name: body.name,
      pattern: body.pattern,
      caseInsensitive: body.caseInsensitive,
      validator: body.validator,
      contextKeywords: [...body.contextKeywords],
      requireContext: body.requireContext,
      severity: body.severity,
      baseConfidence: twoDecimals(body.baseConfidence),
      maskStyle: body.maskStyle,
      enabled: body.enabled,
    };
    this.validate(data);
    try {
      const view = await this.writer.run(async (tx) => {
        await this.repository.lockOrganization(tx, scope);
        const existing = await this.repository.patternByName(tx, scope, body.name);
        if (existing) throw dlpExists('pattern', existing.publicId);
        const count = await this.repository.countPatterns(tx, scope);
        if (count >= this.limits.DLP_CUSTOM_PATTERNS_MAX_PER_TENANT) {
          throw dlpLimitReached('custom_patterns', this.limits.DLP_CUSTOM_PATTERNS_MAX_PER_TENANT);
        }
        const row = await this.repository.createPattern(
          tx,
          scope,
          uuidv7(),
          data,
          userIdOf(principal),
        );
        await this.record(tx, principal, scope, client, DLP_AUDIT.patternCreated, row.publicId, {
          after: patternImage(row),
        });
        return patternView(row);
      });
      this.logChange('created', scope, view.id);
      return view;
    } catch (error) {
      if (isUniqueViolation(error)) throw dlpExists('pattern', null);
      throw error;
    }
  }

  async update(
    principal: Principal,
    scope: TenantScope,
    id: string,
    body: DlpPatternUpdate,
    client: ClientContext,
  ): Promise<DlpPatternView> {
    try {
      const view = await this.writer.run(async (tx) => {
        await this.repository.lockOrganization(tx, scope);
        const current = await this.repository.findPatternForUpdate(tx, scope, id);
        if (!current) throw dlpNotFound('pattern');
        if (current.version !== body.version) throw dlpVersionConflict(current.version);
        if (body.name !== undefined && body.name !== current.name) {
          const other = await this.repository.patternByName(tx, scope, body.name);
          if (other && other.id !== current.id) throw dlpExists('pattern', other.publicId);
        }
        const before = patternImage(current);
        const data: PatternData = {
          name: body.name ?? current.name,
          pattern: body.pattern ?? current.pattern,
          caseInsensitive: body.caseInsensitive ?? current.caseInsensitive,
          validator: body.validator ?? current.validator,
          contextKeywords: body.contextKeywords
            ? [...body.contextKeywords]
            : before.contextKeywords,
          requireContext: body.requireContext ?? current.requireContext,
          severity: body.severity ?? current.severity,
          baseConfidence: twoDecimals(body.baseConfidence ?? current.baseConfidence),
          maskStyle: body.maskStyle ?? current.maskStyle,
          enabled: body.enabled ?? current.enabled,
        };
        // Re-validated on every update: a library upgrade may refuse an old pattern (D9).
        this.validate(data);
        const updated = await this.repository.updatePattern(
          tx,
          scope,
          current.id,
          body.version,
          data,
          userIdOf(principal),
        );
        if (!updated) throw dlpVersionConflict(current.version);
        const row = await this.repository.patternById(tx, scope, current.id);
        await this.record(tx, principal, scope, client, DLP_AUDIT.patternUpdated, row.publicId, {
          before,
          after: patternImage(row),
        });
        return patternView(row);
      });
      this.logChange('updated', scope, view.id);
      return view;
    } catch (error) {
      if (isUniqueViolation(error)) throw dlpExists('pattern', null);
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
      const current = await this.repository.findPatternForUpdate(tx, scope, id);
      if (!current) throw dlpNotFound('pattern');
      if (version !== undefined && current.version !== version) {
        throw dlpVersionConflict(current.version);
      }
      const rules = await this.repository.allRuleConditions(tx, scope);
      const references = rules.filter((rule) =>
        (conditionsOf(rule.conditions).selectors.customPatternIds ?? []).includes(current.publicId),
      ).length;
      if (references > 0) throw dlpInUse('pattern', references);
      await this.repository.deletePattern(tx, scope, current.id);
      await this.record(tx, principal, scope, client, DLP_AUDIT.patternDeleted, current.publicId, {
        before: patternImage(current),
      });
    });
    this.logChange('deleted', scope, id);
  }

  /**
   * `POST /dlp/patterns/test` (D9): validation and ≤ 50 masked matches of the ≤ 4 096-character
   * sample. Persists nothing; logs, audits and echoes neither the sample nor the pattern.
   */
  test(body: DlpPatternTest): DlpPatternTestResult {
    let result: ReturnType<typeof testCustomPattern>;
    try {
      result = testCustomPattern(
        {
          pattern: body.pattern,
          caseInsensitive: body.caseInsensitive,
          ...(body.validator !== undefined && { validator: body.validator }),
          ...(body.contextKeywords !== undefined && { contextKeywords: body.contextKeywords }),
          ...(body.requireContext !== undefined && { requireContext: body.requireContext }),
          ...(body.maskStyle !== undefined && { maskStyle: body.maskStyle }),
        },
        body.sample,
        this.compileLimits,
      );
    } catch (error) {
      // The error message could carry the pattern: only its class name is logged, and the
      // response is a generic 500 without the cause.
      this.metrics.patternTests.inc({ result: 'invalid' });
      this.logger.warn({
        message: 'dlp pattern test failed unexpectedly',
        errorName: error instanceof Error ? error.name : typeof error,
      });
      throw new InternalServerErrorException('The pattern test failed');
    }
    this.metrics.patternTests.inc({ result: result.valid ? 'valid' : 'invalid' });
    return {
      valid: result.valid,
      code: result.code ?? null,
      complexity: { ...result.complexity },
      matches: result.matches.map((m) => ({
        start: m.start,
        end: m.end,
        masked: m.masked,
        validated: m.validated,
        contextMatched: m.contextMatched,
      })),
    };
  }

  /** D9 validation of a stored pattern's fields; `400` with the D9 code otherwise. */
  private validate(data: PatternData): void {
    const result = compileCustomPattern(
      {
        pattern: data.pattern,
        caseInsensitive: data.caseInsensitive,
        validator: data.validator,
        contextKeywords: data.contextKeywords,
        requireContext: data.requireContext,
      },
      this.compileLimits,
    );
    if (result.ok) return;
    const code = isPatternCode(result.code) ? result.code : 'pattern_syntax';
    throw dlpPatternInvalid(code, result.complexity ?? null);
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
      resourceType: DLP_RESOURCE.pattern,
      resourceId,
      metadata,
    });
  }

  /** Ids only: the pattern, its name and keywords are never logged. */
  private logChange(change: string, scope: TenantScope, id: string): void {
    this.logger.log({
      message: `dlp custom pattern ${change}`,
      organizationId: scope.organizationId.toString(),
      id,
    });
  }
}
