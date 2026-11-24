import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  atoAccountsWanted,
  buildReportModel,
  byteLength,
  findTool,
  normalizeSections,
  parseSource,
  plannedSources,
  REPORT_TEMPLATE_VERSION,
  type ReportCardData,
  reportDigestOf,
  reportHasNoData,
  type ReportModel,
  type ReportSourceDef,
  type ReportSourceResult,
  type ReportSourceResults,
  ReportTooLargeError,
  type ReportWindow,
  renderReportHtml,
  resolveReportWindow,
} from '@email-gateway/assistant';
import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../../../api-config.token';
import { AuditService } from '../../../../audit/audit.service';
import {
  ASSISTANT_AUDIT,
  AUDIT_RESOURCE,
  type AssistantConfig,
  REPORT_SOURCE_CONCURRENCY,
  utcDayStart,
} from '../../assistant.constants';
import {
  REPORT_ERROR_CODES,
  REPORT_GUARD_MESSAGES,
  REPORT_GUARDS,
  type ReportGuard,
} from '../../assistant.errors';
import { sourceCorrelationId } from '../../domain/correlation';
import { toolAvailability } from '../../domain/tool-catalog';
import { ReportsRepository } from '../../repositories/reports.repository';
import { AssistantMetrics } from '../assistant-metrics';
import { buildLoopbackRequest, LoopbackDispatcher } from '../loopback-client';
import type { ExecutionContext } from '../tool-executor.service';
import { ReportObjectStore, reportObjectKey, sha256Hex } from './report-object-store';

/** A refusal of a native call (recorded by the executor as `deny`). */
export interface NativeDenial {
  kind: 'denied';
  decision: 'denied_guard' | 'denied_budget' | 'denied_disabled' | 'denied_schema';
  message: string;
  /** The refusing guard (`denied_guard`). */
  guard?: ReportGuard;
  /** A specific code for the envelope and the stored error code (else the decision). */
  code?: string;
  /** Further audit metadata (ids, codes, a domain and a hash only; never an address). */
  auditExtra?: Record<string, string>;
  /**
   * Argument keys whose values are not stored or audited (a refused recipient address: only its
   * domain and SHA-256 are kept, design 31 D5 step 2).
   */
  redact?: readonly string[];
}

/** A failed native execution (recorded by the executor like an API error). */
export interface NativeFailure {
  kind: 'failed';
  status: 'failed' | 'timeout';
  /** The status the envelope and card carry. */
  httpStatus: number;
  /** The stored `http_status` (null when no response, e.g. a timeout); 401 ends the turn. */
  recordedStatus: number | null;
  code: string;
  message: string;
  details?: Record<string, string | number>;
}

/** A stored, available-to-be report (the executor's persist transaction makes it `available`). */
export interface GeneratedReport {
  kind: 'report';
  reportRowId: bigint;
  report: ReportCardData;
  /** `assistant.report_generated` metadata (D11; keys survive the credential scrub). */
  audit: Record<string, unknown>;
}

export type ReportGenerateResult = NativeDenial | NativeFailure | GeneratedReport;

export interface ReportGenerateInput {
  ctx: ExecutionContext;
  /** Public id and sequence of the native execution (header and correlation ids). */
  executionId: string;
  seq: number;
  args: Readonly<Record<string, unknown>>;
}

export { sourceCorrelationId };

/** Runs `fn` over `items` with at most `limit` in flight; results in item order. */
async function mapLimit<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const out: R[] = new Array<R>(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const index = next;
      next += 1;
      if (index >= items.length) return;
      out[index] = await fn(items[index]!, index);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => worker()));
  return out;
}

type SourceRead =
  | { kind: 'result'; result: ReportSourceResult }
  | { kind: 'session_expired' }
  | { kind: 'aborted' };

const codeOf = (body: unknown, status: number): string => {
  const code = (body as { code?: unknown } | null)?.code;
  return typeof code === 'string' && /^[a-z0-9_.:-]{1,64}$/i.test(code) ? code : `http_${status}`;
};

/**
 * `report_generate` (step AI-R D2 steps 1–9, design 31; ADR-0095): the organization check, the
 * per-user daily limit, the window, the fixed source plan of the package with the permission
 * pre-check (a source the principal may not read is NOT requested), the internal loopback reads
 * with the turn's own credential (concurrency 4, the per-call timeout, aborted with the turn), the
 * pure model and renderer of `@email-gateway/assistant`, the size cap and the storage (a
 * `pending` row, then the object, then — in the executor's persist transaction — the row
 * `available` with the execution and the `assistant.report_generated` audit). Every figure comes
 * from an API response read in this request (I15); the HTML is inert (I16) and never stored in
 * MySQL (I5). Logs carry ids and codes only.
 */
@Injectable()
export class ReportGeneratorService {
  private readonly logger = new Logger(ReportGeneratorService.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: AssistantConfig,
    private readonly reports: ReportsRepository,
    private readonly store: ReportObjectStore,
    private readonly loopback: LoopbackDispatcher,
    private readonly audit: AuditService,
    private readonly metrics: AssistantMetrics,
  ) {}

  now(): Date {
    return new Date();
  }

  async generate(input: ReportGenerateInput): Promise<ReportGenerateResult> {
    const { ctx, args } = input;
    const principal = ctx.principal;
    // 1. One organization: a platform principal needs an override.
    if (principal.organizationKind === 'platform' && !principal.override) {
      this.metrics.reports.inc({ outcome: 'denied' });
      return this.guard(REPORT_GUARDS.needsOrganization);
    }
    const now = this.now();
    // 2. The per-user daily generation limit (UTC day, every status counts).
    const used = await this.reports.countSince(ctx.owner, utcDayStart(now));
    if (used >= this.config.ASSISTANT_REPORTS_PER_USER_PER_DAY) {
      this.metrics.reports.inc({ outcome: 'denied' });
      return {
        kind: 'denied',
        decision: 'denied_budget',
        code: REPORT_ERROR_CODES.generationLimit,
        message: `You generated the maximum of ${this.config.ASSISTANT_REPORTS_PER_USER_PER_DAY} reports for today (UTC); try again tomorrow.`,
      };
    }
    // 3. The window (validated again server-side; the schema already checked the shapes).
    const resolved = resolveReportWindow(
      { range: args.range, from: args.from, to: args.to },
      { now, maxRangeDays: this.config.REPORTS_MAX_RANGE_DAYS },
    );
    if (!resolved.ok) {
      this.metrics.reports.inc({ outcome: 'denied' });
      return {
        kind: 'denied',
        decision: 'denied_schema',
        code: resolved.code,
        message: `The arguments do not match the tool’s input schema. ${resolved.message}`,
      };
    }
    const window = resolved.window;
    const sections = normalizeSections(args.sections);

    // 4–6. The source plan, the permission pre-check and the reads.
    const read = await this.readSources(input, window, sections);
    if (read.kind === 'session_expired') {
      this.metrics.reports.inc({ outcome: 'failed' });
      return {
        kind: 'failed',
        status: 'failed',
        httpStatus: 401,
        recordedStatus: 401,
        code: 'unauthorized',
        message: 'Your session expired.',
      };
    }
    if (read.kind === 'aborted') {
      this.metrics.reports.inc({ outcome: 'failed' });
      return {
        kind: 'failed',
        status: 'failed',
        httpStatus: 499,
        recordedStatus: null,
        code: 'tool_aborted',
        message: 'The turn was cancelled.',
      };
    }

    // 7–8. Compose and render (pure); the organization name as the turn knows it.
    const generatedAt = now.toISOString();
    const model = buildReportModel(read.results, {
      window,
      generatedAt,
      organizationName: ctx.organizationName ?? 'Your organization',
      sections,
    });
    this.observeSources(model);
    if (reportHasNoData(model)) {
      this.metrics.reports.inc({ outcome: 'failed' });
      return this.failure(
        503,
        REPORT_ERROR_CODES.sourcesUnavailable,
        'None of the report sources answered; try again later or open the Reports page.',
      );
    }
    let html: string;
    try {
      html = renderReportHtml(model, { maxBytes: this.config.ASSISTANT_REPORT_MAX_HTML_BYTES });
    } catch (error) {
      if (!(error instanceof ReportTooLargeError)) throw error;
      this.metrics.reports.inc({ outcome: 'failed' });
      return this.failure(
        413,
        REPORT_ERROR_CODES.tooLarge,
        'The report is too large; ask for a shorter period or fewer sections.',
        { limit: this.config.ASSISTANT_REPORT_MAX_HTML_BYTES },
      );
    }

    // 9. Store: the pending row, then the object (the executor's transaction makes it available).
    const bytes = Buffer.from(html, 'utf8');
    const sha256 = sha256Hex(bytes);
    const sizeBytes = byteLength(html);
    const reportId = uuidv7(now.getTime());
    const organizationId = ctx.owner.scope.organizationId;
    const key = reportObjectKey(organizationId, reportId, now);
    const digest = reportDigestOf(model);
    const reportRowId = await this.reports.insertPending(ctx.owner, {
      publicId: reportId,
      platformOverrideId: principal.override?.id ?? null,
      conversationId: ctx.conversationId,
      title: digest.title.slice(0, 200),
      periodFrom: new Date(window.from),
      periodTo: new Date(window.to),
      granularity: window.granularity,
      sections: {
        included: digest.sections,
        omitted: digest.omitted,
        atoRange: window.atoRange,
        range: window.range,
        label: digest.period.label,
      } as unknown as Prisma.InputJsonValue,
      figures: digest.figures as unknown as Prisma.InputJsonValue,
      templateVersion: REPORT_TEMPLATE_VERSION,
      objectKey: key,
      sizeBytes,
      sha256,
      createdAt: now,
    });
    try {
      await this.store.put(organizationId, key, bytes, sha256);
    } catch (error) {
      await this.reports.markFailed(ctx.owner, reportRowId, REPORT_ERROR_CODES.storageFailed);
      this.metrics.reports.inc({ outcome: 'failed' });
      this.logger.warn({
        message: 'Assistant report object could not be stored',
        executionId: input.executionId,
        reportId,
        code: (error as { name?: unknown }).name ?? 'error',
      });
      return this.failure(
        502,
        REPORT_ERROR_CODES.storageFailed,
        'The report could not be stored; try again in a moment.',
      );
    }
    this.metrics.reports.inc({ outcome: 'generated' });
    this.metrics.reportBytes.observe(sizeBytes);
    this.logger.log({
      message: 'Assistant report generated',
      executionId: input.executionId,
      reportId,
      sizeBytes,
      omitted: model.omitted.length,
    });
    return {
      kind: 'report',
      reportRowId,
      report: { reportId, generatedAt, sizeBytes, ...digest },
      audit: {
        reportId,
        conversationId: ctx.conversationPublicId,
        executionId: input.executionId,
        period: {
          from: window.from,
          to: window.to,
          granularity: window.granularity,
          atoRange: window.atoRange,
        },
        sections: digest.sections,
        // `code` keys would be dropped by the audit credential-key scrub: `error`.
        omitted: digest.omitted.map((o) => ({
          section: o.section,
          reason: o.reason,
          error: o.code ?? null,
        })),
        sizeBytes,
        sha256,
        templateVersion: REPORT_TEMPLATE_VERSION,
        sources: model.sources
          .filter((s) => s.outcome !== 'not_called' || s.code !== undefined)
          .map((s) => ({
            tool: s.tool,
            outcome: s.outcome,
            httpStatus: s.httpStatus,
            error: s.code ?? null,
          })),
      },
    };
  }

  /**
   * D2 step 9, inside the execution's persist transaction: the row `pending → available` with
   * the execution, and `assistant.report_generated` (D11). A row that moved meanwhile (a sweep)
   * aborts the transaction: the execution is not recorded as a success.
   */
  async finalize(
    ctx: ExecutionContext,
    generated: GeneratedReport,
    executionRowId: bigint,
    tx: Prisma.TransactionClient,
  ): Promise<void> {
    if (!(await this.reports.markAvailable(ctx.owner, generated.reportRowId, executionRowId, tx))) {
      throw new Error('assistant report row is no longer pending');
    }
    await this.audit.record(
      {
        organizationId: ctx.owner.scope.organizationId,
        actor: this.audit.actorFrom(ctx.principal),
        action: ASSISTANT_AUDIT.reportGenerated,
        resourceType: AUDIT_RESOURCE.report,
        resourceId: generated.report.reportId,
        sourceIp: ctx.clientIp,
        metadata: generated.audit,
      },
      tx,
    );
  }

  /**
   * D2 steps 4–6: the planned sources in their fixed order; a source whose tool the principal
   * may not use is not requested (`permission`); `ato_accounts` only after an overview with
   * monitoring on. A `401` ends the turn; an aborted turn aborts the report.
   */
  private async readSources(
    input: ReportGenerateInput,
    window: ReportWindow,
    sections: ReturnType<typeof normalizeSections>,
  ): Promise<
    { kind: 'ok'; results: ReportSourceResults } | { kind: 'session_expired' } | { kind: 'aborted' }
  > {
    const plan = plannedSources(sections);
    const results: ReportSourceResults = {};
    const numbered = plan.map((def, index) => ({ def, n: index + 1 }));
    const first = numbered.filter((entry) => entry.def.after === undefined);
    const reads = await mapLimit(first, REPORT_SOURCE_CONCURRENCY, (entry) =>
      this.readSource(input, entry.def, window, entry.n),
    );
    const outcome = (list: SourceRead[]) =>
      list.some((r) => r.kind === 'session_expired')
        ? ({ kind: 'session_expired' } as const)
        : list.some((r) => r.kind === 'aborted')
          ? ({ kind: 'aborted' } as const)
          : null;
    const stop = outcome(reads);
    if (stop) return stop;
    first.forEach((entry, i) => {
      const read = reads[i]!;
      if (read.kind === 'result') results[entry.def.key] = read.result;
    });
    for (const entry of numbered.filter((e) => e.def.after === 'ato_overview')) {
      const overview = results.ato_overview;
      if (overview?.status !== 'ok') continue;
      const parsed = parseSource('ato_overview', overview.body);
      if (!parsed.ok || !atoAccountsWanted(parsed.data)) continue;
      const read = await this.readSource(input, entry.def, window, entry.n);
      const late = outcome([read]);
      if (late) return late;
      if (read.kind === 'result') results[entry.def.key] = read.result;
    }
    return { kind: 'ok', results };
  }

  private async readSource(
    input: ReportGenerateInput,
    def: ReportSourceDef,
    window: ReportWindow,
    n: number,
  ): Promise<SourceRead> {
    const { ctx } = input;
    const tool = findTool(def.tool);
    if (!tool || tool.access !== 'read' || tool.method !== 'GET') {
      return {
        kind: 'result',
        result: { status: 'unavailable', httpStatus: null, code: 'tool_unavailable' },
      };
    }
    // The pre-filter predicate (`satisfiesRequirement` of the guard): no request without it.
    const availability = toolAvailability(ctx.principal, tool);
    if (!availability.available) {
      return availability.reason === 'permission'
        ? { kind: 'result', result: { status: 'permission' } }
        : {
            kind: 'result',
            result: { status: 'unavailable', httpStatus: null, code: 'tool_disabled' },
          };
    }
    const request = buildLoopbackRequest(tool, def.args(window));
    const result = await this.loopback.send({
      method: 'GET',
      path: request.path,
      authorization: ctx.authorization,
      correlationId: sourceCorrelationId(ctx.correlationBase, input.seq, n),
      clientIp: ctx.clientIp,
      executionId: input.executionId,
      signal: ctx.signal,
    });
    switch (result.kind) {
      case 'response':
        if (result.status === 401) return { kind: 'session_expired' };
        if (result.status >= 200 && result.status < 300) {
          return {
            kind: 'result',
            result: { status: 'ok', httpStatus: result.status, body: result.body },
          };
        }
        return {
          kind: 'result',
          result: {
            status: 'unavailable',
            httpStatus: result.status,
            code: codeOf(result.body, result.status),
          },
        };
      case 'too_large':
        return {
          kind: 'result',
          result: {
            status: 'unavailable',
            httpStatus: result.status,
            code: 'tool_result_too_large',
          },
        };
      case 'timeout':
        return {
          kind: 'result',
          result: { status: 'unavailable', httpStatus: null, code: 'tool_timeout' },
        };
      case 'aborted':
        return { kind: 'aborted' };
      case 'unavailable':
        return {
          kind: 'result',
          result: { status: 'unavailable', httpStatus: null, code: 'tool_unavailable' },
        };
    }
  }

  private observeSources(model: ReportModel): void {
    for (const source of model.sources) {
      if (source.outcome === 'not_called') continue;
      this.metrics.reportSources.inc({ tool: source.tool, outcome: source.outcome });
      if (source.outcome === 'unexpected') {
        this.logger.warn({
          message: 'Assistant report source answered an unexpected shape',
          tool: source.tool,
        });
      }
    }
  }

  private guard(guard: ReportGuard): NativeDenial {
    return {
      kind: 'denied',
      decision: 'denied_guard',
      guard,
      message: REPORT_GUARD_MESSAGES[guard],
    };
  }

  private failure(
    httpStatus: number,
    code: string,
    message: string,
    details?: Record<string, string | number>,
  ): NativeFailure {
    return {
      kind: 'failed',
      status: 'failed',
      httpStatus,
      recordedStatus: httpStatus,
      code,
      message,
      ...(details ? { details } : {}),
    };
  }
}
