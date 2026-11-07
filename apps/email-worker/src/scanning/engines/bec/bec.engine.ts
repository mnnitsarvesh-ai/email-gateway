import { performance } from 'node:perf_hooks';
import {
  type BecAuthInput,
  type BecHistoryInput,
  type BecRuleSettings,
  type BecRulesResult,
  type BecStaticData,
  type BecTenantData,
  type BecUrlInput,
  BecTextTimeoutError,
  buildHistoryUpdates,
  computeAlignment,
  Deadline,
  evaluateBecRules,
  historyReadKeys,
  infrastructureFingerprint,
  fingerprintHash,
  parseEnvelopeAddress,
  parseMailboxList,
  TEXT_DERIVATION_VERSION,
  type TextBodyInput,
  type AuthResultRow,
  type BecHeaders,
  type HistoryUpdate,
  BEC_RULES_VERSION,
} from '@email-gateway/bec';
import type { Logger } from '@email-gateway/logger';
import {
  type BecEffectiveSettings,
  normalizedEngineResultSchema,
  type UrlEffectiveSettings,
} from '@email-gateway/security-contracts';
import type { LookalikeParams } from '@email-gateway/url-security';
import { errorFields } from '../../../mime-ingestion/error-fields';
import {
  type BecResultInput,
  type EngineFailure,
  type EngineHealthCheck,
  type EngineScanContext,
  type EngineScanOutcome,
  type ScanEngineAdapter,
} from '../../engine';
import type { PartPrefixSource, PartSource } from '../../parts/part-reader';
import { parseComplete } from '../url/url-rows';
import type { AiEntry, BecAiLayer } from './ai-layer';
import type { BecMetrics } from './bec-metrics';
import {
  type BecBodyRef,
  type BecReadScope,
  type BecStore,
  type BecTenantRecord,
  InconsistentBecReadError,
} from './bec-store';

/** Bounds of one engine call (B8, B11, B12; validated configuration). */
export interface BecEngineLimits {
  /** BEC_TEXT_MAX_BYTES per stored text part. */
  textMaxBytes: number;
  /** BEC_TEXT_MAX_CHARS. */
  textMaxChars: number;
  /** BEC_TEXT_TIMEOUT_MS (extraction and matching). */
  textTimeoutMs: number;
  /** BEC_HISTORY_MAX_RECIPIENTS. */
  historyMaxRecipients: number;
  /** BEC_HISTORY_MIN_MESSAGES. */
  historyMinMessages: number;
  /** BEC_SUPPRESSION_MAX_WEIGHT. */
  suppressionMaxWeight: number;
}

/** The engines whose results the bec engine reads (its catalog `dependsOn`, B2). */
export interface BecDependencies {
  /** The engine whose final writes `email_auth_results` (`rspamd`). */
  auth: string;
  /** The engine whose final writes `url_scan_results` (`url`). */
  url: string;
}

export interface BecEngineOptions {
  store: BecStore;
  parts: PartSource & PartPrefixSource;
  data: BecStaticData;
  ai: BecAiLayer;
  dependencies: BecDependencies;
  /** BEC_CONTEXT_HMAC_KEY (history key hashes, B12). */
  historyKey: string;
  limits: BecEngineLimits;
  lookalike: LookalikeParams;
  /** URL_PROTECTED_EXTRA_DOMAINS. */
  platformExtraDomains: readonly string[];
  /** The url engine's effective settings of a tenant row (its `lookalike.extraProtectedDomains`). */
  urlSettings: (row: BecTenantRecord['urlSettingsRow']) => UrlEffectiveSettings;
  /** Readiness details (versions and modes only). */
  readiness: Record<string, string>;
  metrics: BecMetrics;
  logger: Logger;
  now?: () => Date;
}

/** Engine-level failure codes that are not retryable (B4 failure classes, as U10). */
const NOT_RETRYABLE = new Set([
  'parse_row_missing',
  'part_unavailable',
  'part_integrity',
  'part_key_mismatch',
  'result_invalid',
]);

interface Failed {
  outcome: 'timeout' | 'error';
  errorCode: string;
  engineFault: boolean;
}
const fail = (outcome: 'timeout' | 'error', errorCode: string, engineFault = false): Failed => ({
  outcome,
  errorCode,
  engineFault,
});

class AttemptFailure extends Error {
  constructor(readonly failure: Failed) {
    super(failure.errorCode);
  }
}

const AUTH_FAILED = new Set(['timeout', 'error']);
const MAX_REASON_CODES = 32;
const MAX_RULE_ENTRIES = 32;

/** The stored assessment JSON (B14): never text; `effect` only for applied ones. */
function storedAssessment(entry: AiEntry, effect: string | null): Record<string, unknown> {
  const a = entry.assessment;
  return {
    layer: entry.layer,
    mode: entry.mode,
    provider: entry.provider,
    modelId: a.modelId,
    modelVersion: a.modelVersion,
    promptTemplateVersion: a.promptTemplateVersion,
    status: a.status,
    labels: a.labels.slice(0, 4),
    confidence: a.confidence,
    indicators: a.indicators.slice(0, 8),
    citedFeatures: a.citedFeatures.slice(0, 8),
    spans: a.spans.slice(0, 8),
    responseSha256: a.responseSha256,
    durationMs: a.durationMs,
    ...(effect !== null ? { effect } : {}),
  };
}

/**
 * The bec engine adapter (step 4.4 B4): for one round of one message (a stage-2 engine,
 * triggered when the round's dependency finals exist) it
 *
 * 1. loads, on the writer with echo checks, the round row, the dependency finals (`rspamd`,
 *    `url`), the `email_auth_results` row, the round's URL results joined with `message_urls`,
 *    the stored headers, the parse row and the subject, and the tenant data (LRU);
 * 2. reads the stored text and HTML bodies (org prefix; full reads SHA-256-verified; a body
 *    above BEC_TEXT_MAX_BYTES read as a prefix and marked incomplete);
 * 3. reads the communication history when the tenant enabled it (B12);
 * 4. evaluates `bec-map/1` (`@email-gateway/bec`), runs the AI layer (B9/B10) and aggregates with
 *    the invariant;
 * 5. returns the definite result with the `bec_scan_results` row and (round 0 of an initial scan)
 *    the history upserts as child rows (B14). Outbound/internal mail is `skipped`
 *    (`bec.not_inbound`) with the history pair updates only.
 *
 * Failure classes: MySQL/S3/network errors are thrown (transient); a wrong read, a part
 * integrity/unavailable/key problem, a missing parse row and the text time budget are attempt
 * failures; AI problems never are. Logs carry ids, codes, counts and durations only.
 */
export class BecEngine implements ScanEngineAdapter {
  readonly name = 'bec' as const;
  private readonly logger: Logger;
  private readonly now: () => Date;

  constructor(private readonly options: BecEngineOptions) {
    this.logger = options.logger.child({ component: 'bec-engine' });
    this.now = options.now ?? (() => new Date());
  }

  get engineVersion(): string {
    return this.options.data.engineVersion;
  }

  healthChecks(): EngineHealthCheck[] {
    return [
      {
        name: 'bec-engine',
        // The packaged model (manifest + hash) and the lexicons were loaded at construction;
        // the LLM is never required for readiness.
        check: () =>
          Promise.resolve({
            engineVersion: this.options.data.engineVersion,
            lexicon: this.options.data.lexicon.version,
            ...this.options.readiness,
          }),
      },
    ];
  }

  async scan(ctx: EngineScanContext, signal: AbortSignal): Promise<EngineScanOutcome> {
    const started = performance.now();
    const elapsed = (): number => Math.max(0, Math.round(performance.now() - started));
    const failure = (f: Failed): EngineFailure => ({
      kind: 'failure',
      outcome: f.outcome,
      errorCode: f.errorCode,
      retryable: !NOT_RETRYABLE.has(f.errorCode),
      engineFault: f.engineFault,
      durationMs: elapsed(),
      engineVersion: this.options.data.engineVersion,
    });
    try {
      return await this.scanRound(ctx, signal, elapsed);
    } catch (error) {
      if (error instanceof AttemptFailure) return failure(error.failure);
      if (error instanceof InconsistentBecReadError) {
        this.options.metrics.inconsistent(error.read);
        this.logger.warn(
          {
            messageId: ctx.messageId.toString(),
            round: ctx.round,
            read: error.read,
            check: error.check,
          },
          'bec engine: inconsistent writer read, attempt retried',
        );
        return failure(fail('error', 'inconsistent_read'));
      }
      if (error instanceof BecTextTimeoutError) {
        return failure(fail('timeout', 'extract_timeout'));
      }
      if (signal.aborted) return failure(fail('timeout', 'timeout', true));
      throw error;
    }
  }

  private async readText(
    ref: BecBodyRef,
    prefix: string,
    signal: AbortSignal,
  ): Promise<TextBodyInput | null> {
    if (ref.key === null) return null;
    if (ref.sha256 === null || ref.sizeBytes === null) {
      throw new InconsistentBecReadError('parse', 'body without hash or size');
    }
    if (!ref.key.startsWith(prefix) || ref.key.includes('..')) {
      throw new AttemptFailure(fail('error', 'part_key_mismatch'));
    }
    const { parts, limits } = this.options;
    if (ref.sizeBytes > limits.textMaxBytes) {
      // B4 step 4: a body above the cap is read as a prefix (no hash check is possible on a
      // partial read) and the text is incomplete.
      const read = await parts.readPrefix(ref.key, limits.textMaxBytes, signal);
      if (read.kind === 'missing') throw new AttemptFailure(fail('error', 'part_unavailable'));
      // `stream: true` holds back a multi-byte sequence cut by the cap instead of emitting U+FFFD.
      return {
        content: new TextDecoder('utf-8').decode(read.bytes, { stream: true }),
        truncated: true,
      };
    }
    const read = await parts.read(ref.key, ref.sizeBytes, ref.sha256, signal);
    if (read.kind === 'missing') throw new AttemptFailure(fail('error', 'part_unavailable'));
    if (read.kind === 'integrity') throw new AttemptFailure(fail('error', 'part_integrity'));
    // Stored bodies are transfer-decoded and converted to UTF-8 (step 3.1 M8).
    return { content: read.bytes.toString('utf8'), truncated: false };
  }

  private async loadDependencies(
    scope: BecReadScope,
    required: readonly string[],
  ): Promise<{ auth: BecAuthInput; url: BecUrlInput; authRow: AuthResultRow | null }> {
    const { store, dependencies } = this.options;
    const inRound = [dependencies.auth, dependencies.url].filter((e) => required.includes(e));
    const finals = await store.loadFinals(scope, inRound);
    for (const engine of inRound) {
      // The stage trigger was written after these finals; a read that misses one is wrong.
      if (!finals.some((f) => f.engine === engine)) {
        throw new InconsistentBecReadError('finals', 'dependency final absent');
      }
    }
    const outcomeOf = (engine: string): string | null =>
      finals.find((f) => f.engine === engine)?.outcome ?? null;

    let auth: BecAuthInput;
    let authRow: AuthResultRow | null = null;
    const authOutcome = outcomeOf(dependencies.auth);
    if (authOutcome === null) auth = { state: 'not_in_round' };
    else if (AUTH_FAILED.has(authOutcome)) auth = { state: 'failed' };
    else {
      authRow = await store.loadAuth(scope, dependencies.auth);
      auth = authRow ? { state: 'available', row: authRow } : { state: 'missing' };
    }

    let url: BecUrlInput;
    const urlOutcome = outcomeOf(dependencies.url);
    if (urlOutcome === null) url = { state: 'not_in_round' };
    else if (AUTH_FAILED.has(urlOutcome)) url = { state: 'failed' };
    else {
      const rows = await store.loadUrlResults(scope);
      url = { state: 'available', rows };
    }
    return { auth, url, authRow };
  }

  /** B12 reads (enabled tenants): the sender row and the (From, recipient) pair rows. */
  private async loadHistory(
    ctx: EngineScanContext,
    headers: BecHeaders,
    tenantDomains: readonly string[],
    fingerprint: string | null,
  ): Promise<BecHistoryInput> {
    const { store, historyKey, limits } = this.options;
    const keys = historyReadKeys(historyKey, {
      organizationId: ctx.organizationId,
      direction: ctx.direction,
      headers,
      envelopeFrom: ctx.envelope.envelopeFrom,
      recipients: ctx.envelope.recipients,
      receivedAt: ctx.receivedAt,
      tenantDomains,
      maxRecipients: limits.historyMaxRecipients,
      fingerprint,
    });
    try {
      const sender = keys.sender
        ? await store.loadHistory(ctx.organizationId, 'sender', [keys.sender])
        : [];
      const pairs = await store.loadHistory(ctx.organizationId, 'pair', keys.pairs);
      const pairByKey = new Map(pairs.map((p) => [p.keyHash, p.row]));
      return {
        sender: sender[0]?.row ?? null,
        pairs: keys.pairs.map((k) => pairByKey.get(k) ?? null),
        fingerprintHash: fingerprint
          ? fingerprintHash(historyKey, ctx.organizationId, fingerprint)
          : null,
      };
    } catch (error) {
      if (error instanceof InconsistentBecReadError) throw error;
      // History is opt-in context: a failed read makes the verdict at least unknown (E1
      // `bec.history_unavailable`) instead of failing the attempt (§12 WP3).
      this.logger.warn(
        { messageId: ctx.messageId.toString(), ...errorFields(error) },
        'bec engine: history read failed; recorded as history unavailable',
      );
      return 'error';
    }
  }

  private historyUpdates(
    ctx: EngineScanContext,
    settings: BecEffectiveSettings,
    headers: BecHeaders,
    tenantDomains: readonly string[],
    fingerprint: string | null,
    inboundEligible: boolean,
  ): HistoryUpdate[] {
    // B12: round 0 of an initial scan only (a rescan sees the same history and writes none).
    if (!settings.history.enabled || ctx.round !== 0 || ctx.scanKind !== 'initial') return [];
    return buildHistoryUpdates(this.options.historyKey, {
      organizationId: ctx.organizationId,
      direction: ctx.direction,
      headers,
      envelopeFrom: ctx.envelope.envelopeFrom,
      recipients: ctx.envelope.recipients,
      receivedAt: ctx.receivedAt,
      tenantDomains,
      maxRecipients: this.options.limits.historyMaxRecipients,
      fingerprint,
      inboundEligible,
    });
  }

  private async scanRound(
    ctx: EngineScanContext,
    signal: AbortSignal,
    elapsed: () => number,
  ): Promise<EngineScanOutcome> {
    const { options } = this;
    const { store, data } = options;
    const settings = ctx.settings as BecEffectiveSettings;
    const ids = { messageId: ctx.messageId.toString(), round: ctx.round };
    const now = this.now();
    const scope: BecReadScope = {
      organizationId: ctx.organizationId,
      messageId: ctx.messageId,
      receivedAt: ctx.receivedAt,
      scanId: ctx.scanId,
      round: ctx.round,
    };

    // 1. Writer reads (echo-checked).
    const round = await store.loadRound(scope);
    if (!round) throw new InconsistentBecReadError('scan', 'round row absent');
    const { auth, url, authRow } = await this.loadDependencies(scope, round.requiredEngines);
    const headerRead = await store.loadHeaders(scope);
    const headers = headerRead.headers;
    const tenantRecord = await store.tenantData(ctx.organizationId);
    const urlSettings = options.urlSettings(tenantRecord.urlSettingsRow);
    const tenant: BecTenantData = {
      tenantDomains: tenantRecord.tenantDomains,
      executives: tenantRecord.executives,
      vendors: tenantRecord.vendors,
      trustedSenders: tenantRecord.trustedSenders,
      suppressions: tenantRecord.suppressions,
      freemailExtraDomains: settings.freemailExtraDomains,
      extraProtectedDomains: [
        ...new Set([
          ...options.platformExtraDomains,
          ...urlSettings.lookalike.extraProtectedDomains,
        ]),
      ],
    };
    const ruleSettings: BecRuleSettings = {
      suspiciousScore: settings.suspiciousScore,
      maliciousScore: settings.maliciousScore,
      suppressionMaxWeight: options.limits.suppressionMaxWeight,
      historyMinMessages: options.limits.historyMinMessages,
      textMaxChars: options.limits.textMaxChars,
      lookalike: options.lookalike,
    };
    const envelope = {
      direction: ctx.direction,
      envelopeFrom: ctx.envelope.envelopeFrom,
      recipients: ctx.envelope.recipients,
      clientIp: ctx.envelope.clientIp,
      receivedAt: ctx.receivedAt,
    };

    // 2. Not inbound (B1): skipped with the history pair updates only.
    if (ctx.direction !== 'inbound') {
      const rules = evaluateBecRules(
        {
          headers,
          envelope,
          auth,
          url,
          text: { subject: null, textBody: null, htmlBody: null, parseIncomplete: false },
          tenant,
          history: settings.history.enabled
            ? { sender: null, pairs: [], fingerprintHash: null }
            : 'disabled',
        },
        ruleSettings,
        data,
        { now },
      );
      // Not inbound: only outbound/internal pair rows, which do not depend on eligibility.
      const history = this.historyUpdates(
        ctx,
        settings,
        headers,
        tenant.tenantDomains,
        null,
        false,
      );
      return this.result(ctx, rules, null, history, elapsed, ids);
    }

    // 3. Text parts (B8).
    const parse = await store.loadParse(scope);
    if (!parse) {
      this.logger.warn(ids, 'bec engine: the message has no parse row');
      throw new AttemptFailure(fail('error', 'parse_row_missing'));
    }
    const subject = await store.loadSubject(scope);
    const prefix = `org/${ctx.organizationId.toString()}/part/`;
    const textBody = await this.readText(parse.textBody, prefix, signal);
    const htmlBody = await this.readText(parse.htmlBody, prefix, signal);
    if (signal.aborted) throw new AttemptFailure(fail('timeout', 'timeout', true));

    // 4. History (B12): the fingerprint comes from the auth row and the trusted envelope only.
    const fromMailbox =
      parseMailboxList(
        Object.entries(headers).find(([name]) => name.toLowerCase() === 'from')?.[1][0] ?? null,
      ).mailboxes.find((m) => m.address !== null) ?? null;
    const alignment = computeAlignment(
      authRow,
      fromMailbox?.domain ?? null,
      parseEnvelopeAddress(ctx.envelope.envelopeFrom)?.domain ?? null,
    );
    const fingerprint = infrastructureFingerprint(
      authRow ? alignment : null,
      ctx.envelope.clientIp,
    );
    const history: BecHistoryInput = settings.history.enabled
      ? await this.loadHistory(ctx, headers, tenant.tenantDomains, fingerprint)
      : 'disabled';

    // 5. Deterministic rules (B6) within the text budget.
    const rules = evaluateBecRules(
      {
        headers,
        envelope,
        auth,
        url,
        text: {
          subject,
          textBody,
          htmlBody,
          parseIncomplete: !parseComplete(parse.status, parse.limitsExceeded),
        },
        tenant,
        history,
        // §2.0 invariant 1: headers past the stored or read cap were never examined.
        headersIncomplete:
          headerRead.truncated || parse.defects.includes('stored_headers_truncated'),
      },
      ruleSettings,
      data,
      { now, deadline: Deadline.after(options.limits.textTimeoutMs) },
    );

    // 6. AI layer (B9/B10): never an attempt failure.
    const ai = await options.ai.run(
      { organizationId: ctx.organizationId, rules, tenant, settings },
      signal,
    );
    // B12 (review round 1): only an authenticated From with a final verdict below suspicious
    // makes the sender "known"; spoofed or flagged mail never warms up the history.
    const finalVerdict = ai ? ai.combined.verdict : rules.verdict;
    const inboundEligible =
      rules.authenticatedAsFrom && (finalVerdict === 'clean' || finalVerdict === 'unknown');
    const updates = this.historyUpdates(
      ctx,
      settings,
      headers,
      tenant.tenantDomains,
      fingerprint,
      inboundEligible,
    );
    return this.result(ctx, rules, ai, updates, elapsed, ids);
  }

  private result(
    ctx: EngineScanContext,
    rules: BecRulesResult,
    ai: Awaited<ReturnType<BecAiLayer['run']>> | null,
    history: HistoryUpdate[],
    elapsed: () => number,
    ids: Record<string, string | number>,
  ): EngineScanOutcome {
    const { metrics, data } = this.options;
    const settings = ctx.settings as BecEffectiveSettings;
    const verdict = ai ? ai.combined.verdict : rules.verdict;
    const score = ai ? ai.combined.score : rules.score;
    const reasonCodes = [...new Set([...rules.codes, ...(ai?.combined.codes ?? [])])].slice(
      0,
      MAX_REASON_CODES,
    );
    const entries = ai?.entries ?? [];
    const applied = entries
      .map((e, i) => ({ e, effect: ai!.combined.effects[i] ?? 'none' }))
      .filter(({ e }) => e.mode === 'active')
      .map(({ e, effect }) => storedAssessment(e, effect));
    const shadow = entries.filter((e) => e.mode === 'shadow').map((e) => storedAssessment(e, null));
    const row: BecResultInput = {
      lifecycleRound: ctx.round,
      engineVersion: data.engineVersion,
      rulesVersion: rules.rulesVersion,
      settingsVersion: ctx.settingsVersion,
      lexiconVersion: data.lexicon.version,
      textVersion: TEXT_DERIVATION_VERSION,
      deterministicScore: rules.score,
      score,
      deterministicVerdict: rules.verdict,
      verdict,
      inputs: { ...rules.inputs },
      rules: rules.firedRules.slice(0, MAX_RULE_ENTRIES).map((r) => ({
        id: r.id,
        code: r.code,
        category: r.category,
        severity: r.severity,
        weight: r.weight,
        suppressed: r.suppressed,
        evidence: r.evidence,
      })),
      features: Object.keys(rules.features).length > 0 ? { ...rules.features } : null,
      identity: rules.identity as unknown as Record<string, unknown>,
      ai: applied.length > 0 ? applied : null,
      aiShadow: shadow.length > 0 ? shadow : null,
      durationMs: elapsed(),
    };
    const base = {
      engine: this.name,
      engineVersion: data.engineVersion,
      score: verdict === 'skipped' ? null : score,
      requiredScore: verdict === 'skipped' ? null : settings.suspiciousScore,
      action: null,
      reasonCodes,
      signals: rules.signals.slice(0, 200),
      durationMs: elapsed(),
      settingsVersion: ctx.settingsVersion,
      mappingVersion: BEC_RULES_VERSION,
    };
    const childRows = {
      bec: {
        result: row,
        history: history.map((h) => ({
          scope: h.scope,
          keyHash: h.keyHash,
          inbound: h.inbound,
          outbound: h.outbound,
          receivedAt: h.receivedAt,
          fingerprintHash: h.fingerprintHash,
        })),
      },
    };
    metrics.result(verdict, rules.verdict, reasonCodes);
    metrics.input('auth', rules.inputs.auth);
    metrics.input('url', rules.inputs.url);
    metrics.input('text', rules.inputs.text);
    metrics.input('history', rules.inputs.history);
    this.logger.debug(
      {
        ...ids,
        verdict,
        deterministicVerdict: rules.verdict,
        score,
        reasonCodes,
        inputs: rules.inputs,
        ai: entries.map((e) => `${e.layer}:${e.mode}:${e.assessment.status}`),
        history: history.length,
      },
      'bec engine result',
    );
    if (verdict === 'skipped') {
      return { kind: 'definite', result: { ...base, outcome: 'skipped' }, childRows };
    }
    // The effective thresholds of this result (B13, after the tenant override), so the scans read
    // API can show both (`scan_engine_results.evidence.thresholds`; bec_scan_results has no
    // threshold columns, step 4.4 §12 WP4 deviation 2).
    const evidence = {
      thresholds: { suspicious: settings.suspiciousScore, malicious: settings.maliciousScore },
    };
    const parsed = normalizedEngineResultSchema.safeParse({ ...base, outcome: verdict });
    if (!parsed.success) {
      this.logger.error(ids, 'bec engine result violates its contract');
      throw new AttemptFailure(fail('error', 'result_invalid'));
    }
    return { kind: 'definite', result: parsed.data, evidence, childRows };
  }
}
