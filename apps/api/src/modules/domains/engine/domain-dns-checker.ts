import { performance } from 'node:perf_hooks';
import { Inject, Injectable } from '@nestjs/common';
import { API_CONFIG } from '../../../api-config.token';
import type { ApiConfig } from '../../../config';
import {
  type DnsQueryOptions,
  DnsResolver,
  type DnsResult,
  DnsResolverSet,
  type MxAnswer,
} from '../../../dns/dns-resolver';
import { dkimRecordHost, dkimTxtValue, evaluateDkim } from './dkim';
import { evaluateDmarc } from './dmarc';
import { type GatewayDnsConfig, gatewayDnsConfigFrom } from './gateway-dns-config';
import { evaluateMx } from './mx';
import { evaluateSpf } from './spf';
import type { DkimAlgorithm, DomainCheckReport, RecordCheckResult } from './types';
import { evaluateVerification } from './verification';

export interface DomainCheckInput {
  /** Normalized ASCII domain name. */
  domain: string;
  /** Ownership record to look for, or null when the domain has no verification row. */
  verification: { host: string; expectedValue: string } | null;
  /** Keys whose records are expected (pending, active, rotating). */
  dkimKeys: ReadonlyArray<{ selector: string; algorithm: DkimAlgorithm; publicKeyDns: string }>;
  /** Defaults to the gateway configuration from `API_CONFIG`. */
  gateway?: GatewayDnsConfig;
}

export interface DomainCheckOptions {
  /** Skip DNS cache reads (user-triggered verification). */
  bypassCache: boolean;
}

/** Serialized evidence limit per record (D10). */
export const EVIDENCE_MAX_BYTES = 8 * 1024;
const EVIDENCE_MAX_STRING = 512;
const EVIDENCE_MAX_ITEMS = 16;

/**
 * Shared overall deadline: queries still running when it passes resolve as
 * `indeterminate/timeout`, and queries started after it (SPF includes) do not reach the network.
 * A query that throws resolves as `indeterminate/other`.
 */
class DeadlineDnsResolver extends DnsResolver {
  constructor(
    private readonly inner: DnsResolver,
    private readonly deadline: { expired: boolean; reached: Promise<void> },
  ) {
    super();
  }

  get upstream(): string {
    return this.inner.upstream;
  }

  resolveTxt(name: string, options?: DnsQueryOptions): Promise<DnsResult<string>> {
    return this.race(name, () => this.inner.resolveTxt(name, options));
  }

  resolveMx(name: string, options?: DnsQueryOptions): Promise<DnsResult<MxAnswer>> {
    return this.race(name, () => this.inner.resolveMx(name, options));
  }

  private race<T>(name: string, run: () => Promise<DnsResult<T>>): Promise<DnsResult<T>> {
    const started = performance.now();
    const timedOut = (): DnsResult<T> => ({
      upstream: this.inner.upstream,
      queriedName: name,
      durationMs: Math.round(performance.now() - started),
      fromCache: false,
      outcome: 'indeterminate',
      reason: 'timeout',
      detail: 'domain check deadline exceeded',
    });
    // A query that throws (e.g. a name an adapter refuses) is unknown, not a failed check:
    // it must not reject the whole check and leave the domain retried forever (D10).
    const failed = (): DnsResult<T> => ({
      upstream: this.inner.upstream,
      queriedName: name,
      durationMs: Math.round(performance.now() - started),
      fromCache: false,
      outcome: 'indeterminate',
      reason: 'other',
      detail: 'query failed',
    });
    if (this.deadline.expired) return Promise.resolve(timedOut());
    const query = Promise.resolve()
      .then(run)
      .catch(() => failed());
    return Promise.race([query, this.deadline.reached.then(timedOut)]);
  }
}

/** JSON-safe summary of one DNS result. */
function describe(result: DnsResult<unknown>): Record<string, unknown> {
  const base: Record<string, unknown> = {
    upstream: result.upstream,
    queriedName: result.queriedName,
    outcome: result.outcome,
    durationMs: result.durationMs,
    fromCache: result.fromCache,
  };
  if (result.dnssecAuthenticated !== undefined) {
    base.dnssecAuthenticated = result.dnssecAuthenticated;
  }
  if (result.outcome === 'indeterminate') {
    base.reason = result.reason;
    base.detail = result.detail;
  } else {
    base.ttlSeconds = result.ttlSeconds;
    if (result.outcome === 'answer') base.answers = result.records;
  }
  return base;
}

function shrink(value: unknown): unknown {
  if (typeof value === 'string') {
    return value.length > EVIDENCE_MAX_STRING ? `${value.slice(0, EVIDENCE_MAX_STRING)}…` : value;
  }
  if (Array.isArray(value)) {
    const items = value.slice(0, EVIDENCE_MAX_ITEMS).map(shrink);
    if (value.length > EVIDENCE_MAX_ITEMS)
      items.push(`… ${value.length - EVIDENCE_MAX_ITEMS} more`);
    return items;
  }
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, shrink(v)]));
  }
  return value;
}

const size = (value: unknown) => Buffer.byteLength(JSON.stringify(value), 'utf8');

/**
 * Keeps evidence JSON-safe and ≤ 8 KiB: long strings and arrays are shortened first; if that is
 * not enough, only scalar top-level fields are kept.
 */
export function boundEvidence(evidence: Record<string, unknown>): Record<string, unknown> {
  const safe = JSON.parse(JSON.stringify(evidence)) as Record<string, unknown>;
  if (size(safe) <= EVIDENCE_MAX_BYTES) return safe;
  const shrunk = { ...(shrink(safe) as Record<string, unknown>), truncated: true };
  if (size(shrunk) <= EVIDENCE_MAX_BYTES) return shrunk;
  const scalars = Object.fromEntries(
    Object.entries(shrunk).filter(([, v]) => v === null || typeof v !== 'object'),
  );
  return { ...(shrink(scalars) as Record<string, unknown>), truncated: true };
}

/**
 * Checks every DNS record of one domain (D10): all queries run in parallel under
 * `DOMAIN_CHECK_DEADLINE_MS`; late queries count as indeterminate. Pure with respect to state:
 * persistence of the report is the caller's job. Never turns an indeterminate lookup into a
 * definitive outcome.
 */
@Injectable()
export class DomainDnsChecker {
  private readonly gateway: GatewayDnsConfig;
  private readonly deadlineMs: number;

  constructor(
    private readonly resolvers: DnsResolverSet,
    @Inject(API_CONFIG) config: ApiConfig,
  ) {
    this.gateway = gatewayDnsConfigFrom(config);
    this.deadlineMs = config.DOMAIN_CHECK_DEADLINE_MS;
  }

  async check(input: DomainCheckInput, options: DomainCheckOptions): Promise<DomainCheckReport> {
    const checkedAt = new Date();
    const gateway = input.gateway ?? this.gateway;
    const query: DnsQueryOptions = { bypassCache: options.bypassCache };

    const deadline = { expired: false, reached: Promise.resolve() };
    let timer: NodeJS.Timeout | undefined;
    deadline.reached = new Promise<void>((resolve) => {
      timer = setTimeout(() => {
        deadline.expired = true;
        resolve();
      }, this.deadlineMs);
      timer.unref();
    });
    const primary = new DeadlineDnsResolver(this.resolvers.primary, deadline);
    const propagation = this.resolvers.propagation.map((r) => new DeadlineDnsResolver(r, deadline));

    try {
      const [verification, mxPrimary, mxPropagation, spfApex, dmarc, dkim] = await Promise.all([
        input.verification ? primary.resolveTxt(input.verification.host, query) : null,
        primary.resolveMx(input.domain, query),
        Promise.all(propagation.map((r) => r.resolveMx(input.domain, query))),
        primary.resolveTxt(input.domain, query).then(async (apex) => ({
          apex,
          evaluation: await evaluateSpf(apex, gateway.spfInclude, primary, query),
        })),
        primary.resolveTxt(`_dmarc.${input.domain}`, query),
        Promise.all(
          input.dkimKeys.map((key) =>
            primary.resolveTxt(dkimRecordHost(key.selector, input.domain), query),
          ),
        ),
      ]);
      return this.report(input, gateway, checkedAt, {
        verification,
        mxPrimary,
        mxPropagation,
        spfApex,
        dmarc,
        dkim,
      });
    } finally {
      clearTimeout(timer);
    }
  }

  private report(
    input: DomainCheckInput,
    gateway: GatewayDnsConfig,
    checkedAt: Date,
    results: {
      verification: DnsResult<string> | null;
      mxPrimary: DnsResult<MxAnswer>;
      mxPropagation: Array<DnsResult<MxAnswer>>;
      spfApex: { apex: DnsResult<string>; evaluation: Awaited<ReturnType<typeof evaluateSpf>> };
      dmarc: DnsResult<string>;
      dkim: Array<DnsResult<string>>;
    },
  ): DomainCheckReport {
    const records: RecordCheckResult[] = [];
    const definitive = <T extends { observedValue: string | null }>(
      outcome: string,
      value: T,
    ): string | null => (outcome === 'indeterminate' ? null : value.observedValue);

    if (input.verification && results.verification) {
      const evaluation = evaluateVerification(
        results.verification,
        input.verification.expectedValue,
      );
      records.push({
        recordKey: 'verification',
        outcome: evaluation.outcome,
        observedValue: definitive(evaluation.outcome, evaluation),
        expectedValue: input.verification.expectedValue,
        warnings: [],
        evidence: boundEvidence({ query: describe(results.verification) }),
      });
    }

    const mx = evaluateMx(results.mxPrimary, gateway, results.mxPropagation);
    const mxEvidence = boundEvidence({
      query: describe(results.mxPrimary),
      propagation: results.mxPropagation.map(describe),
    });
    for (const host of gateway.mxHosts) {
      records.push({
        recordKey: `mx:${host.host}`,
        outcome: mx.outcome,
        observedValue: definitive(mx.outcome, mx),
        expectedValue: `${host.priority} ${host.host}`,
        warnings: [...mx.warnings],
        evidence: mxEvidence,
      });
    }

    const spf = results.spfApex.evaluation;
    records.push({
      recordKey: 'spf',
      outcome: spf.outcome,
      observedValue: definitive(spf.outcome, spf),
      expectedValue: spf.recommendedValue,
      warnings: spf.warnings,
      evidence: boundEvidence({
        query: describe(results.spfApex.apex),
        lookupCount: spf.lookupCount,
        lookupCountExact: spf.lookupCountExact,
        records: spf.records,
        warnings: spf.warnings,
      }),
    });

    input.dkimKeys.forEach((key, index) => {
      const result = results.dkim[index]!;
      const evaluation = evaluateDkim(result, key);
      records.push({
        recordKey: `dkim:${key.selector}`,
        outcome: evaluation.outcome,
        observedValue: definitive(evaluation.outcome, evaluation),
        expectedValue: dkimTxtValue(key.algorithm, key.publicKeyDns),
        warnings: evaluation.warnings,
        evidence: boundEvidence({ query: describe(result) }),
      });
    });

    const dmarc = evaluateDmarc(results.dmarc, input.domain, gateway);
    records.push({
      recordKey: 'dmarc',
      outcome: dmarc.outcome,
      observedValue: definitive(dmarc.outcome, dmarc),
      expectedValue: dmarc.recommendedValue,
      warnings: dmarc.warnings,
      evidence: boundEvidence({
        query: describe(results.dmarc),
        stage: dmarc.stage,
        partial: dmarc.partial,
      }),
    });

    return {
      checkedAt,
      records,
      mx: { observed: mx.observed, propagation: mx.propagation },
      spf: {
        lookupCount: spf.lookupCount,
        lookupCountExact: spf.lookupCountExact,
        recommendedValue: spf.recommendedValue,
      },
      dmarc: {
        stage: dmarc.stage,
        partial: dmarc.partial,
        recommendedValue: dmarc.recommendedValue,
        nextStep: dmarc.nextStep,
      },
      indeterminate: records.some((r) => r.outcome === 'indeterminate'),
    };
  }
}
