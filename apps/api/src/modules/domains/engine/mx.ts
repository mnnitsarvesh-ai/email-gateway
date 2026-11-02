import type { DnsResult, MxAnswer } from '../../../dns/dns-resolver';
import type { GatewayDnsConfig } from './gateway-dns-config';
import type { DnsCheckOutcome } from './types';

export interface MxObservation {
  outcome: DnsCheckOutcome;
  warnings: string[];
}

export interface MxEvaluation {
  outcome: DnsCheckOutcome;
  /** Primary answer sorted by priority then host; [] for NXDOMAIN/NODATA; null if indeterminate. */
  observed: MxAnswer[] | null;
  /** `priority host` lines (Null MX shown as `.`); null unless the primary was definitive. */
  observedValue: string | null;
  warnings: string[];
  /** Each propagation upstream's own outcome. */
  propagation: Array<{ upstream: string; outcome: DnsCheckOutcome }>;
}

function sortMx(records: readonly MxAnswer[]): MxAnswer[] {
  return [...records].sort(
    (a, b) => a.priority - b.priority || a.exchange.localeCompare(b.exchange),
  );
}

/** `priority host` per line; a Null MX (RFC 7505) exchange is shown as `.`. */
export function formatMxRecords(records: readonly MxAnswer[]): string {
  return sortMx(records)
    .map((mx) => `${mx.priority} ${mx.exchange === '' ? '.' : mx.exchange}`)
    .join('\n');
}

/** One resolver's MX answer against the gateway host set. */
export function observeMx(
  result: DnsResult<MxAnswer>,
  gatewayHosts: ReadonlySet<string>,
): MxObservation {
  switch (result.outcome) {
    case 'indeterminate':
      return { outcome: 'indeterminate', warnings: [] };
    case 'nxdomain':
    case 'nodata':
      return { outcome: 'missing', warnings: [] };
    default: {
      const exchanges = result.records.map((mx) => mx.exchange);
      const foreign = exchanges.filter((host) => !gatewayHosts.has(host));
      if (foreign.length === 0) return { outcome: 'valid', warnings: [] };
      const warnings = ['mx_non_gateway_hosts'];
      if (exchanges.some((host) => gatewayHosts.has(host)))
        warnings.push('mx_gateway_bypass_possible');
      return { outcome: 'invalid', warnings };
    }
  }
}

/**
 * MX evaluation with propagation (D6): every exchange a gateway host → valid; any other exchange
 * (including Null MX) → invalid; NXDOMAIN/NODATA → missing. The result is valid only when the
 * primary is valid and no propagation upstream returned a definitive disagreement
 * (`mx_not_propagated`); indeterminate upstreams add `mx_propagation_unknown:<upstream>`. An
 * indeterminate primary makes the whole result indeterminate.
 */
export function evaluateMx(
  primary: DnsResult<MxAnswer>,
  gateway: Pick<GatewayDnsConfig, 'mxHosts'>,
  propagation: ReadonlyArray<DnsResult<MxAnswer>> = [],
): MxEvaluation {
  const hosts = new Set(gateway.mxHosts.map((mx) => mx.host));
  const own = observeMx(primary, hosts);
  const upstreams = propagation.map((result) => ({
    upstream: result.upstream,
    outcome: observeMx(result, hosts).outcome,
  }));
  if (own.outcome === 'indeterminate' || primary.outcome === 'indeterminate') {
    return {
      outcome: 'indeterminate',
      observed: null,
      observedValue: null,
      warnings: [],
      propagation: upstreams,
    };
  }
  const observed = primary.outcome === 'answer' ? sortMx(primary.records) : [];
  const warnings = [...own.warnings];
  let outcome = own.outcome;
  for (const upstream of upstreams) {
    if (upstream.outcome === 'indeterminate') {
      warnings.push(`mx_propagation_unknown:${upstream.upstream}`);
    } else if (outcome === 'valid' && upstream.outcome !== 'valid') {
      outcome = 'invalid';
      if (!warnings.includes('mx_not_propagated')) warnings.push('mx_not_propagated');
    }
  }
  return {
    outcome,
    observed,
    observedValue: observed.length > 0 ? formatMxRecords(observed) : null,
    warnings,
    propagation: upstreams,
  };
}
