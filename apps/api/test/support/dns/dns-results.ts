import type { DnsIndeterminateReason, DnsResult, MxAnswer } from '../../../src/dns/dns-resolver';

/** Builders for `DnsResult` values in pure engine tests (no network). */
const base = (name: string, upstream = 'system:test') => ({
  upstream,
  queriedName: name,
  durationMs: 1,
  fromCache: false,
});

export function txtAnswer(name: string, records: string[], upstream?: string): DnsResult<string> {
  return { ...base(name, upstream), outcome: 'answer', records, ttlSeconds: null };
}

export function mxAnswer(
  name: string,
  records: Array<[number, string]>,
  upstream?: string,
): DnsResult<MxAnswer> {
  return {
    ...base(name, upstream),
    outcome: 'answer',
    records: records.map(([priority, exchange]) => ({ priority, exchange })),
    ttlSeconds: null,
  };
}

export function negative<T>(
  name: string,
  outcome: 'nxdomain' | 'nodata' = 'nxdomain',
  upstream?: string,
): DnsResult<T> {
  return { ...base(name, upstream), outcome, ttlSeconds: null };
}

export function indeterminate<T>(
  name: string,
  reason: DnsIndeterminateReason = 'servfail',
  upstream?: string,
): DnsResult<T> {
  return { ...base(name, upstream), outcome: 'indeterminate', reason, detail: reason };
}
