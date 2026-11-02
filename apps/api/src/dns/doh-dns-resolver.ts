import { performance } from 'node:perf_hooks';
import * as dnsPacket from 'dns-packet';
import {
  assertQueryName,
  type DnsIndeterminateReason,
  type DnsRecordType,
  DnsResolver,
  type DnsResult,
  type MxAnswer,
  stripTrailingDot,
} from './dns-resolver';

export interface DohDnsResolverOptions {
  /** RFC 8484 endpoint, validated by the config (https outside local/ci, no userinfo). */
  url: string;
  /** Per try (`AbortSignal.timeout`). */
  timeoutMs: number;
  tries: number;
  /** Injection point for tests; defaults to the global `fetch`. */
  fetch?: typeof fetch;
}

export const DNS_MESSAGE_MEDIA_TYPE = 'application/dns-message';
/** Largest DoH response body accepted. */
export const DOH_MAX_RESPONSE_BYTES = 64 * 1024;
/** Longest CNAME chain followed inside one answer. */
const MAX_CNAME_HOPS = 16;

type Attempt =
  | { kind: 'response'; body: Buffer }
  | { kind: 'retryable'; reason: DnsIndeterminateReason; detail: string }
  | { kind: 'final'; reason: DnsIndeterminateReason; detail: string };

type Decoded = ReturnType<typeof dnsPacket.decode> & { rcode?: string };

/** Body reader with a hard size limit (the declared length is not trusted). */
async function readLimited(response: Response, limit: number): Promise<Buffer | null> {
  const declared = Number(response.headers.get('content-length') ?? NaN);
  if (Number.isFinite(declared) && declared > limit) {
    await response.body?.cancel().catch(() => undefined);
    return null;
  }
  if (!response.body) return Buffer.alloc(0);
  const reader = (response.body as ReadableStream<Uint8Array>).getReader();
  const chunks: Buffer[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

function sameName(a: string, b: string): boolean {
  return stripTrailingDot(a).toLowerCase() === stripTrailingDot(b).toLowerCase();
}

function txtValue(data: unknown): string {
  const parts = Array.isArray(data) ? data : [data];
  return Buffer.concat(
    parts.map((part) => (Buffer.isBuffer(part) ? part : Buffer.from(String(part), 'utf8'))),
  ).toString('utf8');
}

/**
 * DNS-over-HTTPS adapter (RFC 8484 wire format, `GET ?dns=<base64url>`, message id 0). Retries
 * timeouts, network errors and HTTP 5xx up to `tries` times; every other failure is final.
 */
export class DohDnsResolver extends DnsResolver {
  readonly upstream: string;
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly options: DohDnsResolverOptions) {
    super();
    this.upstream = `doh:${options.url}`;
    this.fetchImpl = options.fetch ?? fetch;
  }

  resolveTxt(name: string): Promise<DnsResult<string>> {
    return this.query(name, 'TXT', (answer) =>
      answer.type === 'TXT' ? txtValue(answer.data) : null,
    );
  }

  resolveMx(name: string): Promise<DnsResult<MxAnswer>> {
    return this.query(name, 'MX', (answer) =>
      answer.type === 'MX'
        ? {
            priority: answer.data.preference ?? 0,
            exchange: stripTrailingDot(answer.data.exchange).toLowerCase(),
          }
        : null,
    );
  }

  private async query<T>(
    name: string,
    type: DnsRecordType,
    extract: (answer: dnsPacket.Answer) => T | null,
  ): Promise<DnsResult<T>> {
    assertQueryName(name);
    const started = performance.now();
    const base = () => ({
      upstream: this.upstream,
      queriedName: name,
      durationMs: Math.round(performance.now() - started),
      fromCache: false,
    });
    const indeterminate = (reason: DnsIndeterminateReason, detail: string): DnsResult<T> => ({
      ...base(),
      outcome: 'indeterminate',
      reason,
      detail,
    });

    const request = dnsPacket.encode({
      type: 'query',
      id: 0,
      // RD: recursion; AD in a query asks the resolver to report DNSSEC status (RFC 6840 §5.7).
      flags: dnsPacket.RECURSION_DESIRED | dnsPacket.AUTHENTIC_DATA,
      questions: [{ type, name, class: 'IN' }],
    });
    const url = new URL(this.options.url);
    url.searchParams.set('dns', request.toString('base64url'));

    let attempt: Attempt = { kind: 'final', reason: 'other', detail: 'no attempt' };
    for (let tryNo = 1; tryNo <= this.options.tries; tryNo++) {
      attempt = await this.attempt(url);
      if (attempt.kind !== 'retryable') break;
    }
    if (attempt.kind !== 'response') return indeterminate(attempt.reason, attempt.detail);

    let message: Decoded;
    try {
      message = dnsPacket.decode(attempt.body);
    } catch {
      return indeterminate('malformed', 'undecodable DNS message');
    }
    const question = message.questions?.[0];
    if (
      !message.flag_qr ||
      message.questions?.length !== 1 ||
      !question ||
      question.type !== type ||
      !sameName(question.name, name)
    ) {
      return indeterminate('malformed', 'response does not match the question');
    }
    const dnssecAuthenticated = message.flag_ad;

    switch (message.rcode) {
      case 'NOERROR':
        break;
      case 'NXDOMAIN':
        return {
          ...base(),
          dnssecAuthenticated,
          outcome: 'nxdomain',
          ttlSeconds: negativeTtl(message),
        };
      case 'SERVFAIL':
        return { ...indeterminate('servfail', 'RCODE SERVFAIL'), dnssecAuthenticated };
      case 'REFUSED':
        return { ...indeterminate('refused', 'RCODE REFUSED'), dnssecAuthenticated };
      default:
        return {
          ...indeterminate('other', `RCODE ${String(message.rcode ?? 'unknown')}`),
          dnssecAuthenticated,
        };
    }

    // Follow a CNAME chain inside the answer section to records of the asked type.
    const answers = message.answers ?? [];
    let current = name;
    const ttls: number[] = [];
    for (let hop = 0; hop <= MAX_CNAME_HOPS; hop++) {
      const matching = answers.filter((a) => a.type === type && sameName(a.name, current));
      if (matching.length > 0) {
        const records = matching.map(extract).filter((r): r is T => r !== null);
        for (const a of matching) ttls.push(ttlOf(a));
        return {
          ...base(),
          dnssecAuthenticated,
          outcome: 'answer',
          records,
          ttlSeconds: Math.min(...ttls),
        };
      }
      const cname = answers.find(
        (a): a is dnsPacket.StringAnswer => a.type === 'CNAME' && sameName(a.name, current),
      );
      if (!cname) break;
      ttls.push(ttlOf(cname));
      current = cname.data;
    }
    return { ...base(), dnssecAuthenticated, outcome: 'nodata', ttlSeconds: negativeTtl(message) };
  }

  private async attempt(url: URL): Promise<Attempt> {
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method: 'GET',
        headers: { accept: DNS_MESSAGE_MEDIA_TYPE },
        redirect: 'error',
        signal: AbortSignal.timeout(this.options.timeoutMs),
      });
    } catch (err) {
      const errName = (err as { name?: unknown } | null)?.name;
      if (errName === 'TimeoutError' || errName === 'AbortError') {
        return { kind: 'retryable', reason: 'timeout', detail: 'DoH request timed out' };
      }
      return { kind: 'retryable', reason: 'network', detail: 'DoH request failed' };
    }
    if (response.status >= 500) {
      await response.body?.cancel().catch(() => undefined);
      return { kind: 'retryable', reason: 'other', detail: `HTTP ${response.status}` };
    }
    if (response.status !== 200) {
      await response.body?.cancel().catch(() => undefined);
      return { kind: 'final', reason: 'other', detail: `HTTP ${response.status}` };
    }
    const contentType = (response.headers.get('content-type') ?? '').split(';')[0]!.trim();
    if (contentType.toLowerCase() !== DNS_MESSAGE_MEDIA_TYPE) {
      await response.body?.cancel().catch(() => undefined);
      return { kind: 'final', reason: 'malformed', detail: 'unexpected content type' };
    }
    let body: Buffer | null;
    try {
      body = await readLimited(response, DOH_MAX_RESPONSE_BYTES);
    } catch (err) {
      const errName = (err as { name?: unknown } | null)?.name;
      return errName === 'TimeoutError' || errName === 'AbortError'
        ? { kind: 'retryable', reason: 'timeout', detail: 'DoH response timed out' }
        : { kind: 'retryable', reason: 'network', detail: 'DoH response failed' };
    }
    if (body === null) {
      return { kind: 'final', reason: 'malformed', detail: 'response larger than 64 KiB' };
    }
    return { kind: 'response', body };
  }
}

function ttlOf(answer: dnsPacket.Answer): number {
  const ttl = (answer as { ttl?: number }).ttl;
  return typeof ttl === 'number' && ttl >= 0 ? ttl : 0;
}

/** RFC 2308 §5: negative TTL = min(SOA TTL, SOA MINIMUM) from the authority section. */
function negativeTtl(message: Decoded): number | null {
  const soa = (message.authorities ?? []).find((a): a is dnsPacket.SoaAnswer => a.type === 'SOA');
  if (!soa) return null;
  const minimum = soa.data.minimum;
  const ttl = ttlOf(soa);
  return typeof minimum === 'number' ? Math.min(ttl, minimum) : ttl;
}
