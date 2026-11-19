import { createHash } from 'node:crypto';
import { promises as dns } from 'node:dns';
import { once } from 'node:events';
import { PassThrough } from 'node:stream';
import { Inject, Injectable, Optional } from '@nestjs/common';
import { RedisService } from '@email-gateway/common';
import {
  type DkimSignatureEvidence,
  dkimReplayCandidates,
  evaluateProviderProof,
  type ProviderProofEvidence,
  type ProviderProofOutcome,
  type ProviderRelayProofPolicy,
} from '@email-gateway/mail-routing';
import { dkimVerify } from 'mailauth/lib/dkim/verify';
import { ADAPTER_CONFIG } from '../config';
import type { ProviderRelayConfig } from './provider-relay.config';

/** Redis key of the replay set of one DKIM signature (`sha256(b=)`, contracts §33). */
export const dkimReplayKey = (signatureId: string): string => `sa:prelay:dkim:${signatureId}`;

/**
 * Adds the queue file to the signature's replay set (once per queue file, so Postfix retries of a
 * tempfailed delivery never count as replays) and returns the number of distinct queue files that
 * carried the signature. The set stops growing one above the cap; its TTL is the replay window
 * from the first use.
 */
const REPLAY_SCRIPT = `
local key = KEYS[1]
if redis.call('SISMEMBER', key, ARGV[1]) == 1 then return redis.call('SCARD', key) end
local n = redis.call('SCARD', key)
if n >= tonumber(ARGV[3]) then return n + 1 end
redis.call('SADD', key, ARGV[1])
if n == 0 then redis.call('EXPIRE', key, ARGV[2]) end
return n + 1
`;

/** mailauth's DNS resolver contract: `(name, rrtype) → resolve()` result. */
export type DkimResolver = (name: string, rrtype: string) => Promise<unknown>;

/** Optional override of the DKIM key resolver (tests); production uses the configured DNS. */
export const DKIM_RESOLVER = Symbol('DKIM_RESOLVER');

export type DkimRunResult =
  | { ok: true; signatures: DkimSignatureEvidence[] }
  | { ok: false; reason: 'verifier_error' | 'aborted' | 'timeout' };

/** One streaming DKIM verification: the ingested bytes are teed into it while they arrive. */
export interface DkimRun {
  /** Never throws; a failed verifier stops consuming and `finish` reports it. */
  write(chunk: Buffer): Promise<void>;
  finish(): Promise<DkimRunResult>;
  abort(): void;
}

interface MailauthDkimResult {
  signingDomain?: string;
  algo?: string;
  signature?: string;
  canonBodyLengthLimited?: boolean;
  signingHeaders?: { keys?: string };
  modulusLength?: number;
  signTime?: string | null;
  status?: { result?: string };
}

/** Lower-case hex SHA-256 of the `b=` value without whitespace (the replay key). */
export function signatureIdOf(bValue: string): string {
  return createHash('sha256').update(bValue.replace(/\s+/g, ''), 'utf8').digest('hex');
}

/** mailauth results → evidence (unsigned messages have no entries; skipped ones are ignored). */
export function toSignatureEvidence(
  results: readonly MailauthDkimResult[],
): DkimSignatureEvidence[] {
  const out: DkimSignatureEvidence[] = [];
  for (const result of results) {
    if (!result.signingDomain || typeof result.signature !== 'string') continue;
    const signedAt = result.signTime ? new Date(result.signTime) : null;
    out.push({
      status: String(result.status?.result ?? 'neutral'),
      domain: result.signingDomain.toLowerCase(),
      algorithm: String(result.algo ?? '').toLowerCase(),
      bodyLengthLimited: result.canonBodyLengthLimited === true,
      signedHeaders: (result.signingHeaders?.keys ?? '')
        .split(':')
        .map((name) => name.trim().toLowerCase())
        .filter((name) => name.length > 0),
      keyBits: typeof result.modulusLength === 'number' ? result.modulusLength : null,
      signedAt: signedAt !== null && !Number.isNaN(signedAt.getTime()) ? signedAt : null,
      signatureId: signatureIdOf(result.signature),
    });
  }
  return out;
}

/** A resolver bound to PROVIDER_RELAY_DNS_SERVERS (empty = system) with the configured timeout. */
export function dkimResolver(servers: readonly string[], timeoutMs: number): DkimResolver {
  const resolver = new dns.Resolver({ timeout: timeoutMs, tries: 1 });
  if (servers.length > 0) resolver.setServers([...servers]);
  return (name, rrtype) => resolver.resolve(name, rrtype);
}

export type ProofVerifierConfig = Pick<
  ProviderRelayConfig,
  | 'PROVIDER_RELAY_DNS_SERVERS'
  | 'PROVIDER_RELAY_DNS_TIMEOUT_MS'
  | 'PROVIDER_RELAY_DKIM_REPLAY_WINDOW_SECONDS'
>;

export interface ProofInput {
  evidence: Omit<
    ProviderProofEvidence,
    'signatures' | 'verifierError' | 'replayCounts' | 'replayError'
  >;
  policy: ProviderRelayProofPolicy;
  dkim: DkimRunResult;
  /** Postfix queue id of the delivery (the member of the replay sets). */
  queueId: string;
}

/**
 * Proof verification of LMTP ingestion (step 8.2 D8, ADR-0078): `mailauth` DKIM verification
 * streamed alongside the S3 upload, key lookups through PROVIDER_RELAY_DNS_SERVERS, the replay
 * counter in Redis, then the pure `evaluateProviderProof`. DNS trouble, a verifier error or a
 * Redis error is `temperror` (I7), never an acceptance.
 */
@Injectable()
export class ProofVerifier {
  private readonly resolver: DkimResolver;

  constructor(
    private readonly redis: RedisService,
    @Inject(ADAPTER_CONFIG) private readonly config: ProofVerifierConfig,
    @Optional() @Inject(DKIM_RESOLVER) resolver?: DkimResolver,
  ) {
    this.resolver =
      resolver ??
      dkimResolver(config.PROVIDER_RELAY_DNS_SERVERS, config.PROVIDER_RELAY_DNS_TIMEOUT_MS);
  }

  startDkim(now: Date): DkimRun {
    const input = new PassThrough();
    let failed = false;
    let aborted = false;
    // Every signature's key lookup gets the DNS timeout; the whole verification a bounded budget.
    const budgetMs = Math.max(5000, this.config.PROVIDER_RELAY_DNS_TIMEOUT_MS * 4);
    const verification = dkimVerify(input, {
      resolver: this.resolver as never,
      curTime: now,
      minBitLength: 1024,
    }).then(
      (result) => result,
      () => {
        failed = true;
        return null;
      },
    );
    input.on('error', () => {
      failed = true;
    });
    return {
      write: async (chunk) => {
        if (failed || aborted || input.destroyed) return;
        if (input.write(chunk)) return;
        await Promise.race([once(input, 'drain').catch(() => undefined), verification]);
      },
      finish: async () => {
        if (aborted) return { ok: false, reason: 'aborted' };
        if (!input.destroyed) input.end();
        let timer: NodeJS.Timeout | undefined;
        const timeout = new Promise<'timeout'>((resolve) => {
          timer = setTimeout(() => resolve('timeout'), budgetMs);
        });
        try {
          const result = await Promise.race([verification, timeout]);
          if (result === 'timeout') {
            input.destroy();
            return { ok: false, reason: 'timeout' };
          }
          if (failed || result === null) return { ok: false, reason: 'verifier_error' };
          return {
            ok: true,
            signatures: toSignatureEvidence(result.results),
          };
        } finally {
          clearTimeout(timer);
        }
      },
      abort: () => {
        aborted = true;
        input.destroy();
      },
    };
  }

  /** Replay counting (only for policies with `dkimReplayMax`) and the proof evaluation. */
  async evaluate(input: ProofInput): Promise<ProviderProofOutcome> {
    const evidence: ProviderProofEvidence = {
      ...input.evidence,
      signatures: input.dkim.ok ? input.dkim.signatures : [],
      verifierError: !input.dkim.ok,
    };
    const candidates = input.dkim.ok ? dkimReplayCandidates(evidence, input.policy) : [];
    if (candidates.length > 0 && input.policy.dkimReplayMax !== undefined) {
      try {
        const counts = new Map<string, number>();
        for (const candidate of candidates) {
          const count = await this.redis.client.eval(
            REPLAY_SCRIPT,
            1,
            dkimReplayKey(candidate.signatureId),
            input.queueId,
            String(this.config.PROVIDER_RELAY_DKIM_REPLAY_WINDOW_SECONDS),
            String(input.policy.dkimReplayMax + 1),
          );
          counts.set(candidate.signatureId, Number(count));
        }
        evidence.replayCounts = counts;
      } catch {
        evidence.replayError = true;
      }
    }
    return evaluateProviderProof(evidence, input.policy);
  }
}
