import { Inject, Injectable } from '@nestjs/common';
import { intakeAddressHash, intakeLocalPart, parseIntakeLocalPart } from '@email-gateway/archive';
import type { Logger } from '@email-gateway/logger';
import { ADAPTER_CONFIG, ADAPTER_LOGGER } from '../config';
import { normalizeFingerprint, parseIpKey } from '../connectors/addresses';
import { InstanceSizeStore } from '../policy/instance-size.store';
import type { PolicyRequest } from '../policy/policy-protocol';
import {
  EgressIndexService,
  EgressIndexUnavailableError,
} from '../provider-relay/egress-index.service';
import { FixedWindowLimiter } from '../rate-limit/fixed-window-limiter';
import {
  DUNNO,
  INTAKE_ONE_DESTINATION,
  INTAKE_SENDER_NOT_AUTHORIZED,
  INTAKE_UNAVAILABLE,
  MUST_STARTTLS,
  POLICY_TEMPFAIL,
  RATE_LIMITED,
  TOO_BIG_FOR_RECIPIENT,
  UNKNOWN_USER,
} from '../shared/replies';
import {
  type AdmissionRefusal,
  admitIntakeRecipient,
  type IntakeRefusalCounter,
} from './admission';
import { InvalidIntakeKeyError, IntakeStateStore } from './intake-state.store';
import {
  type JournalIntakeConfig,
  journalIntakeDomain,
  normalizeIntakeDomain,
} from './journal-intake.config';
import { JournalIntakeCountersService } from './journal-intake-counters.service';
import { type IntakeRefusalCode, JournalIntakeMetrics } from './journal-intake.metrics';
import { JournalIntakeSourceCache } from './source-cache';

export type JournalIntakePolicyConfig = Pick<
  JournalIntakeConfig,
  | 'JOURNAL_INTAKE_ENABLED'
  | 'JOURNAL_INTAKE_DOMAIN'
  | 'JOURNAL_INTAKE_RATE_PER_SOURCE_PER_MINUTE'
  | 'JOURNAL_INTAKE_MAX_MESSAGE_BYTES'
>;

const INSTANCE = /^[A-Za-z0-9._-]{1,64}$/;
const QUEUE_ID = /^[A-Za-z0-9]{1,32}$/;

const REPLY_OF: Record<AdmissionRefusal | 'rate' | 'size', string> = {
  unknown_address: UNKNOWN_USER,
  unavailable: INTAKE_UNAVAILABLE,
  network: INTAKE_SENDER_NOT_AUTHORIZED,
  tls: MUST_STARTTLS,
  rate: RATE_LIMITED,
  size: TOO_BIG_FOR_RECIPIENT,
};

/** The domain part of an envelope address, normalized; null when there is none. */
function recipientParts(address: string | undefined): { local: string; domain: string } | null {
  if (!address) return null;
  const at = address.lastIndexOf('@');
  if (at <= 0 || at === address.length - 1) return null;
  return { local: address.slice(0, at), domain: normalizeIntakeDomain(address.slice(at + 1)) };
}

/** The certificate and public-key fingerprints Postfix passed, normalized. */
export function presentedFingerprints(request: PolicyRequest): string[] {
  return [request.ccert_fingerprint, request.ccert_pubkey_fingerprint]
    .map((value) => normalizeFingerprint(value))
    .filter((value): value is string => value !== null);
}

/**
 * The journal intake branch of the in-session policy (step 8.6 D2.2, ADR-0087), called by
 * `PolicyDecisionService` for `policy_context=inbound`:
 *
 * - `checkRecipient` at RCPT for a recipient in JOURNAL_INTAKE_DOMAIN: steps 1–4 through
 *   `admitIntakeRecipient` (source by address hash through the 30 s cache, organization,
 *   network, TLS), 5 the intake-only transaction (`sa:jintake:inst:<instance>`), 6 the per-source
 *   and per-organization rates, 7 the size (recorded in `InstanceSizeStore` for END-OF-MESSAGE),
 *   8 `DUNNO`. Refusals are answered in-session and counted per source;
 * - `claimTenant` before a tenant recipient's `DUNNO`: records `tenant` for the transaction so
 *   mixing is refused in both orders (`452 4.5.3`);
 * - `endOfMessage`: for an intake transaction, the marker `sa:jintake:q:<queueId>` with the TLS
 *   and certificate facts the LMTP re-check needs (XFORWARD carries none).
 *
 * Fail closed like the rest of the policy: Redis or database errors propagate (the caller
 * answers `DEFER_IF_PERMIT 4.3.5`), an unloaded egress index tempfails, nothing ever answers OK.
 * Logs carry the source public id and codes only, never addresses.
 */
@Injectable()
export class JournalIntakePolicy {
  private readonly logger: Logger;
  private readonly domain: string | null;

  constructor(
    private readonly sources: JournalIntakeSourceCache,
    private readonly egress: EgressIndexService,
    private readonly limiter: FixedWindowLimiter,
    private readonly sizes: InstanceSizeStore,
    private readonly state: IntakeStateStore,
    private readonly counters: JournalIntakeCountersService,
    private readonly metrics: JournalIntakeMetrics,
    @Inject(ADAPTER_CONFIG) private readonly config: JournalIntakePolicyConfig,
    @Inject(ADAPTER_LOGGER) logger: Logger,
  ) {
    this.logger = logger.child({ component: 'journal-intake-policy' });
    this.domain = journalIntakeDomain(config);
  }

  /** The recipient's domain is the intake domain (exactly; subdomains are not intake). */
  isIntakeRecipient(recipient: string | undefined): boolean {
    if (this.domain === null) return false;
    return recipientParts(recipient)?.domain === this.domain;
  }

  /** D2.2 at RCPT for an intake recipient. */
  async checkRecipient(request: PolicyRequest, now: Date): Promise<string> {
    const parts = recipientParts(request.recipient);
    const token = parts ? parseIntakeLocalPart(parts.local) : null;
    if (token === null) return this.refuseUnmatched('unknown_address');
    const snapshot = await this.sources.get(intakeAddressHash(intakeLocalPart(token)));

    let admission;
    try {
      admission = admitIntakeRecipient(snapshot, {
        now,
        clientAddress: request.client_address,
        tls: Boolean(request.encryption_protocol),
        certFingerprints: presentedFingerprints(request),
        egress: () => this.egress.current(),
      });
    } catch (err) {
      if (!(err instanceof EgressIndexUnavailableError)) throw err;
      this.metrics.refused('rcpt', 'egress_unavailable');
      this.logger.warn('provider egress ranges not loaded; tempfailing a journal intake recipient');
      return POLICY_TEMPFAIL;
    }
    if (snapshot === null) return this.refuseUnmatched('unknown_address');
    const source = { publicId: snapshot.source.publicId, id: BigInt(snapshot.source.id) };
    if (!admission.ok) {
      return this.refuse(source, admission.refusal, admission.counter, admission.code, now);
    }

    // 5. One destination kind per transaction.
    const instance = request.instance ?? '';
    if (!INSTANCE.test(instance)) throw new InvalidIntakeKeyError('missing instance attribute');
    if (!(await this.state.claim(instance, `src:${snapshot.source.id}`))) {
      this.metrics.refused('rcpt', 'one_destination');
      return INTAKE_ONE_DESTINATION;
    }

    // 6. Rates: per source (platform key) and per organization (plan limit).
    const limited =
      (await this.limiter.exceeded(
        'jintake_src',
        snapshot.source.id,
        this.config.JOURNAL_INTAKE_RATE_PER_SOURCE_PER_MINUTE,
        now,
      )) ||
      (await this.limiter.exceeded(
        'jintake_org',
        snapshot.source.organizationId,
        snapshot.organization.messagesPerMinute,
        now,
      ));
    if (limited) {
      return this.refuse(source, 'rate', 'refused_rate', 'refused_rate', now);
    }

    // 7. Size: the smallest of the source, plan and platform limits.
    const limit = Math.min(
      snapshot.source.maxMessageBytes ?? Number.MAX_SAFE_INTEGER,
      snapshot.organization.maxMessageBytes,
      this.config.JOURNAL_INTAKE_MAX_MESSAGE_BYTES,
    );
    const declared = Number(request.size ?? '0');
    if (Number.isSafeInteger(declared) && declared > limit) {
      return this.refuse(source, 'size', 'refused_size', 'refused_size', now);
    }
    await this.sizes.recordLimit(instance, limit);

    this.logger.debug(
      { sourceId: snapshot.source.publicId, kind: snapshot.source.kind },
      'journal intake recipient accepted by policy',
    );
    return DUNNO;
  }

  /**
   * D2.2.5 for a tenant recipient (only while intake is on): `452 4.5.3` when the transaction
   * already carries an intake recipient, else null (and `tenant` is recorded).
   */
  async claimTenant(request: PolicyRequest): Promise<string | null> {
    if (this.domain === null) return null;
    const instance = request.instance ?? '';
    if (!INSTANCE.test(instance)) throw new InvalidIntakeKeyError('missing instance attribute');
    if (await this.state.claim(instance, 'tenant')) return null;
    this.metrics.refused('rcpt', 'one_destination');
    return INTAKE_ONE_DESTINATION;
  }

  /**
   * END-OF-MESSAGE of an intake transaction: the marker for the LMTP re-check (null = continue
   * with DUNNO). Errors propagate (tempfail): an intake message must never reach the journal LMTP
   * without its marker.
   */
  async endOfMessage(request: PolicyRequest): Promise<string | null> {
    if (this.domain === null) return null;
    const instance = request.instance ?? '';
    if (!INSTANCE.test(instance)) throw new InvalidIntakeKeyError('missing instance attribute');
    const kind = await this.state.kindOf(instance);
    if (kind === null || kind === 'tenant') return null;
    const queueId = request.queue_id ?? '';
    if (!QUEUE_ID.test(queueId))
      throw new InvalidIntakeKeyError('END-OF-MESSAGE without a queue id');
    await this.state.writeMarker(queueId, {
      v: 1,
      sourceId: kind.slice('src:'.length),
      tls: Boolean(request.encryption_protocol),
      tlsProtocol: request.encryption_protocol ? request.encryption_protocol.slice(0, 16) : null,
      certFingerprints: presentedFingerprints(request).slice(0, 2),
      clientAddress: parseIpKey(request.client_address)?.text ?? 'unknown',
    });
    return null;
  }

  /** END-OF-MESSAGE size refusal of an intake transaction: counted for its source. */
  recordEndOfMessageTooBig(request: PolicyRequest, now: Date): void {
    if (this.domain === null) return;
    const instance = request.instance ?? '';
    if (!INSTANCE.test(instance)) return;
    void this.state
      .kindOf(instance)
      .then((kind) => {
        if (kind === null || kind === 'tenant') return;
        this.metrics.refused('eom', 'size');
        this.counters.record(
          BigInt(kind.slice('src:'.length)),
          { counts: { refused_size: 1 }, refusedAt: now, refusalCode: 'refused_size' },
          now,
        );
      })
      .catch(() => undefined);
  }

  private refuseUnmatched(code: IntakeRefusalCode): string {
    this.metrics.refused('rcpt', code);
    return UNKNOWN_USER;
  }

  private refuse(
    source: { publicId: string; id: bigint },
    code: AdmissionRefusal | 'rate' | 'size',
    counter: IntakeRefusalCounter | null,
    refusalCode: string | null,
    now: Date,
  ): string {
    this.metrics.refused('rcpt', code);
    if (counter !== null) {
      this.counters.record(
        source.id,
        { counts: { [counter]: 1 }, refusedAt: now, refusalCode: refusalCode ?? counter },
        now,
      );
    }
    this.logger.info(
      { sourceId: source.publicId, code: refusalCode ?? code },
      'journal intake recipient refused',
    );
    return REPLY_OF[code];
  }
}
