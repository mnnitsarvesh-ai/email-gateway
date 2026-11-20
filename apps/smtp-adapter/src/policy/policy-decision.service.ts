import { Inject, Injectable, Optional } from '@nestjs/common';
import { type Counter, type Histogram, MetricsService } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import { AtoRestrictionService } from '../ato/restriction.service';
import { AtoTelemetryRecorder } from '../ato/telemetry-recorder';
import { ADAPTER_CONFIG, ADAPTER_LOGGER, type SmtpAdapterConfig } from '../config';
import { parseIpKey } from '../connectors/addresses';
import {
  connectorAllowsIp,
  ConnectorResolver,
  type ConnectorView,
} from '../connectors/connector-resolver.service';
import { JournalIntakePolicy } from '../journal-intake/journal-intake-policy.service';
import { DkimReadinessService } from '../outbound/dkim-readiness.service';
import { ProviderRelayPolicy } from '../provider-relay/provider-relay-policy.service';
import { SuppressionService } from '../outbound/suppression.service';
import { FixedWindowLimiter } from '../rate-limit/fixed-window-limiter';
import {
  ATO_SEND_RESTRICTED,
  ATO_SEND_RESTRICTED_DEFER,
  DUNNO,
  MUST_STARTTLS,
  NOT_READY_FOR_OUTBOUND,
  POLICY_TEMPFAIL,
  RATE_LIMITED,
  RELAY_DENIED,
  SENDER_NOT_AUTHORIZED,
  SIGNING_UNAVAILABLE,
  SUPPRESSED,
  TOO_BIG,
  TOO_BIG_FOR_RECIPIENT,
  UNKNOWN_USER,
} from '../shared/replies';
import { ReputationRecorder } from '../shared/reputation';
import { DomainPolicyService } from '../tenancy/domain-policy.service';
import { RecipientValidator } from '../tenancy/recipient-validator.service';
import { TenantLimitsService } from '../tenancy/tenant-limits.service';
import { InstanceSizeStore } from './instance-size.store';
import type { PolicyRequest } from './policy-protocol';

/** `policy_context` values set per listener in main.cf/master.cf (step 2.2 D9). */
export const POLICY_CONTEXTS = [
  'inbound',
  'submission',
  'relay',
  'reinject-inbound',
  'reinject-outbound',
] as const;
export type PolicyContext = (typeof POLICY_CONTEXTS)[number];

export type PolicyActionLabel = 'dunno' | 'reject' | 'defer' | 'tempfail';

export type PolicyDecisionConfig = Pick<
  SmtpAdapterConfig,
  | 'SMTP_POLICY_DECISION_TIMEOUT_MS'
  | 'SMTP_RATE_CLIENT_RCPT_PER_MINUTE'
  | 'SMTP_OUTBOUND_REQUIRE_DKIM'
  | 'POSTFIX_BOUNCE_DOMAIN'
>;

/** Postfix `instance` attribute (`<pid>.<hex>.<hex>.<n>`); bounded before it becomes a key. */
const INSTANCE = /^[A-Za-z0-9._-]{1,64}$/;

class DecisionTimeoutError extends Error {}
class PolicyMisconfiguredError extends Error {}

interface Address {
  local: string;
  domain: string;
}

/** `local@domain` split at the last `@`; null when either part is empty. */
export function splitAddress(address: string | undefined): Address | null {
  if (!address) return null;
  const at = address.lastIndexOf('@');
  if (at <= 0 || at === address.length - 1) return null;
  return { local: address.slice(0, at), domain: address.slice(at + 1) };
}

/** Policy action → `action` label of `smtp_policy_decisions_total`. */
export function actionLabel(action: string): PolicyActionLabel {
  if (action === DUNNO) return 'dunno';
  if (action.startsWith('REJECT') || /^5\d\d /.test(action)) return 'reject';
  if (action === POLICY_TEMPFAIL) return 'tempfail';
  return 'defer';
}

/** The size attribute (declared SIZE= at RCPT, real size at END-OF-MESSAGE); 0 when absent. */
function sizeOf(request: PolicyRequest): number {
  const value = Number(request.size ?? '0');
  return Number.isSafeInteger(value) && value > 0 ? value : 0;
}

function minLimit(...limits: (number | null)[]): number | null {
  const present = limits.filter((limit): limit is number => limit !== null);
  return present.length === 0 ? null : Math.min(...present);
}

/**
 * In-session policy decisions (step 2.2 D4 inbound, D11 outbound contexts). Postfix holds the
 * SMTP session while we answer, so only indexed, cached lookups happen here; content scanning
 * is post-queue.
 *
 * Fail closed: an unknown or missing `policy_context`, an unexpected `protocol_state`, any
 * thrown error (DB, Redis) and a decision slower than SMTP_POLICY_DECISION_TIMEOUT_MS all answer
 * `DEFER_IF_PERMIT 4.3.5`. The adapter never answers `OK`: a pass is `DUNNO`, which hands the
 * decision back to Postfix's own restrictions. Full recipient addresses are never logged above
 * debug, and only the domain part even there.
 *
 * Step 8.4 (ADR-0073): in `submission` / `relay` at RCPT an active ATO `send_block` on the
 * connector or on the envelope sender's mailbox answers ATO_SEND_RESTRICTED (or its defer form)
 * after the sender checks and before suppression and rate limits (D14; inbound, reinjection and
 * bounce paths are never affected); at END-OF-MESSAGE a passed submission is recorded for ATO
 * detection after the answer (D4, never awaited by the reply).
 *
 * Step 8.6 D2.2 (ADR-0087): in `inbound` at RCPT a recipient in JOURNAL_INTAKE_DOMAIN is decided
 * by the journal intake branch only (never resolved as a tenant domain); a tenant recipient
 * records the transaction kind before its DUNNO, so intake and tenant recipients never share a
 * transaction (`452 4.5.3`, both orders); at END-OF-MESSAGE an intake transaction writes its
 * marker for the journal LMTP. Absent module (intake off) = step 8.5 behaviour.
 */
@Injectable()
export class PolicyDecisionService {
  private readonly logger: Logger;
  private readonly decisions: Counter<'context' | 'action'>;
  private readonly duration: Histogram<'context'>;

  constructor(
    private readonly domains: DomainPolicyService,
    private readonly limits: TenantLimitsService,
    private readonly recipients: RecipientValidator,
    private readonly limiter: FixedWindowLimiter,
    private readonly connectors: ConnectorResolver,
    private readonly suppressions: SuppressionService,
    private readonly dkim: DkimReadinessService,
    private readonly sizes: InstanceSizeStore,
    private readonly reputation: ReputationRecorder,
    metrics: MetricsService,
    @Inject(ADAPTER_CONFIG) private readonly config: PolicyDecisionConfig,
    @Inject(ADAPTER_LOGGER) logger: Logger,
    private readonly restrictions: AtoRestrictionService,
    private readonly telemetry: AtoTelemetryRecorder,
    // Step 8.2 D7/D8/D10 (provider relay); absent = step 2.2 behaviour.
    @Optional() private readonly providerRelay?: ProviderRelayPolicy,
    // Step 8.6 D2.2 (journal intake); absent = intake off.
    @Optional() private readonly journalIntake?: JournalIntakePolicy,
  ) {
    this.logger = logger.child({ component: 'policy-decision' });
    this.decisions = metrics.counter(
      'smtp_policy_decisions_total',
      'Policy delegation answers by context and action',
      ['context', 'action'],
    );
    this.duration = metrics.histogram(
      'smtp_policy_decision_seconds',
      'Policy decision latency',
      ['context'],
      [0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5],
    );
  }

  async decide(request: PolicyRequest): Promise<string> {
    const started = performance.now();
    const context = (POLICY_CONTEXTS as readonly string[]).includes(request.policy_context ?? '')
      ? (request.policy_context as PolicyContext)
      : null;
    let action: string;
    try {
      action = await this.withTimeout(this.dispatch(request, context));
    } catch (err) {
      if (err instanceof DecisionTimeoutError) {
        this.logger.error({ context }, 'policy decision timed out; tempfailing');
      } else if (err instanceof PolicyMisconfiguredError) {
        this.logger.error({ context, reason: err.message }, 'policy request refused; tempfailing');
      } else {
        this.logger.error({ err, context }, 'policy decision failed; tempfailing');
      }
      action = POLICY_TEMPFAIL;
    }
    if (action.startsWith('OK') || action === '') {
      // Defence in depth: nothing in this service may ever accept on Postfix's behalf.
      this.logger.error({ context }, 'refusing to answer OK; tempfailing');
      action = POLICY_TEMPFAIL;
    }
    const contextLabel = context ?? 'unknown';
    this.decisions.inc({ context: contextLabel, action: actionLabel(action) });
    this.duration.observe({ context: contextLabel }, (performance.now() - started) / 1000);
    return action;
  }

  private async withTimeout(decision: Promise<string>): Promise<string> {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new DecisionTimeoutError()),
        this.config.SMTP_POLICY_DECISION_TIMEOUT_MS,
      );
    });
    // A late failure of an abandoned decision must not become an unhandled rejection.
    decision.catch(() => undefined);
    try {
      return await Promise.race([decision, timeout]);
    } finally {
      clearTimeout(timer);
    }
  }

  private async dispatch(request: PolicyRequest, context: PolicyContext | null): Promise<string> {
    if (request.request !== 'smtpd_access_policy') {
      throw new PolicyMisconfiguredError('unsupported policy request type');
    }
    if (context === null) {
      throw new PolicyMisconfiguredError('missing or unknown policy_context');
    }
    const state = request.protocol_state;
    const now = new Date();
    if (state === 'RCPT') {
      // Step 8.6 D2.2: the intake domain is decided by the intake branch alone.
      if (context === 'inbound' && this.journalIntake?.isIntakeRecipient(request.recipient)) {
        return this.journalIntake.checkRecipient(request, now);
      }
      // The bounce-notice address is reserved for postfix-outbound's own postmaster copies
      // (D13): no listener may accept mail for it, or a client could reach the bounce handler
      // through reinjection with a forged notice (review finding, §12.7).
      if (this.isBounceDomain(request.recipient)) return RELAY_DENIED;
      // Step 8.2 D10: probe addresses exist only on provider-relay sessions.
      if (this.providerRelay?.refusesProbeRecipient(request, context)) return UNKNOWN_USER;
      switch (context) {
        case 'inbound':
          return this.inboundRecipient(request, now);
        case 'submission':
        case 'relay':
          return this.connectorRecipient(request, context, now);
        case 'reinject-inbound':
          return this.reinjectInbound(request);
        case 'reinject-outbound':
          return this.reinjectOutbound(request);
      }
    }
    if (
      state === 'END-OF-MESSAGE' &&
      (context === 'inbound' || context === 'submission' || context === 'relay')
    ) {
      const action = await this.endOfMessage(request, context);
      if (action === DUNNO && context !== 'inbound') {
        // After the answer: the connector lookup (cached) never delays the reply.
        setImmediate(() => void this.recordSubmission(request, context, now));
      }
      return action;
    }
    throw new PolicyMisconfiguredError(`unexpected protocol_state for ${context}`);
  }

  /** The recipient is in POSTFIX_BOUNCE_DOMAIN or one of its subdomains. */
  private isBounceDomain(recipient: string | undefined): boolean {
    const domain = splitAddress(recipient)?.domain.toLowerCase().replace(/\.$/, '');
    if (!domain) return false;
    const reserved = this.config.POSTFIX_BOUNCE_DOMAIN;
    return domain === reserved || domain.endsWith(`.${reserved}`);
  }

  /** D4, at RCPT. */
  private async inboundRecipient(request: PolicyRequest, now: Date): Promise<string> {
    const recipient = splitAddress(request.recipient);
    const domain = recipient ? await this.domains.get(recipient.domain) : null;
    if (!recipient || !domain || !domain.inboundEnabled) return RELAY_DENIED;

    const client = parseIpKey(request.client_address)?.text ?? 'unknown';
    if (
      await this.limiter.exceeded('ip', client, this.config.SMTP_RATE_CLIENT_RCPT_PER_MINUTE, now)
    ) {
      return RATE_LIMITED;
    }
    const orgId = domain.organizationId;
    const limits = await this.limits.get(orgId);
    if (
      await this.limiter.exceeded(
        'tenant_in',
        String(orgId),
        limits.inboundRecipientsPerMinute,
        now,
      )
    ) {
      return RATE_LIMITED;
    }

    if ((await this.recipients.validate(domain, recipient.local)) === 'reject') {
      return UNKNOWN_USER;
    }

    const limit = minLimit(domain.maxMessageSizeBytes, limits.maxMessageSizeBytes);
    if (limit !== null) {
      if (sizeOf(request) > limit) return TOO_BIG_FOR_RECIPIENT;
      await this.recordSizeLimit(request, limit);
    }
    // Step 8.6 D2.2.5: no tenant recipient in a transaction that carries an intake recipient.
    const mixed = await this.journalIntake?.claimTenant(request);
    if (mixed) return mixed;
    this.logger.debug(
      { context: 'inbound', organizationId: String(orgId), recipientDomain: domain.name },
      'recipient accepted by policy',
    );
    return DUNNO;
  }

  /** D11 `submission` / `relay`, at RCPT. */
  private async connectorRecipient(
    request: PolicyRequest,
    context: 'submission' | 'relay',
    now: Date,
  ): Promise<string> {
    const connector = await this.resolveConnector(request, context);
    // Step 8.2 D7.4/D7.5: provider-relay answers (null = continue with the checks below).
    const providerAnswer = this.providerRelay?.checkRecipient(request, context, connector);
    if (providerAnswer) return providerAnswer;
    if (!connector) return RELAY_DENIED;
    if (context === 'relay' && connector.requireTls && !request.encryption_protocol) {
      return MUST_STARTTLS;
    }

    const sender = splitAddress(request.sender);
    const senderDomain = sender ? await this.domains.get(sender.domain) : null;
    if (
      !senderDomain ||
      senderDomain.organizationId !== connector.organizationId ||
      !senderDomain.outboundEnabled
    ) {
      return SENDER_NOT_AUTHORIZED;
    }
    if (this.config.SMTP_OUTBOUND_REQUIRE_DKIM && !senderDomain.hasActiveDkimKey) {
      return NOT_READY_FOR_OUTBOUND;
    }

    const orgId = connector.organizationId;
    // D14: ATO sending restriction (cached per organization; errors propagate = tempfail).
    const restriction = await this.restrictions.sendBlock(
      orgId,
      connector.id,
      (request.sender ?? '').toLowerCase(),
      now,
    );
    if (restriction !== null) {
      this.logger.info(
        { context, organizationId: String(orgId), connectorId: connector.publicId, restriction },
        'submission refused by an ATO sending restriction',
      );
      return restriction === 'reject' ? ATO_SEND_RESTRICTED : ATO_SEND_RESTRICTED_DEFER;
    }
    const recipient = request.recipient ?? '';
    const recipientParts = splitAddress(recipient);
    if (!recipientParts) return RELAY_DENIED;
    if (await this.suppressions.isSuppressed(orgId, recipient, now)) {
      void this.reputation.record(orgId, 'suppressed');
      return SUPPRESSED;
    }

    const limits = await this.limits.get(orgId);
    // Per minute first: deferred retries must not burn the daily quota.
    const limited =
      (await this.limiter.exceeded(
        'tenant_out',
        String(orgId),
        limits.outboundRecipientsPerMinute,
        now,
      )) ||
      (await this.limiter.exceeded(
        'tenant_out_day',
        String(orgId),
        limits.outboundRecipientsPerDay,
        now,
      ));
    if (limited) {
      void this.reputation.record(orgId, 'rate_limited');
      return RATE_LIMITED;
    }

    if (limits.maxMessageSizeBytes !== null) {
      if (sizeOf(request) > limits.maxMessageSizeBytes) return TOO_BIG;
      await this.recordSizeLimit(request, limits.maxMessageSizeBytes);
    }

    void this.reputation.record(orgId, 'submitted');
    this.logger.debug(
      {
        context,
        organizationId: String(orgId),
        connectorId: connector.publicId,
        recipientDomain: recipientParts.domain,
      },
      'outbound recipient accepted by policy',
    );
    return DUNNO;
  }

  /** D4: one accepted submission for ATO detection; failures are logged, never answered. */
  private async recordSubmission(
    request: PolicyRequest,
    context: 'submission' | 'relay',
    now: Date,
  ): Promise<void> {
    if (!this.telemetry.enabled) return;
    try {
      const connector = await this.resolveConnector(request, context);
      // Step 8.2 provider_relay connectors are shared provider infrastructure, not an account
      // credential: the 8.4 submission event (SMTP_CONNECTOR_AUTH_TYPE_VALUES) does not cover them.
      if (!connector || connector.authType === 'provider_relay') return;
      const recipients = Number(request.recipient_count ?? '0');
      this.telemetry.recordSubmission({
        occurredAt: now,
        organizationId: connector.organizationId,
        context,
        connectorId: connector.id,
        connectorAuthType: connector.authType,
        queueId: request.queue_id,
        clientIp: request.client_address,
        heloName: request.helo_name,
        tlsProtocol: request.encryption_protocol,
        senderAddress: request.sender,
        recipientCount: Number.isSafeInteger(recipients) ? recipients : 0,
        sizeBytes: sizeOf(request),
      });
    } catch (err) {
      this.logger.warn({ err, context }, 'ATO submission telemetry not recorded');
    }
  }

  /**
   * Certificate wins over IP (D11). A certificate connector's networks restrict the client.
   *
   * Step 8.2 D7.3: the provider relay after certificate and source-IP connectors. A client in the
   * provider egress ranges is shared infrastructure: Microsoft 365 and Google present one
   * certificate and one address pool for every customer, so a certificate or source-IP connector
   * matched there is not tenant-unique. Such a connector applies only to senders of its own
   * organization; every other sender from those ranges is resolved by the provider relay (with
   * its tenant and DKIM proof), so no organization can capture the provider traffic of another
   * one by registering the provider's certificate fingerprint (review finding).
   */
  private async resolveConnector(
    request: PolicyRequest,
    context: 'submission' | 'relay',
  ): Promise<ConnectorView | null> {
    if (context === 'submission') {
      const username = request.sasl_username ?? '';
      return username === '' ? null : this.connectors.bySaslUsername(username);
    }
    const ip = parseIpKey(request.client_address);
    let matched: ConnectorView | null = null;
    let byCertificate = false;
    for (const fingerprint of [request.ccert_fingerprint, request.ccert_pubkey_fingerprint]) {
      if (!fingerprint) continue;
      const connector = await this.connectors.byCertificateFingerprint(fingerprint);
      if (connector) {
        byCertificate = true;
        matched = connectorAllowsIp(connector, ip) ? connector : null;
        break;
      }
    }
    if (!byCertificate) matched = ip ? await this.connectors.byClientAddress(ip) : null;
    if (this.providerRelay?.isSharedProviderClient(request.client_address)) {
      if (matched && (await this.senderOrganization(request)) === matched.organizationId) {
        return matched;
      }
      return (await this.providerRelay.resolve(request)) ?? null;
    }
    if (byCertificate) return matched;
    return matched ?? (await this.providerRelay?.resolve(request)) ?? null;
  }

  /** The organization of the envelope sender's domain (null: none, or not a tenant domain). */
  private async senderOrganization(request: PolicyRequest): Promise<bigint | null> {
    const sender = splitAddress(request.sender);
    const domain = sender ? await this.domains.get(sender.domain) : null;
    return domain?.organizationId ?? null;
  }

  /** D11 `reinject-inbound`: only to active tenant domains (never the Internet). */
  private async reinjectInbound(request: PolicyRequest): Promise<string> {
    const recipient = splitAddress(request.recipient);
    const domain = recipient ? await this.domains.get(recipient.domain) : null;
    return domain ? DUNNO : RELAY_DENIED;
  }

  /** D11 `reinject-outbound`: tenant sender, not suppressed, signing key published. */
  private async reinjectOutbound(request: PolicyRequest): Promise<string> {
    const sender = splitAddress(request.sender);
    const senderDomain = sender ? await this.domains.get(sender.domain) : null;
    if (!senderDomain || !senderDomain.outboundEnabled) return SENDER_NOT_AUTHORIZED;
    const orgId = senderDomain.organizationId;
    const recipient = request.recipient ?? '';
    if (!splitAddress(recipient)) return RELAY_DENIED;
    if (await this.suppressions.isSuppressed(orgId, recipient)) {
      void this.reputation.record(orgId, 'suppressed');
      return SUPPRESSED;
    }
    if (!(await this.dkim.isReady(senderDomain.name))) return SIGNING_UNAVAILABLE;
    void this.reputation.record(orgId, 'relayed');
    return DUNNO;
  }

  /** D4 END-OF-MESSAGE: the real size against the smallest limit recorded at RCPT. */
  private async endOfMessage(request: PolicyRequest, context: PolicyContext): Promise<string> {
    const instance = request.instance ?? '';
    if (!INSTANCE.test(instance)) throw new PolicyMisconfiguredError('missing instance attribute');
    const limit = await this.sizes.limit(instance);
    if (limit !== null && sizeOf(request) > limit) {
      if (context === 'inbound') this.journalIntake?.recordEndOfMessageTooBig(request, new Date());
      return TOO_BIG;
    }
    // Step 8.2 D8.1: the provider relay marker before DUNNO (a Redis error tempfails).
    if (context === 'relay' && this.providerRelay) {
      const answer = await this.providerRelay.endOfMessage(
        request,
        await this.resolveConnector(request, context),
      );
      if (answer !== null) return answer;
    }
    // Step 8.6: the marker of an intake transaction before DUNNO (a Redis error tempfails).
    if (context === 'inbound' && this.journalIntake) {
      const answer = await this.journalIntake.endOfMessage(request);
      if (answer !== null) return answer;
    }
    return DUNNO;
  }

  private async recordSizeLimit(request: PolicyRequest, limit: number): Promise<void> {
    const instance = request.instance ?? '';
    if (!INSTANCE.test(instance)) throw new PolicyMisconfiguredError('missing instance attribute');
    await this.sizes.recordLimit(instance, limit);
  }
}
