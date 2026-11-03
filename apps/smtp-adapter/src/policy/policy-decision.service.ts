import { Inject, Injectable } from '@nestjs/common';
import { type Counter, type Histogram, MetricsService } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import { ADAPTER_CONFIG, ADAPTER_LOGGER, type SmtpAdapterConfig } from '../config';
import { parseIpKey } from '../connectors/addresses';
import {
  connectorAllowsIp,
  ConnectorResolver,
  type ConnectorView,
} from '../connectors/connector-resolver.service';
import { DkimReadinessService } from '../outbound/dkim-readiness.service';
import { SuppressionService } from '../outbound/suppression.service';
import { FixedWindowLimiter } from '../rate-limit/fixed-window-limiter';
import {
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
      // The bounce-notice address is reserved for postfix-outbound's own postmaster copies
      // (D13): no listener may accept mail for it, or a client could reach the bounce handler
      // through reinjection with a forged notice (review finding, §12.7).
      if (this.isBounceDomain(request.recipient)) return RELAY_DENIED;
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
      return this.endOfMessage(request);
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

  /** Certificate wins over IP (D11). A certificate connector's networks restrict the client. */
  private async resolveConnector(
    request: PolicyRequest,
    context: 'submission' | 'relay',
  ): Promise<ConnectorView | null> {
    if (context === 'submission') {
      const username = request.sasl_username ?? '';
      return username === '' ? null : this.connectors.bySaslUsername(username);
    }
    const ip = parseIpKey(request.client_address);
    for (const fingerprint of [request.ccert_fingerprint, request.ccert_pubkey_fingerprint]) {
      if (!fingerprint) continue;
      const byCertificate = await this.connectors.byCertificateFingerprint(fingerprint);
      if (byCertificate) return connectorAllowsIp(byCertificate, ip) ? byCertificate : null;
    }
    return ip ? this.connectors.byClientAddress(ip) : null;
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
  private async endOfMessage(request: PolicyRequest): Promise<string> {
    const instance = request.instance ?? '';
    if (!INSTANCE.test(instance)) throw new PolicyMisconfiguredError('missing instance attribute');
    const limit = await this.sizes.limit(instance);
    return limit !== null && sizeOf(request) > limit ? TOO_BIG : DUNNO;
  }

  private async recordSizeLimit(request: PolicyRequest, limit: number): Promise<void> {
    const instance = request.instance ?? '';
    if (!INSTANCE.test(instance)) throw new PolicyMisconfiguredError('missing instance attribute');
    await this.sizes.recordLimit(instance, limit);
  }
}
