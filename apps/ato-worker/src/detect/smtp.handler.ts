import { NonRetryableError } from '@email-gateway/common';
import {
  canonicalIp,
  hmacKey,
  ipPrefix,
  sha256Hex,
  type AuthOutcome,
} from '@email-gateway/ato-detection';
import {
  smtpAuthRecordedV1,
  smtpSubmissionRecordedV1,
  type EventEnvelope,
  type SmtpAuthRecordedV1,
} from '@email-gateway/event-contracts';
import type { AtoEventResult, AtoEventSource } from '../metrics/ato-metrics';
import { atoEnabled, type OrgContext } from '../reads/org-context';
import { LEDGERS, subEventId } from '../shared/db';
import {
  detectLedgered,
  enrichOutside,
  recordPlatformFailure,
  runLedgered,
  type DetectDeps,
} from './context';
import { authObservation } from './login.handler';
import type { DetectionPipeline } from './pipeline';

type AuthEntry = SmtpAuthRecordedV1['entries'][number];

const OUTCOMES: Readonly<Record<AuthEntry['result'], AuthOutcome>> = {
  ok: 'success',
  fail: 'failure',
  throttled: 'throttled',
  blocked: 'blocked',
};

const hourStart = (at: Date): Date => new Date(Math.floor(at.getTime() / 3_600_000) * 3_600_000);

/**
 * `smtp.auth.recorded.v1` and `smtp.submission.recorded.v1` (D4). Batches are processed entry by
 * entry, each under its own ledger key (`eventId`, `seq`), so a redelivered batch never counts an
 * entry twice and every transaction stays short.
 */
export class SmtpHandler {
  constructor(
    private readonly deps: DetectDeps,
    private readonly pipeline: DetectionPipeline,
  ) {}

  private count(source: AtoEventSource, result: AtoEventResult, n = 1): void {
    this.deps.metrics?.events.inc({ source, result }, n);
  }

  /** Connectors of the batch that belong to the organization (echo-checked). */
  private async connectors(orgId: bigint, ids: readonly string[]): Promise<Set<string>> {
    const unique = [...new Set(ids)].map((id) => BigInt(id));
    if (unique.length === 0) return new Set();
    const rows = await this.deps.prisma.smtpConnector.findMany({
      where: { id: { in: unique } },
      select: { id: true, organizationId: true },
    });
    return new Set(rows.filter((r) => r.organizationId === orgId).map((r) => r.id.toString()));
  }

  private async org(orgId: bigint, source: AtoEventSource, n: number): Promise<OrgContext | null> {
    const org = await this.deps.orgs.get(orgId);
    if (!org.exists || !org.active) {
      this.count(source, 'skipped_org', n);
      return null;
    }
    if (!atoEnabled(org)) {
      this.count(source, 'skipped_feature', n);
      return null;
    }
    return org;
  }

  /** SMTP AUTH decisions (D4, D8): platform IP windows, then connector accounts of ATO tenants. */
  async handleAuth(event: EventEnvelope<unknown>): Promise<'counted'> {
    const parsed = smtpAuthRecordedV1.safeParse(event.payload);
    if (!parsed.success) throw new NonRetryableError('payload_invalid');
    const entries = parsed.data.entries;
    const orgId = BigInt(event.organizationId);
    for (const e of entries) {
      if (e.result === 'ok' || !e.clientIp) continue;
      const member = e.connectorId
        ? `smtp-connector:${e.connectorId}`
        : `smtp-user:${e.usernameHash ?? 'unknown'}`;
      await recordPlatformFailure(
        this.deps,
        `${event.eventId}:${e.seq}`,
        e.clientIp,
        member,
        new Date(e.occurredAt),
      );
    }
    const org = await this.org(orgId, 'smtp_auth', entries.length);
    if (!org) return 'counted';
    const platformId = await this.deps.orgs.platformOrganizationId();
    const known = await this.connectors(
      orgId,
      entries.flatMap((e) => (e.connectorId ? [e.connectorId] : [])),
    );
    const enriched = await enrichOutside(
      this.deps,
      orgId,
      entries.map((e) => e.clientIp),
    );
    for (const e of entries) {
      const occurredAt = new Date(e.occurredAt);
      const ip = e.clientIp ? canonicalIp(e.clientIp) : null;
      const en = ip ? (enriched.get(ip) ?? null) : null;
      const outcome = OUTCOMES[e.result];
      const success = outcome === 'success';
      const authEvent = {
        source: 'smtp_auth' as const,
        channel: 'smtp' as const,
        outcome,
        failureCode: e.failureReason,
        // Successful AUTHs are aggregated per connector, IP and hour (D22).
        occurredAt: success ? hourStart(occurredAt) : occurredAt,
        lastOccurredAt: occurredAt,
        aggregate: success,
        ip,
        ipPrefix: en?.ipPrefix ?? (ip ? ipPrefix(ip) : null),
        geo: en?.geo ?? null,
        reputation: en?.reputation ?? null,
        device: null,
        mechanism: e.mechanism,
        sourceRef: `smtp:${event.eventId}:${e.seq}`.slice(0, 64),
        dedupeKey: success
          ? sha256Hex(
              `smtp-ok|${e.connectorId}|${ip ?? '-'}|${hourStart(occurredAt).toISOString()}`,
            )
          : sha256Hex(`smtp|${event.eventId}|${e.seq}`),
      };
      const ledger = { consumer: LEDGERS.events, source: 'smtp_auth' as const, occurredAt };
      if (e.connectorId === null) {
        // Unknown usernames arrive in batches of the platform organization (account-less rows).
        if (platformId === null || platformId !== orgId) {
          this.count('smtp_auth', 'unattributed');
          continue;
        }
        const result = await runLedgered(
          this.deps,
          { ...ledger, eventId: subEventId(event.eventId, 'auth', String(e.seq)) },
          async (tx) => {
            await this.deps.store.ensureSettings(tx, orgId);
            await this.deps.store.recordAuthEvent(tx, {
              ...authEvent,
              organizationId: orgId,
              accountId: null,
            });
          },
        );
        this.count('smtp_auth', result);
        continue;
      }
      if (!known.has(e.connectorId)) {
        this.count('smtp_auth', 'unattributed');
        continue;
      }
      const connectorId = BigInt(e.connectorId);
      const result = await detectLedgered(
        this.deps,
        { ...ledger, eventId: subEventId(event.eventId, 'auth', String(e.seq)) },
        [
          {
            org,
            subject: { kind: 'smtp_connector', connectorId },
            authEvent,
            observation: () =>
              authObservation({
                key: `${event.eventId}:${e.seq}`,
                source: 'smtp_auth',
                channel: 'smtp',
                outcome,
                failureCode: e.failureReason,
                occurredAt,
                enriched: en,
                device: null,
                breachListed: null,
              }),
            activity: (snapshot) =>
              success
                ? {
                    at: occurredAt,
                    authSuccess: 1,
                    ipPrefix: en?.ipPrefix
                      ? { p: en.ipPrefix, cc: en.geo.country, asn: en.geo.asn }
                      : null,
                    hourPrefixes: snapshot.distinctSuccessPrefixes60m,
                  }
                : { at: occurredAt, authFailure: 1 },
            success: success
              ? { geo: en?.geo ?? null, trusted: en?.trustedNetwork ?? false }
              : null,
          },
        ],
      );
      this.count('smtp_auth', result);
    }
    return 'counted';
  }

  /**
   * Accepted submissions (D4): the connector attribution of the queue id (Redis, 2 h) for the
   * mail handler, and the connector's submission rules (sender spread O8, new client prefix O7).
   */
  async handleSubmission(event: EventEnvelope<unknown>): Promise<'counted'> {
    const parsed = smtpSubmissionRecordedV1.safeParse(event.payload);
    if (!parsed.success) throw new NonRetryableError('payload_invalid');
    const entries = parsed.data.entries;
    const orgId = BigInt(event.organizationId);
    const org = await this.org(orgId, 'smtp_submission', entries.length);
    if (!org) return 'counted';
    const known = await this.connectors(
      orgId,
      entries.map((e) => e.connectorId),
    );
    for (const e of entries) {
      if (!known.has(e.connectorId)) {
        this.count('smtp_submission', 'unattributed');
        continue;
      }
      const occurredAt = new Date(e.occurredAt);
      const clientIp = e.clientIp ? canonicalIp(e.clientIp) : null;
      if (e.queueId) {
        await this.deps.windows.setSubmissionAttribution(orgId, e.queueId, {
          connectorId: e.connectorId,
          clientIp,
          helo: e.heloName,
          tls: e.tlsProtocol,
        });
      }
      const senderHash = hmacKey(this.deps.hmacKey, 'sender', e.senderAddress);
      const prefix = clientIp ? ipPrefix(clientIp) : null;
      const result = await detectLedgered(
        this.deps,
        {
          consumer: LEDGERS.events,
          eventId: subEventId(event.eventId, 'sub', String(e.seq)),
          source: 'smtp_submission',
          occurredAt,
        },
        [
          {
            org,
            subject: { kind: 'smtp_connector', connectorId: BigInt(e.connectorId) },
            observation: () => ({
              type: 'smtp_submission',
              key: `${event.eventId}:${e.seq}`,
              occurredAt,
              clientIpPrefix: prefix,
              senderHash,
            }),
            activity: (snapshot) => ({
              at: occurredAt,
              peer: senderHash.slice(0, 16),
              clientPrefix: prefix,
              hourSenders: snapshot.distinctSenders60m,
            }),
          },
        ],
      );
      this.count('smtp_submission', result);
    }
    return 'counted';
  }
}
