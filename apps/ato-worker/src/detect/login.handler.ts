import { NonRetryableError } from '@email-gateway/common';
import { sha256Hex, type AuthObservation, type AuthOutcome } from '@email-gateway/ato-detection';
import { authLoginRecordedV1, type EventEnvelope } from '@email-gateway/event-contracts';
import { Enricher, type IpEnrichment } from '../enrichment/enricher';
import type { AtoEventResult } from '../metrics/ato-metrics';
import { atoEnabled } from '../reads/org-context';
import { LEDGERS } from '../shared/db';
import { InconsistentReadError } from '../shared/errors';
import {
  detectLedgered,
  enrichOutside,
  FAILURE_OUTCOMES,
  recordPlatformFailure,
  runLedgered,
  type DetectDeps,
} from './context';
import type { AuthConcurrentLocations, DetectionPipeline } from './pipeline';

/** G3: other sessions of the user active within this window (minutes) are located. */
const SESSION_WINDOW_MINUTES = 60;

/**
 * `auth.login.recorded.v1` (D5): the `login_audit_logs` row is read back on the writer and
 * echo-checked; every failure counts in the platform IP windows (also for unknown accounts and
 * organizations without ATO; the attempted e-mail only as an HMAC); a known account of an
 * ATO-enabled organization is a `gateway_user` account with an enriched `ato_auth_events` row and
 * the authentication rules; an unknown account gets an account-less row in the platform
 * organization only when the platform organization has ATO enabled.
 */
export class LoginHandler {
  constructor(
    private readonly deps: DetectDeps,
    private readonly pipeline: DetectionPipeline,
  ) {}

  async handle(event: EventEnvelope<unknown>): Promise<AtoEventResult> {
    const parsed = authLoginRecordedV1.safeParse(event.payload);
    if (!parsed.success) throw new NonRetryableError('payload_invalid');
    const p = parsed.data;
    const orgId = BigInt(event.organizationId);
    const row = await this.deps.prisma.loginAuditLog.findUnique({
      where: { id: BigInt(p.loginAuditId) },
    });
    // Purged after AUTH_LOGIN_AUDIT_RETENTION_DAYS: nothing left to enrich.
    if (!row) return 'skipped_org';
    if (row.id !== BigInt(p.loginAuditId) || row.outcome !== p.outcome) {
      throw new InconsistentReadError('login_audit_log');
    }
    if (p.accountKnown) {
      if (row.userId === null || row.userId !== BigInt(p.userId!) || row.organizationId !== orgId) {
        throw new InconsistentReadError('login_audit_log');
      }
    } else if (row.userId !== null && row.organizationId !== null) {
      throw new InconsistentReadError('login_audit_log');
    }
    const occurredAt = row.createdAt;
    const ip = Enricher.canonical(row.ipAddress);
    if (FAILURE_OUTCOMES.has(p.outcome) && ip) {
      await recordPlatformFailure(
        this.deps,
        event.eventId,
        ip,
        `login:${row.emailAttempted.toLowerCase()}`,
        occurredAt,
      );
    }
    const source = p.outcome === 'mfa_failure' ? 'portal_mfa' : 'portal_login';
    const authEvent = (enriched: IpEnrichment | null) =>
      ({
        source,
        channel: p.channel,
        outcome: p.outcome,
        failureCode: p.failureReason,
        occurredAt,
        ip,
        ipPrefix: enriched?.ipPrefix ?? null,
        geo: enriched?.geo ?? null,
        reputation: enriched?.reputation ?? null,
        device: this.deps.enricher.device(row.userAgent),
        mechanism: null,
        sourceRef: `login:${row.id}`,
        dedupeKey: sha256Hex(`login:${row.id}`),
      }) as const;

    if (!p.accountKnown) {
      const platformId = await this.deps.orgs.platformOrganizationId();
      if (platformId === null || platformId !== orgId) return 'skipped_org';
      const org = await this.deps.orgs.get(orgId);
      if (!atoEnabled(org)) return 'skipped_feature';
      const enriched = ip ? ((await enrichOutside(this.deps, orgId, [ip])).get(ip) ?? null) : null;
      return runLedgered(
        this.deps,
        { consumer: LEDGERS.events, eventId: event.eventId, source: 'portal_login', occurredAt },
        async (tx) => {
          await this.deps.store.ensureSettings(tx, orgId);
          // Never the attempted e-mail (D5): an account-less row of the platform organization.
          await this.deps.store.recordAuthEvent(tx, {
            ...authEvent(enriched),
            organizationId: orgId,
            accountId: null,
          });
        },
      );
    }

    const org = await this.deps.orgs.get(orgId);
    if (!org.exists || !org.active) return 'skipped_org';
    if (!atoEnabled(org)) return 'skipped_feature';
    const user = await this.deps.prisma.user.findUnique({
      where: { id: row.userId! },
      select: { id: true, organizationId: true, email: true },
    });
    if (!user) return 'unattributed';
    if (user.organizationId !== orgId) throw new InconsistentReadError('user');
    const enriched = ip ? ((await enrichOutside(this.deps, orgId, [ip])).get(ip) ?? null) : null;

    const success = p.outcome === 'success';
    return detectLedgered(
      this.deps,
      { consumer: LEDGERS.events, eventId: event.eventId, source: 'portal_login', occurredAt },
      [
        {
          org,
          subject: { kind: 'gateway_user', userId: user.id, address: user.email },
          breachAddress: user.email,
          authEvent: authEvent(enriched),
          observation: ({ breachListed }) =>
            authObservation({
              key: event.eventId,
              source,
              channel: p.channel,
              outcome: p.outcome,
              failureCode: p.failureReason,
              occurredAt,
              enriched,
              device: this.deps.enricher.device(row.userAgent),
              breachListed,
            }),
          activity: (snapshot) =>
            success
              ? {
                  at: occurredAt,
                  authSuccess: 1,
                  ipPrefix: enriched?.ipPrefix
                    ? {
                        p: enriched.ipPrefix,
                        cc: enriched.geo.country,
                        asn: enriched.geo.asn,
                      }
                    : null,
                  hourPrefixes: snapshot.distinctSuccessPrefixes60m,
                }
              : FAILURE_OUTCOMES.has(p.outcome)
                ? { at: occurredAt, authFailure: 1 }
                : null,
          success: success
            ? { geo: enriched?.geo ?? null, trusted: enriched?.trustedNetwork ?? false }
            : null,
          concurrentLocations: this.sessions(user.id, orgId, ip, occurredAt),
        },
      ],
    );
  }

  /** G3: located IPs of the user's other live sessions within 60 minutes. */
  private sessions(
    userId: bigint,
    organizationId: bigint,
    ip: string | null,
    at: Date,
  ): AuthConcurrentLocations {
    return async () => {
      const since = new Date(at.getTime() - SESSION_WINDOW_MINUTES * 60_000);
      const rows = await this.deps.prisma.userSession.findMany({
        where: {
          userId,
          organizationId,
          revokedAt: null,
          OR: [{ lastUsedAt: { gte: since } }, { authenticatedAt: { gte: since } }],
        },
        select: { ipAddress: true, lastUsedAt: true, authenticatedAt: true, organizationId: true },
        orderBy: { id: 'desc' },
        take: 10,
      });
      const out: Awaited<ReturnType<AuthConcurrentLocations>> = [];
      for (const s of rows) {
        if (s.organizationId !== organizationId) continue;
        const sip = Enricher.canonical(s.ipAddress);
        if (!sip || sip === ip) continue;
        const g = this.deps.enricher.geolocate(sip);
        if (
          (g.status === 'located' || g.status === 'stale') &&
          g.country &&
          g.latitude !== null &&
          g.longitude !== null &&
          g.accuracyKm !== null
        ) {
          const seenAt =
            s.lastUsedAt && s.lastUsedAt > s.authenticatedAt ? s.lastUsedAt : s.authenticatedAt;
          out.push({
            country: g.country,
            latitude: g.latitude,
            longitude: g.longitude,
            accuracyKm: g.accuracyKm,
            at: seenAt,
          });
        }
      }
      return out;
    };
  }
}

/** An authentication observation from an enriched IP (portal, SMTP, identity provider). */
export function authObservation(input: {
  key: string;
  source: AuthObservation['source'];
  channel: AuthObservation['channel'];
  outcome: AuthOutcome;
  failureCode: string | null;
  occurredAt: Date;
  enriched: IpEnrichment | null;
  device: { hash: string; label: string } | null;
  breachListed: boolean | null;
}): AuthObservation {
  const e = input.enriched;
  return {
    type: 'auth',
    key: input.key,
    source: input.source,
    channel: input.channel,
    outcome: input.outcome,
    failureCode: input.failureCode,
    occurredAt: input.occurredAt,
    ip: e?.ip ?? null,
    ipPrefix: e?.ipPrefix ?? null,
    geo: e?.geo ?? null,
    device: input.device,
    reputation: e?.reputation ?? null,
    dnsblListed: e?.dnsblListed ?? null,
    ipFlag: e?.ipFlag ?? null,
    blockedNetwork: e?.blockedNetwork ?? false,
    trustedNetwork: e?.trustedNetwork ?? false,
    authEventRef: null,
    breachListed: input.breachListed,
  };
}
