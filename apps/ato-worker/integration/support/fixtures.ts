import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { uuidv7 } from '@email-gateway/common';
import { Prisma, PrismaClient } from '@email-gateway/database';
import { EventTypes, type EventEnvelope } from '@email-gateway/event-contracts';

/** Values from the repository's .env (loaded by vitest.integration.config.ts). Never printed. */
export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set (see .env)`);
  return value;
}

export const sha256 = (value: string): string =>
  createHash('sha256').update(value, 'utf8').digest('hex');

/** A random host inside a synthetic GeoIP range (per-run IPs never collide across runs). */
export const ips = {
  /** 192.0.2.0/25 Mumbai IN (AS64500). */
  mumbai: () => `192.0.2.${2 + (randomBytes(1)[0]! % 60)}`,
  /** 192.0.2.128/25 Pune IN (AS64500). */
  pune: () => `192.0.2.${130 + (randomBytes(1)[0]! % 120)}`,
  /** 198.51.100.0/24 London GB (AS64501). */
  london: () => `198.51.100.${2 + (randomBytes(1)[0]! % 250)}`,
  /** 203.0.113.0/25 São Paulo BR (AS64502). */
  saoPaulo: () => `203.0.113.${70 + (randomBytes(1)[0]! % 50)}`,
  /** 203.0.113.128/25 New York US (AS64503, anonymous VPN in the anonymous database). */
  newYorkVpn: () => `203.0.113.${130 + (randomBytes(1)[0]! % 120)}`,
  /** 2001:db8::/48 Sydney AU. */
  sydney: () => `2001:db8::${(1 + randomBytes(2).readUInt16BE(0)).toString(16)}`,
  /** 2001:db8:1::/48 DE, country only (accuracy 1000 km). */
  germanyCountryOnly: () => `2001:db8:1::${(1 + randomBytes(2).readUInt16BE(0)).toString(16)}`,
};

export interface MessageSpec {
  sender: string;
  direction?: 'outbound' | 'internal' | 'inbound';
  receivedAt: Date;
  /** External (outbound) recipient addresses. */
  recipients?: readonly string[];
  internalRecipients?: readonly string[];
  attachments?: readonly { sha256: string; type: string }[];
  subject?: string;
  headerFrom?: string | null;
  inReplyTo?: string | null;
  clientIp?: string | null;
  queueId?: string | null;
  verdict?: string;
  reasonCodes?: readonly string[];
  domainId?: bigint | null;
}

export interface SeededMessage {
  id: bigint;
  receivedAt: Date;
  scanId: bigint;
  organizationId: bigint;
  direction: 'outbound' | 'internal' | 'inbound';
  verdict: string;
  reasonCodes: string[];
}

const pad = (n: number) => String(n).padStart(2, '0');

/**
 * Synthetic `it-ato-<run>-*` organizations, users, connectors, domains, messages, login and audit
 * rows on the real MySQL writer (D21), and removal of every row the worker writes for them. Never
 * touches pre-existing data: every delete is scoped to the organizations this instance created,
 * the ledger keys it tracked, the indicators it added and its cursors.
 */
export class Fixtures {
  readonly prisma: PrismaClient = new PrismaClient({ datasourceUrl: requireEnv('DATABASE_URL') });
  readonly suffix = randomUUID().slice(0, 8);
  readonly organizationIds: bigint[] = [];
  readonly indicatorIds: bigint[] = [];
  readonly trackedEvents: string[] = [];
  /** Ledger rows of `ato-worker.*` consumers written after this instant belong to the suite (the
   * live worker is paused by the global setup). */
  readonly startedAt = new Date(Date.now() - 1000);
  private planId: bigint | undefined;
  private counter = 0;

  track(eventId: string): string {
    this.trackedEvents.push(eventId);
    return eventId;
  }

  async organization(
    label: string,
    options: { ato?: boolean; kind?: 'customer' | 'platform'; timeZone?: string } = {},
  ): Promise<{ id: bigint; domain: string; domainId: bigint }> {
    if (this.planId === undefined) {
      const plan = await this.prisma.organizationPlan.create({
        data: {
          code: `it-ato-${this.suffix}`,
          name: 'ato-worker integration',
          defaultLimits: {},
          defaultFeatures: {},
        },
      });
      this.planId = plan.id;
    }
    const org = await this.prisma.organization.create({
      data: {
        slug: `it-ato-${this.suffix}-${label}`,
        name: `IT ATO ${label}`,
        planId: this.planId,
        dataRegion: 'ap-south-1',
        kind: options.kind ?? 'customer',
      },
    });
    this.organizationIds.push(org.id);
    if (options.timeZone) {
      await this.prisma.organizationSetting.create({
        data: { organizationId: org.id, timezone: options.timeZone },
      });
    }
    if (options.ato !== false) await this.enableAto(org.id);
    const domain = `${label}-${this.suffix}.it-ato.example`;
    const d = await this.prisma.domain.create({
      data: {
        organizationId: org.id,
        name: domain,
        status: 'active',
        outboundEnabled: true,
      },
    });
    return { id: org.id, domain, domainId: d.id };
  }

  /** The operator's switch (PO1): `organization_features.ato_detection` for a synthetic org. */
  async enableAto(organizationId: bigint, enabled = true): Promise<void> {
    await this.prisma.organizationFeature.upsert({
      where: { organizationId_featureKey: { organizationId, featureKey: 'ato_detection' } },
      create: { organizationId, featureKey: 'ato_detection', enabled, source: 'override' },
      update: { enabled },
    });
  }

  async user(organizationId: bigint, label: string, domain: string) {
    return this.prisma.user.create({
      data: {
        organizationId,
        email: `${label}@${domain}`,
        displayName: `IT ${label}`,
        status: 'active',
      },
      select: { id: true, publicId: true, email: true },
    });
  }

  async connector(organizationId: bigint, label: string) {
    return this.prisma.smtpConnector.create({
      data: {
        organizationId,
        name: `it-ato-${label}-${this.suffix}`,
        authType: 'sasl',
        saslUsername: `egc-it${randomBytes(6).toString('hex')}`,
      },
      select: { id: true, publicId: true },
    });
  }

  /** A `login_audit_logs` row and its `auth.login.recorded.v1` envelope (as the api writes it). */
  async login(input: {
    organizationId: bigint;
    envelopeOrganizationId?: bigint;
    userId: bigint | null;
    email: string;
    outcome: 'success' | 'failure' | 'locked' | 'mfa_required' | 'mfa_failure' | 'rate_limited';
    ip: string | null;
    userAgent?: string | null;
    at: Date;
    channel?: 'portal' | 'api';
  }): Promise<EventEnvelope> {
    const row = await this.prisma.loginAuditLog.create({
      data: {
        organizationId: input.userId === null ? null : input.organizationId,
        userId: input.userId,
        emailAttempted: input.email.toLowerCase(),
        outcome: input.outcome,
        failureReason:
          input.outcome === 'success' || input.outcome === 'mfa_required'
            ? null
            : 'invalid_credentials',
        ipAddress: input.ip,
        userAgent: input.userAgent ?? null,
        createdAt: input.at,
      },
    });
    return this.envelope(
      EventTypes.AuthLoginRecorded,
      input.envelopeOrganizationId ?? input.organizationId,
      {
        loginAuditId: row.id.toString(),
        occurredAt: input.at.toISOString(),
        outcome: input.outcome,
        failureReason: row.failureReason,
        accountKnown: input.userId !== null,
        userId: input.userId?.toString() ?? null,
        channel: input.channel ?? 'portal',
      },
      input.at,
    );
  }

  /** An `audit_logs` row and its `auth.account.changed.v1` envelope. */
  async accountChange(input: {
    organizationId: bigint;
    action: string;
    actorPublicId: string | null;
    at: Date;
    resourceType?: string;
    resourcePublicId?: string | null;
    /** `system` as the api audits a refresh-token reuse (actor id null). */
    actorType?: 'user' | 'system';
  }): Promise<EventEnvelope> {
    const actorType = input.actorType ?? 'user';
    const row = await this.prisma.auditLog.create({
      data: {
        organizationId: input.organizationId,
        actorType,
        actorId: input.actorPublicId,
        action: input.action,
        resourceType: input.resourceType ?? 'user',
        resourceId: input.resourcePublicId ?? input.actorPublicId,
        createdAt: input.at,
      },
    });
    return this.envelope(
      EventTypes.AuthAccountChanged,
      input.organizationId,
      {
        auditLogId: row.id.toString(),
        auditCreatedAt: input.at.toISOString(),
        action: input.action,
        actorType,
        actorPublicId: input.actorPublicId,
        resourceType: input.resourceType ?? 'user',
        resourcePublicId: input.resourcePublicId ?? input.actorPublicId,
      },
      input.at,
    );
  }

  envelope(
    eventType: string,
    organizationId: bigint,
    payload: unknown,
    at: Date = new Date(),
  ): EventEnvelope {
    return {
      eventId: this.track(uuidv7()),
      eventType,
      occurredAt: at.toISOString(),
      correlationId: `it-ato-${this.suffix}`,
      organizationId: organizationId.toString(),
      payload,
    };
  }

  /** `smtp.auth.recorded.v1` of entries (seq assigned in order). */
  smtpAuth(
    organizationId: bigint,
    entries: Array<{
      at: Date;
      result: 'ok' | 'fail' | 'throttled' | 'blocked';
      connectorId: bigint | null;
      clientIp: string | null;
      usernameHash?: string | null;
    }>,
  ): EventEnvelope {
    return this.envelope(EventTypes.SmtpAuthRecorded, organizationId, {
      producer: { instance: 'it-smtp-adapter' },
      entries: entries.map((e, seq) => ({
        seq,
        occurredAt: e.at.toISOString(),
        result: e.result,
        mechanism: 'plain',
        connectorId: e.connectorId?.toString() ?? null,
        clientIp: e.clientIp,
        usernameClass: e.connectorId ? 'connector' : 'unknown_other',
        usernameHash: e.connectorId ? null : (e.usernameHash ?? randomBytes(8).toString('hex')),
        failureReason:
          e.result === 'ok'
            ? null
            : e.result === 'blocked'
              ? 'ato_blocked'
              : e.result === 'throttled'
                ? 'ip_throttled'
                : 'bad_credentials',
      })),
    });
  }

  smtpSubmission(
    organizationId: bigint,
    entries: Array<{
      at: Date;
      connectorId: bigint;
      queueId: string | null;
      clientIp: string | null;
      sender: string;
      recipients?: number;
    }>,
  ): EventEnvelope {
    return this.envelope(EventTypes.SmtpSubmissionRecorded, organizationId, {
      producer: { instance: 'it-smtp-adapter' },
      entries: entries.map((e, seq) => ({
        seq,
        occurredAt: e.at.toISOString(),
        context: 'submission',
        connectorId: e.connectorId.toString(),
        connectorAuthType: 'sasl',
        queueId: e.queueId,
        clientIp: e.clientIp,
        heloName: 'mail.client.example',
        tlsProtocol: 'TLSv1.3',
        senderAddress: e.sender.toLowerCase(),
        recipientCount: e.recipients ?? 1,
        sizeBytes: 2048,
      })),
    });
  }

  /** A Postfix-like queue id (unique per run). */
  queueId(): string {
    return `Q${randomBytes(6).toString('hex').toUpperCase()}`;
  }

  /**
   * Outbound/internal messages with recipients, attachments, an optional `In-Reply-To` header and
   * a completed scan round, inserted in bulk (multi-row INSERTs; the high-volume suite seeds tens
   * of thousands). No object is written: ATO never reads object storage.
   */
  async messages(organizationId: bigint, specs: readonly MessageSpec[]): Promise<SeededMessage[]> {
    const out: SeededMessage[] = [];
    for (let i = 0; i < specs.length; i += 500) {
      out.push(...(await this.messageChunk(organizationId, specs.slice(i, i + 500))));
    }
    return out;
  }

  private async messageChunk(
    organizationId: bigint,
    specs: readonly MessageSpec[],
  ): Promise<SeededMessage[]> {
    const p = this.prisma;
    const out: SeededMessage[] = [];
    const keys = specs.map(() => {
      this.counter += 1;
      return `it-ato-${this.suffix}-${this.counter}`;
    });
    await p.$executeRaw`
      INSERT INTO message_identities (public_id, organization_id, ingest_key, received_at, created_at)
      VALUES ${Prisma.join(
        specs.map(
          (s, i) =>
            Prisma.sql`(${uuidv7()}, ${organizationId}, ${keys[i]}, ${s.receivedAt}, ${s.receivedAt})`,
        ),
      )}`;
    const ids = await p.messageIdentity.findMany({
      where: { organizationId, ingestKey: { in: keys } },
      select: { id: true, ingestKey: true },
    });
    const idOf = new Map(ids.map((r) => [r.ingestKey, r.id]));
    const rows = specs.map((s, i) => {
      const id = idOf.get(keys[i]!)!;
      const at = s.receivedAt;
      const day = `${at.getUTCFullYear()}/${pad(at.getUTCMonth() + 1)}/${pad(at.getUTCDate())}`;
      return { id, s, emlKey: `org/${organizationId}/eml/${day}/${id}.eml` };
    });
    await p.$executeRaw`
      INSERT INTO email_messages
        (id, received_at, organization_id, domain_id, direction, status, status_changed_at, version,
         lifecycle_round, internet_message_id, envelope_from, header_from, subject, size_bytes,
         recipient_count, attachment_count, eml_object_key, eml_sha256, client_ip, mta_queue_id,
         final_verdict, final_action, created_at, updated_at)
      VALUES ${Prisma.join(
        rows.map(({ id, s, emlKey }) => {
          const recipients = (s.recipients?.length ?? 0) + (s.internalRecipients?.length ?? 0);
          return Prisma.sql`(${id}, ${s.receivedAt}, ${organizationId}, ${s.domainId ?? null},
            ${s.direction ?? 'outbound'}, 'delivered', ${s.receivedAt}, 2, 0,
            ${`<it-${id}-${this.suffix}@it-ato.example>`}, ${s.sender},
            ${s.headerFrom === undefined ? `Sender <${s.sender}>` : s.headerFrom},
            ${s.subject ?? `ATO test ${id}`}, 2048, ${recipients}, ${s.attachments?.length ?? 0},
            ${emlKey}, ${sha256(emlKey)}, ${s.clientIp ?? null}, ${s.queueId ?? null},
            'clean', 'deliver', ${s.receivedAt}, ${s.receivedAt})`;
        }),
      )}`;
    const recipientRows = rows.flatMap(({ id, s }) => [
      ...(s.recipients ?? []).map((address) => ({ id, s, address, direction: 'outbound' })),
      ...(s.internalRecipients ?? []).map((address) => ({ id, s, address, direction: 'internal' })),
    ]);
    for (let i = 0; i < recipientRows.length; i += 2000) {
      const chunk = recipientRows.slice(i, i + 2000);
      const seq = new Map<bigint, number>();
      await p.$executeRaw`
        INSERT INTO email_recipients
          (received_at, message_id, organization_id, rcpt_seq, address, status, direction,
           created_at, updated_at)
        VALUES ${Prisma.join(
          chunk.map((r) => {
            const n = seq.get(r.id) ?? 0;
            seq.set(r.id, n + 1);
            return Prisma.sql`(${r.s.receivedAt}, ${r.id}, ${organizationId}, ${n}, ${r.address},
              'delivered', ${r.direction}, ${r.s.receivedAt}, ${r.s.receivedAt})`;
          }),
        )}`;
    }
    const attachmentRows = rows.flatMap(({ id, s }) =>
      (s.attachments ?? []).map((a, partIndex) => ({ id, s, a, partIndex })),
    );
    if (attachmentRows.length > 0) {
      await p.$executeRaw`
        INSERT INTO email_attachments
          (received_at, message_id, organization_id, part_index, size_bytes, sha256,
           detected_content_type, created_at, updated_at)
        VALUES ${Prisma.join(
          attachmentRows.map(
            (r) => Prisma.sql`(${r.s.receivedAt}, ${r.id}, ${organizationId}, ${r.partIndex + 1},
              1024, ${r.a.sha256}, ${r.a.type}, ${r.s.receivedAt}, ${r.s.receivedAt})`,
          ),
        )}`;
    }
    const headerRows = rows.filter(({ s }) => s.inReplyTo);
    if (headerRows.length > 0) {
      await p.$executeRaw`
        INSERT INTO email_headers (received_at, message_id, organization_id, seq, name, value, created_at)
        VALUES ${Prisma.join(
          headerRows.map(
            ({ id, s }) =>
              Prisma.sql`(${s.receivedAt}, ${id}, ${organizationId}, 0, 'In-Reply-To', ${s.inReplyTo!}, ${s.receivedAt})`,
          ),
        )}`;
    }
    await p.$executeRaw`
      INSERT INTO email_scans
        (received_at, message_id, organization_id, scan_kind, attempt, status, lifecycle_round,
         scan_verdict, reason_codes, started_at, completed_at, created_at, updated_at)
      VALUES ${Prisma.join(
        rows.map(
          ({ id, s }) => Prisma.sql`(${s.receivedAt}, ${id}, ${organizationId}, 'initial', 1,
            'completed', 0, ${s.verdict ?? 'clean'}, ${JSON.stringify(s.reasonCodes ?? [])},
            ${s.receivedAt}, ${s.receivedAt}, ${s.receivedAt}, ${s.receivedAt})`,
        ),
      )}`;
    const scans = await p.emailScan.findMany({
      where: { organizationId, messageId: { in: rows.map((r) => r.id) } },
      select: { id: true, messageId: true },
    });
    const scanOf = new Map(scans.map((s) => [s.messageId, s.id]));
    for (const { id, s } of rows) {
      out.push({
        id,
        receivedAt: s.receivedAt,
        scanId: scanOf.get(id)!,
        organizationId,
        direction: s.direction ?? 'outbound',
        verdict: s.verdict ?? 'clean',
        reasonCodes: [...(s.reasonCodes ?? [])],
      });
    }
    return out;
  }

  /** The `mail.message.scanned.v1` envelope of a seeded message (as the email-worker writes it). */
  scanned(m: SeededMessage): EventEnvelope {
    return this.envelope(
      EventTypes.MessageScanned,
      m.organizationId,
      {
        messageId: m.id.toString(),
        receivedAt: m.receivedAt.toISOString(),
        direction: m.direction,
        emlS3Key: `org/${m.organizationId}/eml/x/${m.id}.eml`,
        lifecycleRound: 0,
        scanId: m.scanId.toString(),
        scanKind: 'initial',
        outcome: 'scanned',
        verdict: m.verdict,
        engines: [{ engine: 'rspamd', required: true, outcome: m.verdict, attempts: 1 }],
        reasonCodes: m.reasonCodes,
        completedAt: m.receivedAt.toISOString(),
      },
      m.receivedAt,
    );
  }

  /** A platform `threat_indicators` row (local feed of `ReputationService`, T1/T6; or T4 email). */
  async indicator(
    type: 'ip' | 'email',
    value: string,
    severity: 'low' | 'medium' | 'high' | 'critical' = 'high',
  ): Promise<void> {
    const existing = await this.prisma.threatIndicator.findFirst({
      where: {
        orgScope: 0n,
        source: `feed:it-ato-${this.suffix}`,
        indicatorType: type,
        valueSha256: sha256(value),
      },
      select: { id: true },
    });
    if (existing) return;
    const row = await this.prisma.threatIndicator.create({
      data: {
        organizationId: null,
        indicatorType: type,
        value,
        valueSha256: sha256(value),
        source: `feed:it-ato-${this.suffix}`,
        severity,
        confidence: 90,
        firstSeenAt: new Date(),
        lastSeenAt: new Date(),
        category: 'other',
      },
    });
    this.indicatorIds.push(row.id);
  }

  async cleanup(): Promise<void> {
    const p = this.prisma;
    const ids = this.organizationIds;
    if (ids.length > 0) {
      const where = { organizationId: { in: ids } };
      await p.atoResponseActionLog.deleteMany({ where });
      await p.atoResponseAction.deleteMany({ where });
      await p.atoSmtpRestriction.deleteMany({ where });
      await p.atoIncidentDetail.deleteMany({ where });
      await p.securityIncidentLink.deleteMany({ where });
      await p.securityIncidentEvent.deleteMany({ where });
      await p.securityIncident.deleteMany({ where });
      await p.atoTrustedContext.deleteMany({ where });
      await p.atoRiskOverride.deleteMany({ where });
      await p.atoRiskSignal.deleteMany({ where });
      await p.atoRiskScore.deleteMany({ where });
      await p.atoAuthEvent.deleteMany({ where });
      await p.atoAccountActivityDaily.deleteMany({ where });
      await p.atoAccountBaseline.deleteMany({ where });
      // Step 8.5 tables before the 8.4 rows they reference.
      await p.atoProviderMailboxItem.deleteMany({ where });
      await p.atoProviderStream.deleteMany({ where });
      await p.atoAccountIdentity.deleteMany({ where });
      await p.atoAccount.deleteMany({ where });
      await p.atoProviderIntegration.deleteMany({ where });
      await p.atoSettingsVersion.deleteMany({ where });
      await p.atoSetting.deleteMany({ where });
      await p.notificationAlertWindow.deleteMany({ where });
      await p.messageOutbox.deleteMany({ where });
      await p.auditLog.deleteMany({ where });
      await p.loginAuditLog.deleteMany({ where: { emailAttempted: { contains: this.suffix } } });
      await p.emailHeader.deleteMany({ where });
      await p.emailAttachment.deleteMany({ where });
      await p.emailRecipient.deleteMany({ where });
      await p.emailScan.deleteMany({ where });
      await p.emailMessage.deleteMany({ where });
      await p.messageIdentity.deleteMany({ where });
      await p.smtpConnector.deleteMany({ where });
      await p.userSession.deleteMany({ where });
      await p.user.deleteMany({ where });
      await p.domain.deleteMany({ where });
      await p.organizationFeature.deleteMany({ where });
      await p.organizationSetting.deleteMany({ where });
      await p.streamCursor.deleteMany({
        where: { name: { in: ids.map((id) => `ato-mail-catchup:${id}`) } },
      });
      await p.organization.deleteMany({ where: { id: { in: ids } } });
    }
    if (this.indicatorIds.length > 0) {
      await p.threatIndicator.deleteMany({ where: { id: { in: this.indicatorIds } } });
    }
    await p.threatIndicator.deleteMany({
      where: { source: { startsWith: `feed:it-ato-${this.suffix}` } },
    });
    await p.auditLog.deleteMany({
      where: {
        organizationId: null,
        action: 'threat_intel.breach_imported',
        resourceId: { startsWith: `feed:it-ato-${this.suffix}` },
      },
    });
    // The capabilities row written by the suites' maintenance runs (synthetic GeoIP, the fake
    // provider) must not outlive them: the live worker (paused) rewrites it every 5 minutes.
    await p.systemSetting.deleteMany({
      where: { key: 'ato.worker.capabilities', updatedAt: { gte: this.startedAt } },
    });
    await p.messageIdempotency.deleteMany({
      where: { consumer: { startsWith: 'ato-worker.' }, processedAt: { gte: this.startedAt } },
    });
    if (this.planId !== undefined) {
      await p.organizationPlan.delete({ where: { id: this.planId } });
    }
    await p.$disconnect();
  }
}
