import { Inject, Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import {
  isRelayProvider,
  parseProviderRelayProofPolicy,
  probeTokenOf,
  probeTokenSha256,
  type ProofResult,
  type ProviderProofOutcome,
  type ProviderRelayProofPolicy,
  type RelayProvider,
} from '@email-gateway/mail-routing';
import { ADAPTER_CONFIG, ADAPTER_LOGGER } from '../config';
import type { HeaderMetadata } from '../ingestion/header-scanner';
import type { IngestDirection, QueueFileRef } from '../ingestion/ingestion-keys';
import {
  addressDomain,
  groupByOrganization,
  type IngestRecipient,
  type OrganizationGroup,
  type OrganizationOutcome,
  parseAddressList,
} from '../ingestion/tenant-split';
import { withTimeout } from '../lmtp/timeout';
import { LMTP_OK, LMTP_TEMPFAIL, PROVIDER_PROOF_FAILED, type SmtpReply } from '../shared/replies';
import { ProbeRecorderRepository } from './probe-recorder.repository';
import { type DkimRun, ProofVerifier } from './proof-verifier';
import type { ProviderRelayConfig } from './provider-relay.config';
import { ProviderRelayMetrics } from './provider-relay.metrics';
import { type RelayMarker, RelayMarkerStore } from './relay-marker.store';
import { RelayCountersService } from './relay-counters.service';

/** `email_events.details.providerRelay` of the `received` event (D8). */
export interface ProviderRelayEventDetails {
  provider: RelayProvider;
  /** Connection public id. */
  connectionId: string;
  proof: 'pass';
}

/** What the relay needs of the LMTP transaction. */
export interface RelayTransactionView {
  direction: IngestDirection;
  ref: QueueFileRef;
  envelopeFrom: string;
}

export type ProviderRelayIngestionConfig = Pick<ProviderRelayConfig, 'PROVIDER_PROBE_DOMAIN'> & {
  INGEST_DB_TIMEOUT_MS: number;
};

interface ConnectionContext {
  id: bigint;
  organizationId: bigint;
  provider: RelayProvider;
  publicId: string;
  tenantId: string | null;
  linkedDomains: string[];
  policy: ProviderRelayProofPolicy;
}

type Setup =
  | { kind: 'ready'; marker: RelayMarker; connection: ConnectionContext }
  /** The proof cannot be evaluated now (Redis, database, invalid stored policy): 451. */
  | { kind: 'unavailable'; marker: RelayMarker | null; reason: string }
  /** The marker does not belong to this transaction's organization or connection: 550. */
  | { kind: 'mismatch'; marker: RelayMarker; reason: string };

const domainOf = (address: string): string =>
  address.slice(address.lastIndexOf('@') + 1).toLowerCase();

/** Domain of the single header-From address; null when there is not exactly one. */
export function headerFromDomain(headers: HeaderMetadata | null): string | null {
  if (!headers || headers.fromValues.length !== 1) return null;
  const addresses = parseAddressList(headers.fromValues[0]!);
  return addresses.length === 1 ? addressDomain(addresses[0]!) : null;
}

/**
 * LMTP ingestion's provider relay step (step 8.2 D8.2, D10; ADR-0078, ADR-0079). For every
 * outbound transaction it reads the marker `sa:prelay:{queueId}` (one GET): no marker means the
 * step 2.2 path, unchanged. With a marker it returns a `RelayIngestion` that the ingestion
 * service drives: the message bytes are teed into the DKIM verifier, the proof is evaluated
 * before anything is committed, probe recipients are intercepted (evidence row, nothing in S3,
 * no message row) and the hourly counters are recorded.
 */
@Injectable()
export class ProviderRelayIngestion {
  private readonly logger: Logger;

  constructor(
    private readonly markers: RelayMarkerStore,
    private readonly prisma: PrismaService,
    private readonly verifier: ProofVerifier,
    private readonly probes: ProbeRecorderRepository,
    private readonly counters: RelayCountersService,
    private readonly metrics: ProviderRelayMetrics,
    @Inject(ADAPTER_CONFIG) private readonly config: ProviderRelayIngestionConfig,
    @Inject(ADAPTER_LOGGER) logger: Logger,
  ) {
    this.logger = logger.child({ component: 'provider-relay-ingestion' });
  }

  /** Null: no marker (or not the outbound listener) — the transaction is not a provider relay. */
  async begin(
    transaction: RelayTransactionView,
    recipients: readonly IngestRecipient[],
  ): Promise<RelayIngestion | null> {
    if (transaction.direction !== 'outbound') return null;
    const { queueId } = transaction.ref;
    let marker: RelayMarker | null;
    try {
      marker = await this.markers.read(queueId);
    } catch (err) {
      this.metrics.markerFailed('read');
      this.logger.error({ err, queueId }, 'provider relay marker read failed; tempfailing');
      return this.create(transaction, recipients, {
        kind: 'unavailable',
        marker: null,
        reason: 'marker_unavailable',
      });
    }
    if (marker === null) return null;
    return this.create(transaction, recipients, await this.setup(marker, recipients));
  }

  private create(
    transaction: RelayTransactionView,
    recipients: readonly IngestRecipient[],
    setup: Setup,
  ): RelayIngestion {
    return new RelayIngestion(this, transaction, recipients, setup, new Date());
  }

  private async setup(marker: RelayMarker, recipients: readonly IngestRecipient[]): Promise<Setup> {
    const organizationId = BigInt(marker.organizationId);
    if (recipients.some((recipient) => recipient.organizationId !== organizationId)) {
      return { kind: 'mismatch', marker, reason: 'organization_mismatch' };
    }
    let row;
    try {
      row = await withTimeout(
        this.prisma.providerConnection.findUnique({
          where: { publicId: marker.connectionPublicId },
          select: {
            id: true,
            publicId: true,
            organizationId: true,
            provider: true,
            externalTenantId: true,
            relayProof: true,
            domains: {
              select: { domain: { select: { name: true, status: true, organizationId: true } } },
            },
          },
        }),
        this.config.INGEST_DB_TIMEOUT_MS,
        'provider connection lookup',
      );
    } catch (err) {
      this.logger.error(
        { err, connectionId: marker.connectionPublicId },
        'connection lookup failed',
      );
      return { kind: 'unavailable', marker, reason: 'connection_lookup_failed' };
    }
    if (
      !row ||
      row.organizationId !== organizationId ||
      row.provider !== marker.provider ||
      !isRelayProvider(row.provider)
    ) {
      return { kind: 'mismatch', marker, reason: 'connection_mismatch' };
    }
    let policy: ProviderRelayProofPolicy;
    try {
      policy = parseProviderRelayProofPolicy(row.provider, row.relayProof);
    } catch (err) {
      this.logger.error(
        { err, connectionId: row.publicId },
        'stored relay_proof policy is invalid; tempfailing',
      );
      return { kind: 'unavailable', marker, reason: 'invalid_policy' };
    }
    return {
      kind: 'ready',
      marker,
      connection: {
        id: row.id,
        organizationId: row.organizationId,
        provider: row.provider,
        publicId: row.publicId,
        tenantId: row.externalTenantId,
        linkedDomains: row.domains
          .map((link) => link.domain)
          .filter(
            (domain) => domain.status === 'active' && domain.organizationId === organizationId,
          )
          .map((domain) => domain.name.toLowerCase()),
        policy,
      },
    };
  }

  /** @internal */ get probeDomain(): string {
    return this.config.PROVIDER_PROBE_DOMAIN;
  }
  /** @internal */ get dependencies() {
    return {
      verifier: this.verifier,
      probes: this.probes,
      counters: this.counters,
      metrics: this.metrics,
      markers: this.markers,
      logger: this.logger,
    };
  }
}

/** One provider-relay LMTP transaction (created by `ProviderRelayIngestion.begin`). */
export class RelayIngestion {
  /** RCPT positions of probe recipients (intercepted; never stored). */
  readonly probeIndexes: ReadonlyMap<number, string>;
  private readonly dkim: DkimRun | null;
  private headers: HeaderMetadata | null = null;
  private outcome: ProviderProofOutcome | null = null;
  private verdict: ProofResult | null = null;

  constructor(
    private readonly owner: ProviderRelayIngestion,
    private readonly transaction: RelayTransactionView,
    private readonly recipients: readonly IngestRecipient[],
    private readonly setup: Setup,
    private readonly now: Date,
  ) {
    const probes = new Map<number, string>();
    recipients.forEach((recipient, index) => {
      const token = probeTokenOf(recipient.address, owner.probeDomain);
      if (token !== null) probes.set(index, token);
    });
    this.probeIndexes = probes;
    this.dkim = setup.kind === 'ready' ? owner.dependencies.verifier.startDkim(now) : null;
  }

  /** The tee of the message bytes into the DKIM verifier (null when no proof can run). */
  get tee(): { write(chunk: Buffer): Promise<void> } | null {
    return this.dkim;
  }

  /** Organization groups of the non-probe recipients, with their positions in the RCPT list. */
  groups(): OrganizationGroup[] {
    const positions: number[] = [];
    const normal = this.recipients.filter((_, index) => {
      if (this.probeIndexes.has(index)) return false;
      positions.push(index);
      return true;
    });
    return groupByOrganization(normal).map((group) => ({
      ...group,
      indexes: group.indexes.map((index) => positions[index]!),
    }));
  }

  onHeaders(headers: HeaderMetadata): void {
    this.headers = headers;
  }

  /** `details.providerRelay` of the received event, once the proof passed. */
  get eventDetails(): ProviderRelayEventDetails | null {
    if (this.verdict !== 'pass' || this.setup.kind !== 'ready') return null;
    const { connection } = this.setup;
    return { provider: connection.provider, connectionId: connection.publicId, proof: 'pass' };
  }

  /**
   * The proof verdict after the whole message was read (before anything is committed). An
   * incomplete read only stops the verifier (the transaction tempfails anyway).
   */
  async conclude(readComplete: boolean): Promise<ProofResult> {
    const deps = this.owner.dependencies;
    const { queueId } = this.transaction.ref;
    if (!readComplete || this.setup.kind !== 'ready') {
      this.dkim?.abort();
      this.verdict = this.setup.kind === 'mismatch' && readComplete ? 'fail' : 'temperror';
      if (this.setup.kind === 'mismatch' && readComplete) {
        deps.logger.warn(
          { queueId, provider: this.setup.marker.provider, failureCode: this.setup.reason },
          'provider relay marker does not match the transaction; refusing',
        );
      }
      await this.keepMarkerOnTempfail();
      return this.verdict;
    }
    const { connection, marker } = this.setup;
    const dkim = await this.dkim!.finish();
    const outcome = await deps.verifier.evaluate({
      evidence: {
        provider: connection.provider,
        expectedTenantId: connection.tenantId,
        tenantHeaderValues: this.headers?.crossTenantIds ?? [],
        headerFromDomain: headerFromDomain(this.headers),
        linkedDomains: connection.linkedDomains,
        headerBlockComplete: this.headers?.complete === true && !this.headers.truncated,
        now: this.now,
      },
      policy: connection.policy,
      dkim,
      queueId,
    });
    this.outcome = outcome;
    this.verdict = outcome.result;
    for (const { rule, result } of outcome.rules) {
      deps.metrics.proofRule(connection.provider, rule, result);
    }
    if (outcome.result !== 'pass') {
      deps.logger.warn(
        {
          queueId,
          provider: connection.provider,
          connectionId: connection.publicId,
          result: outcome.result,
          failureCode: outcome.failureCode,
          tenantHeader: outcome.tenantHeader,
          dkim: outcome.dkim,
          envelopeFromDomain: domainOf(this.transaction.envelopeFrom),
          headerFromDomain: headerFromDomain(this.headers),
          dkimDomains: outcome.dkimDomains,
          clientAddress: marker.clientAddress,
        },
        outcome.result === 'fail'
          ? 'provider relay proof failed; refusing every recipient'
          : 'provider relay proof could not be evaluated; tempfailing',
      );
    }
    await this.keepMarkerOnTempfail();
    return outcome.result;
  }

  private async keepMarkerOnTempfail(): Promise<void> {
    if (this.verdict !== 'temperror' || this.setup.marker === null) return;
    try {
      await this.owner.dependencies.markers.extend(this.transaction.ref.queueId);
    } catch (err) {
      this.owner.dependencies.logger.warn(
        { err, queueId: this.transaction.ref.queueId },
        'could not extend the provider relay marker of a tempfailed delivery',
      );
    }
  }

  /**
   * The final replies: probe recipients get their own (observation recorded: `250` on pass,
   * `550 5.7.26` on fail; `451` when the proof or the evidence write could not complete), every
   * other position keeps the ingestion's reply. Records the hourly counters.
   */
  async finish(
    replies: SmtpReply[],
    outcomes: ReadonlyMap<bigint, OrganizationOutcome>,
  ): Promise<SmtpReply[]> {
    const deps = this.owner.dependencies;
    const out = [...replies];
    const verdict = this.verdict ?? 'temperror';
    let recorded = 0;
    for (const [index, token] of this.probeIndexes) {
      if (this.setup.kind !== 'ready' || this.outcome === null || verdict === 'temperror') {
        out[index] =
          this.setup.kind === 'mismatch' && verdict === 'fail'
            ? PROVIDER_PROOF_FAILED
            : LMTP_TEMPFAIL;
        if (this.setup.kind === 'ready')
          deps.metrics.probe(this.setup.connection.provider, 'temperror');
        continue;
      }
      const probe = await this.recordProbe(token, this.setup, this.outcome);
      out[index] = probe.reply;
      // A redelivery of the same queue file (duplicate observation) is not counted again (I9).
      if (probe.recorded) recorded += 1;
    }
    if (this.setup.kind === 'ready') {
      const { connection } = this.setup;
      const record = (counter: 'accepted' | 'proofFailed' | 'tempFailed' | 'probes', by = 1) =>
        deps.counters.record(connection.organizationId, connection.id, counter, this.now, by);
      const values = [...outcomes.values()];
      if (verdict === 'fail') record('proofFailed');
      else if (verdict === 'temperror' || values.includes('tempfail')) record('tempFailed');
      if (verdict === 'pass' && values.includes('stored')) record('accepted');
      record('probes', recorded);
    }
    return out;
  }

  private async recordProbe(
    token: string,
    setup: Extract<Setup, { kind: 'ready' }>,
    outcome: ProviderProofOutcome,
  ): Promise<{ reply: SmtpReply; recorded: boolean }> {
    const deps = this.owner.dependencies;
    const { connection, marker } = setup;
    try {
      const result = await deps.probes.record({
        organizationId: connection.organizationId,
        connectionId: connection.id,
        tokenSha256: probeTokenSha256(token),
        queueId: this.transaction.ref.queueId,
        provider: connection.provider,
        clientIp: marker.clientAddress,
        tlsProtocol: marker.tlsProtocol,
        tlsCipher: marker.tlsCipher,
        envelopeFromDomain: domainOf(this.transaction.envelopeFrom),
        headerFromDomain: headerFromDomain(this.headers),
        tenantHeader: outcome.tenantHeader,
        dkim: outcome.dkim,
        dkimDomains: outcome.dkimDomains,
        dkimAgeSeconds: outcome.dkimAgeSeconds,
        proofResult: outcome.result,
        failureCode: outcome.failureCode,
        receivedAt: this.now,
      });
      deps.metrics.probe(
        connection.provider,
        result === 'duplicate' ? 'duplicate' : outcome.result,
      );
      return {
        reply: outcome.result === 'pass' ? LMTP_OK : PROVIDER_PROOF_FAILED,
        recorded: result === 'recorded',
      };
    } catch (err) {
      deps.metrics.probe(connection.provider, 'error');
      deps.logger.error(
        { err, queueId: this.transaction.ref.queueId, connectionId: connection.publicId },
        'probe observation write failed; tempfailing the probe',
      );
      return { reply: LMTP_TEMPFAIL, recorded: false };
    }
  }
}
