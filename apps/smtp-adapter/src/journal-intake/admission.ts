import { addressInCidrs } from '@email-gateway/archive';
import {
  intakeKindProvider,
  type IntakeNetworkProof,
  type ProviderEgressIndex,
} from '@email-gateway/mail-routing';
import { parseIpKey } from '../connectors/addresses';
import type { IntakeSourceSnapshot } from './source-snapshot';

/** Per-source counter fields of D2.8 that a refusal increments. */
export type IntakeRefusalCounter =
  | 'refused_address'
  | 'refused_network'
  | 'refused_tls'
  | 'refused_size'
  | 'refused_rate'
  | 'refused_unavailable';

/** Why an intake recipient was refused (steps 1–4 of D2.2, shared by RCPT and LMTP). */
export type AdmissionRefusal = 'unknown_address' | 'unavailable' | 'network' | 'tls';

export interface AdmissionFacts {
  now: Date;
  /** The SMTP client (policy `client_address`, LMTP XFORWARD ADDR). */
  clientAddress: string | null | undefined;
  /** The session used TLS. */
  tls: boolean;
  /** Normalized SHA-256 client certificate / public key fingerprints the session presented. */
  certFingerprints: readonly string[];
  /** The provider egress index; throws `EgressIndexUnavailableError` before the first load. */
  egress: () => ProviderEgressIndex;
}

export type Admission =
  | {
      ok: true;
      network: IntakeNetworkProof;
      clientCertMatched: boolean;
    }
  | {
      ok: false;
      refusal: AdmissionRefusal;
      /** Per-source counter (null: no source matched, counted in metrics only). */
      counter: IntakeRefusalCounter | null;
      /** `journal_intake_sources.last_refusal_code` (null with `counter`). */
      code: string | null;
    };

const refuse = (
  refusal: AdmissionRefusal,
  counter: IntakeRefusalCounter | null,
  code: string | null = counter,
): Admission => ({ ok: false, refusal, counter, code });

/** The source of a snapshot may still be used with this address (D1 rotation, disable). */
export function addressUsable(snapshot: IntakeSourceSnapshot, now: Date): boolean {
  if (snapshot.source.status === 'disabled') return false;
  if (!snapshot.source.matchedPrevious) return true;
  const until = snapshot.source.previousValidUntil;
  return until !== null && Date.parse(until) > now.getTime();
}

/**
 * The intake entitlement (8.6 D1, relaxed by step API-1 D6 / ADR-0098): the `journal_intake`
 * feature and either archiving (feature entitled and archiving enabled, as 8.6) or API mode
 * active for the organization (`apiDetect`). Pure.
 */
export function intakeEntitled(
  organization: Pick<
    IntakeSourceSnapshot['organization'],
    'journalIntakeFeature' | 'archivingFeature' | 'archivingEnabled' | 'apiDetect'
  >,
): boolean {
  if (!organization.journalIntakeFeature) return false;
  return (organization.archivingFeature && organization.archivingEnabled) || organization.apiDetect;
}

/**
 * Steps 1–4 of the intake RCPT decision (D2.2), pure. The LMTP re-check (D2.5) runs the same
 * function on a fresh writer snapshot with the facts Postfix passed (XFORWARD client address,
 * TLS and certificate facts of the END-OF-MESSAGE marker).
 *
 * 1. a snapshot (address hash, current or unexpired previous) of a non-disabled source;
 * 2. organization active and entitled (`intakeEntitled`: `journal_intake` and either `archiving`
 *    with archiving enabled or API mode active, step API-1 D6); source not paused;
 * 3. network: provider kinds → the bound, non-disabled connection of the same organization and
 *    provider, and the client in that provider's egress set; on-premises kinds → the client in
 *    the source's networks and in no provider egress set; the client certificate when
 *    configured;
 * 4. TLS when the source requires it.
 */
export function admitIntakeRecipient(
  snapshot: IntakeSourceSnapshot | null,
  facts: AdmissionFacts,
): Admission {
  if (snapshot === null) return refuse('unknown_address', null);
  const { source, organization, connection } = snapshot;
  if (!addressUsable(snapshot, facts.now)) {
    return refuse(
      'unknown_address',
      'refused_address',
      source.status === 'disabled' ? 'refused_disabled' : 'refused_address_expired',
    );
  }
  if (!organization.active || !intakeEntitled(organization)) {
    return refuse('unavailable', 'refused_unavailable');
  }
  if (source.status === 'paused')
    return refuse('unavailable', 'refused_unavailable', 'refused_paused');

  const ip = parseIpKey(facts.clientAddress ?? undefined);
  const provider = intakeKindProvider(source.kind);
  let network: IntakeNetworkProof;
  if (provider !== null) {
    if (
      connection === null ||
      connection.provider !== provider ||
      connection.organizationId !== source.organizationId ||
      connection.status === 'disabled' ||
      !connection.bound
    ) {
      return refuse('network', 'refused_network', 'refused_connection');
    }
    if (ip === null || !facts.egress().contains(provider, ip)) {
      return refuse('network', 'refused_network');
    }
    network = 'provider_egress';
  } else {
    if (source.networksInvalid || source.networks.length === 0 || ip === null) {
      return refuse('network', 'refused_network');
    }
    if (!addressInCidrs(ip.text, source.networks)) return refuse('network', 'refused_network');
    // Shared provider infrastructure is never an on-premises credential (8.2 D10 rule).
    if (facts.egress().providersFor(ip).length > 0) {
      return refuse('network', 'refused_network', 'refused_provider_range');
    }
    network = 'source_networks';
  }

  let clientCertMatched = false;
  if (source.clientCertInvalid) return refuse('network', 'refused_network', 'refused_client_cert');
  if (source.clientCertFingerprints.length > 0) {
    clientCertMatched = facts.certFingerprints.some((fp) =>
      source.clientCertFingerprints.includes(fp),
    );
    if (!clientCertMatched) return refuse('network', 'refused_network', 'refused_client_cert');
  }

  if (source.requireTls && !facts.tls) return refuse('tls', 'refused_tls');
  return { ok: true, network, clientCertMatched };
}
