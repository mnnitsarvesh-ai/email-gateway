import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import type {
  DkimProofResult,
  ProofResult,
  RelayProvider,
  TenantHeaderResult,
} from '@email-gateway/mail-routing';

/** One intercepted probe (step 8.2 D10): bounded, non-content evidence only (I8). */
export interface ProbeObservationInput {
  organizationId: bigint;
  connectionId: bigint;
  tokenSha256: string;
  queueId: string;
  provider: RelayProvider;
  clientIp: string;
  tlsProtocol: string | null;
  tlsCipher: string | null;
  envelopeFromDomain: string;
  headerFromDomain: string | null;
  tenantHeader: TenantHeaderResult;
  dkim: DkimProofResult;
  dkimDomains: string[];
  dkimAgeSeconds: number | null;
  proofResult: ProofResult;
  failureCode: string | null;
  receivedAt: Date;
}

const cut = (value: string | null, max: number): string | null =>
  value === null ? null : value.slice(0, max);

/**
 * Writer persistence of probe observations (`provider_probe_observations`). Idempotent on
 * `(token_sha256, queue_id)`: a redelivery of the same queue file is a `duplicate`, never a second
 * row. The observation is linked to the validation run that awaits this probe token (same
 * connection, `awaiting_probe`, not expired); an unknown or expired token is still recorded
 * without a run (evidence for the connection). Database errors propagate (the probe is
 * tempfailed and retried by Postfix).
 */
@Injectable()
export class ProbeRecorderRepository {
  constructor(private readonly prisma: PrismaService) {}

  async record(input: ProbeObservationInput): Promise<'recorded' | 'duplicate'> {
    const run = await this.prisma.providerValidationRun.findUnique({
      where: { probeTokenSha256: input.tokenSha256 },
      select: { id: true, connectionId: true, status: true, probeExpiresAt: true },
    });
    const linked =
      run !== null &&
      run.connectionId === input.connectionId &&
      run.status === 'awaiting_probe' &&
      (run.probeExpiresAt === null || run.probeExpiresAt > input.receivedAt);
    try {
      await this.prisma.providerProbeObservation.create({
        data: {
          organizationId: input.organizationId,
          connectionId: input.connectionId,
          validationRunId: linked ? run.id : null,
          tokenSha256: input.tokenSha256,
          queueId: input.queueId.slice(0, 32),
          provider: input.provider,
          clientIp: input.clientIp.slice(0, 45),
          tlsProtocol: cut(input.tlsProtocol, 16),
          tlsCipher: cut(input.tlsCipher, 64),
          envelopeFromDomain: input.envelopeFromDomain.slice(0, 253),
          headerFromDomain: cut(input.headerFromDomain, 253),
          tenantHeader: input.tenantHeader,
          dkim: input.dkim,
          dkimDomains: input.dkimDomains.slice(0, 5).map((domain) => domain.slice(0, 253)),
          dkimAgeSeconds: input.dkimAgeSeconds,
          proofResult: input.proofResult,
          failureCode: cut(input.failureCode, 64),
          receivedAt: input.receivedAt,
        },
        select: { id: true },
      });
      return 'recorded';
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') {
        return 'duplicate';
      }
      throw err;
    }
  }
}
