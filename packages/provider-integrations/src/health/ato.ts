import type { Prisma, PrismaClient } from '@email-gateway/database';
import { z } from 'zod';
import type { CheckStatus } from '../types';
import {
  MAIL_FLOW_HEALTH_CHECKS,
  registerHealthChecks,
  type HealthCheckDefinition,
} from './checks';

/**
 * Step 8.5's connection health check `ato.identity_provider`
 * (docs/plan/steps/26-ato-provider-adapters.md D11, ADR-0084): the health of the connection's
 * account takeover integration as the ato-worker's probe last stored it on
 * `ato_provider_integrations` (by `connector_ref`; one indexed writer read, no provider call, no
 * ATO credential). No integration ⇒ `skipped`; `healthy` ⇒ `pass`; `degraded` for more than one
 * hour ⇒ `warn`; `unhealthy` ⇒ `fail` with severity **warning** (an ATO outage must not mark mail
 * flow critical, PQ15). 8.2's health machinery records transitions and publishes the event and
 * webhook; its `integration_unhealthy` alert fires on `critical` only, so not for this check.
 */
export const ATO_IDENTITY_PROVIDER_CHECK: HealthCheckDefinition = Object.freeze({
  code: 'ato.identity_provider',
  provider: 'any',
  severityOnFail: 'warning',
  periodic: true,
  title: 'Account takeover identity provider integration is healthy',
  remediation: 'docs/deployment/ato-identity-providers.md#troubleshooting',
});

// Registered after 8.2's checks whatever the import order (re-registering the same definitions is
// a no-op), so `HEALTH_CHECKS` keeps 8.2's order first.
registerHealthChecks(MAIL_FLOW_HEALTH_CHECKS);
registerHealthChecks([ATO_IDENTITY_PROVIDER_CHECK]);

/** `paused_reason` of an integration paused by a user (the check is then `skipped`). */
export const ATO_USER_PAUSED_REASON = 'user';

/** `degraded` turns into `warn` after this long (D11). */
export const ATO_DEGRADED_WARN_AFTER_MS = 60 * 60_000;
const MAX_FAILING_STREAMS = 7;
const MAX_MISSING_PERMISSIONS = 10;

export type AtoIntegrationHealth = 'unknown' | 'healthy' | 'degraded' | 'unhealthy';

/** One non-disabled ATO integration of the connection, as stored by the ato-worker. */
export interface AtoIntegrationHealthInput {
  publicId: string;
  status: 'active' | 'paused' | 'error' | 'disabled';
  pausedReason: string | null;
  healthStatus: AtoIntegrationHealth;
  /** `ato_provider_integrations.health_detail` (the last `ProbeReport`), untrusted JSON. */
  healthDetail: unknown;
  healthCheckedAt: Date | null;
}

export interface AtoIdentityProviderOutcome {
  status: CheckStatus;
  evidence: Record<string, unknown>;
}

const CODE = /^[a-z0-9_.-]{1,64}$/;
const PERMISSION = /^[A-Za-z0-9._:/-]{1,256}$/;

const detailSchema = z
  .object({
    streams: z
      .record(z.string(), z.object({ availability: z.string() }).loose())
      .optional()
      .catch(undefined),
    grants: z
      .array(z.object({ missingPermissions: z.array(z.string()).catch([]) }).loose())
      .optional()
      .catch(undefined),
  })
  .loose();

/** Failing stream names and missing permission names of a stored probe report (bounded). */
export function atoHealthFacts(detail: unknown): {
  failingStreams: string[];
  missingPermissions: string[];
} {
  const parsed = detailSchema.safeParse(detail);
  if (!parsed.success) return { failingStreams: [], missingPermissions: [] };
  const failingStreams = Object.entries(parsed.data.streams ?? {})
    .filter(
      ([name, s]) => CODE.test(name) && !['available', 'not_offered'].includes(s.availability),
    )
    .map(([name]) => name)
    .sort()
    .slice(0, MAX_FAILING_STREAMS);
  const missing = new Set<string>();
  for (const grant of parsed.data.grants ?? []) {
    for (const permission of grant.missingPermissions) {
      if (PERMISSION.test(permission)) missing.add(permission);
    }
  }
  return {
    failingStreams,
    missingPermissions: [...missing].sort().slice(0, MAX_MISSING_PERMISSIONS),
  };
}

const RANK: Readonly<Record<AtoIntegrationHealth, number>> = Object.freeze({
  unknown: 0,
  healthy: 1,
  degraded: 2,
  unhealthy: 3,
});

/**
 * The D11 evaluation (pure). `previousDegradedSince` is the `degradedSince` of the previous
 * result of this check (its stored evidence), so "degraded for more than one hour" survives
 * between runs without an extra column.
 */
export function evaluateAtoIdentityProvider(input: {
  integrations: readonly AtoIntegrationHealthInput[];
  previousDegradedSince: Date | null;
  now: Date;
}): AtoIdentityProviderOutcome {
  const live = input.integrations.filter((i) => i.status !== 'disabled');
  if (live.length === 0) return { status: 'skipped', evidence: { reason: 'no_integration' } };
  const watched = live.filter(
    (i) => !(i.status === 'paused' && i.pausedReason === ATO_USER_PAUSED_REASON),
  );
  if (watched.length === 0) {
    return { status: 'skipped', evidence: { reason: 'paused', integrations: live.length } };
  }
  const worst = watched.reduce((a, b) => (RANK[b.healthStatus] > RANK[a.healthStatus] ? b : a));
  const facts = atoHealthFacts(worst.healthDetail);
  const base = {
    health: worst.healthStatus,
    integrationId: worst.publicId,
    checkedAt: worst.healthCheckedAt?.toISOString() ?? null,
  };
  switch (worst.healthStatus) {
    case 'unknown':
      return { status: 'skipped', evidence: { ...base, reason: 'not_probed' } };
    case 'healthy':
      return { status: 'pass', evidence: base };
    case 'degraded': {
      const since = input.previousDegradedSince ?? input.now;
      const long = input.now.getTime() - since.getTime() > ATO_DEGRADED_WARN_AFTER_MS;
      return {
        status: long ? 'warn' : 'pass',
        evidence: { ...base, degradedSince: since.toISOString(), ...facts },
      };
    }
    case 'unhealthy':
      return { status: 'fail', evidence: { ...base, ...facts } };
  }
}

/** `degradedSince` of a stored evidence document, or null. */
export function degradedSinceOf(evidence: Prisma.JsonValue | null | undefined): Date | null {
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) return null;
  const value = (evidence as Record<string, unknown>).degradedSince;
  if (typeof value !== 'string') return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : new Date(ms);
}

/** The non-disabled ATO integrations bound to a connection (writer read; indexed by org). */
export async function readAtoIntegrationHealth(
  db: PrismaClient | Prisma.TransactionClient,
  organizationId: bigint,
  connectionPublicId: string,
): Promise<AtoIntegrationHealthInput[]> {
  const rows = await db.atoProviderIntegration.findMany({
    where: { organizationId, connectorRef: connectionPublicId, status: { not: 'disabled' } },
    select: {
      publicId: true,
      status: true,
      pausedReason: true,
      healthStatus: true,
      healthDetail: true,
      healthCheckedAt: true,
    },
    orderBy: { id: 'asc' },
    take: 10,
  });
  return rows;
}
