import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import { intakeNetworksSchema } from '@email-gateway/archive';
import { isRelayProvider, JOURNAL_INTAKE_KINDS } from '@email-gateway/mail-routing';
import { z } from 'zod';
import { normalizeFingerprint } from '../connectors/addresses';

/** Feature keys an organization needs for journal intake (D1 entitlement). */
export const INTAKE_FEATURE_KEYS = ['archiving', 'journal_intake'] as const;
/** Plan / organization limit keys of journal intake (D13). */
export const INTAKE_LIMIT_KEYS = {
  messagesPerMinute: 'journal_intake_messages_per_minute',
  maxMessageBytes: 'journal_intake_max_message_bytes',
} as const;

/** Domain statuses that count as the organization's side (D3). */
export const ORG_SIDE_DOMAIN_STATUSES = ['verified', 'active', 'suspended'] as const;
/** Upper bounds of the lists a snapshot carries (cached JSON stays small). */
export const MAX_SNAPSHOT_DOMAINS = 1000;
export const MAX_LINKED_DOMAINS = 500;
export const MAX_CLIENT_CERT_FINGERPRINTS = 4;

const decimal = z.string().regex(/^\d{1,20}$/);
const sha256Hex = z.string().regex(/^[0-9a-f]{64}$/);

/**
 * Everything the RCPT policy and the LMTP re-check need about one intake source (JSON-safe: ids
 * as decimal strings, instants as ISO strings). Cached by the policy under
 * `sa:jintake:src:<addressHash>`; the LMTP reads it from the writer each time. Hashes only, never
 * an address or token.
 */
export const intakeSourceSnapshotSchema = z.object({
  v: z.literal(1),
  source: z.object({
    id: decimal,
    publicId: z.string().min(1).max(36),
    organizationId: decimal,
    kind: z.enum(JOURNAL_INTAKE_KINDS),
    status: z.enum(['pending_verification', 'active', 'paused', 'disabled']),
    /** The looked-up hash matched `previous_address_hash` (valid until `previousValidUntil`). */
    matchedPrevious: z.boolean(),
    previousValidUntil: z.string().datetime().nullable(),
    /** Canonical CIDRs of `intake-networks/1`; empty = none usable (on-premises kinds refuse). */
    networks: z.array(z.string()).max(32),
    /** `networks` was set but did not parse (refused like an empty list). */
    networksInvalid: z.boolean(),
    requireTls: z.boolean(),
    /** Normalized SHA-256 fingerprints (64 lower-case hex); empty = no certificate required. */
    clientCertFingerprints: z.array(sha256Hex).max(MAX_CLIENT_CERT_FINGERPRINTS),
    /** `client_cert_fingerprints` was set but did not parse (refused: fail closed). */
    clientCertInvalid: z.boolean(),
    maxMessageBytes: z.number().int().nonnegative().nullable(),
    headerTokenHash: sha256Hex.nullable(),
    previousHeaderTokenHash: sha256Hex.nullable(),
    verified: z.boolean(),
  }),
  organization: z.object({
    active: z.boolean(),
    archivingFeature: z.boolean(),
    journalIntakeFeature: z.boolean(),
    archivingEnabled: z.boolean(),
    /** Plan / organization limit `journal_intake_messages_per_minute` (missing = 0, none). */
    messagesPerMinute: z.number().int().nonnegative(),
    /** Plan / organization limit `journal_intake_max_message_bytes` (missing = 0, none). */
    maxMessageBytes: z.number().int().nonnegative(),
  }),
  connection: z
    .object({
      id: decimal,
      publicId: z.string().max(36),
      provider: z.enum(['microsoft_365', 'google_workspace']),
      organizationId: decimal,
      status: z.string().max(32),
      externalTenantId: z.string().max(64).nullable(),
      /** `active_tenant_key` is set (the 8.2 binding). */
      bound: z.boolean(),
      linkedDomains: z.array(z.string()).max(MAX_LINKED_DOMAINS),
    })
    .nullable(),
  /** Org-side domains (verified / active / suspended), lowest id first. */
  domains: z
    .array(z.object({ id: decimal, name: z.string(), status: z.string() }))
    .max(MAX_SNAPSHOT_DOMAINS),
});

export type IntakeSourceSnapshot = z.infer<typeof intakeSourceSnapshotSchema>;

/** `client_cert_fingerprints`: a JSON array of SHA-256 fingerprints (hex, colons allowed). */
export function parseClientCertFingerprints(raw: unknown): { list: string[]; invalid: boolean } {
  if (raw === null || raw === undefined) return { list: [], invalid: false };
  const values =
    Array.isArray(raw) && raw.every((v) => typeof v === 'string')
      ? raw
      : typeof raw === 'object' &&
          raw !== null &&
          Array.isArray((raw as { fingerprints?: unknown }).fingerprints)
        ? (raw as { fingerprints: unknown[] }).fingerprints
        : null;
  if (values === null) return { list: [], invalid: true };
  const list: string[] = [];
  for (const value of values) {
    const normalized = typeof value === 'string' ? normalizeFingerprint(value) : null;
    if (normalized === null) return { list: [], invalid: true };
    if (!list.includes(normalized)) list.push(normalized);
  }
  if (list.length > MAX_CLIENT_CERT_FINGERPRINTS) return { list: [], invalid: true };
  return { list, invalid: false };
}

/** `networks` (`intake-networks/1`) → canonical CIDRs; NULL = none. */
export function parseIntakeNetworks(raw: unknown): { cidrs: string[]; invalid: boolean } {
  if (raw === null || raw === undefined) return { cidrs: [], invalid: false };
  const parsed = intakeNetworksSchema.safeParse(raw);
  return parsed.success
    ? { cidrs: parsed.data.cidrs, invalid: false }
    : { cidrs: [], invalid: true };
}

/** Effective boolean feature: the organization row, else the plan's `default_features`. */
function featureOf(
  rows: readonly { featureKey: string; enabled: boolean }[],
  planDefaults: unknown,
  key: string,
): boolean {
  const row = rows.find((r) => r.featureKey === key);
  if (row) return row.enabled;
  const value =
    planDefaults && typeof planDefaults === 'object'
      ? (planDefaults as Record<string, unknown>)[key]
      : undefined;
  return value === true;
}

/** Effective limit: the organization row, else the plan's `default_limits`, else 0 (none). */
function limitOf(
  rows: readonly { limitKey: string; limitValue: bigint }[],
  planDefaults: unknown,
  key: string,
): number {
  const row = rows.find((r) => r.limitKey === key);
  const raw =
    row?.limitValue ??
    (planDefaults && typeof planDefaults === 'object'
      ? (planDefaults as Record<string, unknown>)[key]
      : undefined);
  const value =
    typeof raw === 'bigint' ? raw : typeof raw === 'number' ? BigInt(Math.trunc(raw)) : 0n;
  if (value <= 0n) return 0;
  return value > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(value);
}

/**
 * Writer reads of an intake source by address hash (current or previous), with its
 * organization's state, entitlement, limits and archive switch, the bound connection and the
 * org-side domains (ADR-0014: mail-path decisions never use the replica). Database errors
 * propagate (the policy tempfails, the LMTP answers 451).
 */
@Injectable()
export class JournalIntakeSourceRepository {
  constructor(private readonly prisma: PrismaService) {}

  async loadByAddressHash(addressHash: string): Promise<IntakeSourceSnapshot | null> {
    if (!/^[0-9a-f]{64}$/.test(addressHash)) return null;
    const source = await this.prisma.journalIntakeSource.findFirst({
      where: { OR: [{ addressHash }, { previousAddressHash: addressHash }] },
      select: {
        id: true,
        publicId: true,
        organizationId: true,
        kind: true,
        status: true,
        providerConnectionId: true,
        networks: true,
        requireTls: true,
        clientCertFingerprints: true,
        maxMessageBytes: true,
        addressHash: true,
        previousAddressHash: true,
        headerTokenHash: true,
        previousHeaderTokenHash: true,
        previousValidUntil: true,
        verifiedAt: true,
        organization: {
          select: {
            status: true,
            plan: { select: { defaultFeatures: true, defaultLimits: true } },
          },
        },
      },
    });
    if (!source) return null;
    const organizationId = source.organizationId;
    const [features, limits, settings, connection, domains] = await Promise.all([
      this.prisma.organizationFeature.findMany({
        where: { organizationId, featureKey: { in: [...INTAKE_FEATURE_KEYS] } },
        select: { featureKey: true, enabled: true },
      }),
      this.prisma.organizationLimit.findMany({
        where: { organizationId, limitKey: { in: Object.values(INTAKE_LIMIT_KEYS) } },
        select: { limitKey: true, limitValue: true },
      }),
      this.prisma.archiveSetting.findUnique({
        where: { organizationId },
        select: { enabled: true },
      }),
      source.providerConnectionId === null
        ? Promise.resolve(null)
        : this.prisma.providerConnection.findUnique({
            where: { id: source.providerConnectionId },
            select: {
              id: true,
              publicId: true,
              provider: true,
              organizationId: true,
              status: true,
              externalTenantId: true,
              activeTenantKey: true,
              domains: {
                select: { domain: { select: { name: true } } },
                orderBy: { id: 'asc' },
                take: MAX_LINKED_DOMAINS,
              },
            },
          }),
      this.prisma.domain.findMany({
        where: { organizationId, status: { in: [...ORG_SIDE_DOMAIN_STATUSES] } },
        select: { id: true, name: true, status: true },
        orderBy: { id: 'asc' },
        take: MAX_SNAPSHOT_DOMAINS,
      }),
    ]);
    const plan = source.organization.plan;
    const networks = parseIntakeNetworks(source.networks);
    const fingerprints = parseClientCertFingerprints(source.clientCertFingerprints);
    return intakeSourceSnapshotSchema.parse({
      v: 1,
      source: {
        id: source.id.toString(),
        publicId: source.publicId,
        organizationId: organizationId.toString(),
        kind: source.kind,
        status: source.status,
        matchedPrevious: source.addressHash !== addressHash,
        previousValidUntil: source.previousValidUntil?.toISOString() ?? null,
        networks: networks.cidrs,
        networksInvalid: networks.invalid,
        requireTls: source.requireTls,
        clientCertFingerprints: fingerprints.list,
        clientCertInvalid: fingerprints.invalid,
        maxMessageBytes: source.maxMessageBytes,
        headerTokenHash: source.headerTokenHash,
        previousHeaderTokenHash: source.previousHeaderTokenHash,
        verified: source.verifiedAt !== null,
      },
      organization: {
        active: source.organization.status === 'active',
        archivingFeature: featureOf(features, plan.defaultFeatures, 'archiving'),
        journalIntakeFeature: featureOf(features, plan.defaultFeatures, 'journal_intake'),
        archivingEnabled: settings?.enabled === true,
        messagesPerMinute: limitOf(limits, plan.defaultLimits, INTAKE_LIMIT_KEYS.messagesPerMinute),
        maxMessageBytes: limitOf(limits, plan.defaultLimits, INTAKE_LIMIT_KEYS.maxMessageBytes),
      },
      connection:
        connection && isRelayProvider(connection.provider)
          ? {
              id: connection.id.toString(),
              publicId: connection.publicId,
              provider: connection.provider,
              organizationId: connection.organizationId.toString(),
              status: connection.status,
              externalTenantId: connection.externalTenantId,
              bound: connection.activeTenantKey !== null && connection.externalTenantId !== null,
              linkedDomains: connection.domains.map((link) => link.domain.name.toLowerCase()),
            }
          : null,
      domains: domains.map((d) => ({
        id: d.id.toString(),
        name: d.name.toLowerCase(),
        status: d.status,
      })),
    } satisfies IntakeSourceSnapshot);
  }
}
