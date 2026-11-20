import { randomUUID } from 'node:crypto';
import { sha256Hex, PROVIDER_STREAMS, type ResponseActionType } from '@email-gateway/ato-detection';
import type { AtoProviderIntegration, AtoResponseAction } from '@email-gateway/database';
import {
  backfillReplay,
  cursorSeq,
  defaultBindingSettings,
  directoryRefHash,
  GOOGLE_ADAPTER_VERSION,
  initialCursor,
  MICROSOFT_ADAPTER_VERSION,
  PROVIDER_RETENTION_DAYS,
  STREAM_ROLES,
  type AtoProviderKind,
  type IdpBindingSettings,
} from '@email-gateway/idp-adapters';
import {
  defaultGoogleGrants,
  defaultMicrosoftGrants,
  GS_ADMIN_EMAIL,
  GS_CUSTOMER_ID,
  GS_DOMAIN,
  googleCustomer,
  InMemoryConnectionAccess,
  microsoftDirectory,
  MS_DOMAIN,
  MS_MFA_GROUP_ID,
  MS_TENANT_ID,
  startSimulators,
  type GsCustomer,
  type InMemoryGrant,
  type MsDirectory,
  type RunningSimulators,
} from '@email-gateway/idp-adapters/testing';
import type { IncidentActor } from '@email-gateway/security-incidents';
import type { Fixtures } from './fixtures';
import { type Clock, harness, testConfig, type Harness } from './harness';

export const DAY = 86_400_000;
export const MIN = 60_000;

/** A Microsoft directory cloned under another tenant id and domain (tenant isolation). */
export function msDirectoryAs(now: Date, tenantId: string, domain: string): MsDirectory {
  const json = JSON.stringify(microsoftDirectory(now))
    .split(MS_TENANT_ID)
    .join(tenantId)
    .split(MS_DOMAIN)
    .join(domain);
  return JSON.parse(json) as MsDirectory;
}

/** A Google customer cloned under another customer id and domain. */
export function gsCustomerAs(now: Date, customerId: string, domain: string): GsCustomer {
  const json = JSON.stringify(googleCustomer(now))
    .split(GS_CUSTOMER_ID)
    .join(customerId)
    .split(GS_DOMAIN)
    .join(domain);
  return JSON.parse(json) as GsCustomer;
}

export interface Connection {
  publicId: string;
  organizationId: bigint;
  kind: AtoProviderKind;
  tenantId: string;
  domain: string;
}

/**
 * The step 8.5 world of an integration suite: the in-process provider simulators (Graph, Office
 * 365 Management, Google Admin SDK, Gmail) on 127.0.0.1 driven by synthetic directories, the
 * in-memory 8.2 connection port whose tokens the simulators accept (permissions per grant), and
 * the ato-worker harness configured to call the simulators (APP_ENV local, http allowed). Nothing
 * reaches a real provider or the Internet.
 */
export class IdpWorld {
  sims!: RunningSimulators;
  connections!: InMemoryConnectionAccess;
  h!: Harness;

  constructor(
    readonly fx: Fixtures,
    readonly clock: Clock,
  ) {}

  async start(
    dataset: { microsoft?: MsDirectory[]; google?: GsCustomer[] },
    configOverrides: Record<string, string> = {},
  ): Promise<void> {
    this.sims = await startSimulators({
      dataset: {
        microsoft: { directories: dataset.microsoft ?? [] },
        google: { customers: dataset.google ?? [] },
      },
      now: () => this.clock.now().getTime(),
    });
    this.connections = new InMemoryConnectionAccess(this.sims.tokens, {
      now: () => this.clock.now().getTime(),
    });
    this.h = await harness(this.fx, {
      clock: this.clock,
      config: testConfig({
        ATO_IDP_ADAPTERS_ENABLED: 'true',
        PROVIDER_ALLOW_HTTP_ENDPOINTS: 'true',
        ATO_IDP_GRAPH_BASE_URL: this.sims.baseUrl('graph'),
        ATO_IDP_O365_MANAGEMENT_BASE_URL: this.sims.baseUrl('o365'),
        ATO_IDP_GOOGLE_ADMIN_BASE_URL: this.sims.baseUrl('google-admin'),
        ATO_IDP_GMAIL_BASE_URL: this.sims.baseUrl('gmail'),
        ATO_IDP_HTTP_TIMEOUT_MS: '5000',
        ...configOverrides,
      }),
      // The real Redis rate budget and its real ≤ 1 s wait (D7.5).
      idp: { connections: this.connections },
    });
  }

  async stop(): Promise<void> {
    await this.h?.close();
    await this.sims?.stop();
  }

  /** An active 8.2 connection (in memory) with the three ATO grants of the provider. */
  connect(
    organizationId: bigint,
    kind: AtoProviderKind,
    options: {
      tenantId?: string;
      domain?: string;
      grants?: InMemoryGrant[];
      status?: 'active' | 'configuring' | 'disabled';
    } = {},
  ): Connection {
    const tenantId =
      options.tenantId ?? (kind === 'microsoft_entra' ? MS_TENANT_ID : GS_CUSTOMER_ID);
    const domain = options.domain ?? (kind === 'microsoft_entra' ? MS_DOMAIN : GS_DOMAIN);
    const publicId = randomUUID();
    const grants =
      options.grants ??
      (kind === 'microsoft_entra'
        ? defaultMicrosoftGrants()
        : defaultGoogleGrants().map((g) => ({
            ...g,
            subjectEmail: GS_ADMIN_EMAIL.replace(GS_DOMAIN, domain),
          })));
    this.connections.add({
      publicId,
      organizationId: organizationId.toString(),
      provider: kind === 'microsoft_entra' ? 'microsoft_365' : 'google_workspace',
      displayName: `IT ${kind} (example)`,
      status: options.status ?? 'active',
      externalTenantId: tenantId,
      linkedDomains: [{ name: domain, providerVerified: true }],
      grants: grants.map((g) => ({ ...g, publicId: randomUUID() })),
      updatedAt: this.clock.now().toISOString(),
    });
    return { publicId, organizationId, kind, tenantId, domain };
  }

  /**
   * The integration and stream rows as the api's bind (WP5, D4) creates them: one stream row per
   * 8.4 stream with the provider's role, backfill when `backfillDays > 0`, `next_poll_at = now`,
   * `next_health_at = now` (the probe runs first).
   */
  async bind(
    connection: Connection,
    options: {
      settings?: (s: IdpBindingSettings) => IdpBindingSettings;
      backfillDays?: number;
      /** Leave `directory_ref_hash` to the first probe. */
      unknownDirectory?: boolean;
    } = {},
  ): Promise<AtoProviderIntegration> {
    const now = this.clock.now();
    let settings = defaultBindingSettings();
    settings.backfillDays = options.backfillDays ?? 0;
    if (connection.kind === 'microsoft_entra') settings.mfaEnforcement.groupId = MS_MFA_GROUP_ID;
    else settings.mfaEnforcement.orgUnitPath = '/Security/2SV-Enforced';
    if (options.settings) settings = options.settings(settings);
    const integration = await this.fx.prisma.atoProviderIntegration.create({
      data: {
        organizationId: connection.organizationId,
        provider: connection.kind,
        connectorRef: connection.publicId,
        bindingKey: sha256Hex(`${connection.kind}|${connection.publicId}`),
        status: 'active',
        capabilities: {},
        cursors: {},
        nextPollAt: now,
        settings: settings as never,
        directoryRefHash: options.unknownDirectory
          ? null
          : directoryRefHash(connection.kind, connection.tenantId),
        nextHealthAt: now,
      },
    });
    for (const stream of PROVIDER_STREAMS) {
      const role = STREAM_ROLES[connection.kind][stream].role;
      const retention = PROVIDER_RETENTION_DAYS[connection.kind][stream];
      const backfill = role === 'primary' && settings.backfillDays > 0 && retention > 0;
      const from = backfill
        ? new Date(now.getTime() - Math.min(settings.backfillDays, retention) * DAY)
        : null;
      await this.fx.prisma.atoProviderStream.create({
        data: {
          organizationId: connection.organizationId,
          integrationId: integration.id,
          stream,
          role,
          enabled: settings.streams[stream].enabled && role !== 'unsupported',
          status: role === 'unsupported' ? 'unsupported' : backfill ? 'backfilling' : 'active',
          nextPollAt: now,
          ...(from ? { backfillFrom: from, backfillRequestedAt: now } : { coveredFrom: now }),
        },
      });
    }
    this.h.comps.providers.invalidate();
    return integration;
  }

  /**
   * A backfill of one primary stream from `from` as the api's `POST …/backfill` writes it (D8.1):
   * the earlier ingested range becomes the replay window, the cursor restarts at `from`.
   */
  async backfill(
    integration: AtoProviderIntegration,
    stream: (typeof PROVIDER_STREAMS)[number],
    from: Date,
  ): Promise<void> {
    const current = await this.fx.prisma.atoProviderStream.findUniqueOrThrow({
      where: { integrationId_stream: { integrationId: integration.id, stream } },
    });
    const version =
      integration.provider === 'microsoft_entra'
        ? MICROSOFT_ADAPTER_VERSION
        : GOOGLE_ADAPTER_VERSION;
    const seq = Math.max(cursorSeq(current.cursor, version), Number(current.cursorSeq));
    await this.fx.prisma.atoProviderStream.update({
      where: { id: current.id },
      data: {
        status: 'backfilling',
        ...backfillReplay(current),
        backfillFrom: from,
        backfillRequestedAt: this.clock.now(),
        backfillCompletedAt: null,
        watermarkAt: from,
        cursor: initialCursor(version, from, seq),
        nextPollAt: this.clock.now(),
        rowVersion: { increment: 1 },
      },
    });
  }

  /** Forgets the Redis seen-set of an integration (as after its 6 h TTL). */
  async expireSeen(integration: AtoProviderIntegration): Promise<void> {
    const pattern = `ato:idp:ev:${integration.organizationId.toString()}:${integration.id.toString()}:*`;
    let cursor = '0';
    do {
      const [next, keys] = await this.h.redis.scan(cursor, 'MATCH', pattern, 'COUNT', 500);
      cursor = next;
      if (keys.length > 0) await this.h.redis.del(...keys);
    } while (cursor !== '0');
  }

  /** Drops pending scripted token failures of the in-memory connection port (test-only). */
  clearTokenFailures(): void {
    (this.connections as unknown as { failures: unknown[] }).failures.length = 0;
  }

  /** Probe due integrations, then poll due streams until idle (bounded). */
  async probe(): Promise<void> {
    await this.h.comps.probeLoop!.runOnce();
    this.h.comps.providers.invalidate();
  }

  async poll(maxPasses = 50): Promise<number> {
    let passes = 0;
    while (passes < maxPasses) {
      passes += 1;
      const more = await this.h.comps.streamRunner!.runOnce();
      if (!more) {
        const due = await this.fx.prisma.atoProviderStream.count({
          where: {
            organizationId: { in: this.fx.organizationIds },
            role: 'primary',
            enabled: true,
            status: { in: ['active', 'backfilling'] },
            nextPollAt: { lte: this.clock.now() },
            integration: { status: 'active' },
          },
        });
        if (due === 0) break;
      }
    }
    return passes;
  }

  /** Makes every stream of the suite due now. */
  async due(integrationId?: bigint): Promise<void> {
    await this.fx.prisma.atoProviderStream.updateMany({
      where: {
        organizationId: { in: this.fx.organizationIds },
        ...(integrationId !== undefined ? { integrationId } : {}),
      },
      data: { nextPollAt: new Date(this.clock.now().getTime() - 1) },
    });
  }

  async healthDue(integrationId: bigint): Promise<void> {
    await this.fx.prisma.atoProviderIntegration.updateMany({
      where: { id: integrationId },
      data: { nextHealthAt: new Date(this.clock.now().getTime() - 1) },
    });
  }
}

export const userActor = (u: { id: bigint; publicId: string }): IncidentActor => ({
  type: 'user',
  id: u.publicId,
  userId: u.id,
});

/** An approved provider action (requested by one user, approved by a second, D13). */
export async function approvedAction(
  w: IdpWorld,
  org: { id: bigint; domain: string },
  accountId: bigint,
  type: ResponseActionType,
  params: Record<string, string | number | boolean> = {},
  providerKind: string | null = null,
): Promise<AtoResponseAction> {
  const { fx, h } = w;
  const account = await fx.prisma.atoAccount.findUniqueOrThrow({ where: { id: accountId } });
  const a1 = await fx.user(org.id, `rq-${randomUUID().slice(0, 6)}`, org.domain);
  const a2 = await fx.user(org.id, `ap-${randomUUID().slice(0, 6)}`, org.domain);
  const action = await h.comps.db.transaction((tx) =>
    h.comps.store.requestResponse(tx, {
      organizationId: org.id,
      accountId,
      incidentId: account.activeIncidentId,
      actionType: type,
      target: { scope: 'account', accountPublicId: account.publicId },
      params,
      actor: userActor(a1),
      reason: 'contain',
      authorization: 'manual',
      providerKind,
    }),
  );
  if (action.status !== 'pending_approval') return action;
  return h.comps.db.transaction((tx) =>
    h.comps.store.decideResponse(tx, {
      organizationId: org.id,
      actionId: action.id,
      decision: 'approve',
      actor: userActor(a2),
    }),
  );
}
