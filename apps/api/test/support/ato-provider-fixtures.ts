/**
 * The in-memory identity-provider world of the step 8.5 e2e suites
 * (docs/plan/steps/26-ato-provider-adapters.md §11.4): doubles of the providers and mailbox item
 * repositories (integrations, stream rows, mailbox items, identities, the platform-wide directory
 * key and the organization lock), and of the 8.2 connection directory (connection views run
 * through the real `toDirectoryConnection` of `@email-gateway/idp-adapters`, so profiles and
 * eligibility are the library's). Pending provider actions live in the 8.4 `AtoWorld` and are
 * ended by its `AtoStore` double. The real writer, replica and 8.2 tables run in
 * integration/ato-providers.test.ts. Nothing here is used by production code.
 */
import { randomUUID } from 'node:crypto';
import {
  type AtoAccountIdentity,
  type AtoProviderMailboxItem,
  Prisma,
} from '@email-gateway/database';
import {
  type DirectoryConnection,
  type ProviderConnectionView,
  toDirectoryConnection,
} from '@email-gateway/idp-adapters';
import type { TenantScope } from '../../src/auth-contracts/tenant-scope';
import { AtoConnectionDirectory } from '../../src/modules/ato/providers/connection-directory.provider';
import { AtoMailboxItemsRepository } from '../../src/modules/ato/repositories/ato-mailbox-items.repository';
import {
  AtoProvidersRepository,
  type IntegrationRow,
  type IntegrationUpdate,
  type IntegrationWrite,
  type StreamRow,
  type StreamUpdate,
  type StreamWrite,
} from '../../src/modules/ato/repositories/ato-providers.repository';
import type { AtoWorld } from './ato-fixtures';

const own = (scope: TenantScope) => scope.organizationId;

/** A Prisma JSON null (`Prisma.DbNull` / `JsonNull`) as the stored `null`; anything else as is. */
function stored(value: unknown): unknown {
  return value === Prisma.DbNull || value === Prisma.JsonNull ? null : value;
}

/** Applies a Prisma-style update (`{ increment }` included) to a plain row. */
function apply<T extends object>(row: T, data: object): void {
  const target = row as Record<string, unknown>;
  for (const [key, value] of Object.entries(data)) {
    if (value === undefined) continue;
    if (value !== null && typeof value === 'object' && 'increment' in value) {
      const inc = (value as { increment: number }).increment;
      const current = target[key];
      target[key] = typeof current === 'bigint' ? current + BigInt(inc) : Number(current) + inc;
    } else {
      target[key] = stored(value);
    }
  }
}

/** A synthetic 8.2 connection view (port shape) of an organization. */
export function connectionView(
  organizationId: bigint,
  over: Partial<ProviderConnectionView> & {
    telemetry?: 'active' | 'pending' | 'error' | 'revoked' | null;
  } = {},
): ProviderConnectionView {
  const provider = over.provider ?? 'microsoft_365';
  const telemetry = over.telemetry === undefined ? 'active' : over.telemetry;
  const profile = provider === 'microsoft_365' ? 'm365.ato_telemetry' : 'google.ato_telemetry';
  const observed =
    provider === 'microsoft_365'
      ? [
          'AuditLog.Read.All',
          'Directory.Read.All',
          'IdentityRiskEvent.Read.All',
          'User.Read.All',
          'MailboxSettings.Read',
        ]
      : [
          'https://www.googleapis.com/auth/admin.reports.audit.readonly',
          'https://www.googleapis.com/auth/admin.directory.user.readonly',
          'https://www.googleapis.com/auth/gmail.settings.basic',
        ];
  const { telemetry: _t, ...rest } = over;
  return {
    publicId: randomUUID(),
    organizationId: organizationId.toString(),
    provider,
    displayName: `EXAMPLE connection ${randomUUID().slice(0, 8)}`,
    status: 'active',
    externalTenantId: provider === 'microsoft_365' ? randomUUID() : `C${randomUUID().slice(0, 8)}`,
    linkedDomains: [{ name: 'contoso-it.example', providerVerified: true }],
    grants:
      telemetry === null
        ? []
        : [
            {
              publicId: randomUUID(),
              profile,
              status: telemetry,
              observedPermissions: telemetry === 'active' ? observed : null,
              subjectEmail: provider === 'google_workspace' ? 'admin@fabrikam-it.example' : null,
            },
          ],
    updatedAt: new Date().toISOString(),
    ...rest,
  };
}

/** The world every provider double reads and writes. */
export class AtoProviderWorld {
  private seq = 50_000n;
  integrations: IntegrationRow[] = [];
  streams: StreamRow[] = [];
  items: AtoProviderMailboxItem[] = [];
  identities: AtoAccountIdentity[] = [];
  connections: ProviderConnectionView[] = [];
  /** Organizations whose binding lock was taken (asserted by tests). */
  locks: bigint[] = [];

  constructor(readonly ato: AtoWorld) {}

  id(): bigint {
    this.seq += 1n;
    return this.seq;
  }

  reset(): void {
    this.integrations = [];
    this.streams = [];
    this.items = [];
    this.identities = [];
    this.connections = [];
    this.locks = [];
  }

  addConnection(
    organizationId: bigint,
    over: Parameters<typeof connectionView>[1] = {},
  ): ProviderConnectionView {
    const view = connectionView(organizationId, over);
    this.connections.push(view);
    return view;
  }

  directory(organizationId: bigint): DirectoryConnection[] {
    return this.connections
      .filter((c) => c.organizationId === organizationId.toString())
      .map(toDirectoryConnection);
  }

  /** An integration row as `POST /ato/providers` would create it (for reads and mutations). */
  addIntegration(organizationId: bigint, over: Partial<IntegrationRow> = {}): IntegrationRow {
    const now = new Date();
    const row: IntegrationRow = {
      id: this.id(),
      publicId: randomUUID(),
      organizationId,
      provider: 'microsoft_entra',
      connectorRef: randomUUID(),
      bindingKey: 'b'.repeat(64),
      status: 'active',
      capabilities: {},
      cursors: {},
      lastSuccessAt: null,
      lastErrorCode: null,
      consecutiveFailures: 0,
      nextPollAt: now,
      displayName: 'EXAMPLE integration',
      directoryRefHash: randomUUID().replace(/-/g, '').padEnd(64, '0'),
      directoryDomains: ['contoso-it.example'],
      grantedPermissions: ['AuditLog.Read.All'],
      settings: {},
      settingsVersion: 1,
      healthStatus: 'healthy',
      healthDetail: null,
      healthCheckedAt: now,
      nextHealthAt: now,
      pausedReason: null,
      disabledReason: null,
      disabledAt: null,
      createdByUserId: null,
      updatedByUserId: null,
      activeMarker: 1,
      rowVersion: 1,
      createdAt: now,
      updatedAt: now,
      ...over,
    };
    row.activeMarker = row.status === 'disabled' ? null : 1;
    this.integrations.push(row);
    return row;
  }

  addStream(integration: IntegrationRow, over: Partial<StreamRow> = {}): StreamRow {
    const now = new Date();
    const row: StreamRow = {
      id: this.id(),
      organizationId: integration.organizationId,
      integrationId: integration.id,
      stream: 'sign_ins',
      role: 'primary',
      enabled: true,
      status: 'active',
      availability: 'available',
      availabilityCode: null,
      cursor: null,
      cursorSeq: 0n,
      watermarkAt: new Date(now.getTime() - 300_000),
      backfillFrom: null,
      backfillRequestedAt: null,
      backfillCompletedAt: null,
      coveredFrom: null,
      replayFrom: null,
      replayUntil: null,
      nextPollAt: now,
      throttledUntil: null,
      lastAttemptAt: now,
      lastSuccessAt: now,
      lastEventAt: now,
      lastErrorCode: null,
      consecutiveFailures: 0,
      eventsTotal: 10n,
      pagesTotal: 2n,
      rowVersion: 1,
      createdAt: now,
      updatedAt: now,
      ...over,
    };
    this.streams.push(row);
    return row;
  }

  addItem(
    integration: IntegrationRow,
    accountId: bigint,
    over: Partial<AtoProviderMailboxItem> = {},
  ): AtoProviderMailboxItem {
    const now = new Date();
    const row: AtoProviderMailboxItem = {
      id: this.id(),
      publicId: randomUUID(),
      organizationId: integration.organizationId,
      integrationId: integration.id,
      accountId,
      identityExternalIdHash: 'e'.repeat(64),
      itemKind: 'inbox_rule',
      itemHash: randomUUID().replace(/-/g, '').padEnd(64, 'f'),
      providerItemRef: 'rule-1',
      targetDomain: 'external-example.net',
      traits: ['forwards', 'forwards_external'],
      enabled: true,
      state: 'present',
      source: 'snapshot',
      firstSeenAt: now,
      lastSeenAt: now,
      removedAt: null,
      emittedSeq: 1n,
      lastChange: 'added',
      createdAt: now,
      updatedAt: now,
      ...over,
    };
    this.items.push(row);
    return row;
  }

  addIdentity(
    integration: IntegrationRow | null,
    organizationId: bigint,
    accountId: bigint,
    over: Partial<AtoAccountIdentity> = {},
  ): AtoAccountIdentity {
    const now = new Date();
    const row: AtoAccountIdentity = {
      id: this.id(),
      organizationId,
      accountId,
      provider: integration?.provider ?? 'microsoft_entra',
      externalId: randomUUID(),
      externalIdHash: 'c'.repeat(64),
      userPrincipalName: 'jane.doe@corp.example',
      firstSeenAt: now,
      lastSeenAt: now,
      integrationId: integration?.id ?? null,
      primaryEmailDomain: 'corp.example',
      directoryStatus: 'active',
      directoryStatusAt: now,
      mailboxRefreshRequestedAt: null,
      ...over,
    };
    this.identities.push(row);
    return row;
  }
}

class FakeProvidersRepository extends AtoProvidersRepository {
  constructor(private readonly w: AtoProviderWorld) {
    super({} as never);
  }

  override readClient(): never {
    throw new Error('the e2e suite replaces the connection directory');
  }

  override list(
    scope: TenantScope,
    input: { includeDisabled: boolean; disabledLimit: number; activeLimit: number },
  ) {
    const mine = this.w.integrations.filter((r) => r.organizationId === own(scope));
    const active = mine.filter((r) => r.status !== 'disabled').slice(0, input.activeLimit);
    const disabled = input.includeDisabled
      ? mine
          .filter((r) => r.status === 'disabled')
          .sort((a, b) => (b.id > a.id ? 1 : -1))
          .slice(0, input.disabledLimit)
      : [];
    return Promise.resolve([...active, ...disabled]);
  }

  override findByPublicId(scope: TenantScope, publicId: string) {
    return Promise.resolve(
      this.w.integrations.find((r) => r.organizationId === own(scope) && r.publicId === publicId) ??
        null,
    );
  }

  override findByIds(scope: TenantScope, ids: readonly bigint[]) {
    return Promise.resolve(
      this.w.integrations.filter((r) => r.organizationId === own(scope) && ids.includes(r.id)),
    );
  }

  override streams(scope: TenantScope, integrationIds: readonly bigint[]) {
    return Promise.resolve(
      this.w.streams.filter(
        (s) => s.organizationId === own(scope) && integrationIds.includes(s.integrationId),
      ),
    );
  }

  override nonDisabled(scope: TenantScope) {
    return Promise.resolve(
      this.w.integrations.filter((r) => r.organizationId === own(scope) && r.status !== 'disabled'),
    );
  }

  override lockOrganization(_tx: unknown, scope: TenantScope) {
    this.w.locks.push(own(scope));
    return Promise.resolve();
  }

  override lockByPublicId(_tx: unknown, scope: TenantScope, publicId: string) {
    return this.findByPublicId(scope, publicId);
  }

  override byBindingKey(_tx: unknown, scope: TenantScope, bindingKey: string) {
    return Promise.resolve(
      this.w.integrations.find(
        (r) => r.organizationId === own(scope) && r.bindingKey === bindingKey,
      ) ?? null,
    );
  }

  override directoryInUse(_tx: unknown, provider: string, hash: string) {
    return Promise.resolve(
      this.w.integrations.some(
        (r) => r.provider === provider && r.directoryRefHash === hash && r.status !== 'disabled',
      ),
    );
  }

  override create(_tx: unknown, scope: TenantScope, data: IntegrationWrite) {
    const row = this.w.addIntegration(own(scope), {
      ...(data as Partial<IntegrationRow>),
      healthDetail: stored(data.healthDetail) as IntegrationRow['healthDetail'],
      healthCheckedAt: null,
    });
    return Promise.resolve(row);
  }

  override update(_tx: unknown, scope: TenantScope, id: bigint, data: IntegrationUpdate) {
    const row = this.w.integrations.find((r) => r.organizationId === own(scope) && r.id === id);
    if (!row) throw new Error('ato provider integration update matched no row');
    apply(row, data);
    row.activeMarker = row.status === 'disabled' ? null : 1;
    row.updatedAt = new Date();
    return Promise.resolve(row);
  }

  override replaceStreams(
    _tx: unknown,
    scope: TenantScope,
    integrationId: bigint,
    rows: readonly StreamWrite[],
  ) {
    this.w.streams = this.w.streams.filter(
      (s) => !(s.organizationId === own(scope) && s.integrationId === integrationId),
    );
    const integration = this.w.integrations.find((r) => r.id === integrationId)!;
    for (const r of rows) {
      this.w.addStream(integration, {
        availability: 'unknown',
        watermarkAt: null,
        lastAttemptAt: null,
        lastSuccessAt: null,
        lastEventAt: null,
        eventsTotal: 0n,
        pagesTotal: 0n,
        ...(r as Partial<StreamRow>),
      });
    }
    return Promise.resolve();
  }

  override updateStream(
    _tx: unknown,
    scope: TenantScope,
    integrationId: bigint,
    stream: StreamRow['stream'],
    data: StreamUpdate,
  ) {
    for (const s of this.w.streams) {
      if (
        s.organizationId === own(scope) &&
        s.integrationId === integrationId &&
        s.stream === stream
      ) {
        apply(s, data);
        s.rowVersion += 1;
      }
    }
    return Promise.resolve();
  }

  override pendingProviderActions(_tx: unknown, scope: TenantScope, integrationId: bigint) {
    return Promise.resolve(
      this.w.ato.responses
        .filter(
          (r) =>
            r.organizationId === own(scope) &&
            r.integrationId === integrationId &&
            ['approved', 'executing', 'rollback_requested'].includes(r.status),
        )
        .map((r) => ({ id: r.id, status: r.status })),
    );
  }
}

class FakeMailboxItemsRepository extends AtoMailboxItemsRepository {
  constructor(private readonly w: AtoProviderWorld) {
    super({} as never);
  }

  override items(
    scope: TenantScope,
    accountId: bigint,
    input: { removedSince: Date; limit: number },
  ) {
    const mine = this.w.items.filter(
      (i) => i.organizationId === own(scope) && i.accountId === accountId,
    );
    const present = mine.filter((i) => i.state === 'present');
    const removed = mine.filter(
      (i) => i.state === 'removed' && i.removedAt !== null && i.removedAt >= input.removedSince,
    );
    return Promise.resolve([...present, ...removed].slice(0, input.limit));
  }

  override identities(scope: TenantScope, accountId: bigint) {
    return Promise.resolve(
      this.w.identities.filter((i) => i.organizationId === own(scope) && i.accountId === accountId),
    );
  }

  override requestRefresh(
    _tx: unknown,
    scope: TenantScope,
    input: { accountId: bigint; integrationIds: readonly bigint[]; at: Date },
  ) {
    let n = 0;
    for (const i of this.w.identities) {
      if (
        i.organizationId === own(scope) &&
        i.accountId === input.accountId &&
        i.integrationId !== null &&
        input.integrationIds.includes(i.integrationId)
      ) {
        i.mailboxRefreshRequestedAt = input.at;
        n += 1;
      }
    }
    return Promise.resolve(n);
  }
}

class FakeConnectionDirectory extends AtoConnectionDirectory {
  constructor(private readonly w: AtoProviderWorld) {
    super({} as never);
  }

  override list(scope: TenantScope) {
    return Promise.resolve(this.w.directory(own(scope)));
  }

  override get(scope: TenantScope, publicId: string) {
    return Promise.resolve(
      this.w.directory(own(scope)).find((e) => e.connection.publicId === publicId) ?? null,
    );
  }
}

/** The provider overrides (repositories and the connection directory) of a testing module. */
export function providerOverrides(world: AtoProviderWorld): Array<[unknown, unknown]> {
  return [
    [AtoProvidersRepository, new FakeProvidersRepository(world)],
    [AtoMailboxItemsRepository, new FakeMailboxItemsRepository(world)],
    [AtoConnectionDirectory, new FakeConnectionDirectory(world)],
  ];
}
