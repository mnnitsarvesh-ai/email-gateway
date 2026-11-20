import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { validateIntakeNetworks } from '@email-gateway/archive';
import { uuidv7 } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { intakeAttestationByCode } from '@email-gateway/provider-integrations';
import { z } from 'zod';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { TransactionRunner } from '../../../database/transaction-runner';
import { CodedForbiddenException } from '../../../http/coded-exception';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import {
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  type IdempotentResult,
  IdempotencyService,
} from '../../../http/idempotency/idempotency.service';
import { decideKeysetPage } from '../../../http/listing/scan-budget';
import { OrganizationFeaturesService } from '../../../tenancy/organization-features.service';
import { OrganizationLimitsService } from '../../../tenancy/organization-limits.service';
import { formatZodIssues } from '../../../validation/zod-validation.pipe';
import { ArchiveConfigRepository } from '../../archive/repositories/archive-config.repository';
import {
  decimalKey,
  decodeListCursor,
  encodeListCursor,
  listBinding,
} from '../../messages/domain/v1-list';
import { computeIntakeWizard, type IntakeKind, isProviderKind } from '../domain/intake-wizard';
import {
  connectionIssue,
  maxMessageBytesIssue,
  resumedStatus,
  sourceFieldIssues,
} from '../domain/source-rules';
import {
  type AttestationBody,
  AttestationBodySchema,
  type AttestationsView,
  type CreatedIntakeSourceView,
  type CreateIntakeSourceBody,
  CreateIntakeSourceBodySchema,
  type IntakeCountersView,
  type IntakeSourceDetailView,
  type IntakeSourceListQuery,
  type IntakeSourcePage,
  type IntakeSourceView,
  type IntakeWizardView,
  PublicIdSchema,
  type UpdateIntakeSourceBody,
  UpdateIntakeSourceBodySchema,
} from '../dto/journaling.schemas';
import {
  ARCHIVING_FEATURE,
  COUNTER_DAYS_SHOWN,
  INTAKE_ATTESTATIONS_SCHEMA,
  INTAKE_SOURCES_CURSOR_RESOURCE,
  JOURNAL_AUDIT,
  JOURNAL_INTAKE_FEATURE,
  JOURNAL_INTAKE_RESOURCE,
  JOURNAL_OPERATIONS,
  JOURNAL_PERMISSIONS as P,
  JOURNAL_TX_TIMEOUT_MS,
  type JournalingConfig,
  MAX_INTAKE_ATTESTATIONS,
} from '../journaling.constants';
import {
  archivingNotEnabledForIntake,
  intakeAttestationUnknown,
  intakeConnectionInvalid,
  intakeDomainRequired,
  intakeNetworksInvalid,
  intakeSourceConflict,
  intakeSourceDisabled,
  intakeSourceLimit,
  intakeSourceNameTaken,
  intakeSourceNotFound,
  journalIntakeNotEnabled,
  journalIntakeUnavailable,
} from '../journaling.errors';
import {
  type ConnectionRef,
  JournalingRepository,
  type SourceRow,
  type SourceUpdate,
} from '../repositories/journaling.repository';
import { IntakeAddressService } from './intake-address.service';
import { utcDay } from './journaling-settings.service';

type Tx = Prisma.TransactionClient;
type Config = Pick<
  JournalingConfig,
  | 'APP_ENV'
  | 'JOURNAL_INTAKE_MAX_MESSAGE_BYTES'
  | 'JOURNAL_INTAKE_ROTATION_OVERLAP_DAYS'
  | 'JOURNAL_INTAKE_MAX_SOURCES_PER_ORG'
>;

const DAY_MS = 86_400_000;

/** A path id: a UUID, `400` before any read (lower-cased). */
export function parseSourceId(raw: unknown): string {
  const parsed = PublicIdSchema.safeParse(raw);
  if (!parsed.success) throw new BadRequestException(['sourceId: must be a UUID']);
  return parsed.data.toLowerCase();
}

/** A body parsed in the service (after the Idempotency-Key checks); `400 validation_failed`. */
function parseBody<S extends z.ZodType>(schema: S, raw: unknown): z.output<S> {
  const parsed = schema.safeParse(raw ?? {});
  if (!parsed.success) throw new BadRequestException(formatZodIssues(parsed.error));
  return parsed.data;
}

const iso = (d: Date | null): string | null => (d === null ? null : d.toISOString());

const stringList = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];

/** The CIDRs of a stored `intake-networks/1` document, or null. */
const networksOf = (value: unknown): string[] | null =>
  value !== null && typeof value === 'object' && !Array.isArray(value)
    ? stringList((value as { cidrs?: unknown }).cidrs)
    : null;

const attestationEntry = z.object({
  code: z.string().min(1).max(64),
  userId: z.string().max(64).nullable(),
  at: z.iso.datetime({ offset: true }),
});
type AttestationEntry = z.infer<typeof attestationEntry>;

/** The stored `provider-attestations/1` items (malformed → none). */
function attestationsOf(value: unknown): AttestationEntry[] {
  const parsed = z.object({ items: z.array(attestationEntry) }).safeParse(value);
  return parsed.success ? parsed.data.items : [];
}

const principalPublicId = (p: Principal): string =>
  p.kind === 'api_key' ? p.apiKeyPublicId : p.userPublicId;
const principalUserId = (p: Principal): bigint | null => (p.kind === 'user' ? p.userId : null);

const isNameConflict = (error: unknown): boolean =>
  error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';

/**
 * Journal intake sources (step 8.6 D1, D10, D11; ADR-0087): list, detail with health and the
 * last 7 days of counters, creation (entitlement, archiving enabled with a default retention
 * policy, a TXT-verified domain, the per-organization limit, kind-specific fields, the bound 8.2
 * connection of provider kinds, the network rules of on-premises kinds against the active
 * provider egress ranges), updates with CAS (`paused` ↔ resumed), disabling (terminal), address
 * rotation with an overlap, attestations and the computed wizard. Intake addresses and header
 * tokens are derived (never stored): the database gets SHA-256 hashes; the clear values are shown
 * once on creation and rotation (ADR-0057: the stored idempotent response carries `null`) and on
 * an audited reveal by `journal:manage` holders. Every route is tenant-scoped; ids of another
 * organization answer `404`.
 */
@Injectable()
export class IntakeSourcesService {
  constructor(
    @Inject(API_CONFIG) private readonly config: Config,
    private readonly sources: JournalingRepository,
    private readonly configs: ArchiveConfigRepository,
    private readonly addresses: IntakeAddressService,
    private readonly features: OrganizationFeaturesService,
    private readonly limits: OrganizationLimitsService,
    private readonly idempotency: IdempotencyService,
    private readonly runner: TransactionRunner,
    private readonly audit: AuditService,
    private readonly codec: CursorCodec,
  ) {}

  now(): Date {
    return new Date();
  }

  // ---- views -----------------------------------------------------------------------------------

  /** The source view; `reveal` shows the address and token in clear. */
  view(row: SourceRow, reveal = false): IntakeSourceView {
    const shown = this.addresses.shown(
      row.publicId,
      row.addressVersion,
      row.kind === 'google_workspace_copy',
      reveal,
    );
    return {
      id: row.publicId,
      kind: row.kind,
      displayName: row.displayName,
      status: row.status,
      providerConnectionId: row.providerConnection?.publicId ?? null,
      networks: networksOf(row.networks),
      requireTls: row.requireTls,
      clientCertFingerprints: stringList(row.clientCertFingerprints),
      maxMessageBytes: row.maxMessageBytes,
      silenceAlertMinutes: row.silenceAlertMinutes,
      address: shown.address,
      headerToken: shown.headerToken,
      revealed: reveal && shown.address !== null,
      addressVersion: row.addressVersion,
      previousAddressValidUntil: iso(row.previousValidUntil),
      verifiedAt: iso(row.verifiedAt),
      lastAcceptedAt: iso(row.lastAcceptedAt),
      lastRefusedAt: iso(row.lastRefusedAt),
      lastRefusalCode: row.lastRefusalCode,
      health: { status: row.healthStatus, changedAt: iso(row.healthChangedAt) },
      attestations: attestationsOf(row.attestations),
      rowVersion: row.rowVersion,
      createdAt: row.createdAt.toISOString(),
      updatedAt: row.updatedAt.toISOString(),
      disabledAt: iso(row.disabledAt),
    };
  }

  /** `GET /journaling/intake-sources` (v1 cursor list, newest first). */
  async list(
    principal: Principal,
    scope: TenantScope,
    query: IntakeSourceListQuery,
  ): Promise<IntakeSourcePage> {
    const binding = listBinding({
      resource: INTAKE_SOURCES_CURSOR_RESOURCE,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 1);
    const fetched = await this.sources.list(scope, {
      take: query.limit + 1,
      ...(decoded && { beforeId: decimalKey(decoded.keys[0]) }),
      ...(query.filters.status?.values && { statuses: query.filters.status.values }),
      ...(query.filters.kind?.values && { kinds: query.filters.kind.values }),
      ...(query.filters.health?.values && { health: query.filters.health.values }),
    });
    const decision = decideKeysetPage({ fetched, limit: query.limit, keyOf: (r) => r.id });
    return {
      data: fetched.slice(0, decision.rows).map((r) => this.view(r)),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, [decision.next.toString()]),
    };
  }

  private async load(scope: TenantScope, rawId: unknown): Promise<SourceRow> {
    const row = await this.sources.byPublicId(scope, parseSourceId(rawId));
    if (row === null) throw intakeSourceNotFound();
    return row;
  }

  /**
   * `GET /journaling/intake-sources/{id}`: `?reveal=true` needs `journal:manage` (`403`) and an
   * intake domain (`503`); the `journal_intake.address_revealed` audit row commits before the
   * response.
   */
  async get(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    reveal: boolean,
    sourceIp: string | null,
  ): Promise<IntakeSourceDetailView> {
    const row = await this.load(scope, rawId);
    if (reveal) {
      if (!principal.permissions.has(P.manage)) {
        throw new CodedForbiddenException('forbidden', `Missing permission ${P.manage}`);
      }
      if (!this.addresses.available) throw journalIntakeUnavailable();
      await this.runner.run((tx) =>
        this.record(tx, principal, scope, sourceIp, JOURNAL_AUDIT.addressRevealed, row, {
          via: 'detail',
          addressVersion: row.addressVersion,
        }),
      );
    }
    const today = utcDay(this.now());
    const from = new Date(today.getTime() - (COUNTER_DAYS_SHOWN - 1) * DAY_MS);
    const counters = await this.sources.counters(scope, row.id, from);
    return {
      ...this.view(row, reveal),
      counters: counters.map((c): IntakeCountersView => ({
        day: c.day.toISOString().slice(0, 10),
        accepted: c.accepted,
        duplicates: c.duplicates,
        bytes: Number(c.bytes),
        refusedAddress: c.refusedAddress,
        refusedNetwork: c.refusedNetwork,
        refusedTls: c.refusedTls,
        refusedSize: c.refusedSize,
        refusedRate: c.refusedRate,
        refusedUnavailable: c.refusedUnavailable,
        droppedProof: c.droppedProof,
        unwrapFailed: c.unwrapFailed,
      })),
    };
  }

  // ---- rules -------------------------------------------------------------------------------------

  /**
   * D1 entitlement on the writer: features `archiving` and `journal_intake` (`403
   * journal_intake_not_enabled`), archiving enabled with a live default retention policy (`409
   * archiving_not_enabled`).
   */
  private async requireEntitled(tx: Tx, scope: TenantScope): Promise<void> {
    const f = await this.features.effective(
      scope.organizationId,
      [ARCHIVING_FEATURE, JOURNAL_INTAKE_FEATURE],
      tx,
    );
    if (f[ARCHIVING_FEATURE] !== true || f[JOURNAL_INTAKE_FEATURE] !== true) {
      throw journalIntakeNotEnabled();
    }
    const settings = await this.configs.settingsOnWriter(scope, tx);
    if (settings === null || !settings.enabled || settings.defaultRetentionPolicyId === null) {
      throw archivingNotEnabledForIntake();
    }
    const policy = await this.configs.policyById(tx, scope, settings.defaultRetentionPolicyId);
    if (policy === null || policy.deletedAt !== null) throw archivingNotEnabledForIntake();
  }

  /** D1 domain requirement: a TXT-verified domain; provider kinds: one linked to the connection. */
  private async requireDomains(
    tx: Tx,
    scope: TenantScope,
    kind: IntakeKind,
    connectionId: bigint | null,
  ): Promise<void> {
    if ((await this.sources.verifiedDomainCount(scope, tx)) === 0) {
      throw intakeDomainRequired('no_verified_domain');
    }
    if (
      isProviderKind(kind) &&
      connectionId !== null &&
      (await this.sources.linkedVerifiedDomainCount(scope, connectionId, tx)) === 0
    ) {
      throw intakeDomainRequired('no_linked_domain');
    }
  }

  /** The bound connection of a provider kind (`422 journal_intake_connection_invalid`). */
  private async requireConnection(
    tx: Tx,
    scope: TenantScope,
    kind: IntakeKind,
    connectionPublicId: string,
  ): Promise<ConnectionRef> {
    const connection = await this.sources.connectionByPublicId(
      scope,
      connectionPublicId.toLowerCase(),
      tx,
    );
    const issue = connectionIssue(kind, connection);
    if (issue !== null || connection === null) throw intakeConnectionInvalid(issue ?? 'not_found');
    return connection;
  }

  /** The canonical `intake-networks/1` document (`422 journal_intake_networks_invalid`). */
  private async networksDocument(
    tx: Tx,
    cidrs: readonly string[],
  ): Promise<{ v: 1; cidrs: string[] }> {
    const result = validateIntakeNetworks(cidrs, {
      allowPrivate: this.config.APP_ENV === 'local' || this.config.APP_ENV === 'ci',
      providerRanges: await this.sources.providerEgressRanges(tx),
    });
    if (!result.ok) throw intakeNetworksInvalid(result.issues);
    return { v: 1, cidrs: result.cidrs };
  }

  private fieldChecks(
    kind: IntakeKind,
    body: { providerConnectionId?: unknown; networks?: unknown; maxMessageBytes?: number | null },
    mode: 'create' | 'update',
  ): void {
    const issues = sourceFieldIssues(kind, body, mode);
    const size = maxMessageBytesIssue(
      body.maxMessageBytes,
      this.config.JOURNAL_INTAKE_MAX_MESSAGE_BYTES,
    );
    if (size !== null) issues.push(size);
    if (issues.length > 0) throw new BadRequestException(issues);
  }

  private async record(
    tx: Tx,
    principal: Principal,
    scope: TenantScope,
    sourceIp: string | null,
    action: string,
    row: Pick<SourceRow, 'publicId' | 'kind'>,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    await this.audit.record(
      {
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action,
        resourceType: JOURNAL_INTAKE_RESOURCE,
        resourceId: row.publicId,
        sourceIp,
        metadata: { sourceId: row.publicId, kind: row.kind, ...metadata },
      },
      tx,
    );
  }

  private async reload(tx: Tx, scope: TenantScope, publicId: string): Promise<SourceRow> {
    const row = await this.sources.byPublicId(scope, publicId, tx);
    if (row === null) throw intakeSourceNotFound();
    return row;
  }

  // ---- mutations ---------------------------------------------------------------------------------

  /** `POST /journaling/intake-sources` (keyed; address shown once, ADR-0057). */
  async create(
    principal: Principal,
    scope: TenantScope,
    input: { idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<CreatedIntakeSourceView>> {
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body: CreateIntakeSourceBody = parseBody(CreateIntakeSourceBodySchema, input.body);
    this.fieldChecks(body.kind, body, 'create');
    if (!this.addresses.available) throw journalIntakeUnavailable();
    const operation = JOURNAL_OPERATIONS.sourceCreate;
    const live: { address: string | null; headerToken: string | null } = {
      address: null,
      headerToken: null,
    };
    const result = await this.idempotency.execute<CreatedIntakeSourceView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: '-',
        fingerprint: requestFingerprint({ operation, resourceId: '-', body }),
      },
      async (tx) => {
        live.address = null;
        live.headerToken = null;
        await this.limits.lockOrganization(tx, scope.organizationId);
        await this.requireEntitled(tx, scope);
        const max = this.config.JOURNAL_INTAKE_MAX_SOURCES_PER_ORG;
        if ((await this.sources.countLive(tx, scope)) >= max) throw intakeSourceLimit(max);
        if (await this.sources.nameTaken(tx, scope, body.displayName)) {
          throw intakeSourceNameTaken();
        }
        const connection =
          body.providerConnectionId === undefined
            ? null
            : await this.requireConnection(tx, scope, body.kind, body.providerConnectionId);
        await this.requireDomains(tx, scope, body.kind, connection?.id ?? null);
        const networks =
          body.networks === undefined ? null : await this.networksDocument(tx, body.networks);
        const publicId = uuidv7();
        const credentials = this.addresses.derive(
          publicId,
          1,
          body.kind === 'google_workspace_copy',
        );
        try {
          await this.sources.create(tx, scope, {
            publicId,
            kind: body.kind,
            displayName: body.displayName,
            providerConnectionId: connection?.id ?? null,
            networks,
            requireTls: body.requireTls ?? true,
            clientCertFingerprints:
              body.clientCertFingerprints === undefined || body.clientCertFingerprints.length === 0
                ? null
                : [...new Set(body.clientCertFingerprints)],
            maxMessageBytes: body.maxMessageBytes ?? null,
            silenceAlertMinutes:
              body.silenceAlertMinutes === undefined ? 240 : body.silenceAlertMinutes,
            addressHash: credentials.addressHash,
            headerTokenHash: credentials.headerTokenHash,
            createdByUserId: principalUserId(principal),
          });
        } catch (error) {
          if (isNameConflict(error)) throw intakeSourceNameTaken();
          throw error;
        }
        const row = await this.reload(tx, scope, publicId);
        await this.record(tx, principal, scope, sourceIp, JOURNAL_AUDIT.sourceCreated, row, {
          ...(connection !== null && { providerConnectionId: connection.publicId }),
          networkCount: networks?.cidrs.length ?? 0,
          requireTls: row.requireTls,
          addressVersion: 1,
        });
        live.address = credentials.address;
        live.headerToken = credentials.headerToken;
        // ADR-0057: the stored response never holds the clear address or token.
        return {
          statusCode: 201,
          body: { source: this.view(row), address: null, headerToken: null },
        };
      },
      { timeoutMs: JOURNAL_TX_TIMEOUT_MS },
    );
    if (result.replayed) return result;
    return { ...result, body: { ...result.body, ...live } };
  }

  /** `PATCH /journaling/intake-sources/{id}` (keyed, CAS). */
  async update(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<IntakeSourceView>> {
    const publicId = parseSourceId(input.id);
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body: UpdateIntakeSourceBody = parseBody(UpdateIntakeSourceBodySchema, input.body);
    const operation = JOURNAL_OPERATIONS.sourceUpdate;
    return this.idempotency.execute<IntakeSourceView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({ operation, resourceId: publicId, body }),
      },
      async (tx) => {
        const row = await this.sources.lock(tx, scope, publicId);
        if (row === null) throw intakeSourceNotFound();
        if (row.rowVersion !== body.expectedRowVersion) throw intakeSourceConflict(row.rowVersion);
        if (row.status === 'disabled') throw intakeSourceDisabled();
        this.fieldChecks(row.kind, body, 'update');
        const data: SourceUpdate = {};
        const changed: string[] = [];
        if (body.displayName !== undefined && body.displayName !== row.displayName) {
          if (await this.sources.nameTaken(tx, scope, body.displayName, row.id)) {
            throw intakeSourceNameTaken();
          }
          data.displayName = body.displayName;
          changed.push('displayName');
        }
        if (body.networks !== undefined) {
          const doc = await this.networksDocument(tx, body.networks);
          if (JSON.stringify(doc.cidrs) !== JSON.stringify(networksOf(row.networks))) {
            data.networks = doc;
            changed.push('networks');
          }
        }
        if (body.requireTls !== undefined && body.requireTls !== row.requireTls) {
          data.requireTls = body.requireTls;
          changed.push('requireTls');
        }
        if (body.clientCertFingerprints !== undefined) {
          const next = [...new Set(body.clientCertFingerprints)];
          if (JSON.stringify(next) !== JSON.stringify(stringList(row.clientCertFingerprints))) {
            data.clientCertFingerprints = next.length === 0 ? null : next;
            changed.push('clientCertFingerprints');
          }
        }
        if (body.maxMessageBytes !== undefined && body.maxMessageBytes !== row.maxMessageBytes) {
          data.maxMessageBytes = body.maxMessageBytes;
          changed.push('maxMessageBytes');
        }
        if (
          body.silenceAlertMinutes !== undefined &&
          body.silenceAlertMinutes !== row.silenceAlertMinutes
        ) {
          data.silenceAlertMinutes = body.silenceAlertMinutes;
          changed.push('silenceAlertMinutes');
        }
        let action: string = JOURNAL_AUDIT.sourceUpdated;
        if (body.status === 'paused' && row.status !== 'paused') {
          data.status = 'paused';
          changed.push('status');
          action = JOURNAL_AUDIT.sourcePaused;
        } else if (body.status === 'active' && row.status === 'paused') {
          // D1: resuming needs the same entitlement and domains as creating.
          await this.requireEntitled(tx, scope);
          await this.requireDomains(tx, scope, row.kind, row.providerConnectionId);
          if (row.providerConnectionId !== null) {
            const connection = await this.sources.connectionById(
              scope,
              row.providerConnectionId,
              tx,
            );
            const issue = connectionIssue(row.kind, connection);
            if (issue !== null) throw intakeConnectionInvalid(issue);
          }
          data.status = resumedStatus(row.verifiedAt);
          changed.push('status');
          action = JOURNAL_AUDIT.sourceResumed;
        }
        if (changed.length === 0) return { statusCode: 200, body: this.view(row) };
        try {
          if (!(await this.sources.update(tx, scope, row.id, row.rowVersion, data))) {
            throw intakeSourceConflict(row.rowVersion);
          }
        } catch (error) {
          if (isNameConflict(error)) throw intakeSourceNameTaken();
          throw error;
        }
        const after = await this.reload(tx, scope, publicId);
        await this.record(tx, principal, scope, sourceIp, action, after, {
          changedPaths: changed,
          ...(data.status !== undefined && { from: row.status, to: data.status }),
          rowVersion: after.rowVersion,
        });
        return { statusCode: 200, body: this.view(after) };
      },
      { timeoutMs: JOURNAL_TX_TIMEOUT_MS },
    );
  }

  /** `DELETE /journaling/intake-sources/{id}`: `disabled` (terminal; repeat = no change). */
  async disable(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    sourceIp: string | null,
  ): Promise<IntakeSourceView> {
    const publicId = parseSourceId(rawId);
    return this.runner.run(
      async (tx) => {
        const row = await this.sources.lock(tx, scope, publicId);
        if (row === null) throw intakeSourceNotFound();
        if (row.status === 'disabled') return this.view(row);
        const now = this.now();
        const ok = await this.sources.update(tx, scope, row.id, row.rowVersion, {
          status: 'disabled',
          disabledAt: now,
          disabledByUserId: principalUserId(principal),
        });
        if (!ok) throw intakeSourceConflict(row.rowVersion);
        const after = await this.reload(tx, scope, publicId);
        await this.record(tx, principal, scope, sourceIp, JOURNAL_AUDIT.sourceDisabled, after, {
          from: row.status,
          rowVersion: after.rowVersion,
        });
        return this.view(after);
      },
      { timeoutMs: JOURNAL_TX_TIMEOUT_MS },
    );
  }

  /**
   * `POST /journaling/intake-sources/{id}/rotate-address` (keyed, D1): `address_version + 1`; the
   * current hashes stay valid as `previous_*` until now + JOURNAL_INTAKE_ROTATION_OVERLAP_DAYS
   * (none with 0 days). The new address and token are shown once (ADR-0057).
   */
  async rotate(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<CreatedIntakeSourceView>> {
    const publicId = parseSourceId(input.id);
    const key = parseIdempotencyKey(input.idempotencyKey);
    if (!this.addresses.available) throw journalIntakeUnavailable();
    const operation = JOURNAL_OPERATIONS.rotateAddress;
    const live: { address: string | null; headerToken: string | null } = {
      address: null,
      headerToken: null,
    };
    const result = await this.idempotency.execute<CreatedIntakeSourceView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({ operation, resourceId: publicId, body: {} }),
      },
      async (tx) => {
        live.address = null;
        live.headerToken = null;
        const row = await this.sources.lock(tx, scope, publicId);
        if (row === null) throw intakeSourceNotFound();
        if (row.status === 'disabled') throw intakeSourceDisabled();
        const google = row.kind === 'google_workspace_copy';
        const version = row.addressVersion + 1;
        const current = this.addresses.derive(row.publicId, row.addressVersion, google);
        const next = this.addresses.derive(row.publicId, version, google);
        const days = this.config.JOURNAL_INTAKE_ROTATION_OVERLAP_DAYS;
        const now = this.now();
        const overlap = days > 0;
        const ok = await this.sources.update(tx, scope, row.id, row.rowVersion, {
          addressVersion: version,
          addressHash: next.addressHash,
          headerTokenHash: next.headerTokenHash,
          previousAddressHash: overlap ? current.addressHash : null,
          previousHeaderTokenHash: overlap ? current.headerTokenHash : null,
          previousValidUntil: overlap ? new Date(now.getTime() + days * DAY_MS) : null,
        });
        if (!ok) throw intakeSourceConflict(row.rowVersion);
        const after = await this.reload(tx, scope, publicId);
        await this.record(tx, principal, scope, sourceIp, JOURNAL_AUDIT.addressRotated, after, {
          fromVersion: row.addressVersion,
          toVersion: version,
          overlapDays: days,
          ...(overlap && { previousValidUntil: after.previousValidUntil?.toISOString() }),
        });
        live.address = next.address;
        live.headerToken = next.headerToken;
        return {
          statusCode: 200,
          body: { source: this.view(after), address: null, headerToken: null },
        };
      },
      { timeoutMs: JOURNAL_TX_TIMEOUT_MS },
    );
    if (result.replayed) return result;
    return { ...result, body: { ...result.body, ...live } };
  }

  /** `POST /journaling/intake-sources/{id}/attestations` (D10; ≤ 32 kept). */
  async attest(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    rawBody: unknown,
    sourceIp: string | null,
  ): Promise<AttestationsView> {
    const publicId = parseSourceId(rawId);
    const body: AttestationBody = parseBody(AttestationBodySchema, rawBody);
    return this.runner.run(
      async (tx) => {
        const row = await this.sources.lock(tx, scope, publicId);
        if (row === null) throw intakeSourceNotFound();
        if (row.status === 'disabled') throw intakeSourceDisabled();
        if (!intakeAttestationByCode(row.kind, body.code)) throw intakeAttestationUnknown();
        const items = attestationsOf(row.attestations).filter((a) => a.code !== body.code);
        if (body.attested) {
          items.push({
            code: body.code,
            userId: principalPublicId(principal),
            at: this.now().toISOString(),
          });
        }
        const kept = items.slice(-MAX_INTAKE_ATTESTATIONS);
        const ok = await this.sources.update(tx, scope, row.id, row.rowVersion, {
          attestations: { schema: INTAKE_ATTESTATIONS_SCHEMA, items: kept },
        });
        if (!ok) throw intakeSourceConflict(row.rowVersion);
        await this.record(tx, principal, scope, sourceIp, JOURNAL_AUDIT.attested, row, {
          attestation: body.code,
          attested: body.attested,
        });
        return { sourceId: row.publicId, attestations: kept, rowVersion: row.rowVersion + 1 };
      },
      { timeoutMs: JOURNAL_TX_TIMEOUT_MS },
    );
  }

  /** `GET /journaling/intake-sources/{id}/wizard` (D10), from replica rows. */
  async wizard(scope: TenantScope, rawId: unknown): Promise<IntakeWizardView> {
    const row = await this.load(scope, rawId);
    const [features, settings, verifiedDomains, connection] = await Promise.all([
      this.features.effective(scope.organizationId, [ARCHIVING_FEATURE, JOURNAL_INTAKE_FEATURE]),
      this.configs.settings(scope),
      this.sources.verifiedDomainCount(scope),
      row.providerConnectionId === null
        ? Promise.resolve(null)
        : this.sources.connectionById(scope, row.providerConnectionId),
    ]);
    const linked =
      row.providerConnectionId === null
        ? 0
        : await this.sources.linkedVerifiedDomainCount(scope, row.providerConnectionId);
    const state = computeIntakeWizard({
      kind: row.kind,
      sourceStatus: row.status,
      archiving: {
        entitled: features[ARCHIVING_FEATURE] === true,
        intakeEntitled: features[JOURNAL_INTAKE_FEATURE] === true,
        enabled: settings?.enabled ?? false,
        defaultRetention: settings?.defaultRetentionPolicyPublicId != null,
      },
      verifiedDomains,
      linkedVerifiedDomains: linked,
      connection:
        connection === null
          ? null
          : {
              status: connection.status,
              bound: connection.activeTenantKey !== null && connection.externalTenantId !== null,
            },
      attestations: attestationsOf(row.attestations).map((a) => a.code),
      verified: row.verifiedAt !== null,
      health: row.healthStatus,
    });
    return { sourceId: row.publicId, kind: row.kind, ...state };
  }

  /** The guide inputs of a source (the guide service renders them). */
  async guideFacts(scope: TenantScope, rawId: unknown) {
    const row = await this.load(scope, rawId);
    const connection =
      row.providerConnectionId === null
        ? null
        : await this.sources.connectionById(scope, row.providerConnectionId);
    const domains = await this.sources.verifiedDomainNames(
      scope,
      isProviderKind(row.kind) ? row.providerConnectionId : null,
    );
    return {
      row,
      connection,
      domains,
      networks: networksOf(row.networks) ?? [],
      attestations: attestationsOf(row.attestations),
    };
  }

  /** Commits a reveal audit row (the guide of a `journal:manage` holder shows the address). */
  async recordReveal(
    principal: Principal,
    scope: TenantScope,
    row: SourceRow,
    via: string,
    sourceIp: string | null,
  ): Promise<void> {
    await this.runner.run((tx) =>
      this.record(tx, principal, scope, sourceIp, JOURNAL_AUDIT.addressRevealed, row, {
        via,
        addressVersion: row.addressVersion,
      }),
    );
  }
}
