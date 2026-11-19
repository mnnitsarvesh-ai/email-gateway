import { Inject, Injectable } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import { generateProbeToken, probeAddress, probeTokenSha256 } from '@email-gateway/mail-routing';
import { API_CONFIG } from '../../../api-config.token';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../../config';
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
import {
  decimalKey,
  decodeListCursor,
  encodeListCursor,
  listBinding,
} from '../../messages/domain/v1-list';
import {
  CreateValidationBodySchema,
  type CreatedValidationView,
  type ValidationListQuery,
  type ValidationPage,
  type ValidationRunDetailView,
  type ValidationRunView,
} from '../dto/provider-connections.schemas';
import {
  PROVIDER_AUDIT,
  PROVIDER_OPERATIONS,
  PROVIDER_TX_TIMEOUT_MS,
  PROVIDER_VALIDATIONS_RESOURCE,
} from '../provider-connections.constants';
import {
  connectionDisabled,
  connectionNotFound,
  validationRunNotFound,
} from '../provider-connections.errors';
import { ProviderConnectionsRepository } from '../repositories/provider-connections.repository';
import {
  ProviderRunsRepository,
  type ValidationRunDetailRow,
  type ValidationRunRow,
} from '../repositories/provider-runs.repository';
import { parseBody, parsePublicId, principalPublicId, principalType } from './provider-common';
import { ProviderConnectionsService } from './provider-connections.service';

export type ProviderValidationConfig = Pick<
  ApiConfig,
  'PROVIDER_PROBE_DOMAIN' | 'PROVIDER_PROBE_TTL_SECONDS'
>;

const SUMMARY_KEYS = ['pass', 'warn', 'fail', 'skipped', 'error'] as const;

function summaryOf(value: unknown): ValidationRunView['summary'] {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const out = {} as Record<(typeof SUMMARY_KEYS)[number], number>;
  for (const key of SUMMARY_KEYS) {
    const n = record[key];
    out[key] = typeof n === 'number' && Number.isInteger(n) && n >= 0 ? n : 0;
  }
  return out;
}

export function toRunView(row: ValidationRunRow): ValidationRunView {
  return {
    id: row.publicId,
    kind: row.kind,
    status: row.status,
    requestedBy: { type: row.requestedByType, id: row.requestedById },
    probeExpiresAt: row.probeExpiresAt?.toISOString() ?? null,
    summary: summaryOf(row.summary),
    startedAt: row.startedAt?.toISOString() ?? null,
    completedAt: row.completedAt?.toISOString() ?? null,
    createdAt: row.createdAt.toISOString(),
  };
}

const RESULT_STATUSES = new Set(['pass', 'warn', 'fail', 'skipped', 'error']);
const RESULT_SEVERITIES = new Set(['info', 'warning', 'critical']);

/** `provider-validation/1` results as stored by the worker (malformed entries are skipped). */
function resultsOf(value: unknown): ValidationRunDetailView['results'] {
  const list = Array.isArray(value)
    ? value
    : value !== null &&
        typeof value === 'object' &&
        Array.isArray((value as { results?: unknown }).results)
      ? (value as { results: unknown[] }).results
      : [];
  return list.flatMap((entry) => {
    if (entry === null || typeof entry !== 'object') return [];
    const r = entry as Record<string, unknown>;
    if (
      typeof r.code !== 'string' ||
      !RESULT_STATUSES.has(r.status as string) ||
      !RESULT_SEVERITIES.has(r.severity as string)
    ) {
      return [];
    }
    return [
      {
        code: r.code,
        subject: typeof r.subject === 'string' ? r.subject : '',
        status: r.status as ValidationRunDetailView['results'][number]['status'],
        severity: r.severity as ValidationRunDetailView['results'][number]['severity'],
        evidence:
          r.evidence !== null && typeof r.evidence === 'object' && !Array.isArray(r.evidence)
            ? (r.evidence as Record<string, unknown>)
            : {},
        remediation: typeof r.remediation === 'string' ? r.remediation : null,
      },
    ];
  });
}

export function toRunDetailView(row: ValidationRunDetailRow): ValidationRunDetailView {
  return {
    ...toRunView(row),
    results: resultsOf(row.results),
    probeObservations: row.observations.map((o) => ({
      receivedAt: o.receivedAt.toISOString(),
      clientIp: o.clientIp,
      tlsProtocol: o.tlsProtocol,
      envelopeFromDomain: o.envelopeFromDomain,
      headerFromDomain: o.headerFromDomain,
      tenantHeader: o.tenantHeader,
      dkim: o.dkim,
      dkimDomains: Array.isArray(o.dkimDomains)
        ? o.dkimDomains.filter((d): d is string => typeof d === 'string').slice(0, 5)
        : [],
      proofResult: o.proofResult,
      failureCode: o.failureCode,
    })),
  };
}

/**
 * Validation runs of a connection (step 8.2 §5.2 #19–21, D10, ADR-0079): creation (keyed; the
 * integration-worker's `tasks` role claims queued runs), the run list and detail. An
 * `outbound`/`full` run of a connection whose outbound mode is not `off` gets a single-use probe
 * address: shown ONLY in the live response (ADR-0057 redacted replay: the stored response says
 * `probeAddress: null`); only the token's SHA-256 is stored.
 */
@Injectable()
export class ProviderValidationService {
  constructor(
    @Inject(API_CONFIG) private readonly config: ProviderValidationConfig,
    private readonly connections: ProviderConnectionsRepository,
    private readonly runs: ProviderRunsRepository,
    private readonly idempotency: IdempotencyService,
    private readonly base: ProviderConnectionsService,
    private readonly codec: CursorCodec,
  ) {}

  now(): Date {
    return new Date();
  }

  async create(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<CreatedValidationView>> {
    const publicId = parsePublicId(input.id, 'id');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(CreateValidationBodySchema, input.body);
    const live: { probeAddress: string | null } = { probeAddress: null };
    const result = await this.idempotency.execute<CreatedValidationView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation: PROVIDER_OPERATIONS.validationCreate,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({
          operation: PROVIDER_OPERATIONS.validationCreate,
          resourceId: publicId,
          body,
        }),
      },
      async (tx) => {
        live.probeAddress = null;
        const aggregate = await this.connections.lock(tx, scope, publicId);
        if (!aggregate) throw connectionNotFound();
        const c = aggregate.connection;
        if (c.status === 'disabled') throw connectionDisabled();
        const now = this.now();
        const probe =
          (body.kind === 'full' || body.kind === 'outbound') && c.outboundMode !== 'off'
            ? generateProbeToken()
            : null;
        const run = await this.runs.insertRun(tx, scope, {
          publicId: uuidv7(now.getTime()),
          connectionId: c.id,
          kind: body.kind,
          requestedByType: principalType(principal),
          requestedById: principalPublicId(principal),
          probeTokenSha256: probe === null ? null : probeTokenSha256(probe),
          probeExpiresAt:
            probe === null
              ? null
              : new Date(now.getTime() + this.config.PROVIDER_PROBE_TTL_SECONDS * 1000),
        });
        await this.base.record(tx, principal, scope, sourceIp, {
          action: PROVIDER_AUDIT.validationRequested,
          connectionPublicId: c.publicId,
          metadata: { runId: run.publicId, kind: body.kind, probe: probe !== null },
        });
        if (probe !== null)
          live.probeAddress = probeAddress(probe, this.config.PROVIDER_PROBE_DOMAIN);
        return { statusCode: 201, body: { ...toRunView(run), probeAddress: null } };
      },
      { timeoutMs: PROVIDER_TX_TIMEOUT_MS },
    );
    if (result.replayed || live.probeAddress === null) return result;
    return { ...result, body: { ...result.body, probeAddress: live.probeAddress } };
  }

  async list(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    query: ValidationListQuery,
  ): Promise<ValidationPage> {
    const aggregate = await this.base.load(scope, rawId);
    const binding = listBinding({
      resource: PROVIDER_VALIDATIONS_RESOURCE,
      principal,
      // The cursor is bound to the connection too (a cursor of another connection is refused).
      filters: { ...query.filters, connection: { values: [aggregate.connection.publicId] } },
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 1);
    const fetched = await this.runs.listRuns(scope, aggregate.connection.id, {
      take: query.limit + 1,
      ...(decoded && { beforeId: decimalKey(decoded.keys[0]) }),
      ...(query.filters.kind?.values && { kinds: query.filters.kind.values }),
      ...(query.filters.status?.values && { statuses: query.filters.status.values }),
    });
    const decision = decideKeysetPage({ fetched, limit: query.limit, keyOf: (r) => r.id });
    return {
      data: fetched.slice(0, decision.rows).map(toRunView),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, [decision.next.toString()]),
    };
  }

  async get(
    scope: TenantScope,
    rawId: unknown,
    rawRunId: unknown,
  ): Promise<ValidationRunDetailView> {
    const runId = parsePublicId(rawRunId, 'runId');
    const aggregate = await this.base.load(scope, rawId);
    const row = await this.runs.findRun(scope, aggregate.connection.id, runId);
    if (!row) throw validationRunNotFound();
    return toRunDetailView(row);
  }
}
