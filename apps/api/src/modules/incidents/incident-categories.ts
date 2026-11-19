import { type AtoStore, atoIncidentHandler, ruleTitle } from '@email-gateway/ato-detection';
import type { Prisma } from '@email-gateway/database';
import type { SecurityIncidentSeverity } from '@email-gateway/security-contracts';
import {
  type IncidentActor,
  type IncidentCategoryHandler,
  IncidentCategoryRegistry,
  type IncidentReportSection,
  type IncidentRow,
  type IncidentStore,
  type ResolvedSubject,
} from '@email-gateway/security-incidents';
import type { CodedHttpException } from '../../http/coded-exception';
import { isAtoStoreError } from '@email-gateway/ato-detection';
import { atoNotEnabled, mapAtoStoreError } from '../ato/ato.errors';

type Db = Prisma.TransactionClient;

/** What a category handler needs from the api (lazy: the ATO store needs the incident store). */
export interface IncidentHandlerDeps {
  ato: () => AtoStore;
  /** `API_ATO_REPORT_MAX_ITEMS`. */
  reportMaxItems: number;
}

/**
 * One incident category as the api serves it (D24): the library handler, the plan feature that
 * gates it (D17: off → its incidents are invisible and its mutations answer the category's
 * `403`), and how list items display the subject (masked per ADR-0062 where it is a recipient;
 * for ATO the account's own address, connector name or user display name).
 */
export interface IncidentCategoryDefinition {
  readonly category: string;
  handler(deps: IncidentHandlerDeps): IncidentCategoryHandler;
  /** `organization_features.feature_key` that must be enabled (null = always on). */
  readonly featureKey: string | null;
  /** The category's answer to a mutation while its feature is off. */
  notEnabled(): CodedHttpException;
  /** Display strings of subjects by `subject_ref_id` (bounded batch; replica or writer). */
  subjectDisplays(
    db: Db,
    organizationId: bigint,
    refIds: readonly bigint[],
  ): Promise<Map<bigint, string | null>>;
  /**
   * Opens a manual incident for a resolved subject (`POST /incidents`, D12) in the caller's
   * transaction, with the category's own detail rows.
   */
  openManual(
    stores: { ato: AtoStore; incidents: IncidentStore },
    tx: Db,
    input: {
      organizationId: bigint;
      subjectType: string;
      subject: ResolvedSubject;
      severity: SecurityIncidentSeverity;
      note: string;
      actor: IncidentActor;
      sourceIp: string | null;
    },
  ): Promise<IncidentRow>;
  /** Throws the coded answer of a category library error (a no-op for any other error). */
  mapError?(error: unknown): void;
  /** The category's report sections as served (internal ids replaced by public ids). */
  augmentReport?(
    db: Db,
    incident: IncidentRow,
    sections: IncidentReportSection[],
  ): Promise<IncidentReportSection[]>;
  /** Extra detail of reads (rendered texts, summaries) over the handler's `loadDetail`. */
  augmentDetail?(
    db: Db,
    incident: IncidentRow,
    detail: Record<string, unknown>,
  ): Promise<Record<string, unknown>>;
}

/** The ATO category (step 8.4): subject `ato_account`, feature `ato_detection`. */
/**
 * The ATO handler's account view names the user and connector by internal id; the api answers
 * public ids only (§5): replace them (`userId` → the user's public id, `connectorId` → the
 * connector's public id; null when not found in the organization).
 */
async function publicAccount(db: Db, organizationId: bigint, account: unknown): Promise<unknown> {
  if (account === null || typeof account !== 'object') return account;
  const a = account as Record<string, unknown>;
  const asId = (v: unknown): bigint | null =>
    typeof v === 'string' && /^[1-9]\d{0,19}$/.test(v) ? BigInt(v) : null;
  const userId = asId(a.userId);
  const connectorId = asId(a.connectorId);
  const [user, connector] = await Promise.all([
    userId === null
      ? null
      : db.user.findFirst({
          where: { id: userId, organizationId },
          select: { organizationId: true, publicId: true },
        }),
    connectorId === null
      ? null
      : db.smtpConnector.findFirst({
          where: { id: connectorId, organizationId },
          select: { organizationId: true, publicId: true },
        }),
  ]);
  return {
    ...a,
    userId: user && user.organizationId === organizationId ? user.publicId : null,
    connectorId:
      connector && connector.organizationId === organizationId ? connector.publicId : null,
  };
}

const atoCategory: IncidentCategoryDefinition = {
  category: 'account_takeover',
  handler: (deps: IncidentHandlerDeps) =>
    atoIncidentHandler({ store: deps.ato, reportMaxItems: deps.reportMaxItems }),
  featureKey: 'ato_detection',
  notEnabled: atoNotEnabled,
  async subjectDisplays(db: Db, organizationId: bigint, refIds: readonly bigint[]) {
    const out = new Map<bigint, string | null>();
    if (refIds.length === 0) return out;
    const accounts = await db.atoAccount.findMany({
      where: { organizationId, id: { in: [...new Set(refIds)] } },
      select: {
        id: true,
        organizationId: true,
        kind: true,
        address: true,
        userId: true,
        connectorId: true,
      },
    });
    const userIds = accounts.flatMap((a) =>
      a.kind === 'gateway_user' && a.userId ? [a.userId] : [],
    );
    const connectorIds = accounts.flatMap((a) =>
      a.kind === 'smtp_connector' && a.connectorId ? [a.connectorId] : [],
    );
    const [users, connectors] = await Promise.all([
      userIds.length === 0
        ? []
        : db.user.findMany({
            where: { organizationId, id: { in: userIds } },
            select: { id: true, organizationId: true, displayName: true, email: true },
          }),
      connectorIds.length === 0
        ? []
        : db.smtpConnector.findMany({
            where: { organizationId, id: { in: connectorIds } },
            select: { id: true, organizationId: true, name: true },
          }),
    ]);
    for (const a of accounts) {
      if (a.organizationId !== organizationId) continue;
      if (a.kind === 'mailbox') out.set(a.id, a.address);
      else if (a.kind === 'gateway_user') {
        const u = users.find((x) => x.id === a.userId && x.organizationId === organizationId);
        out.set(a.id, u?.displayName ?? a.address ?? null);
      } else {
        const c = connectors.find(
          (x) => x.id === a.connectorId && x.organizationId === organizationId,
        );
        out.set(a.id, c?.name ?? null);
      }
    }
    return out;
  },
  openManual(stores, tx, input) {
    return stores.ato.createManualIncident(tx, {
      organizationId: input.organizationId,
      accountPublicId: input.subject.publicId,
      severity: input.severity,
      note: input.note,
      actor: input.actor,
      sourceIp: input.sourceIp,
    });
  },
  mapError(error) {
    if (isAtoStoreError(error)) mapAtoStoreError(error);
  },
  async augmentReport(db, incident, sections) {
    return Promise.all(
      sections.map(async (section) => {
        if (
          section.id !== 'ato.detection' ||
          section.data === null ||
          typeof section.data !== 'object'
        ) {
          return section;
        }
        const data = section.data as Record<string, unknown>;
        return {
          ...section,
          data: {
            ...data,
            account: await publicAccount(db, incident.organizationId, data.account),
          },
        };
      }),
    );
  },
  async augmentDetail(db, incident, detail) {
    const reason = detail.detectionReason as { contributions?: unknown } | null;
    const lines = Array.isArray(reason?.contributions)
      ? reason.contributions.slice(0, 10).flatMap((c: unknown) => {
          const x = c as { code?: unknown; contribution?: unknown };
          return typeof x.code === 'string'
            ? [`${ruleTitle(x.code)} +${Number(x.contribution ?? 0)}`]
            : [];
        })
      : [];
    const groups = await db.atoResponseAction.groupBy({
      by: ['status'],
      where: { organizationId: incident.organizationId, incidentId: incident.id },
      _count: { _all: true },
    });
    const byStatus: Record<string, number> = {};
    for (const g of groups) byStatus[g.status] = g._count._all;
    return {
      ...detail,
      account: await publicAccount(db, incident.organizationId, detail.account),
      detectionReasonText: lines,
      responses: {
        total: Object.values(byStatus).reduce((a, b) => a + b, 0),
        pendingApproval: byStatus.pending_approval ?? 0,
        byStatus,
      },
    };
  },
};
export const ATO_INCIDENT_CATEGORY: IncidentCategoryDefinition = Object.freeze(atoCategory);

/**
 * The registered categories, in registration order. ATP-4 appends its categories here (D24): the
 * generic routes' `RequireAnyPermission` lists, the service's category filtering and the subject
 * display grow from this list. `registerIncidentCategory` appends one before the incident routes
 * are first loaded (the permission lists are read once, when the controllers are decorated).
 */
const DEFINITIONS: IncidentCategoryDefinition[] = [ATO_INCIDENT_CATEGORY];
let sealed = false;

export function registerIncidentCategory(definition: IncidentCategoryDefinition): void {
  if (sealed) throw new Error('Incident categories are sealed once the incident routes are loaded');
  if (DEFINITIONS.some((d) => d.category === definition.category)) {
    throw new Error(`Incident category ${definition.category} is already registered`);
  }
  DEFINITIONS.push(definition);
}

/** The registered category definitions (seals the list). */
export function incidentCategoryDefinitions(): readonly IncidentCategoryDefinition[] {
  sealed = true;
  return [...DEFINITIONS];
}

/** A registry of every registered category's handler. */
export function buildIncidentRegistry(deps: IncidentHandlerDeps): IncidentCategoryRegistry {
  return new IncidentCategoryRegistry(incidentCategoryDefinitions().map((d) => d.handler(deps)));
}

const unavailable = (): never => {
  throw new Error('permission discovery only');
};

/**
 * The read and manage permissions of every registered category (8.4: exactly `ato:read` and
 * `ato:manage`), for the generic routes' `RequireAnyPermission` lists (D17, D24).
 */
export function incidentPermissionLists(): { read: string[]; manage: string[] } {
  const registry = buildIncidentRegistry({ ato: unavailable, reportMaxItems: 1 });
  return { read: registry.readPermissions(), manage: registry.managePermissions() };
}
