/**
 * `AtoStore` (step 8.4 §4.4, D8–D14, D21, D22): the transactional store of the ATO tables, used by
 * the ato-worker and the api so both write identical rows. Every method takes the caller's Prisma
 * transaction client first and never opens or retries a transaction; incidents are written through
 * the shared `IncidentStore` (category `account_takeover`, detail in `ato_incident_details`).
 * Writes run on the writer; decisions are made under the account row lock (`lockAccounts`, ascending
 * ids) or the action/incident row lock.
 */
import { uuidv7 } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import type {
  AtoAccount,
  AtoResponseAction,
  AtoRiskSignal,
  AtoSmtpRestriction,
} from '@email-gateway/database';
import { EventTypes } from '@email-gateway/event-contracts';
import {
  atoMailboxSha256,
  atoRiskLevelRank,
  atoSubjectHash,
  normalizeAtoMailboxAddress,
  type AtoAccountKind,
  type AtoRiskLevel,
  type SecurityIncidentSeverity,
} from '@email-gateway/security-contracts';
import {
  insertRegisteredOutboxRow,
  isActiveIncident,
  securityIncidentSeverityRank,
  writeAuditRow,
  type IncidentActor,
  type IncidentRow,
  type IncidentStore,
  type LibraryAuditEntry,
} from '@email-gateway/security-incidents';
import {
  applyActivityDelta,
  emptyActivityDay,
  utcDayStart,
  type ActivityDayRow,
  type ActivityDelta,
} from '../baseline';
import { assertEvidenceSafe } from '../explain';
import { restrictionSubjectHash } from '../keys';
import { parseCidr } from '../net';
import {
  AUTOMATABLE_ACTION_TYPES,
  automationDecision,
  COMPLETED_RESPONSE_STATUSES,
  impactFor,
  isResponseActionType,
  RESPONSE_CATALOGUE,
  recommendResponses,
  responseDedupeHash,
  supportsRollback,
  type AutomationGuardReason,
  type Contributor,
  type Recommendation,
  type ResponseActionType,
  type ResponseTarget,
} from '../responses';
import type { GeoView, SignalCandidate, TrustedContextView } from '../rules/types';
import {
  scoreAccount,
  scoreExplanation,
  DECAY_HALF_LIVES,
  type ScoreResult,
  type ScoreSignal,
} from '../scoring';
import {
  atoSettingsSchema,
  canonicalSettingsJson,
  isLearning,
  normalizeAtoSettings,
  resolveAtoSettings,
  settingsDiffPaths,
  settingsSha256,
  type ResolvedAtoSettings,
} from '../settings';
import type { ResponseStatus, ScoreTrigger } from '../taxonomy';
import { ATO_RULES_VERSION, ATO_SCORER_VERSION } from '../versions';
import { AtoStoreError } from './errors';

export * from './errors';

type Tx = Prisma.TransactionClient;

/**
 * Isolation level of every transaction that calls the store (worker, api, maintenance). The store
 * locks a row with `SELECT … FOR UPDATE` and then reads it (and the signals, actions and counts it
 * decides on) with ordinary reads: under READ COMMITTED each ordinary read sees the latest committed
 * data, i.e. what the transaction that held the lock committed. Under REPEATABLE READ it would see
 * the transaction's first snapshot (taken before the lock was granted) and lose updates. The server
 * default is READ-COMMITTED (ADR-0004); callers pin it anyway so a writer configured otherwise (a
 * managed MySQL defaults to REPEATABLE READ) cannot corrupt baselines, scores or dedupe.
 */
export const ATO_TRANSACTION_ISOLATION = Prisma.TransactionIsolationLevel.ReadCommitted;

export const ATO_INCIDENT_CATEGORY = 'account_takeover' as const;
export const ATO_INCIDENT_SUBJECT_TYPE = 'ato_account' as const;

export interface AtoStoreConfig {
  approvalTtlHours: number;
  automatedResponsesEnabled: boolean;
  maxAutomatedPerOrgPerHour: number;
  maxActiveRestrictionsPerOrg: number;
}

export interface AtoStoreOptions {
  now?: () => Date;
  incidents: IncidentStore;
  config: AtoStoreConfig;
}

export interface LoadedSettings {
  settings: ResolvedAtoSettings;
  stored: unknown;
  version: number;
  rowVersion: number;
  invalid: boolean;
  learningStartedAt: Date;
  learning: boolean;
}

export type AccountSubject =
  | { kind: 'mailbox'; address: string }
  | { kind: 'gateway_user'; userId: bigint; address?: string | null }
  | { kind: 'smtp_connector'; connectorId: bigint };

export interface AuthEventInput {
  organizationId: bigint;
  accountId: bigint | null;
  source: 'portal_login' | 'portal_mfa' | 'smtp_auth' | 'idp_sign_in';
  channel: 'portal' | 'api' | 'smtp' | 'idp';
  outcome:
    | 'success'
    | 'failure'
    | 'locked'
    | 'mfa_required'
    | 'mfa_failure'
    | 'rate_limited'
    | 'throttled'
    | 'blocked';
  failureCode: string | null;
  occurredAt: Date;
  ip: string | null;
  ipPrefix: string | null;
  geo: GeoView | null;
  reputation: unknown;
  device: { hash: string; label: string } | null;
  mechanism: string | null;
  sourceRef: string | null;
  /** 64 hex. Duplicates of a non-aggregated event are ignored. */
  dedupeKey: string;
  /** Aggregate (successful SMTP AUTH per connector/IP/hour): duplicates add to `attempt_count`. */
  aggregate?: boolean;
  /**
   * Actual time of the attempt when `occurredAt` is an aggregate bucket start (hour of a successful
   * SMTP AUTH); default `occurredAt`. Stored in `last_occurred_at` (moves forward only).
   */
  lastOccurredAt?: Date;
}

export interface RescoreResult {
  result: ScoreResult;
  previousScore: number;
  previousLevel: AtoRiskLevel;
  changed: boolean;
  levelChanged: boolean;
  rowWritten: boolean;
  overrideContradicted: boolean;
}

export interface IncidentPolicyContext {
  hasAtoPolicyRule: boolean;
  /** Provider action types the account's adapter supports. */
  providerActions: ReadonlySet<string>;
  /** Contributors' client IPs (connector + IP block recommendations). */
  contributorIps?: ReadonlyMap<string, string>;
}

export interface IncidentPolicyResult {
  incident: IncidentRow | null;
  opened: boolean;
  escalated: boolean;
  recommendations: Recommendation[];
  contributors: Contributor[];
  /** Why no incident was opened (null when one exists or was opened). */
  skipped: 'below_threshold' | 'benign_override' | 'cooldown' | null;
}

export interface EvidenceRefs {
  signals: readonly { id: bigint; detectedAt: Date }[];
  authEvents: readonly { id: bigint; occurredAt: Date }[];
  messages: readonly { id: bigint; receivedAt: Date }[];
  codes: readonly string[];
}

export interface RequestResponseInput {
  organizationId: bigint;
  accountId: bigint;
  incidentId: bigint | null;
  actionType: ResponseActionType;
  target: ResponseTarget;
  params?: Record<string, string | number | boolean>;
  actor: IncidentActor;
  reason?: string | null;
  authorization: 'manual' | 'automation_policy' | 'low_impact_default';
  /** Provider kind of the account's integration (provider actions); null when none. */
  providerKind?: string | null;
  /** Automation guard reason recorded on an action that needs approval. */
  guardReason?: AutomationGuardReason | null;
  sourceIp?: string | null;
}

export interface NotificationInput {
  organizationId: bigint;
  kind: 'incident_alert' | 'approval_requested' | 'response_failed' | 'digest';
  audience: 'tenant' | 'soc' | 'platform_soc';
  severity: SecurityIncidentSeverity | null;
  refs: { incidentPublicId?: string; actionPublicId?: string; accountPublicId?: string };
  /** Throttle window: kind (`notification_alert_windows.kind`), scope and length. */
  throttle: { kind: string; scope: string; minutes: number; windowStart?: Date };
  counts?: {
    incidents?: number;
    criticalIncidents?: number;
    pendingApprovals?: number;
    restrictedAccounts?: number;
  };
  digestPeriod?: 'daily' | 'weekly' | null;
}

const LEVEL_TO_SEVERITY: Readonly<Record<AtoRiskLevel, SecurityIncidentSeverity>> = {
  low: 'low',
  medium: 'medium',
  high: 'high',
  critical: 'critical',
};

const MAX_REASON_CODES = 16;
const SIGNAL_LOOKBACK_EXTRA_MS = 30 * 86_400_000;
/** Bound of `recentSignals` (the newest signals are kept when an account has more). */
export const RECENT_SIGNALS_LIMIT = 5000;

const json = (value: unknown): Prisma.InputJsonValue =>
  JSON.parse(
    JSON.stringify(value, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString(10) : v)),
  ) as Prisma.InputJsonValue;

/** Prisma unique violation (P2002) or the raw MySQL duplicate-key error (P2010 / 1062). */
const isUniqueViolation = (error: unknown): boolean =>
  error instanceof Prisma.PrismaClientKnownRequestError &&
  (error.code === 'P2002' ||
    (error.code === 'P2010' && (error.meta as { code?: unknown } | undefined)?.code === '1062'));

const clip = (value: string | null | undefined, max: number): string | null =>
  value === null || value === undefined ? null : value.slice(0, max);

export class AtoStore {
  readonly incidents: IncidentStore;
  readonly config: AtoStoreConfig;
  private readonly clock: () => Date;

  constructor(options: AtoStoreOptions) {
    this.incidents = options.incidents;
    this.config = options.config;
    this.clock = options.now ?? (() => new Date());
  }

  now(): Date {
    return this.clock();
  }

  // =================================================================== settings

  private toLoaded(row: {
    settings: Prisma.JsonValue;
    version: number;
    rowVersion: number;
    learningStartedAt: Date;
  }): LoadedSettings {
    const { settings, invalid } = resolveAtoSettings(row.settings);
    return {
      settings,
      stored: row.settings,
      version: row.version,
      rowVersion: row.rowVersion,
      invalid,
      learningStartedAt: row.learningStartedAt,
      learning: isLearning(settings, row.learningStartedAt, this.clock()),
    };
  }

  /** The organization's settings, or null when no row exists yet. */
  async loadSettings(tx: Tx, organizationId: bigint): Promise<LoadedSettings | null> {
    const row = await tx.atoSetting.findUnique({ where: { organizationId } });
    return row ? this.toLoaded(row) : null;
  }

  /**
   * The settings row, created with the defaults (`{ mode: 'monitor' }`, version 1, learning from
   * now) when missing (first event after the operator enabled the feature, PO1).
   */
  async ensureSettings(tx: Tx, organizationId: bigint): Promise<LoadedSettings> {
    const existing = await this.loadSettings(tx, organizationId);
    if (existing) return existing;
    const stored = normalizeAtoSettings({});
    const sha = settingsSha256(stored);
    const at = this.clock();
    try {
      await tx.atoSetting.create({
        data: {
          organizationId,
          settings: json(stored),
          settingsSha256: sha,
          version: 1,
          learningStartedAt: at,
        },
      });
      await tx.atoSettingsVersion.create({
        data: { organizationId, version: 1, settings: json(stored), settingsSha256: sha },
      });
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
    }
    const row = await tx.atoSetting.findUniqueOrThrow({ where: { organizationId } });
    return this.toLoaded(row);
  }

  /**
   * Saves settings (§4.3): strict validation with the cross-field rules, normalized storage,
   * compare-and-set on `row_version`, a new `version` with its `ato_settings_versions` row and an
   * audit row with the changed paths. Unchanged settings are a no-op.
   */
  async saveSettings(
    tx: Tx,
    input: {
      organizationId: bigint;
      settings: unknown;
      expectedRowVersion: number;
      actor: IncidentActor;
      sourceIp?: string | null;
    },
  ): Promise<LoadedSettings> {
    const parsed = atoSettingsSchema.safeParse(input.settings);
    if (!parsed.success) {
      throw new AtoStoreError('ato_settings_invalid', 'Invalid ATO settings', {
        issues: parsed.error.issues.map((i) => ({
          path: i.path.map(String).join('.'),
          message: i.message,
        })),
      });
    }
    const current = await this.ensureSettings(tx, input.organizationId);
    if (current.rowVersion !== input.expectedRowVersion) {
      throw new AtoStoreError('ato_settings_conflict', 'Settings changed by someone else', {
        expected: input.expectedRowVersion,
        actual: current.rowVersion,
      });
    }
    const stored = normalizeAtoSettings(parsed.data);
    const sha = settingsSha256(stored);
    if (canonicalSettingsJson(stored) === canonicalSettingsJson(current.stored)) return current;
    const version = current.version + 1;
    const result = await tx.atoSetting.updateMany({
      where: { organizationId: input.organizationId, rowVersion: input.expectedRowVersion },
      data: {
        settings: json(stored),
        settingsSha256: sha,
        version,
        rowVersion: { increment: 1 },
        updatedByUserId: input.actor.type === 'user' ? (input.actor.userId ?? null) : null,
      },
    });
    if (result.count !== 1) {
      throw new AtoStoreError('ato_settings_conflict', 'Settings changed by someone else');
    }
    await tx.atoSettingsVersion.create({
      data: {
        organizationId: input.organizationId,
        version,
        settings: json(stored),
        settingsSha256: sha,
        createdByUserId: input.actor.type === 'user' ? (input.actor.userId ?? null) : null,
      },
    });
    const next = (await this.loadSettings(tx, input.organizationId))!;
    await this.audit(tx, {
      organizationId: input.organizationId,
      actor: input.actor,
      action: 'ato.settings_updated',
      resourceType: 'ato_settings',
      resourceId: `v${version}`,
      sourceIp: input.sourceIp ?? null,
      metadata: {
        version,
        settingsSha256: sha,
        changedPaths: settingsDiffPaths(current.settings, next.settings).slice(0, 100),
      },
    });
    return next;
  }

  // =================================================================== accounts

  /**
   * The monitored account of a subject (D1), created on first sight; `last_seen_at` moves forward.
   * Concurrency-safe (`INSERT … ON DUPLICATE KEY UPDATE` on the unique subject key).
   */
  async ensureAccount(
    tx: Tx,
    input: { organizationId: bigint; subject: AccountSubject; domainId?: bigint | null; at: Date },
  ): Promise<AtoAccount> {
    const s = input.subject;
    let kind: AtoAccountKind;
    let hash: string;
    let address: string | null = null;
    let userId: bigint | null = null;
    let connectorId: bigint | null = null;
    if (s.kind === 'mailbox') {
      kind = 'mailbox';
      address = normalizeAtoMailboxAddress(s.address);
      hash = atoSubjectHash('mailbox', address);
    } else if (s.kind === 'gateway_user') {
      kind = 'gateway_user';
      userId = s.userId;
      hash = atoSubjectHash('user', s.userId);
      address = s.address ? normalizeAtoMailboxAddress(s.address) : null;
    } else {
      kind = 'smtp_connector';
      connectorId = s.connectorId;
      hash = atoSubjectHash('connector', s.connectorId);
    }
    await tx.$executeRaw`
      INSERT INTO ato_accounts
        (public_id, organization_id, kind, subject_hash, address, domain_id, user_id, connector_id,
         first_seen_at, last_seen_at, updated_at)
      VALUES (${uuidv7(input.at.getTime())}, ${input.organizationId}, ${kind}, ${hash}, ${address},
              ${input.domainId ?? null}, ${userId}, ${connectorId}, ${input.at}, ${input.at},
              ${this.clock()})
      ON DUPLICATE KEY UPDATE
        last_seen_at = GREATEST(last_seen_at, VALUES(last_seen_at)),
        domain_id = COALESCE(domain_id, VALUES(domain_id)),
        address = COALESCE(address, VALUES(address))`;
    const row = await tx.atoAccount.findUnique({
      where: {
        organizationId_kind_subjectHash: {
          organizationId: input.organizationId,
          kind,
          subjectHash: hash,
        },
      },
    });
    if (!row || row.organizationId !== input.organizationId) {
      throw new AtoStoreError('ato_inconsistent_read', 'Account read did not echo the key');
    }
    return row;
  }

  /** Locks accounts of the organization in ascending id order (`FOR UPDATE`). */
  async lockAccounts(
    tx: Tx,
    organizationId: bigint,
    ids: readonly bigint[],
  ): Promise<AtoAccount[]> {
    const sorted = [...new Set(ids)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const out: AtoAccount[] = [];
    for (const id of sorted) {
      const locked = await tx.$queryRaw<{ id: bigint }[]>`
        SELECT id FROM ato_accounts WHERE id = ${id} AND organization_id = ${organizationId} FOR UPDATE`;
      if (locked.length === 0)
        throw new AtoStoreError('ato_account_not_found', 'Account not found');
      out.push(await tx.atoAccount.findUniqueOrThrow({ where: { id } }));
    }
    return out;
  }

  /**
   * Locks the subject account of an incident (`FOR UPDATE`) before the incident row
   * (`IncidentCategoryHandler.lockSubject`); a missing account is not an error here.
   */
  async lockSubjectAccount(tx: Tx, organizationId: bigint, accountId: bigint): Promise<void> {
    await tx.$queryRaw<{ id: bigint }[]>`
      SELECT id FROM ato_accounts WHERE id = ${accountId} AND organization_id = ${organizationId} FOR UPDATE`;
  }

  /** An account of the organization by public id (null for none or another tenant's). */
  async findAccount(tx: Tx, organizationId: bigint, publicId: string): Promise<AtoAccount | null> {
    const row = await tx.atoAccount.findUnique({ where: { publicId } });
    return row && row.organizationId === organizationId ? row : null;
  }

  private async requireAccount(
    tx: Tx,
    organizationId: bigint,
    accountId: bigint,
  ): Promise<AtoAccount> {
    const [row] = await this.lockAccounts(tx, organizationId, [accountId]);
    return row!;
  }

  /** Records the last successful authentication location (fallback of Redis `ato:last`). */
  async recordAuthSuccess(
    tx: Tx,
    input: { organizationId: bigint; accountId: bigint; at: Date; geo: unknown },
  ): Promise<void> {
    await tx.atoAccount.updateMany({
      where: { id: input.accountId, organizationId: input.organizationId },
      data: {
        lastAuthSuccessAt: input.at,
        lastAuthGeo: input.geo === null ? Prisma.DbNull : json(input.geo),
      },
    });
  }

  // =================================================================== auth events and activity

  /**
   * Inserts an `ato_auth_events` row (D7 enrichment, never the attempted e-mail). Duplicates of the
   * same `(organization, dedupe_key, occurred_at)` are ignored, or counted for an aggregate row.
   */
  async recordAuthEvent(
    tx: Tx,
    input: AuthEventInput,
  ): Promise<{ id: bigint; occurredAt: Date; created: boolean }> {
    if (!/^[0-9a-f]{64}$/.test(input.dedupeKey)) {
      throw new AtoStoreError('ato_inconsistent_read', 'dedupeKey must be 64 lower-case hex');
    }
    // Existence is decided by the unique key `(organization_id, dedupe_key, occurred_at)` rather
    // than by the affected-row count of an upsert: the MySQL client reports found rows, so an
    // unchanged duplicate and a fresh insert would both answer 1.
    const existing = await this.findAuthEvent(tx, input);
    if (existing) return this.duplicateAuthEvent(tx, input, existing);
    const g = input.geo;
    try {
      await tx.$executeRaw`
        INSERT INTO ato_auth_events
          (occurred_at, organization_id, account_id, source, channel, outcome, failure_code,
           ip_address, ip_prefix, country_code, region, city, latitude, longitude, accuracy_km,
           geo_status, asn, asn_org, anonymizer_flags, reputation, device_hash, device_label,
           mechanism, attempt_count, last_occurred_at, source_ref, dedupe_key)
        VALUES (${input.occurredAt}, ${input.organizationId}, ${input.accountId}, ${input.source},
                ${input.channel}, ${input.outcome}, ${clip(input.failureCode, 64)}, ${input.ip},
                ${input.ipPrefix}, ${g?.country ?? null}, ${clip(g?.region, 64)}, ${clip(g?.city, 64)},
                ${g?.latitude ?? null}, ${g?.longitude ?? null}, ${g?.accuracyKm ?? null},
                ${g?.status ?? 'unavailable'}, ${g?.asn ?? null}, ${clip(g?.asnOrg, 128)},
                ${g?.anonymizerFlags ?? null},
                ${input.reputation === null || input.reputation === undefined ? null : JSON.stringify(input.reputation)},
                ${input.device?.hash ?? null}, ${clip(input.device?.label, 96)}, ${clip(input.mechanism, 16)},
                1, ${input.lastOccurredAt ?? input.occurredAt}, ${clip(input.sourceRef, 64)},
                ${input.dedupeKey})`;
    } catch (error) {
      // A concurrent insert of the same key (account-less events are not serialized by an
      // account lock): continue on the duplicate path.
      if (!isUniqueViolation(error)) throw error;
      const raced = await this.findAuthEvent(tx, input);
      if (!raced) throw error;
      return this.duplicateAuthEvent(tx, input, raced);
    }
    const row = await this.findAuthEvent(tx, input);
    if (!row) {
      throw new AtoStoreError('ato_inconsistent_read', 'Auth event read did not echo the key');
    }
    return { id: row, occurredAt: input.occurredAt, created: true };
  }

  /** The id of the auth event with the input's unique key (echo-checked organization). */
  private async findAuthEvent(
    tx: Tx,
    input: Pick<AuthEventInput, 'organizationId' | 'dedupeKey' | 'occurredAt'>,
  ): Promise<bigint | null> {
    const rows = await tx.$queryRaw<{ id: bigint; organization_id: bigint }[]>`
      SELECT id, organization_id FROM ato_auth_events
      WHERE organization_id = ${input.organizationId} AND dedupe_key = ${input.dedupeKey}
        AND occurred_at = ${input.occurredAt}`;
    const row = rows[0];
    if (!row) return null;
    if (BigInt(row.organization_id) !== input.organizationId) {
      throw new AtoStoreError('ato_inconsistent_read', 'Auth event read did not echo the key');
    }
    return BigInt(row.id);
  }

  /** A duplicate auth event: ignored, or counted on an aggregate row (successful SMTP AUTH). */
  private async duplicateAuthEvent(
    tx: Tx,
    input: AuthEventInput,
    id: bigint,
  ): Promise<{ id: bigint; occurredAt: Date; created: boolean }> {
    if (input.aggregate === true) {
      await tx.$executeRaw`
        UPDATE ato_auth_events
        SET attempt_count = attempt_count + 1,
            last_occurred_at = GREATEST(last_occurred_at, ${input.lastOccurredAt ?? input.occurredAt})
        WHERE id = ${id} AND occurred_at = ${input.occurredAt}
          AND organization_id = ${input.organizationId}`;
    }
    return { id, occurredAt: input.occurredAt, created: false };
  }

  /** Merges a delta into the account's day row (`ato_account_activity_daily`, bounded lists). */
  async upsertActivityDay(
    tx: Tx,
    input: { organizationId: bigint; accountId: bigint; delta: ActivityDelta },
  ): Promise<ActivityDayRow> {
    const dayStart = utcDayStart(input.delta.at);
    const empty = emptyActivityDay(dayStart);
    // `ON DUPLICATE KEY UPDATE` (not `INSERT IGNORE`): on an existing day row InnoDB then takes an
    // EXCLUSIVE lock at once instead of a shared lock that the `FOR UPDATE` below would have to
    // upgrade, which deadlocked concurrent events of one hot account (step 8.4 WP4 fix).
    await tx.$executeRaw`
      INSERT INTO ato_account_activity_daily
        (day_start, organization_id, account_id, hour_counts, ip_prefixes, recipient_domains,
         attachment_types, peers, content, updated_at)
      VALUES (${dayStart}, ${input.organizationId}, ${input.accountId},
              ${JSON.stringify(empty.hourCounts)}, '[]', '[]', '[]', '[]', '{}', ${this.clock()})
      ON DUPLICATE KEY UPDATE organization_id = organization_id`;
    const locked = await tx.$queryRaw<{ id: bigint }[]>`
      SELECT id FROM ato_account_activity_daily
      WHERE organization_id = ${input.organizationId} AND account_id = ${input.accountId}
        AND day_start = ${dayStart}
      FOR UPDATE`;
    if (locked.length === 0) throw new AtoStoreError('ato_inconsistent_read', 'Day row missing');
    const row = await tx.atoAccountActivityDaily.findUniqueOrThrow({
      where: {
        organizationId_accountId_dayStart: {
          organizationId: input.organizationId,
          accountId: input.accountId,
          dayStart,
        },
      },
    });
    const current = activityFromRow(row);
    const next = applyActivityDelta(current, input.delta);
    await tx.atoAccountActivityDaily.update({
      where: { id_dayStart: { id: row.id, dayStart } },
      data: {
        authSuccess: next.authSuccess,
        authFailure: next.authFailure,
        messages: next.messages,
        recipients: next.recipients,
        externalRecipients: next.externalRecipients,
        internalRecipients: next.internalRecipients,
        attachments: next.attachments,
        findings: next.findings,
        maxHourMessages: next.maxHourMessages,
        hourCounts: json(next.hourCounts),
        ipPrefixes: json(next.ipPrefixes),
        recipientDomains: json(next.recipientDomains),
        attachmentTypes: json(next.attachmentTypes),
        peers: json(next.peers),
        content: json(next.content),
      },
    });
    return next;
  }

  // =================================================================== signals

  /**
   * Persists candidates under the account lock (D8): a candidate whose dedupe key exists within its
   * window increments `occurrences` and `last_occurred_at` of that signal (never a second
   * contribution); otherwise a new signal (`informational` in the learning period) linked to the
   * active incident if any.
   */
  async recordSignals(
    tx: Tx,
    input: {
      organizationId: bigint;
      account: AtoAccount;
      candidates: readonly SignalCandidate[];
      settingsVersion: number;
      at: Date;
    },
  ): Promise<{ created: AtoRiskSignal[]; duplicates: AtoRiskSignal[] }> {
    const created: AtoRiskSignal[] = [];
    const duplicates: AtoRiskSignal[] = [];
    for (const c of input.candidates) {
      assertEvidenceSafe(c.evidence);
      const since = new Date(input.at.getTime() - c.dedupeWindowMinutes * 60_000);
      const existing = await tx.atoRiskSignal.findFirst({
        where: {
          organizationId: input.organizationId,
          accountId: input.account.id,
          dedupeKey: c.dedupeKey,
          detectedAt: { gte: since },
        },
        orderBy: { detectedAt: 'desc' },
      });
      if (existing) {
        const updated = await tx.atoRiskSignal.update({
          where: { id_detectedAt: { id: existing.id, detectedAt: existing.detectedAt } },
          data: {
            occurrences: { increment: 1 },
            lastOccurredAt: existing.lastOccurredAt > input.at ? existing.lastOccurredAt : input.at,
          },
        });
        duplicates.push(updated);
        continue;
      }
      const row = await tx.atoRiskSignal.create({
        data: {
          detectedAt: input.at,
          organizationId: input.organizationId,
          accountId: input.account.id,
          ruleCode: c.code,
          category: c.category,
          strength: c.strength,
          weight: c.informational ? 0 : c.weight,
          status: c.informational ? 'informational' : 'active',
          dedupeKey: c.dedupeKey,
          firstOccurredAt: input.at,
          lastOccurredAt: input.at,
          evidence: json(c.evidence),
          sourceKind: c.sourceKind,
          sourceRef: c.sourceRef,
          messageId: c.messageRef?.id ?? null,
          messageReceivedAt: c.messageRef?.receivedAt ?? null,
          authEventId: c.authEventRef?.id ?? null,
          authEventOccurredAt: c.authEventRef?.occurredAt ?? null,
          incidentId: input.account.activeIncidentId,
          rulesVersion: ATO_RULES_VERSION,
          settingsVersion: input.settingsVersion,
        },
      });
      created.push(row);
    }
    if (created.some((s) => s.status === 'active')) {
      await tx.atoAccount.update({
        where: { id: input.account.id },
        data: { lastSignalAt: input.at },
        select: { id: true },
      });
    }
    return { created, duplicates };
  }

  /** Active and recent signals of accounts (scoring window + 30 days of dedupe refresh). */
  async recentSignals(
    tx: Tx,
    organizationId: bigint,
    accountIds: readonly bigint[],
    settings: ResolvedAtoSettings,
    now: Date,
  ): Promise<AtoRiskSignal[]> {
    const maxHalfLife = Math.max(...Object.values(settings.scoring.halfLifeMinutes));
    const since = new Date(
      now.getTime() - maxHalfLife * 60_000 * DECAY_HALF_LIVES - SIGNAL_LOOKBACK_EXTRA_MS,
    );
    // Newest first so the bound keeps the most recent signals, then returned oldest first.
    const rows = await tx.atoRiskSignal.findMany({
      where: {
        organizationId,
        accountId: { in: [...accountIds] },
        detectedAt: { gte: since },
        status: { in: ['active', 'informational'] },
      },
      orderBy: [{ detectedAt: 'desc' }, { id: 'desc' }],
      take: RECENT_SIGNALS_LIMIT,
    });
    return rows.reverse();
  }

  /** Dismisses the active signals linked to an incident (false-positive resolution). */
  async dismissIncidentSignals(
    tx: Tx,
    input: {
      organizationId: bigint;
      incidentId: bigint;
      actor: IncidentActor;
      reason: string | null;
    },
  ): Promise<number> {
    const result = await tx.atoRiskSignal.updateMany({
      where: {
        organizationId: input.organizationId,
        incidentId: input.incidentId,
        status: 'active',
      },
      data: {
        status: 'dismissed',
        dismissedAt: this.clock(),
        dismissedByUserId: input.actor.type === 'user' ? (input.actor.userId ?? null) : null,
        dismissReason: clip(input.reason, 512),
      },
    });
    return result.count;
  }

  // =================================================================== scoring

  /**
   * Rescores a (locked) account (D11): writes `ato_accounts.risk_*`, an `ato_risk_scores` row when
   * the score moved (decay: only on a level change or a drop of ≥ 5 since the last row), and
   * `ato.account.risk.updated.v1` when the level changed. A benign override contradicted by a later
   * strong signal is marked `contradicted` (timeline entry on the active incident).
   */
  async rescore(
    tx: Tx,
    input: {
      organizationId: bigint;
      accountId: bigint;
      trigger: ScoreTrigger;
      settings: LoadedSettings;
    },
  ): Promise<RescoreResult> {
    const now = this.clock();
    const account = await this.requireAccount(tx, input.organizationId, input.accountId);
    const signals = await this.recentSignals(
      tx,
      input.organizationId,
      [account.id],
      input.settings.settings,
      now,
    );
    const scoreSignals: ScoreSignal[] = signals.map((s) => ({
      id: s.id,
      code: s.ruleCode,
      category: s.category,
      strength: s.strength,
      weight: s.weight,
      status: s.status,
      lastOccurredAt: s.lastOccurredAt,
    }));
    const override =
      account.overrideId !== null
        ? await tx.atoRiskOverride.findFirst({
            where: { id: account.overrideId, organizationId: input.organizationId },
          })
        : null;
    const result = scoreAccount(scoreSignals, input.settings.settings, override, now);
    let overrideContradicted = false;
    if (
      override &&
      result.override.outcome === 'contradicted' &&
      override.contradictedAt === null
    ) {
      overrideContradicted = true;
      await tx.atoRiskOverride.update({
        where: { id: override.id },
        data: { contradictedAt: now },
      });
      if (account.activeIncidentId !== null) {
        await this.incidents.recordEvent(tx, {
          organizationId: input.organizationId,
          incidentId: account.activeIncidentId,
          eventType: 'ato.override_contradicted',
          actor: { type: 'system', id: null },
          details: { overridePublicId: override.publicId, verdict: override.verdict },
        });
      }
      await this.audit(tx, {
        organizationId: input.organizationId,
        actor: { type: 'system', id: null },
        action: 'ato.override_contradicted',
        resourceType: 'ato_account',
        resourceId: account.publicId,
        metadata: { overridePublicId: override.publicId },
      });
    }
    const overrideStillActive = override !== null && result.override.outcome === 'applied';
    const previousScore = account.riskScore;
    const previousLevel = account.riskLevel;
    const changed = result.score !== previousScore;
    const levelChanged = result.level !== previousLevel;
    let rowWritten = false;
    let writeRow = false;
    if (input.trigger === 'decay') {
      const last = await tx.atoRiskScore.findFirst({
        where: { organizationId: input.organizationId, accountId: account.id },
        orderBy: [{ computedAt: 'desc' }, { id: 'desc' }],
        select: { score: true },
      });
      writeRow = levelChanged || (last !== null && last.score - result.score >= 5);
    } else {
      writeRow = changed;
    }
    const explanation = scoreExplanation(result, input.settings.version);
    if (writeRow) {
      await tx.atoRiskScore.create({
        data: {
          computedAt: now,
          organizationId: input.organizationId,
          accountId: account.id,
          score: result.score,
          level: result.level,
          previousScore,
          previousLevel,
          trigger: input.trigger,
          explanation: json(explanation),
          scorerVersion: ATO_SCORER_VERSION,
          rulesVersion: ATO_RULES_VERSION,
          settingsVersion: input.settings.version,
        },
      });
      rowWritten = true;
    }
    await tx.atoAccount.update({
      where: { id: account.id },
      data: {
        riskScore: result.score,
        riskLevel: result.level,
        riskUpdatedAt: now,
        riskExplanation: json(explanation),
        ...(override && !overrideStillActive && result.override.outcome !== 'none'
          ? { overrideId: null }
          : {}),
      },
      select: { id: true },
    });
    if (levelChanged) {
      await this.emit(
        tx,
        input.organizationId,
        EventTypes.AtoAccountRiskUpdated,
        account.id.toString(),
        {
          accountId: account.id.toString(),
          accountPublicId: account.publicId,
          kind: account.kind,
          score: result.score,
          level: result.level,
          previousScore,
          previousLevel,
          trigger: input.trigger,
          computedAt: now.toISOString(),
        },
      );
    }
    return {
      result,
      previousScore,
      previousLevel,
      changed,
      levelChanged,
      rowWritten,
      overrideContradicted,
    };
  }

  // =================================================================== incidents

  /**
   * The incident policy (D12) after a rescore, in the same transaction: link new evidence to the
   * active ATO incident (peak score and severity escalate, never de-escalate automatically), or
   * open one when the score reaches the incident threshold, no benign override applies and the
   * false-positive cooldown passed (or a strong signal fired).
   */
  async applyIncidentPolicy(
    tx: Tx,
    input: {
      organizationId: bigint;
      accountId: bigint;
      rescore: RescoreResult;
      settings: LoadedSettings;
      evidence: EvidenceRefs;
      newStrongSignal: boolean;
      context: IncidentPolicyContext;
    },
  ): Promise<IncidentPolicyResult> {
    const now = this.clock();
    let account = await this.requireAccount(tx, input.organizationId, input.accountId);
    const result = input.rescore.result;
    const contributors: Contributor[] = result.contributions
      .filter((c) => c.counted)
      .map((c) => ({
        code: c.code,
        category: c.category,
        strength: c.strength,
        ip: input.context.contributorIps?.get(c.code) ?? null,
      }));
    const recommendations = recommendResponses(
      {
        kind: account.kind,
        publicId: account.publicId,
        level: result.level,
        connectorId: account.connectorId?.toString() ?? null,
        mailboxSha256:
          account.kind === 'mailbox' && account.address ? atoMailboxSha256(account.address) : null,
      },
      contributors,
      { providerActions: input.context.providerActions },
      input.context.hasAtoPolicyRule,
    );

    let incident: IncidentRow | null = null;
    if (account.activeIncidentId !== null) {
      incident = await this.incidents.lockForUpdate(
        tx,
        input.organizationId,
        account.activeIncidentId,
      );
      if (!incident || !isActiveIncident(incident) || incident.category !== ATO_INCIDENT_CATEGORY) {
        incident = null;
        await tx.atoAccount.update({
          where: { id: account.id },
          data: { activeIncidentId: null },
          select: { id: true },
        });
        account = { ...account, activeIncidentId: null };
      }
    }

    if (incident) {
      let escalated = false;
      const severity = LEVEL_TO_SEVERITY[result.level];
      if (
        securityIncidentSeverityRank(severity) > securityIncidentSeverityRank(incident.severity)
      ) {
        incident = await this.incidents.setSeverity(tx, {
          organizationId: input.organizationId,
          incidentId: incident.id,
          severity,
          actor: { type: 'system', id: null },
          reason: `Account risk reached ${result.level}`,
          locked: incident,
        });
        escalated = true;
      }
      await tx.atoIncidentDetail.updateMany({
        where: { incidentId: incident.id, organizationId: input.organizationId },
        data: {
          peakRiskScore: { set: Math.max(result.score, await this.peakOf(tx, incident.id)) },
          ...(escalated && { recommendedActions: json(recommendations) }),
        },
      });
      incident = await this.linkEvidence(tx, {
        organizationId: input.organizationId,
        incident,
        evidence: input.evidence,
      });
      if (escalated)
        await this.maybeIncidentAlert(tx, input.organizationId, incident, account, input.settings);
      return { incident, opened: false, escalated, recommendations, contributors, skipped: null };
    }

    const scoring = input.settings.settings.scoring;
    if (result.score < scoring.incidentThreshold) {
      return {
        incident: null,
        opened: false,
        escalated: false,
        recommendations,
        contributors,
        skipped: 'below_threshold',
      };
    }
    if (result.override.verdict === 'benign' && result.override.outcome === 'applied') {
      return {
        incident: null,
        opened: false,
        escalated: false,
        recommendations,
        contributors,
        skipped: 'benign_override',
      };
    }
    const lastFalsePositive = await tx.securityIncident.findFirst({
      where: {
        organizationId: input.organizationId,
        category: ATO_INCIDENT_CATEGORY,
        subjectType: ATO_INCIDENT_SUBJECT_TYPE,
        subjectRefId: account.id,
        status: 'false_positive',
      },
      orderBy: { resolvedAt: 'desc' },
      select: { resolvedAt: true },
    });
    if (
      lastFalsePositive?.resolvedAt &&
      now.getTime() - lastFalsePositive.resolvedAt.getTime() <
        scoring.incidentReopenCooldownMinutes * 60_000 &&
      !input.newStrongSignal
    ) {
      return {
        incident: null,
        opened: false,
        escalated: false,
        recommendations,
        contributors,
        skipped: 'cooldown',
      };
    }

    const counted = result.contributions.filter((c) => c.counted);
    const reasonCodes = [...new Set(counted.map((c) => c.code))].slice(0, MAX_REASON_CODES);
    const opened = await this.incidents.open(tx, {
      organizationId: input.organizationId,
      category: ATO_INCIDENT_CATEGORY,
      subject: {
        type: ATO_INCIDENT_SUBJECT_TYPE,
        refId: account.id,
        refTime: null,
        publicId: account.publicId,
      },
      origin: 'detection',
      severity: result.level === 'low' ? 'medium' : LEVEL_TO_SEVERITY[result.level],
      titleCode: counted[0]?.code ?? null,
      reasonCodes,
      detectorVersion: ATO_RULES_VERSION,
      detectedAt: now,
      actor: { type: 'system', id: null },
      details: { score: result.score, level: result.level },
    });
    await tx.atoIncidentDetail.create({
      data: {
        incidentId: opened.id,
        organizationId: input.organizationId,
        accountId: account.id,
        riskScoreAtOpen: result.score,
        peakRiskScore: result.score,
        detectionReason: json({
          codes: reasonCodes,
          contributions: scoreExplanation(result, input.settings.version).top,
          versions: {
            rules: ATO_RULES_VERSION,
            scorer: ATO_SCORER_VERSION,
            settings: input.settings.version,
          },
        }),
        recommendedActions: json(recommendations),
        relatedIps: json([]),
      },
    });
    await tx.atoAccount.update({
      where: { id: account.id },
      data: { activeIncidentId: opened.id },
      select: { id: true },
    });
    // The account's recent active signals are the incident's opening evidence.
    const recent = await this.recentSignals(
      tx,
      input.organizationId,
      [account.id],
      input.settings.settings,
      now,
    );
    const active = recent.filter((s) => s.status === 'active');
    await tx.atoRiskSignal.updateMany({
      where: {
        organizationId: input.organizationId,
        accountId: account.id,
        id: { in: active.map((s) => s.id) },
        incidentId: null,
      },
      data: { incidentId: opened.id },
    });
    const evidence: EvidenceRefs = {
      signals: [
        ...active.map((s) => ({ id: s.id, detectedAt: s.detectedAt })),
        ...input.evidence.signals,
      ],
      authEvents: [
        ...active
          .filter((s) => s.authEventId !== null && s.authEventOccurredAt !== null)
          .map((s) => ({ id: s.authEventId!, occurredAt: s.authEventOccurredAt! })),
        ...input.evidence.authEvents,
      ],
      messages: [
        ...active
          .filter((s) => s.messageId !== null && s.messageReceivedAt !== null)
          .map((s) => ({ id: s.messageId!, receivedAt: s.messageReceivedAt! })),
        ...input.evidence.messages,
      ],
      codes: reasonCodes,
    };
    const incidentRow = await this.linkEvidence(tx, {
      organizationId: input.organizationId,
      incident: opened,
      evidence,
      emitUpdate: false,
    });
    await this.maybeIncidentAlert(tx, input.organizationId, incidentRow, account, input.settings);
    return {
      incident: incidentRow,
      opened: true,
      escalated: false,
      recommendations,
      contributors,
      skipped: null,
    };
  }

  private async peakOf(tx: Tx, incidentId: bigint): Promise<number> {
    const d = await tx.atoIncidentDetail.findUnique({
      where: { incidentId },
      select: { peakRiskScore: true },
    });
    return d?.peakRiskScore ?? 0;
  }

  private async maybeIncidentAlert(
    tx: Tx,
    organizationId: bigint,
    incident: IncidentRow,
    account: AtoAccount,
    settings: LoadedSettings,
  ): Promise<void> {
    const n = settings.settings.notifications;
    if (
      securityIncidentSeverityRank(incident.severity) <
      securityIncidentSeverityRank(n.incidentMinSeverity)
    ) {
      return;
    }
    await this.requestNotification(tx, {
      organizationId,
      kind: 'incident_alert',
      audience: 'tenant',
      severity: incident.severity,
      refs: { incidentPublicId: incident.publicId, accountPublicId: account.publicId },
      throttle: { kind: 'ato_incident', scope: '-', minutes: n.throttleMinutes },
    });
  }

  /**
   * Links evidence to an ATO incident (D12): signals, auth events and messages within the per-type
   * caps (counts beyond them in `ato_incident_details`), related IPs (≤ 20) refreshed, one
   * `evidence_linked` timeline entry and the throttled `security.incident.updated.v1`.
   */
  async linkEvidence(
    tx: Tx,
    input: {
      organizationId: bigint;
      incident: IncidentRow;
      evidence: EvidenceRefs;
      emitUpdate?: boolean;
    },
  ): Promise<IncidentRow> {
    const e = input.evidence;
    if (e.signals.length + e.authEvents.length + e.messages.length === 0) return input.incident;
    const linked = await this.incidents.link(tx, {
      organizationId: input.organizationId,
      incidentId: input.incident.id,
      links: [
        ...e.signals.map((s) => ({
          type: 'ato_signal' as const,
          refId: s.id,
          refTime: s.detectedAt,
        })),
        ...e.authEvents.map((a) => ({
          type: 'ato_auth_event' as const,
          refId: a.id,
          refTime: a.occurredAt,
        })),
        ...e.messages.map((m) => ({
          type: 'message' as const,
          refId: m.id,
          refTime: m.receivedAt,
        })),
      ],
    });
    const add = (t: 'ato_signal' | 'ato_auth_event' | 'message') =>
      linked.linked[t] + linked.overflow[t];
    const relatedIps = await this.relatedIps(tx, input.organizationId, input.incident.id);
    await tx.atoIncidentDetail.updateMany({
      where: { incidentId: input.incident.id, organizationId: input.organizationId },
      data: {
        signalCount: { increment: add('ato_signal') },
        authEventCount: { increment: add('ato_auth_event') },
        messageCount: { increment: add('message') },
        relatedIps: json(relatedIps.ips),
        geoSummary:
          relatedIps.countries.length > 0
            ? json({ countries: relatedIps.countries })
            : Prisma.DbNull,
        deviceSummary:
          relatedIps.devices.length > 0 ? json({ devices: relatedIps.devices }) : Prisma.DbNull,
        lastSignalsEventAt: this.clock(),
      },
    });
    const row = await tx.securityIncident.findUniqueOrThrow({ where: { id: input.incident.id } });
    const counts = {
      signals: add('ato_signal'),
      authEvents: add('ato_auth_event'),
      messages: add('message'),
    };
    if (input.emitUpdate === false) {
      await this.incidents.recordEvent(tx, {
        organizationId: input.organizationId,
        incidentId: row.id,
        eventType: 'evidence_linked',
        actor: { type: 'system', id: null },
        details: { codes: [...new Set(e.codes)].slice(0, 10), counts },
      });
      return row;
    }
    return this.incidents.recordEvidence(tx, row, { codes: e.codes, counts });
  }

  /** Related IPs (≤ 20 with country, ASN, reputation status and counts), countries and devices. */
  private async relatedIps(
    tx: Tx,
    organizationId: bigint,
    incidentId: bigint,
  ): Promise<{
    ips: Array<{
      ip: string;
      country: string | null;
      asn: number | null;
      reputation: string | null;
      count: number;
    }>;
    countries: string[];
    devices: string[];
  }> {
    const rows = await tx.$queryRaw<
      {
        ip_address: string | null;
        country_code: string | null;
        asn: number | null;
        reputation: unknown;
        device_label: string | null;
        attempt_count: number;
      }[]
    >`
      SELECT e.ip_address, e.country_code, e.asn, e.reputation, e.device_label, e.attempt_count
      FROM security_incident_links l
      JOIN ato_auth_events e
        ON e.id = l.ref_id AND e.occurred_at = l.ref_time AND e.organization_id = l.organization_id
      WHERE l.organization_id = ${organizationId} AND l.incident_id = ${incidentId}
        AND l.link_type = 'ato_auth_event'
      ORDER BY l.ref_time DESC
      LIMIT 1000`;
    const ips = new Map<
      string,
      {
        ip: string;
        country: string | null;
        asn: number | null;
        reputation: string | null;
        count: number;
      }
    >();
    const countries = new Set<string>();
    const devices = new Set<string>();
    for (const r of rows) {
      if (r.country_code) countries.add(r.country_code);
      if (r.device_label) devices.add(r.device_label);
      if (!r.ip_address) continue;
      const rep = r.reputation as { status?: string } | null;
      const entry = ips.get(r.ip_address) ?? {
        ip: r.ip_address,
        country: r.country_code,
        asn: r.asn === null ? null : Number(r.asn),
        reputation: rep?.status ?? null,
        count: 0,
      };
      entry.count += Number(r.attempt_count);
      ips.set(r.ip_address, entry);
    }
    return {
      ips: [...ips.values()]
        .sort((a, b) => b.count - a.count || a.ip.localeCompare(b.ip))
        .slice(0, 20),
      countries: [...countries].sort().slice(0, 20),
      devices: [...devices].sort().slice(0, 20),
    };
  }

  /**
   * A manual ATO incident for an account (D12 `POST /incidents` with `account_takeover`): opened
   * through the shared store (origin `manual`) with its detail row; one active incident per account.
   */
  async createManualIncident(
    tx: Tx,
    input: {
      organizationId: bigint;
      accountPublicId: string;
      severity: SecurityIncidentSeverity;
      note?: string | null;
      actor: IncidentActor;
      sourceIp?: string | null;
    },
  ): Promise<IncidentRow> {
    const found = await this.findAccount(tx, input.organizationId, input.accountPublicId);
    if (!found) throw new AtoStoreError('ato_account_not_found', 'Account not found');
    const account = await this.requireAccount(tx, input.organizationId, found.id);
    const incident = await this.incidents.open(tx, {
      organizationId: input.organizationId,
      category: ATO_INCIDENT_CATEGORY,
      subject: {
        type: ATO_INCIDENT_SUBJECT_TYPE,
        refId: account.id,
        refTime: null,
        publicId: account.publicId,
      },
      origin: 'manual',
      severity: input.severity,
      titleCode: null,
      reasonCodes: [],
      detectorVersion: null,
      detectedAt: this.clock(),
      actor: input.actor,
      note: input.note ?? null,
      sourceIp: input.sourceIp ?? null,
    });
    await tx.atoIncidentDetail.create({
      data: {
        incidentId: incident.id,
        organizationId: input.organizationId,
        accountId: account.id,
        riskScoreAtOpen: account.riskScore,
        peakRiskScore: account.riskScore,
        detectionReason: json({
          codes: [],
          manual: true,
          versions: { rules: ATO_RULES_VERSION, scorer: ATO_SCORER_VERSION },
        }),
        recommendedActions: json([]),
        relatedIps: json([]),
      },
    });
    await tx.atoAccount.update({
      where: { id: account.id },
      data: { activeIncidentId: incident.id },
      select: { id: true },
    });
    return incident;
  }

  /**
   * Clears `active_incident_id` when the account's active ATO incident closed (called by the ATO
   * incident handler on terminal transitions).
   */
  async clearActiveIncident(tx: Tx, organizationId: bigint, incident: IncidentRow): Promise<void> {
    await tx.atoAccount.updateMany({
      where: { id: incident.subjectRefId, organizationId, activeIncidentId: incident.id },
      data: { activeIncidentId: null },
    });
  }

  // =================================================================== responses

  private async lockAction(
    tx: Tx,
    organizationId: bigint,
    actionId: bigint,
  ): Promise<AtoResponseAction> {
    const locked = await tx.$queryRaw<{ id: bigint }[]>`
      SELECT id FROM ato_response_actions WHERE id = ${actionId} AND organization_id = ${organizationId} FOR UPDATE`;
    if (locked.length === 0)
      throw new AtoStoreError('ato_response_not_found', 'Response not found');
    return tx.atoResponseAction.findUniqueOrThrow({ where: { id: actionId } });
  }

  /** A response action of the organization by public id (null for none or another tenant's). */
  async findAction(
    tx: Tx,
    organizationId: bigint,
    publicId: string,
  ): Promise<AtoResponseAction | null> {
    const row = await tx.atoResponseAction.findUnique({ where: { publicId } });
    return row && row.organizationId === organizationId ? row : null;
  }

  private async logAction(
    tx: Tx,
    action: AtoResponseAction,
    phase: 'authorize' | 'execute' | 'confirm' | 'rollback',
    outcome: 'succeeded' | 'pending' | 'failed' | 'unsupported' | 'retry_scheduled' | 'skipped',
    extra: { providerStatus?: string | null; errorCode?: string | null; durationMs?: number } = {},
  ): Promise<void> {
    await tx.atoResponseActionLog.create({
      data: {
        organizationId: action.organizationId,
        actionId: action.id,
        phase,
        attemptNo: Math.max(1, action.attempts),
        outcome,
        providerStatus: clip(extra.providerStatus, 32),
        errorCode: clip(extra.errorCode, 64),
        durationMs: Math.max(0, Math.round(extra.durationMs ?? 0)),
      },
    });
  }

  private async actionTimeline(
    tx: Tx,
    action: AtoResponseAction,
    event: string,
    actor: IncidentActor,
    details: Record<string, unknown> = {},
    note?: string | null,
  ): Promise<void> {
    if (action.incidentId === null) return;
    await this.incidents.recordEvent(tx, {
      organizationId: action.organizationId,
      incidentId: action.incidentId,
      eventType: `ato.response_${event}`,
      actor,
      note: note ?? null,
      details: { actionPublicId: action.publicId, actionType: action.actionType, ...details },
    });
  }

  private async actionAudit(
    tx: Tx,
    action: AtoResponseAction,
    verb: string,
    actor: IncidentActor,
    metadata: Record<string, unknown> = {},
    sourceIp?: string | null,
  ): Promise<void> {
    await this.audit(tx, {
      organizationId: action.organizationId,
      actor,
      action: `ato.response_${verb}`,
      resourceType: 'ato_response',
      resourceId: action.publicId,
      sourceIp: sourceIp ?? null,
      metadata: { actionType: action.actionType, status: action.status, ...metadata },
    });
  }

  private async emitCompleted(
    tx: Tx,
    action: AtoResponseAction,
    phase: 'execute' | 'rollback',
  ): Promise<void> {
    if (!(COMPLETED_RESPONSE_STATUSES as readonly string[]).includes(action.status)) return;
    const [account, incident] = await Promise.all([
      tx.atoAccount.findUniqueOrThrow({
        where: { id: action.accountId },
        select: { publicId: true },
      }),
      action.incidentId === null
        ? Promise.resolve(null)
        : tx.securityIncident.findUnique({
            where: { id: action.incidentId },
            select: { publicId: true },
          }),
    ]);
    const ps = action.providerStatus;
    await this.emit(
      tx,
      action.organizationId,
      EventTypes.AtoResponseCompleted,
      action.id.toString(),
      {
        actionId: action.id.toString(),
        actionPublicId: action.publicId,
        phase,
        actionType: action.actionType,
        provider: action.provider,
        status: action.status,
        providerStatus: ps === null || ps === 'pending' ? null : ps,
        resultCode: action.resultCode,
        incidentPublicId: incident?.publicId ?? null,
        accountPublicId: account.publicId,
        completedAt: (action.completedAt ?? this.clock()).toISOString(),
      },
    );
  }

  private async updateAction(
    tx: Tx,
    action: AtoResponseAction,
    data: Prisma.AtoResponseActionUncheckedUpdateInput,
  ): Promise<AtoResponseAction> {
    const result = await tx.atoResponseAction.updateMany({
      where: { id: action.id, rowVersion: action.rowVersion },
      data: {
        ...data,
        rowVersion: { increment: 1 },
      },
    });
    if (result.count !== 1)
      throw new AtoStoreError('ato_response_state', 'Response changed concurrently');
    return tx.atoResponseAction.findUniqueOrThrow({ where: { id: action.id } });
  }

  /**
   * Requests a response (D13). One non-terminal action per (incident, type, target)
   * (`ato_response_active`). `record_manual_action` is `attested`; low impact (or an automation
   * decision) is approved and executed now (gateway inline, provider through
   * `ato.response.requested.v1`); medium/high impact waits for approval (`pending_approval`, expires
   * after `approvalTtlHours`).
   */
  async requestResponse(tx: Tx, input: RequestResponseInput): Promise<AtoResponseAction> {
    if (!isResponseActionType(input.actionType)) {
      throw new AtoStoreError('ato_response_invalid', 'Unknown action type');
    }
    const now = this.clock();
    const account = await this.requireAccount(tx, input.organizationId, input.accountId);
    if (input.target.accountPublicId !== account.publicId) {
      throw new AtoStoreError('ato_response_invalid', 'Target does not name the account');
    }
    if (input.incidentId !== null) {
      const incident = await tx.securityIncident.findFirst({
        where: {
          id: input.incidentId,
          organizationId: input.organizationId,
          category: ATO_INCIDENT_CATEGORY,
        },
        select: { subjectRefId: true },
      });
      if (!incident || incident.subjectRefId !== account.id) {
        throw new AtoStoreError('ato_incident_not_found', 'Incident not found for the account');
      }
    }
    const entry = RESPONSE_CATALOGUE[input.actionType];
    this.validateTarget(input.actionType, input.target, account);
    const params = { ...(input.params ?? {}) };
    if (input.actionType === 'restrict_smtp_sending' || input.actionType === 'block_smtp_auth') {
      const loaded = await this.ensureSettings(tx, input.organizationId);
      const automation = loaded.settings.automation[input.actionType];
      const duration = Number(
        params.durationMinutes ??
          automation.durationMinutes ??
          loaded.settings.restrictions.defaultDurationMinutes,
      );
      if (!Number.isInteger(duration) || duration < 15 || duration > 10080) {
        throw new AtoStoreError('ato_response_invalid', 'durationMinutes must be 15-10080');
      }
      params.durationMinutes = duration;
      const mode = String(params.mode ?? loaded.settings.restrictions.defaultMode);
      if (mode !== 'reject' && mode !== 'defer')
        throw new AtoStoreError('ato_response_invalid', 'mode must be reject or defer');
      params.mode = mode;
    }
    const impact = impactFor(input.actionType, input.target);
    const provider =
      entry.provider === 'provider' ? (input.providerKind ?? 'unbound') : entry.provider;
    const dedupeHash = responseDedupeHash(input.incidentId, input.actionType, input.target);
    const active = await tx.atoResponseAction.findFirst({
      where: { organizationId: input.organizationId, dedupeHash, activeMarker: 1 },
      select: { publicId: true },
    });
    if (active) {
      throw new AtoStoreError('ato_response_active', 'An active response exists', {
        actionPublicId: active.publicId,
      });
    }
    const manual = entry.provider === 'manual';
    const requiresApproval =
      !manual && impact !== 'low' && input.authorization !== 'automation_policy';
    const status: ResponseStatus = manual
      ? 'attested'
      : requiresApproval
        ? 'pending_approval'
        : 'approved';
    const reason = input.guardReason
      ? clip(
          `${input.reason ? `${input.reason} ` : ''}(automation guard: ${input.guardReason})`,
          1000,
        )
      : clip(input.reason, 1000);
    let action: AtoResponseAction;
    try {
      action = await tx.atoResponseAction.create({
        data: {
          organizationId: input.organizationId,
          incidentId: input.incidentId,
          accountId: account.id,
          actionType: input.actionType,
          provider,
          impact,
          target: json(input.target),
          params: json(params),
          status,
          requiresApproval,
          authorization: input.authorization,
          requestedByType: input.actor.type,
          requestedById: input.actor.id,
          requestReason: reason,
          approvalExpiresAt: requiresApproval
            ? new Date(now.getTime() + this.config.approvalTtlHours * 3_600_000)
            : null,
          decidedAt: requiresApproval || manual ? null : now,
          completedAt: manual ? now : null,
          providerStatus: manual ? 'unconfirmed' : null,
          resultCode: manual ? 'attested_by_analyst' : null,
          dedupeHash,
        },
      });
    } catch (error) {
      if (isUniqueViolation(error))
        throw new AtoStoreError('ato_response_active', 'An active response exists');
      throw error;
    }
    await this.logAction(tx, action, 'authorize', requiresApproval ? 'pending' : 'succeeded');
    await this.actionTimeline(
      tx,
      action,
      manual ? 'attested' : 'requested',
      input.actor,
      {
        impact,
        status,
        ...(input.guardReason && { guardReason: input.guardReason }),
      },
      input.reason ?? null,
    );
    await this.actionAudit(
      tx,
      action,
      manual ? 'attested' : 'requested',
      input.actor,
      {
        impact,
        authorization: input.authorization,
        ...(input.guardReason && { automation: { reason: input.guardReason } }),
      },
      input.sourceIp,
    );
    if (manual) {
      await this.emitCompleted(tx, action, 'execute');
      return action;
    }
    if (requiresApproval) {
      await this.requestNotification(tx, {
        organizationId: input.organizationId,
        kind: 'approval_requested',
        audience: 'tenant',
        severity: null,
        refs: { actionPublicId: action.publicId, accountPublicId: account.publicId },
        throttle: { kind: 'ato_approval', scope: action.publicId, minutes: 60 },
      });
      return action;
    }
    return this.executeApproved(tx, action, input.actor);
  }

  private validateTarget(
    type: ResponseActionType,
    target: ResponseTarget,
    account: AtoAccount,
  ): void {
    const bad = (m: string) => new AtoStoreError('ato_response_invalid', m);
    if (type === 'restrict_smtp_sending') {
      if (target.scope === 'mailbox') {
        if (account.kind !== 'mailbox' || !account.address)
          throw bad('Mailbox scope needs a mailbox account');
        if (target.mailboxSha256 !== atoMailboxSha256(account.address))
          throw bad('Mailbox hash mismatch');
      } else if (target.scope === 'connector') {
        if (!target.connectorId || !/^[1-9][0-9]{0,19}$/.test(target.connectorId))
          throw bad('Connector scope needs connectorId');
        if (
          account.kind === 'smtp_connector' &&
          account.connectorId?.toString() !== target.connectorId
        ) {
          throw bad('Connector mismatch');
        }
      } else throw bad('restrict_smtp_sending has scopes mailbox and connector');
    } else if (type === 'block_smtp_auth') {
      if (target.scope !== 'connector' && target.scope !== 'connector_ip') {
        throw bad('block_smtp_auth has scopes connector and connector_ip');
      }
      if (!target.connectorId || !/^[1-9][0-9]{0,19}$/.test(target.connectorId))
        throw bad('Needs connectorId');
      if (
        account.kind === 'smtp_connector' &&
        account.connectorId?.toString() !== target.connectorId
      ) {
        throw bad('Connector mismatch');
      }
      if (
        target.scope === 'connector_ip' &&
        (!target.cidr || !parseCidr(target.cidr, { minV4Prefix: 8, minV6Prefix: 32 }))
      ) {
        throw bad('connector_ip needs a CIDR (IPv4 /8 or longer, IPv6 /32 or longer)');
      }
    } else if (target.scope !== 'account') {
      throw bad('This action targets the account');
    }
  }

  private async executeApproved(
    tx: Tx,
    action: AtoResponseAction,
    actor: IncidentActor,
  ): Promise<AtoResponseAction> {
    const entry = RESPONSE_CATALOGUE[action.actionType as ResponseActionType];
    if (entry.provider === 'gateway') return this.executeGatewayAction(tx, action, actor);
    // Provider action: executed asynchronously by the respond role; without an integration it is
    // unsupported (never executed, never claimed).
    if (action.provider === 'unbound') {
      const done = await this.updateAction(tx, action, {
        status: 'unsupported',
        providerStatus: 'unsupported',
        resultCode: 'no_provider_integration',
        completedAt: this.clock(),
      });
      await this.logAction(tx, done, 'execute', 'unsupported', {
        errorCode: 'no_provider_integration',
      });
      await this.actionTimeline(tx, done, 'unsupported', actor, {
        resultCode: 'no_provider_integration',
      });
      await this.actionAudit(tx, done, 'unsupported', actor);
      await this.emitCompleted(tx, done, 'execute');
      return done;
    }
    await this.emit(
      tx,
      action.organizationId,
      EventTypes.AtoResponseRequested,
      action.id.toString(),
      {
        actionId: action.id.toString(),
        actionPublicId: action.publicId,
        phase: 'execute',
        actionType: action.actionType,
        provider: action.provider,
        incidentId: action.incidentId?.toString() ?? null,
        accountId: action.accountId.toString(),
        requestedAt: this.clock().toISOString(),
      },
    );
    return action;
  }

  /**
   * Executes an approved gateway action inline (D13): notifications are `succeeded` with
   * `unconfirmed` (`queued_for_delivery`), escalation raises the incident, restrictions write an
   * `ato_smtp_restrictions` row (`applied`, `ato.restriction.changed.v1`). Used by automation (detect
   * transaction) and approvals (api transaction).
   */
  async executeGatewayAction(
    tx: Tx,
    action: AtoResponseAction,
    actor: IncidentActor,
  ): Promise<AtoResponseAction> {
    if (action.status !== 'approved')
      throw new AtoStoreError('ato_response_state', 'Action is not approved');
    const now = this.clock();
    const incident =
      action.incidentId === null
        ? null
        : await tx.securityIncident.findUnique({ where: { id: action.incidentId } });
    const account = await tx.atoAccount.findUniqueOrThrow({ where: { id: action.accountId } });
    const params = (action.params ?? {}) as Record<string, string | number | boolean>;
    const target = action.target as unknown as ResponseTarget;
    let outcome: {
      status: 'succeeded' | 'failed' | 'unsupported';
      providerStatus: 'applied' | 'unconfirmed' | 'unsupported' | 'failed';
      resultCode: string;
      restrictionId?: bigint;
      effectiveUntil?: Date;
    };
    const settings = await this.ensureSettings(tx, action.organizationId);
    switch (action.actionType as ResponseActionType) {
      case 'alert_tenant_admins': {
        if (!incident) {
          outcome = {
            status: 'unsupported',
            providerStatus: 'unsupported',
            resultCode: 'incident_required',
          };
          break;
        }
        await this.requestNotification(tx, {
          organizationId: action.organizationId,
          kind: 'incident_alert',
          audience: 'tenant',
          severity: incident.severity,
          refs: { incidentPublicId: incident.publicId, accountPublicId: account.publicId },
          throttle: {
            kind: 'ato_incident',
            scope: '-',
            minutes: settings.settings.notifications.throttleMinutes,
          },
        });
        outcome = {
          status: 'succeeded',
          providerStatus: 'unconfirmed',
          resultCode: 'queued_for_delivery',
        };
        break;
      }
      case 'notify_soc':
      case 'escalate_investigation': {
        if (!incident) {
          outcome = {
            status: 'unsupported',
            providerStatus: 'unsupported',
            resultCode: 'incident_required',
          };
          break;
        }
        let current = incident;
        if (action.actionType === 'escalate_investigation') {
          current = await this.incidents.escalate(tx, {
            organizationId: action.organizationId,
            incidentId: incident.id,
            actor,
            minSeverity: 'high',
            reason: action.requestReason,
          });
        }
        await this.requestNotification(tx, {
          organizationId: action.organizationId,
          kind: 'incident_alert',
          audience: 'soc',
          severity: current.severity,
          refs: { incidentPublicId: current.publicId, accountPublicId: account.publicId },
          throttle: {
            kind: 'ato_incident',
            scope: 'soc',
            minutes: settings.settings.notifications.throttleMinutes,
          },
        });
        if (current.severity === 'critical') {
          await this.requestNotification(tx, {
            organizationId: action.organizationId,
            kind: 'incident_alert',
            audience: 'platform_soc',
            severity: 'critical',
            refs: { incidentPublicId: current.publicId },
            throttle: {
              kind: 'ato_incident',
              scope: 'platform_soc',
              minutes: settings.settings.notifications.throttleMinutes,
            },
          });
        }
        outcome =
          action.actionType === 'escalate_investigation'
            ? { status: 'succeeded', providerStatus: 'applied', resultCode: 'escalated' }
            : {
                status: 'succeeded',
                providerStatus: 'unconfirmed',
                resultCode: 'queued_for_delivery',
              };
        break;
      }
      case 'restrict_smtp_sending':
      case 'block_smtp_auth': {
        const applied = await this.applyRestriction(tx, action, account, target, params, now);
        outcome = applied;
        break;
      }
      default:
        throw new AtoStoreError('ato_response_invalid', 'Not a gateway action');
    }
    const done = await this.updateAction(tx, action, {
      status: outcome.status,
      providerStatus: outcome.providerStatus,
      resultCode: outcome.resultCode,
      executedAt: now,
      completedAt: now,
      attempts: { increment: 1 },
      ...(outcome.restrictionId !== undefined && { restrictionId: outcome.restrictionId }),
      ...(outcome.effectiveUntil !== undefined && { effectiveUntil: outcome.effectiveUntil }),
    });
    await this.logAction(
      tx,
      done,
      'execute',
      outcome.status === 'succeeded' ? 'succeeded' : outcome.status,
      {
        providerStatus: outcome.providerStatus,
        errorCode: outcome.status === 'succeeded' ? null : outcome.resultCode,
      },
    );
    await this.actionTimeline(tx, done, outcome.status, actor, { resultCode: outcome.resultCode });
    await this.actionAudit(tx, done, outcome.status, actor, { resultCode: outcome.resultCode });
    await this.emitCompleted(tx, done, 'execute');
    if (outcome.status === 'failed') await this.notifyFailure(tx, done, account);
    return done;
  }

  private async applyRestriction(
    tx: Tx,
    action: AtoResponseAction,
    account: AtoAccount,
    target: ResponseTarget,
    params: Record<string, string | number | boolean>,
    now: Date,
  ): Promise<{
    status: 'succeeded' | 'failed';
    providerStatus: 'applied' | 'failed';
    resultCode: string;
    restrictionId?: bigint;
    effectiveUntil?: Date;
  }> {
    const activeCount = await tx.atoSmtpRestriction.count({
      where: { organizationId: action.organizationId, status: 'active', expiresAt: { gt: now } },
    });
    if (activeCount >= this.config.maxActiveRestrictionsPerOrg) {
      return { status: 'failed', providerStatus: 'failed', resultCode: 'restriction_limit' };
    }
    const kind = action.actionType === 'restrict_smtp_sending' ? 'send_block' : 'auth_block';
    const scope = target.scope as 'mailbox' | 'connector' | 'connector_ip';
    const cidr = scope === 'connector_ip' && target.cidr ? parseCidr(target.cidr) : null;
    const connectorId = scope === 'mailbox' ? null : BigInt(target.connectorId!);
    const mailboxSha256 = scope === 'mailbox' ? target.mailboxSha256! : null;
    const subjectHash = restrictionSubjectHash({
      kind,
      scope,
      connectorId,
      mailboxSha256,
      cidr: cidr?.cidr ?? null,
    });
    const expiresAt = new Date(now.getTime() + Number(params.durationMinutes) * 60_000);
    let restriction: AtoSmtpRestriction;
    try {
      restriction = await tx.atoSmtpRestriction.create({
        data: {
          organizationId: action.organizationId,
          kind,
          scope,
          connectorId,
          mailboxSha256,
          mailboxAddress: scope === 'mailbox' ? account.address : null,
          ipCidr: cidr?.cidr ?? null,
          ipVersion: cidr?.version ?? null,
          rangeStart: cidr ? new Uint8Array(cidr.start) : null,
          rangeEnd: cidr ? new Uint8Array(cidr.end) : null,
          mode: params.mode === 'defer' ? 'defer' : 'reject',
          status: 'active',
          reasonCode: `ato.response.${action.actionType}`.slice(0, 64),
          responseActionId: action.id,
          startsAt: now,
          expiresAt,
          subjectHash,
        },
      });
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
      const found = await tx.atoSmtpRestriction.findFirst({
        where: { organizationId: action.organizationId, subjectHash, activeMarker: 1 },
        select: { id: true },
      });
      if (!found) throw error;
      const locked = await tx.$queryRaw<{ id: bigint }[]>`
        SELECT id FROM ato_smtp_restrictions
        WHERE id = ${found.id} AND organization_id = ${action.organizationId} FOR UPDATE`;
      if (locked.length === 0) throw error;
      const existing = await tx.atoSmtpRestriction.findUniqueOrThrow({ where: { id: found.id } });
      if (existing.status === 'active' && existing.expiresAt <= now) {
        // Past `expires_at` but not yet swept (the smtp-adapter already ignores it): expire it now
        // and apply the new restriction in its place, so the response is really enforced.
        await this.expireRestriction(tx, existing, now);
        return this.applyRestriction(tx, action, account, target, params, now);
      }
      if (existing.status !== 'active') throw error;
      // Still running: the same subject stays restricted until the later of the two expiries. The
      // row keeps its owning action; this action shares it (a rollback of either lifts it only
      // when no other succeeded action still relies on it).
      let effective = existing;
      if (expiresAt > existing.expiresAt) {
        effective = await tx.atoSmtpRestriction.update({
          where: { id: existing.id },
          data: { expiresAt },
        });
        await this.emitRestriction(tx, effective, now);
        if (existing.responseActionId !== null) {
          await tx.atoResponseAction.updateMany({
            where: {
              id: existing.responseActionId,
              organizationId: action.organizationId,
              restrictionId: existing.id,
              status: 'succeeded',
            },
            data: { effectiveUntil: expiresAt, rowVersion: { increment: 1 } },
          });
        }
      }
      return {
        status: 'succeeded',
        providerStatus: 'applied',
        resultCode: 'restriction_already_active',
        restrictionId: effective.id,
        effectiveUntil: effective.expiresAt,
      };
    }
    await this.emitRestriction(tx, restriction, now);
    return {
      status: 'succeeded',
      providerStatus: 'applied',
      resultCode: 'restriction_applied',
      restrictionId: restriction.id,
      effectiveUntil: expiresAt,
    };
  }

  private async emitRestriction(tx: Tx, r: AtoSmtpRestriction, at: Date): Promise<void> {
    await this.emit(tx, r.organizationId, EventTypes.AtoRestrictionChanged, r.id.toString(), {
      restrictionId: r.id.toString(),
      kind: r.kind,
      scope: r.scope,
      connectorId: r.connectorId?.toString() ?? null,
      mailboxSha256: r.mailboxSha256,
      status: r.status,
      expiresAt: r.expiresAt.toISOString(),
      changedAt: at.toISOString(),
    });
  }

  private async notifyFailure(
    tx: Tx,
    action: AtoResponseAction,
    account: AtoAccount,
  ): Promise<void> {
    await this.requestNotification(tx, {
      organizationId: action.organizationId,
      kind: 'response_failed',
      audience: 'tenant',
      severity: null,
      refs: { actionPublicId: action.publicId, accountPublicId: account.publicId },
      throttle: { kind: 'ato_response_failed', scope: action.publicId, minutes: 60 },
    });
  }

  /**
   * Approves or rejects a pending action (D13): users only (API keys never approve), never the
   * requesting user nor, for a request made with an API key, the user who created that key (four
   * eyes; any user for system requests), before `approval_expires_at`. The
   * api enforces `ato:respond` and the MFA session. Approval executes the action.
   */
  async decideResponse(
    tx: Tx,
    input: {
      organizationId: bigint;
      actionId: bigint;
      decision: 'approve' | 'reject';
      actor: IncidentActor;
      reason?: string | null;
      sourceIp?: string | null;
    },
  ): Promise<AtoResponseAction> {
    const now = this.clock();
    const action = await this.lockAction(tx, input.organizationId, input.actionId);
    if (input.actor.type !== 'user' || !input.actor.id) {
      throw new AtoStoreError('ato_approver_invalid', 'Only users approve or reject responses');
    }
    if (action.status !== 'pending_approval') {
      throw new AtoStoreError('ato_response_state', `Action is ${action.status}`);
    }
    if (action.approvalExpiresAt && action.approvalExpiresAt <= now) {
      await this.expireOne(tx, action);
      throw new AtoStoreError('ato_response_expired', 'The approval window expired');
    }
    if (action.requestedByType === 'user' && action.requestedById === input.actor.id) {
      throw new AtoStoreError('ato_self_approval', 'The requester cannot decide their own request');
    }
    if (await this.isKeyCreator(tx, action, input.actor)) {
      // Four eyes (ADR-0072): a request made with an API key is accountable to the user who created
      // the key, so that user cannot approve or reject it either.
      throw new AtoStoreError('ato_self_approval', 'The key creator cannot decide its request');
    }
    const decided = await this.updateAction(tx, action, {
      status: input.decision === 'approve' ? 'approved' : 'rejected',
      approvedByUserId: input.decision === 'approve' ? (input.actor.userId ?? null) : null,
      decidedAt: now,
      decisionReason: clip(input.reason, 1000),
      ...(input.decision === 'reject' && { completedAt: now }),
    });
    const verb = input.decision === 'approve' ? 'approved' : 'rejected';
    await this.logAction(
      tx,
      decided,
      'authorize',
      input.decision === 'approve' ? 'succeeded' : 'skipped',
    );
    await this.actionTimeline(tx, decided, verb, input.actor, {}, input.reason ?? null);
    await this.actionAudit(tx, decided, verb, input.actor, {}, input.sourceIp);
    if (input.decision === 'reject') {
      await this.emitCompleted(tx, decided, 'execute');
      return decided;
    }
    return this.executeApproved(tx, decided, input.actor);
  }

  /**
   * Whether `actor` (a user) created the API key that requested `action` (`api_keys.
   * created_by_user_id`, the key of the action's organization). A key whose creator was deleted
   * (`SET NULL`) has no accountable user left to compare.
   */
  private async isKeyCreator(
    tx: Tx,
    action: AtoResponseAction,
    actor: IncidentActor,
  ): Promise<boolean> {
    if (action.requestedByType !== 'api_key' || !action.requestedById) return false;
    const key = await tx.apiKey.findUnique({
      where: { publicId: action.requestedById },
      select: {
        organizationId: true,
        createdByUserId: true,
        createdBy: { select: { publicId: true } },
      },
    });
    if (!key || key.organizationId !== action.organizationId || key.createdByUserId === null) {
      return false;
    }
    return (
      (actor.userId !== undefined &&
        actor.userId !== null &&
        key.createdByUserId === actor.userId) ||
      (key.createdBy !== null && actor.id !== null && key.createdBy.publicId === actor.id)
    );
  }

  /** Cancels a pending action (requester or another responder). */
  async cancelResponse(
    tx: Tx,
    input: {
      organizationId: bigint;
      actionId: bigint;
      actor: IncidentActor;
      reason?: string | null;
      sourceIp?: string | null;
    },
  ): Promise<AtoResponseAction> {
    const action = await this.lockAction(tx, input.organizationId, input.actionId);
    if (action.status !== 'pending_approval') {
      throw new AtoStoreError('ato_response_state', `Action is ${action.status}`);
    }
    const done = await this.updateAction(tx, action, {
      status: 'cancelled',
      decidedAt: this.clock(),
      completedAt: this.clock(),
      decisionReason: clip(input.reason, 1000),
    });
    await this.actionTimeline(tx, done, 'cancelled', input.actor, {}, input.reason ?? null);
    await this.actionAudit(tx, done, 'cancelled', input.actor, {}, input.sourceIp);
    await this.emitCompleted(tx, done, 'execute');
    return done;
  }

  private async expireOne(tx: Tx, action: AtoResponseAction): Promise<AtoResponseAction> {
    const done = await this.updateAction(tx, action, {
      status: 'expired',
      completedAt: this.clock(),
    });
    const system: IncidentActor = { type: 'system', id: null };
    await this.actionTimeline(tx, done, 'expired', system);
    await this.actionAudit(tx, done, 'expired', system);
    await this.emitCompleted(tx, done, 'execute');
    return done;
  }

  /** Expires pending approvals past `approval_expires_at` (maintenance role, platform-wide). */
  async expireApprovals(tx: Tx, input: { limit: number }): Promise<number> {
    const now = this.clock();
    const due = await tx.$queryRaw<{ id: bigint; organization_id: bigint }[]>`
      SELECT id, organization_id FROM ato_response_actions
      WHERE status = 'pending_approval' AND approval_expires_at <= ${now}
      ORDER BY approval_expires_at, id
      LIMIT ${input.limit}
      FOR UPDATE SKIP LOCKED`;
    for (const row of due) {
      const action = await tx.atoResponseAction.findUniqueOrThrow({
        where: { id: BigInt(row.id) },
      });
      if (action.status === 'pending_approval') await this.expireOne(tx, action);
    }
    return due.length;
  }

  /**
   * Settles provider actions the respond role gave up on (maintenance role, D15): an `approved`
   * action, or a `rollback_requested` one that is not polled (`next_check_at` null), with no
   * progress since `before` (the `ato.responses` retry horizon, 24 h, has passed: its message was
   * dead-lettered or lost without the consumer's last attempt recording `failed`). Each ends
   * `failed` / `rollback_failed` with `provider_retry_exhausted` (timeline, audit,
   * `ato.response.completed.v1`, `response_failed` notification), which also frees the
   * `active_marker` so a new request for the same incident, type and target is accepted.
   * `organizationIds` restricts the sweep (integration suites); omitted = platform-wide.
   */
  async failStaleProviderActions(
    tx: Tx,
    input: { before: Date; limit: number; organizationIds?: readonly bigint[] },
  ): Promise<number> {
    const ids = input.organizationIds;
    if (ids !== undefined && ids.length === 0) return 0;
    const orgs =
      ids === undefined ? Prisma.empty : Prisma.sql`AND organization_id IN (${Prisma.join(ids)})`;
    const due = await tx.$queryRaw<{ id: bigint; organization_id: bigint }[]>`
      SELECT id, organization_id FROM ato_response_actions
      WHERE ((status = 'approved') OR (status = 'rollback_requested' AND next_check_at IS NULL))
        AND provider NOT IN ('gateway', 'manual')
        AND updated_at <= ${input.before}
        ${orgs}
      ORDER BY updated_at, id
      LIMIT ${input.limit}
      FOR UPDATE SKIP LOCKED`;
    for (const row of due) {
      const action = await tx.atoResponseAction.findUniqueOrThrow({
        where: { id: BigInt(row.id) },
      });
      if (action.organizationId !== BigInt(row.organization_id)) {
        throw new AtoStoreError('ato_inconsistent_read', 'Action read did not echo the key');
      }
      if (action.status !== 'approved' && action.status !== 'rollback_requested') continue;
      await this.completeProviderAction(tx, {
        organizationId: action.organizationId,
        actionId: action.id,
        phase: action.status === 'approved' ? 'execute' : 'rollback',
        result: { status: 'failed', code: 'provider_retry_exhausted', retryable: false },
        final: true,
      });
    }
    return due.length;
  }

  /**
   * Requests a rollback (D13): users only, a `succeeded` action whose type supports rollback.
   * Gateway restrictions are lifted in the same transaction (`rolled_back`); provider actions get
   * `rollback_requested` and `ato.response.requested.v1` (phase rollback).
   */
  async requestRollback(
    tx: Tx,
    input: {
      organizationId: bigint;
      actionId: bigint;
      actor: IncidentActor;
      reason: string;
      sourceIp?: string | null;
    },
  ): Promise<AtoResponseAction> {
    if (input.actor.type !== 'user')
      throw new AtoStoreError('ato_approver_invalid', 'Only users roll back');
    const action = await this.lockAction(tx, input.organizationId, input.actionId);
    if (action.status !== 'succeeded')
      throw new AtoStoreError('ato_response_state', `Action is ${action.status}`);
    if (!supportsRollback(action.actionType as ResponseActionType)) {
      throw new AtoStoreError('ato_rollback_unsupported', 'This action has no rollback');
    }
    const requested = await this.updateAction(tx, action, {
      status: 'rollback_requested',
      rolledBackByUserId: input.actor.userId ?? null,
      rollbackReason: clip(input.reason, 1000),
      completedAt: null,
    });
    await this.actionTimeline(tx, requested, 'rollback_requested', input.actor, {}, input.reason);
    await this.actionAudit(tx, requested, 'rollback_requested', input.actor, {}, input.sourceIp);
    if (RESPONSE_CATALOGUE[action.actionType as ResponseActionType].provider === 'gateway') {
      // A restriction shared with another succeeded action (`restriction_already_active`) stays
      // enforced for that action; it is lifted with the last action that relies on it.
      const sharedBy =
        action.restrictionId === null
          ? 0
          : await tx.atoResponseAction.count({
              where: {
                organizationId: input.organizationId,
                restrictionId: action.restrictionId,
                status: 'succeeded',
                id: { not: action.id },
              },
            });
      if (action.restrictionId !== null && sharedBy === 0) {
        await this.liftRestriction(tx, {
          organizationId: input.organizationId,
          restrictionId: action.restrictionId,
          actor: input.actor,
          reason: input.reason,
        });
      }
      const done = await this.updateAction(tx, requested, {
        status: 'rolled_back',
        completedAt: this.clock(),
        ...(sharedBy > 0 && { resultCode: 'restriction_kept_shared' }),
      });
      await this.logAction(tx, done, 'rollback', 'succeeded', { providerStatus: 'applied' });
      await this.actionTimeline(tx, done, 'rolled_back', input.actor);
      await this.actionAudit(tx, done, 'rolled_back', input.actor, {}, input.sourceIp);
      await this.emitCompleted(tx, done, 'rollback');
      return done;
    }
    await this.emit(
      tx,
      action.organizationId,
      EventTypes.AtoResponseRequested,
      action.id.toString(),
      {
        actionId: action.id.toString(),
        actionPublicId: action.publicId,
        phase: 'rollback',
        actionType: action.actionType,
        provider: action.provider,
        incidentId: action.incidentId?.toString() ?? null,
        accountId: action.accountId.toString(),
        requestedAt: this.clock().toISOString(),
      },
    );
    return requested;
  }

  /**
   * Records a provider result (respond role, D15): `confirmed` → `succeeded` (or `rolled_back`),
   * `pending` → `executing` with `next_check_at`, `unsupported` → `unsupported`, `failed` →
   * `failed` (or `rollback_failed`) unless retryable and `final` is false (logged, state kept).
   */
  async completeProviderAction(
    tx: Tx,
    input: {
      organizationId: bigint;
      actionId: bigint;
      phase: 'execute' | 'rollback';
      result:
        | { status: 'confirmed'; providerReference: string; confirmedAt: string }
        | { status: 'pending'; providerReference: string; pollAfterMs: number }
        | { status: 'unsupported' }
        | { status: 'failed'; code: string; retryable: boolean };
      final?: boolean;
      durationMs?: number;
    },
  ): Promise<AtoResponseAction> {
    const now = this.clock();
    const action = await this.lockAction(tx, input.organizationId, input.actionId);
    const system: IncidentActor = { type: 'system', id: null };
    const allowed =
      input.phase === 'execute'
        ? action.status === 'approved' || action.status === 'executing'
        : action.status === 'rollback_requested';
    if (!allowed) return action; // a redelivered result of an already settled action
    const r = input.result;
    const phaseLog =
      input.phase === 'execute'
        ? action.status === 'executing'
          ? 'confirm'
          : 'execute'
        : 'rollback';
    let data: Prisma.AtoResponseActionUncheckedUpdateInput;
    let event: string;
    if (r.status === 'confirmed') {
      data =
        input.phase === 'execute'
          ? {
              status: 'succeeded',
              providerStatus: 'confirmed',
              providerReference: clip(r.providerReference, 128),
              completedAt: now,
              executedAt: action.executedAt ?? now,
              nextCheckAt: null,
              resultCode: 'provider_confirmed',
            }
          : {
              status: 'rolled_back',
              providerStatus: 'confirmed',
              completedAt: now,
              nextCheckAt: null,
              resultCode: 'provider_confirmed',
            };
      event = input.phase === 'execute' ? 'succeeded' : 'rolled_back';
    } else if (r.status === 'pending') {
      data = {
        ...(input.phase === 'execute' && {
          status: 'executing',
          executedAt: action.executedAt ?? now,
        }),
        providerStatus: 'pending',
        providerReference: clip(r.providerReference, 128),
        nextCheckAt: new Date(now.getTime() + Math.max(1000, r.pollAfterMs)),
      };
      event = 'pending';
    } else if (r.status === 'unsupported') {
      data =
        input.phase === 'execute' && action.status === 'approved'
          ? {
              status: 'unsupported',
              providerStatus: 'unsupported',
              resultCode: 'provider_unsupported',
              completedAt: now,
            }
          : input.phase === 'execute'
            ? {
                status: 'failed',
                providerStatus: 'unsupported',
                resultCode: 'provider_unsupported',
                completedAt: now,
              }
            : {
                status: 'rollback_failed',
                providerStatus: 'unsupported',
                resultCode: 'provider_unsupported',
                completedAt: now,
              };
      event =
        input.phase === 'execute'
          ? action.status === 'approved'
            ? 'unsupported'
            : 'failed'
          : 'rollback_failed';
    } else {
      if (r.retryable && input.final !== true) {
        const kept = await this.updateAction(tx, action, { attempts: { increment: 1 } });
        await this.logAction(tx, kept, phaseLog, 'retry_scheduled', {
          errorCode: r.code,
          durationMs: input.durationMs,
        });
        return kept;
      }
      data =
        input.phase === 'execute'
          ? {
              status: 'failed',
              providerStatus: 'failed',
              resultCode: clip(r.code, 64),
              completedAt: now,
              nextCheckAt: null,
            }
          : {
              status: 'rollback_failed',
              providerStatus: 'failed',
              resultCode: clip(r.code, 64),
              completedAt: now,
              nextCheckAt: null,
            };
      event = input.phase === 'execute' ? 'failed' : 'rollback_failed';
    }
    const done = await this.updateAction(tx, action, { ...data, attempts: { increment: 1 } });
    await this.logAction(
      tx,
      done,
      phaseLog,
      r.status === 'confirmed'
        ? 'succeeded'
        : r.status === 'pending'
          ? 'pending'
          : r.status === 'unsupported'
            ? 'unsupported'
            : 'failed',
      {
        providerStatus: done.providerStatus,
        errorCode: r.status === 'failed' ? r.code : null,
        durationMs: input.durationMs,
      },
    );
    if (event !== 'pending') {
      await this.actionTimeline(tx, done, event, system, { resultCode: done.resultCode });
      await this.actionAudit(tx, done, event, system, { resultCode: done.resultCode });
      await this.emitCompleted(tx, done, input.phase);
      if (event === 'failed' || event === 'rollback_failed') {
        const account = await tx.atoAccount.findUniqueOrThrow({ where: { id: done.accountId } });
        await this.notifyFailure(tx, done, account);
      }
    }
    return done;
  }

  // =================================================================== restrictions

  /** Lifts an active restriction (rollback or an analyst), with `ato.restriction.changed.v1`. */
  async liftRestriction(
    tx: Tx,
    input: { organizationId: bigint; restrictionId: bigint; actor: IncidentActor; reason: string },
  ): Promise<AtoSmtpRestriction> {
    const now = this.clock();
    const r = await tx.atoSmtpRestriction.findFirst({
      where: { id: input.restrictionId, organizationId: input.organizationId },
    });
    if (!r) throw new AtoStoreError('ato_restriction_not_found', 'Restriction not found');
    if (r.status !== 'active') return r;
    const lifted = await tx.atoSmtpRestriction.update({
      where: { id: r.id },
      data: {
        status: 'lifted',
        liftedAt: now,
        liftedByType: input.actor.type === 'system' ? 'system' : 'user',
        liftedById: input.actor.id,
        liftReason: clip(input.reason, 512),
      },
    });
    await this.emitRestriction(tx, lifted, now);
    await this.audit(tx, {
      organizationId: input.organizationId,
      actor: input.actor,
      action: 'ato.restriction_lifted',
      resourceType: 'ato_restriction',
      resourceId: lifted.publicId,
      metadata: { kind: lifted.kind, scope: lifted.scope },
    });
    return lifted;
  }

  /** Expires restrictions past `expires_at` (maintenance role, platform-wide). */
  async expireRestrictions(tx: Tx, input: { limit: number }): Promise<number> {
    const now = this.clock();
    const due = await tx.$queryRaw<{ id: bigint }[]>`
      SELECT id FROM ato_smtp_restrictions
      WHERE status = 'active' AND expires_at <= ${now}
      ORDER BY expires_at, id
      LIMIT ${input.limit}
      FOR UPDATE SKIP LOCKED`;
    for (const row of due) {
      const r = await tx.atoSmtpRestriction.findUniqueOrThrow({ where: { id: BigInt(row.id) } });
      if (r.status === 'active') await this.expireRestriction(tx, r, now);
    }
    return due.length;
  }

  /** Marks a locked active restriction past `expires_at` as `expired` (`ato.restriction.changed.v1`). */
  private async expireRestriction(
    tx: Tx,
    r: AtoSmtpRestriction,
    now: Date,
  ): Promise<AtoSmtpRestriction> {
    const expired = await tx.atoSmtpRestriction.update({
      where: { id: r.id },
      data: { status: 'expired', liftedByType: 'system', liftReason: 'expired' },
    });
    await this.emitRestriction(tx, expired, now);
    return expired;
  }

  // =================================================================== overrides, trusted contexts, protection

  /** Sets an analyst override (benign or compromised), replacing an active one, and rescores. */
  async setOverride(
    tx: Tx,
    input: {
      organizationId: bigint;
      accountId: bigint;
      verdict: 'benign' | 'compromised';
      reason: string;
      expiresAt: Date;
      actor: IncidentActor;
      sourceIp?: string | null;
    },
  ): Promise<{ overridePublicId: string; rescore: RescoreResult }> {
    const now = this.clock();
    const reason = input.reason.trim();
    if (reason.length < 1 || reason.length > 1000)
      throw new AtoStoreError('ato_override_invalid', 'Reason 1-1000 characters');
    if (input.expiresAt <= now || input.expiresAt.getTime() - now.getTime() > 90 * 86_400_000) {
      throw new AtoStoreError('ato_override_invalid', 'Expiry within 90 days');
    }
    const account = await this.requireAccount(tx, input.organizationId, input.accountId);
    if (account.overrideId !== null) {
      await tx.atoRiskOverride.updateMany({
        where: { id: account.overrideId, clearedAt: null },
        data: {
          clearedAt: now,
          clearedByUserId: input.actor.userId ?? null,
          clearReason: 'replaced',
        },
      });
    }
    const created = await tx.atoRiskOverride.create({
      data: {
        organizationId: input.organizationId,
        accountId: account.id,
        verdict: input.verdict,
        reason,
        expiresAt: input.expiresAt,
        createdByUserId: input.actor.userId ?? null,
        createdAt: now,
      },
    });
    await tx.atoAccount.update({
      where: { id: account.id },
      data: { overrideId: created.id },
      select: { id: true },
    });
    if (account.activeIncidentId !== null) {
      await this.incidents.recordEvent(tx, {
        organizationId: input.organizationId,
        incidentId: account.activeIncidentId,
        eventType: 'ato.override_set',
        actor: input.actor,
        note: reason,
        details: {
          overridePublicId: created.publicId,
          verdict: input.verdict,
          expiresAt: input.expiresAt.toISOString(),
        },
      });
    }
    await this.audit(tx, {
      organizationId: input.organizationId,
      actor: input.actor,
      action: 'ato.override_set',
      resourceType: 'ato_account',
      resourceId: account.publicId,
      sourceIp: input.sourceIp ?? null,
      metadata: {
        overridePublicId: created.publicId,
        verdict: input.verdict,
        expiresAt: input.expiresAt,
      },
    });
    const settings = await this.ensureSettings(tx, input.organizationId);
    const rescore = await this.rescore(tx, {
      organizationId: input.organizationId,
      accountId: account.id,
      trigger: 'override',
      settings,
    });
    return { overridePublicId: created.publicId, rescore };
  }

  /** Clears the active override and rescores. */
  async clearOverride(
    tx: Tx,
    input: {
      organizationId: bigint;
      accountId: bigint;
      reason: string;
      actor: IncidentActor;
      sourceIp?: string | null;
    },
  ): Promise<RescoreResult | null> {
    const now = this.clock();
    const account = await this.requireAccount(tx, input.organizationId, input.accountId);
    if (account.overrideId === null) return null;
    const override = await tx.atoRiskOverride.findUniqueOrThrow({
      where: { id: account.overrideId },
    });
    await tx.atoRiskOverride.update({
      where: { id: override.id },
      data: {
        clearedAt: now,
        clearedByUserId: input.actor.userId ?? null,
        clearReason: clip(input.reason, 1000),
      },
    });
    await tx.atoAccount.update({
      where: { id: account.id },
      data: { overrideId: null },
      select: { id: true },
    });
    if (account.activeIncidentId !== null) {
      await this.incidents.recordEvent(tx, {
        organizationId: input.organizationId,
        incidentId: account.activeIncidentId,
        eventType: 'ato.override_cleared',
        actor: input.actor,
        note: input.reason,
        details: { overridePublicId: override.publicId },
      });
    }
    await this.audit(tx, {
      organizationId: input.organizationId,
      actor: input.actor,
      action: 'ato.override_cleared',
      resourceType: 'ato_account',
      resourceId: account.publicId,
      sourceIp: input.sourceIp ?? null,
      metadata: { overridePublicId: override.publicId },
    });
    const settings = await this.ensureSettings(tx, input.organizationId);
    return this.rescore(tx, {
      organizationId: input.organizationId,
      accountId: account.id,
      trigger: 'override',
      settings,
    });
  }

  /** Normalizes and validates a trusted-context value; throws on an invalid one. */
  normalizeTrustedContext(
    kind: 'ip_cidr' | 'asn' | 'country' | 'device',
    value: string,
  ): {
    value: string;
    ipVersion: number | null;
    start: Buffer | null;
    end: Buffer | null;
  } {
    const bad = () => new AtoStoreError('ato_trusted_context_invalid', `Invalid ${kind} value`);
    switch (kind) {
      case 'ip_cidr': {
        const parsed = parseCidr(value.trim(), { minV4Prefix: 8, minV6Prefix: 32 });
        if (!parsed) throw bad();
        return {
          value: parsed.cidr,
          ipVersion: parsed.version,
          start: parsed.start,
          end: parsed.end,
        };
      }
      case 'asn': {
        const v = value.trim().replace(/^as/i, '');
        if (!/^[1-9][0-9]{0,9}$/.test(v) || Number(v) > 4294967295) throw bad();
        return { value: v, ipVersion: null, start: null, end: null };
      }
      case 'country': {
        const v = value.trim().toUpperCase();
        if (!/^[A-Z]{2}$/.test(v)) throw bad();
        return { value: v, ipVersion: null, start: null, end: null };
      }
      case 'device': {
        const v = value.trim().toLowerCase();
        if (!/^[0-9a-f]{16}$/.test(v)) throw bad();
        return { value: v, ipVersion: null, start: null, end: null };
      }
    }
  }

  /** Adds (or renews) a trusted context of an account (expiry ≤ 365 days). */
  async addTrustedContext(
    tx: Tx,
    input: {
      organizationId: bigint;
      accountId: bigint;
      kind: 'ip_cidr' | 'asn' | 'country' | 'device';
      value: string;
      reason: string;
      expiresAt: Date;
      source: 'analyst' | 'false_positive_feedback';
      incidentId?: bigint | null;
      actor: IncidentActor;
      sourceIp?: string | null;
    },
  ): Promise<{ publicId: string }> {
    const now = this.clock();
    if (input.expiresAt <= now || input.expiresAt.getTime() - now.getTime() > 365 * 86_400_000) {
      throw new AtoStoreError('ato_trusted_context_invalid', 'Expiry within 365 days');
    }
    const reason = input.reason.trim().slice(0, 512);
    if (reason.length === 0)
      throw new AtoStoreError('ato_trusted_context_invalid', 'A reason is required');
    const normalized = this.normalizeTrustedContext(input.kind, input.value);
    const account = await this.requireAccount(tx, input.organizationId, input.accountId);
    const existing = await tx.atoTrustedContext.findUnique({
      where: {
        accountId_kind_value: { accountId: account.id, kind: input.kind, value: normalized.value },
      },
    });
    const row = existing
      ? await tx.atoTrustedContext.update({
          where: { id: existing.id },
          data: {
            expiresAt: input.expiresAt,
            reason,
            source: input.source,
            incidentId: input.incidentId ?? null,
          },
        })
      : await tx.atoTrustedContext.create({
          data: {
            organizationId: input.organizationId,
            accountId: account.id,
            kind: input.kind,
            value: normalized.value,
            ipVersion: normalized.ipVersion,
            rangeStart: normalized.start ? new Uint8Array(normalized.start) : null,
            rangeEnd: normalized.end ? new Uint8Array(normalized.end) : null,
            reason,
            source: input.source,
            incidentId: input.incidentId ?? null,
            createdByUserId: input.actor.userId ?? null,
            createdAt: now,
            expiresAt: input.expiresAt,
          },
        });
    await this.audit(tx, {
      organizationId: input.organizationId,
      actor: input.actor,
      action: 'ato.trusted_context_added',
      resourceType: 'ato_account',
      resourceId: account.publicId,
      sourceIp: input.sourceIp ?? null,
      metadata: {
        contextPublicId: row.publicId,
        kind: input.kind,
        source: input.source,
        expiresAt: input.expiresAt,
      },
    });
    return { publicId: row.publicId };
  }

  /** Removes a trusted context (the audit row keeps the trail). */
  async removeTrustedContext(
    tx: Tx,
    input: {
      organizationId: bigint;
      publicId: string;
      actor: IncidentActor;
      sourceIp?: string | null;
    },
  ): Promise<void> {
    const row = await tx.atoTrustedContext.findUnique({ where: { publicId: input.publicId } });
    if (!row || row.organizationId !== input.organizationId) {
      throw new AtoStoreError('ato_trusted_context_not_found', 'Trusted context not found');
    }
    await tx.atoTrustedContext.delete({ where: { id: row.id } });
    const account = await tx.atoAccount.findUniqueOrThrow({
      where: { id: row.accountId },
      select: { publicId: true },
    });
    await this.audit(tx, {
      organizationId: input.organizationId,
      actor: input.actor,
      action: 'ato.trusted_context_removed',
      resourceType: 'ato_account',
      resourceId: account.publicId,
      sourceIp: input.sourceIp ?? null,
      metadata: { contextPublicId: row.publicId, kind: row.kind },
    });
  }

  /** Unexpired trusted contexts of an account (rule context). */
  async trustedContexts(
    tx: Tx,
    organizationId: bigint,
    accountId: bigint,
  ): Promise<TrustedContextView[]> {
    const rows = await tx.atoTrustedContext.findMany({
      where: { organizationId, accountId, expiresAt: { gt: this.clock() } },
      orderBy: { id: 'asc' },
      take: 500,
    });
    return rows.map((r) => ({ kind: r.kind, value: r.value, expiresAt: r.expiresAt }));
  }

  /** Marks an account protected (never acted on automatically) or clears the mark. */
  async setProtected(
    tx: Tx,
    input: {
      organizationId: bigint;
      accountId: bigint;
      protected: boolean;
      reason: string | null;
      actor: IncidentActor;
      sourceIp?: string | null;
    },
  ): Promise<AtoAccount> {
    const account = await this.requireAccount(tx, input.organizationId, input.accountId);
    const updated = await tx.atoAccount.update({
      where: { id: account.id },
      data: input.protected
        ? {
            protected: true,
            protectedReason: clip(input.reason, 512),
            protectedByUserId: input.actor.userId ?? null,
            protectedAt: this.clock(),
          }
        : { protected: false, protectedReason: null, protectedByUserId: null, protectedAt: null },
    });
    await this.audit(tx, {
      organizationId: input.organizationId,
      actor: input.actor,
      action: input.protected ? 'ato.account_protected' : 'ato.account_unprotected',
      resourceType: 'ato_account',
      resourceId: account.publicId,
      sourceIp: input.sourceIp ?? null,
      metadata: {},
    });
    return updated;
  }

  // =================================================================== automation

  /**
   * Whether a detection of this organization at `level` could execute a medium/high-impact action
   * automatically (platform switch on, tenant `enforce`, an `automatic` medium/high type whose
   * `minLevel` the level reaches). The detect role then calls `lockAutomation` before the incident
   * policy, so the organization-level locks are always taken in the order automation row →
   * notification windows (no deadlock with `runAutomation`'s own notifications).
   */
  automationMayExecute(settings: LoadedSettings, level: AtoRiskLevel): boolean {
    const s = settings.settings;
    if (!this.config.automatedResponsesEnabled || s.mode !== 'enforce') return false;
    return AUTOMATABLE_ACTION_TYPES.some((type) => {
      const a = s.automation[type];
      const mayBeMediumOrHigh =
        RESPONSE_CATALOGUE[type].impact !== 'low' || type === 'block_smtp_auth';
      return (
        mayBeMediumOrHigh &&
        a.mode === 'automatic' &&
        atoRiskLevelRank(level) >= atoRiskLevelRank(a.minLevel)
      );
    });
  }

  /**
   * Serializes the automatic medium/high-impact responses of an organization (D13 hourly caps): an
   * exclusive lock on its `ato_settings` row (created when missing) until the transaction ends.
   * Under READ COMMITTED the count read after the wait sees every action the previous holder
   * committed.
   */
  async lockAutomation(tx: Tx, organizationId: bigint): Promise<void> {
    const lock = () => tx.$queryRaw<{ organization_id: bigint }[]>`
      SELECT organization_id FROM ato_settings WHERE organization_id = ${organizationId} FOR UPDATE`;
    if ((await lock()).length > 0) return;
    await this.ensureSettings(tx, organizationId);
    if ((await lock()).length === 0) {
      throw new AtoStoreError('ato_inconsistent_read', 'Settings row missing after creation');
    }
  }

  /**
   * Runs the automation of D13 for an incident's recommendations (detect transaction): `off` and
   * `recommend` types create nothing (recommendations only); `automatic` low-impact actions execute;
   * `automatic` medium/high actions execute only when `automationDecision` allows it, otherwise they
   * are created `pending_approval` with the guard reason. Returns the created actions and reasons.
   */
  async runAutomation(
    tx: Tx,
    input: {
      organizationId: bigint;
      accountId: bigint;
      incident: IncidentRow;
      recommendations: readonly Recommendation[];
      contributors: readonly Contributor[];
      settings: LoadedSettings;
      platformOrganization: boolean;
      providerKind?: string | null;
    },
  ): Promise<
    Array<{
      action: AtoResponseAction | null;
      actionType: string;
      guard: AutomationGuardReason | null;
    }>
  > {
    const out: Array<{
      action: AtoResponseAction | null;
      actionType: string;
      guard: AutomationGuardReason | null;
    }> = [];
    const s = input.settings.settings;
    const account = await this.requireAccount(tx, input.organizationId, input.accountId);
    let automationLocked = false;
    const override =
      account.overrideId === null
        ? null
        : await tx.atoRiskOverride.findUnique({ where: { id: account.overrideId } });
    const benignOverride =
      override !== null &&
      override.verdict === 'benign' &&
      override.clearedAt === null &&
      override.contradictedAt === null &&
      override.expiresAt > this.clock();
    for (const rec of input.recommendations) {
      if (rec.actionType === 'policy_hold_outbound' || rec.actionType === 'record_manual_action')
        continue;
      if (rec.availability !== 'available' || rec.target === null) continue;
      const type = rec.actionType;
      const automation = s.automation[type];
      if (automation.mode !== 'automatic') continue;
      const impact = impactFor(type, rec.target);
      if (impact !== 'low' && !automationLocked) {
        // The hourly caps count the organization's automatic actions: serialize that count and the
        // action it allows per organization (D13 blast radius), or concurrent detections of
        // different accounts would each see the same count. Usually already held (lockAutomation
        // before the incident policy); re-locking a held row is a no-op.
        await this.lockAutomation(tx, input.organizationId);
        automationLocked = true;
      }
      const since = new Date(this.clock().getTime() - 3_600_000);
      const automaticLastHour =
        impact === 'low'
          ? 0
          : await tx.atoResponseAction.count({
              where: {
                organizationId: input.organizationId,
                authorization: 'automation_policy',
                createdAt: { gte: since },
              },
            });
      const decision = automationDecision({
        impact,
        tenantMode: s.mode,
        automation: { mode: automation.mode, minLevel: automation.minLevel },
        level: account.riskLevel,
        contributors: input.contributors,
        account: {
          protected: account.protected,
          benignOverride,
          platformOrganization: input.platformOrganization,
        },
        automaticLastHour,
        tenantMaxPerHour: s.automation.maxAutomaticPerHour,
        platformMaxPerHour: this.config.maxAutomatedPerOrgPerHour,
        globallyEnabled: this.config.automatedResponsesEnabled,
      });
      const guard = decision.automatic ? null : decision.reason;
      try {
        const action = await this.requestResponse(tx, {
          organizationId: input.organizationId,
          accountId: account.id,
          incidentId: input.incident.id,
          actionType: type,
          target: rec.target,
          params: { durationMinutes: automation.durationMinutes, mode: s.restrictions.defaultMode },
          actor: { type: 'system', id: null },
          reason: `Automation for ${rec.reason}`,
          authorization: decision.automatic
            ? impact === 'low'
              ? 'low_impact_default'
              : 'automation_policy'
            : 'manual',
          providerKind: input.providerKind ?? null,
          guardReason: guard,
        });
        out.push({ action, actionType: type, guard });
      } catch (error) {
        if (error instanceof AtoStoreError && error.code === 'ato_response_active') {
          out.push({ action: null, actionType: type, guard });
          continue;
        }
        throw error;
      }
    }
    return out;
  }

  // =================================================================== notifications

  /**
   * Requests an ATO notification (D16): the first event of a throttle window
   * (`notification_alert_windows`) writes `ato.notification.requested.v1`; later events only count.
   * Returns the event id or null when suppressed.
   */
  async requestNotification(tx: Tx, input: NotificationInput): Promise<string | null> {
    const now = this.clock();
    const ms = Math.max(1, input.throttle.minutes) * 60_000;
    const start = input.throttle.windowStart ?? new Date(Math.floor(now.getTime() / ms) * ms);
    const end = new Date(start.getTime() + ms);
    const sourceId = uuidv7(now.getTime());
    const scope = input.throttle.scope.slice(0, 64);
    const kind = input.throttle.kind.slice(0, 32);
    const affected = await tx.$executeRaw`
      INSERT INTO notification_alert_windows
        (organization_id, kind, scope_key, window_start, event_count, first_source_event_id, updated_at)
      VALUES (${input.organizationId}, ${kind}, ${scope}, ${start}, 1, ${sourceId}, ${now})
      ON DUPLICATE KEY UPDATE event_count = event_count + 1, updated_at = VALUES(updated_at)`;
    if (affected !== 1) return null;
    const previous = await tx.notificationAlertWindow.findUnique({
      where: {
        organizationId_kind_scopeKey_windowStart: {
          organizationId: input.organizationId,
          kind,
          scopeKey: scope,
          windowStart: new Date(start.getTime() - ms),
        },
      },
      select: { eventCount: true },
    });
    const eventId = await this.emit(
      tx,
      input.organizationId,
      EventTypes.AtoNotificationRequested,
      input.organizationId.toString(),
      {
        kind: input.kind,
        audience: input.audience,
        severity: input.severity,
        refs: input.refs,
        window: { from: start.toISOString(), to: end.toISOString() },
        counts: {
          suppressedBefore: Math.max(0, (previous?.eventCount ?? 1) - 1),
          ...(input.counts ?? {}),
        },
        digestPeriod: input.digestPeriod ?? null,
        requestedAt: now.toISOString(),
      },
    );
    await tx.notificationAlertWindow.update({
      where: {
        organizationId_kind_scopeKey_windowStart: {
          organizationId: input.organizationId,
          kind,
          scopeKey: scope,
          windowStart: start,
        },
      },
      data: { alertEventId: eventId },
    });
    return eventId;
  }

  // =================================================================== retention

  /**
   * Deletes closed `account_takeover` incidents resolved before `before` with their events, links,
   * details (cascade) and response actions (logs cascade) (D22, `ATO_RETENTION_INCIDENT_DAYS`).
   */
  async purgeClosedIncidents(tx: Tx, input: { before: Date; limit: number }): Promise<number> {
    const rows = await tx.securityIncident.findMany({
      where: {
        category: ATO_INCIDENT_CATEGORY,
        status: { in: ['false_positive', 'resolved'] },
        resolvedAt: { lt: input.before },
      },
      orderBy: { resolvedAt: 'asc' },
      take: input.limit,
      select: { id: true },
    });
    if (rows.length === 0) return 0;
    const ids = rows.map((r) => r.id);
    await tx.atoResponseAction.deleteMany({ where: { incidentId: { in: ids } } });
    const deleted = await tx.securityIncident.deleteMany({ where: { id: { in: ids } } });
    return deleted.count;
  }

  /** Deletes action logs and cleared overrides older than `before` (730 days, D22). */
  async purgeHistory(
    tx: Tx,
    input: { before: Date; limit: number },
  ): Promise<{ logs: number; overrides: number }> {
    const logs =
      await tx.$executeRaw`DELETE FROM ato_response_action_logs WHERE created_at < ${input.before} LIMIT ${input.limit}`;
    const overrides = await tx.$executeRaw`
      DELETE FROM ato_risk_overrides WHERE cleared_at IS NOT NULL AND cleared_at < ${input.before} LIMIT ${input.limit}`;
    return { logs, overrides };
  }

  // =================================================================== events and audit

  /** Registry-validated outbox insert (D2). Returns the event id. */
  emit(
    tx: Tx,
    organizationId: bigint,
    eventType: string,
    aggregateId: string,
    payload: unknown,
  ): Promise<string> {
    return insertRegisteredOutboxRow(tx, {
      organizationId,
      eventType,
      aggregateId,
      payload,
      at: this.clock(),
    });
  }

  /** One `audit_logs` row (mirrors `AuditService.record`). */
  audit(tx: Tx, entry: LibraryAuditEntry): Promise<void> {
    return writeAuditRow(tx, entry);
  }
}

/** In-memory form of an `ato_account_activity_daily` row. */
export function activityFromRow(row: {
  dayStart: Date;
  authSuccess: number;
  authFailure: number;
  messages: number;
  recipients: number;
  externalRecipients: number;
  internalRecipients: number;
  attachments: number;
  findings: number;
  maxHourMessages: number;
  hourCounts: Prisma.JsonValue;
  ipPrefixes: Prisma.JsonValue;
  recipientDomains: Prisma.JsonValue;
  attachmentTypes: Prisma.JsonValue;
  peers: Prisma.JsonValue;
  content: Prisma.JsonValue;
}): ActivityDayRow {
  const arr = <T>(v: Prisma.JsonValue): T[] => (Array.isArray(v) ? (v as unknown as T[]) : []);
  const hours = arr<{ m: number; a: number }>(row.hourCounts);
  return {
    dayStart: row.dayStart,
    authSuccess: row.authSuccess,
    authFailure: row.authFailure,
    messages: row.messages,
    recipients: row.recipients,
    externalRecipients: row.externalRecipients,
    internalRecipients: row.internalRecipients,
    attachments: row.attachments,
    findings: row.findings,
    maxHourMessages: row.maxHourMessages,
    hourCounts: hours.length === 24 ? hours : emptyActivityDay(row.dayStart).hourCounts,
    ipPrefixes: arr(row.ipPrefixes),
    recipientDomains: arr(row.recipientDomains),
    attachmentTypes: arr(row.attachmentTypes),
    peers: arr(row.peers),
    content:
      row.content && typeof row.content === 'object' && !Array.isArray(row.content)
        ? row.content
        : {},
  };
}
