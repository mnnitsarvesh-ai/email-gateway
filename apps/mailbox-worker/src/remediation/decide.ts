import { uuidv7 } from '@email-gateway/common';
import type { ApiCopyRemediationState, IntegrationProvider, Prisma } from '@email-gateway/database';
import {
  buildDecisionRecord,
  decideRemediation,
  remediationActionKey,
  type ApiCopyStatus,
  type DomainEffectiveMode,
  type MessageVerdict,
  type RemediationAction,
  type RemediationDecision,
  type RemediationInput,
  type RiskLevel,
} from '@email-gateway/mailbox-api';
import { mailboxProfileOf } from '../domain/connections';
import type { CounterDelta } from '../runtime/redis-stores';
import { big, bool, type Db } from '../shared/db';
import { InconsistentReadError } from '../shared/errors';
import type { RemediationPolicyLoader } from './policy-loader';

/** What the decision step did for one copy (counters and metrics follow the commit). */
export type DecisionResult =
  | { kind: 'none' }
  /** The copy already has a remediation in flight, done or reversed (R4 last paragraph). */
  | { kind: 'unchanged' }
  | {
      kind: 'skipped' | 'simulated' | 'pending';
      apiConnectionId: bigint;
      provider: IntegrationProvider;
      action: RemediationAction;
      /** False when the unique `action_key` already existed (nothing written). */
      inserted: boolean;
      counters: CounterDelta;
    };

/** The copy row the decision reads (inside the copies transaction that wrote it). */
export interface DecisionCopy {
  id: bigint;
  receivedAt: Date;
  publicId: string;
  organizationId: bigint;
  apiConnectionId: bigint;
  mailboxId: bigint;
  messageId: bigint;
  status: ApiCopyStatus;
  verdict: MessageVerdict | null;
  riskScore: number | null;
  verdictAuthority: 'copy' | 'inline';
  verdictAt: Date | null;
  remediationState: ApiCopyRemediationState;
  remediationGeneration: number;
}

/** States in which a new policy decision leaves the copy alone (R4, R5.5, API2-15). */
const DECIDED_STATES: readonly ApiCopyRemediationState[] = ['pending', 'remediated', 'restored'];

interface ConnectionFacts {
  provider: IntegrationProvider;
  paused: boolean;
  grantActive: boolean;
}

/** Per-transaction memo: one event's copies share their connection and organization facts. */
export interface DecisionMemo {
  connections: Map<bigint, ConnectionFacts>;
  domainModes: Map<string, DomainEffectiveMode | null>;
}

export const newDecisionMemo = (): DecisionMemo => ({
  connections: new Map(),
  domainModes: new Map(),
});

/** The latest revision of the copy's scan round (`message_risk_scores`), or null. */
export interface RoundRisk {
  level: RiskLevel | null;
  hardBlocks: string[];
}

/** Hard-block ids of a stored risk row (`[{ id, verdict, action }]`; plain strings tolerated). */
export function hardBlockIds(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const ids: string[] = [];
  for (const item of raw) {
    const id =
      typeof item === 'string'
        ? item
        : item && typeof item === 'object' && typeof (item as { id?: unknown }).id === 'string'
          ? (item as { id: string }).id
          : null;
    if (id !== null && /^[a-z0-9_.:-]{1,64}$/.test(id) && !ids.includes(id)) ids.push(id);
  }
  return ids;
}

/** Reads the copy row for the decision (organization echo-checked). */
export async function loadDecisionCopy(
  db: Db,
  key: { id: bigint; receivedAt: Date; organizationId: bigint },
): Promise<DecisionCopy | null> {
  const row = await db.apiMessageCopy.findUnique({
    where: { id_receivedAt: { id: key.id, receivedAt: key.receivedAt } },
    select: {
      id: true,
      receivedAt: true,
      publicId: true,
      organizationId: true,
      apiConnectionId: true,
      mailboxId: true,
      messageId: true,
      status: true,
      verdict: true,
      riskScore: true,
      verdictAuthority: true,
      verdictAt: true,
      remediationState: true,
      remediationGeneration: true,
    },
  });
  if (!row) return null;
  if (row.organizationId !== key.organizationId) {
    throw new InconsistentReadError('api_message_copies');
  }
  return row;
}

/** R4 step 1: the round's latest risk row, by message, scan and highest revision. */
export async function loadRoundRisk(
  db: Db,
  copy: Pick<DecisionCopy, 'messageId' | 'receivedAt' | 'organizationId'>,
  scanId: string | null,
): Promise<RoundRisk | null> {
  if (scanId === null || !/^[1-9][0-9]{0,19}$/.test(scanId)) return null;
  const rows = await db.$queryRaw<
    Array<{ organization_id: bigint | number; level: RiskLevel | null; hard_blocks: unknown }>
  >`
    SELECT organization_id, level, hard_blocks FROM message_risk_scores
    WHERE message_id = ${copy.messageId} AND received_at = ${copy.receivedAt}
      AND scan_id = ${BigInt(scanId)}
    ORDER BY revision DESC
    LIMIT 1`;
  const row = rows[0];
  if (!row) return null;
  if (big(row.organization_id) !== copy.organizationId) {
    throw new InconsistentReadError('message_risk_scores');
  }
  const blocks = typeof row.hard_blocks === 'string' ? safeJson(row.hard_blocks) : row.hard_blocks;
  return { level: row.level ?? null, hardBlocks: hardBlockIds(blocks) };
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

/**
 * The decision step of the copies role (step API-2 R4, ADR-0101): after a copy row was recorded
 * or finalized, **inside the same ledger transaction**, the copy's verdict and its round's risk
 * row are run through the effective remediation policy (R2.6) with the connection's pause flag,
 * the mailbox-access grant, the domain's effective mode and the mailbox status
 * (`decideRemediation`, R2.2):
 *
 * - `none` → nothing (the copy keeps `remediation_state = none`);
 * - `skip` → an action row `skipped` with the reason (`INSERT IGNORE` on `action_key`), copy
 *   `skipped`;
 * - simulated (detect-only) → an action row `simulated`, copy `simulated` (no provider call ever);
 * - `act` → an action row `pending` due now, copy `pending` with `remediation_action` and
 *   `last_action_id`; the `remediate` role executes it.
 *
 * A copy whose remediation is pending, done or reversed is left alone (late verdicts are not
 * re-decided in API-2, API2-15). Content-free: ids, enums, codes and the decision record (R2.4).
 */
export class RemediationDecider {
  constructor(
    private readonly deps: {
      policies: RemediationPolicyLoader;
      hardDeleteEnabled: boolean;
    },
  ) {}

  async decide(
    tx: Prisma.TransactionClient,
    copy: DecisionCopy,
    scanId: string | null,
    now: Date,
    memo: DecisionMemo = newDecisionMemo(),
  ): Promise<DecisionResult> {
    if (DECIDED_STATES.includes(copy.remediationState)) return { kind: 'unchanged' };
    // Cheap exits first: nothing to remediate (R2.2 step 1) needs no context reads.
    if (copy.status !== 'scanned' || copy.verdict === null || copy.verdict === 'clean') {
      return { kind: 'none' };
    }
    if (copy.verdict === 'unknown') return { kind: 'none' };

    const mailbox = await tx.apiMailbox.findUnique({
      where: { id: copy.mailboxId },
      select: { organizationId: true, apiConnectionId: true, status: true, domainId: true },
    });
    if (!mailbox || mailbox.organizationId !== copy.organizationId) {
      throw new InconsistentReadError('api_mailboxes');
    }
    const connection = await this.connectionFacts(tx, copy, memo);
    const risk = await loadRoundRisk(tx, copy, scanId);
    const domainEffectiveMode = await this.domainMode(
      tx,
      copy.organizationId,
      mailbox.domainId,
      memo,
    );
    const effective = await this.deps.policies.effective(tx, copy.organizationId, mailbox.domainId);
    const input: RemediationInput = {
      copy: {
        status: copy.status,
        verdict: copy.verdict,
        riskScore: copy.riskScore,
        verdictAuthority: copy.verdictAuthority,
      },
      risk,
      policyOutcome: null,
      context: {
        provider: connection.provider,
        grantActive: connection.grantActive,
        remediationPaused: connection.paused,
        domainEffectiveMode,
        mailboxStatus: mailbox.status,
      },
    };
    const decision: RemediationDecision = decideRemediation(input, effective.policy, {
      hardDeleteEnabled: this.deps.hardDeleteEnabled,
    });
    if (decision.outcome === 'none') return { kind: 'none' };
    const record = buildDecisionRecord(effective, input, decision);
    const action = decision.action as RemediationAction;
    const kind: 'skipped' | 'simulated' | 'pending' =
      decision.outcome === 'skip' ? 'skipped' : decision.simulated ? 'simulated' : 'pending';
    const terminal = kind !== 'pending';
    const actionKey = remediationActionKey(copy.publicId, action, copy.remediationGeneration);
    const inserted = await tx.$executeRaw`
      INSERT IGNORE INTO api_remediation_actions
        (public_id, organization_id, api_connection_id, mailbox_id, copy_id, copy_received_at,
         message_id, action, generation, action_key, \`trigger\`, status, reason_code, decision,
         requested_by_type, attempts, locate_attempts, next_attempt_at, verdict_at, completed_at,
         row_version, created_at, updated_at)
      VALUES (${uuidv7(now.getTime())}, ${copy.organizationId}, ${copy.apiConnectionId},
              ${copy.mailboxId}, ${copy.id}, ${copy.receivedAt}, ${copy.messageId}, ${action},
              ${copy.remediationGeneration}, ${actionKey}, 'policy', ${kind},
              ${decision.outcome === 'skip' ? decision.reason : null}, ${JSON.stringify(record)},
              'system', 0, 0, ${terminal ? null : now}, ${copy.verdictAt}, ${terminal ? now : null},
              1, ${now}, ${now})`;
    const base = {
      kind,
      apiConnectionId: copy.apiConnectionId,
      provider: connection.provider,
      action,
    } as const;
    if (inserted !== 1) return { ...base, inserted: false, counters: {} };
    const rows = await tx.$queryRaw<
      Array<{ id: bigint | number; organization_id: bigint | number }>
    >`
      SELECT id, organization_id FROM api_remediation_actions WHERE action_key = ${actionKey}`;
    const row = rows[0];
    if (!row || big(row.organization_id) !== copy.organizationId) {
      throw new InconsistentReadError('api_remediation_actions');
    }
    await tx.$executeRaw`
      UPDATE api_message_copies
      SET remediation_state = ${kind}, remediation_action = ${action},
          last_action_id = ${big(row.id)}, remediation_updated_at = ${now}
      WHERE id = ${copy.id} AND received_at = ${copy.receivedAt}
        AND organization_id = ${copy.organizationId}`;
    const counters: CounterDelta =
      kind === 'skipped'
        ? { remediation_skipped: 1 }
        : kind === 'simulated'
          ? { remediation_simulated: 1 }
          : {};
    return { ...base, inserted: true, counters };
  }

  /** The connection's provider, pause flag and mailbox-access grant (organization echo). */
  private async connectionFacts(
    tx: Prisma.TransactionClient,
    copy: DecisionCopy,
    memo: DecisionMemo,
  ): Promise<ConnectionFacts> {
    const known = memo.connections.get(copy.apiConnectionId);
    if (known) return known;
    const rows = await tx.$queryRaw<
      Array<{
        organization_id: bigint | number;
        provider: IntegrationProvider;
        remediation_paused: unknown;
        provider_connection_id: bigint | number;
      }>
    >`
      SELECT organization_id, provider, remediation_paused, provider_connection_id
      FROM api_mode_connections WHERE id = ${copy.apiConnectionId}`;
    const row = rows[0];
    if (!row || big(row.organization_id) !== copy.organizationId) {
      throw new InconsistentReadError('api_mode_connections');
    }
    const grant = await tx.providerConnectionGrant.findUnique({
      where: {
        connectionId_profile: {
          connectionId: big(row.provider_connection_id),
          profile: mailboxProfileOf(row.provider),
        },
      },
      select: { organizationId: true, status: true },
    });
    if (grant && grant.organizationId !== copy.organizationId) {
      throw new InconsistentReadError('provider_connection_grants');
    }
    const facts: ConnectionFacts = {
      provider: row.provider,
      paused: bool(row.remediation_paused),
      grantActive: grant?.status === 'active',
    };
    memo.connections.set(copy.apiConnectionId, facts);
    return facts;
  }

  /** `COALESCE(domains.protection_mode, organizations.protection_mode)`; null without a domain. */
  private async domainMode(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    domainId: bigint | null,
    memo: DecisionMemo,
  ): Promise<DomainEffectiveMode | null> {
    if (domainId === null) return null;
    const key = domainId.toString();
    if (memo.domainModes.has(key)) return memo.domainModes.get(key) ?? null;
    const domain = await tx.domain.findUnique({
      where: { id: domainId },
      select: {
        organizationId: true,
        protectionMode: true,
        deletedAt: true,
        organization: { select: { id: true, protectionMode: true } },
      },
    });
    if (domain && domain.organizationId !== organizationId) {
      throw new InconsistentReadError('domains');
    }
    const mode =
      !domain || domain.deletedAt !== null
        ? null
        : (domain.protectionMode ?? domain.organization.protectionMode);
    memo.domainModes.set(key, mode);
    return mode;
  }
}
