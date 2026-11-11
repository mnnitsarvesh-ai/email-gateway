// The input builder keys directory maps by `normalizeAddress` (lower case, NFC, punycode
// domain), exported by the package index for exactly this use.
import {
  normalizeAddress,
  type PolicyRoundRows,
  type PolicySnapshotSource,
} from '@email-gateway/policy-dsl';
import type {
  DirectoryRows,
  FactsMessageRow,
  FactsScanRow,
  RoundFactRows,
  SnapshotRows,
} from '../repositories/policy-facts.repository';
import { INLINE_POLICY_ID } from './policy-definition';

/**
 * Pure part of the policy test and dry-run (step 5.2 P5, P8, P12, P22, P23): the snapshot source
 * of a target, the directory maps and the stored round rows → `PolicyRoundRows` exactly as the
 * policy-engine assembles them (JSON columns as read). No I/O.
 */

/** Round states the dry-run refuses (`409 scan_round_not_complete`). */
export const OPEN_SCAN_STATUSES: ReadonlySet<string> = new Set(['pending', 'running']);

export type SnapshotPolicy = PolicySnapshotSource['policies'][number];

/** The active snapshot (P12) with a target applied (`replace` swaps or adds one policy). */
export function snapshotSource(
  rows: SnapshotRows,
  platformDefaultId: string,
  target: { kind: 'active' } | { kind: 'platform' } | { kind: 'replace'; policy: SnapshotPolicy },
): PolicySnapshotSource {
  let policies: SnapshotPolicy[] =
    target.kind === 'platform'
      ? []
      : rows.policies.map((p) => ({
          publicId: p.publicId,
          versionNo: p.versionNo,
          definition: p.definition,
          definitionSha256: p.definitionSha256,
        }));
  if (target.kind === 'replace') {
    policies = [...policies.filter((p) => p.publicId !== target.policy.publicId), target.policy];
  }
  return {
    generation: rows.generation.toString(),
    settings: rows.settings,
    platformDefaultId,
    policies,
  };
}

/** The inline definition of a test as a snapshot policy (validated by the caller). */
export const inlinePolicy = (definition: unknown, definitionSha256: string): SnapshotPolicy => ({
  publicId: INLINE_POLICY_ID,
  versionNo: 1,
  definition,
  definitionSha256,
});

/** The normalized address of a raw one (the builder's key), or null when empty. */
export function addressKey(raw: string | null | undefined): string | null {
  if (typeof raw !== 'string' || raw.length === 0) return null;
  return normalizeAddress(raw).address;
}

/** The normalized addresses whose memberships the round needs (recipients and the sender). */
export function roundAddresses(message: FactsMessageRow, rows: RoundFactRows): string[] {
  const out = new Set<string>();
  for (const r of rows.recipients) {
    const key = addressKey(r.address);
    if (key !== null) out.add(key);
  }
  for (const raw of [message.envelopeFrom, message.headerFrom]) {
    const key = addressKey(raw);
    if (key !== null) out.add(key);
  }
  return [...out].sort();
}

/** Directory pairs → the builder's maps (sorted, unique ids per address). */
export function directoryMaps(rows: DirectoryRows): PolicyRoundRows['directory'] {
  const build = (pairs: ReadonlyArray<[string, string]>) => {
    const map = new Map<string, Set<string>>();
    for (const [address, id] of pairs) {
      const set = map.get(address) ?? new Set<string>();
      set.add(id);
      map.set(address, set);
    }
    const out: Record<string, string[]> = {};
    for (const [address, ids] of [...map.entries()].sort(([a], [b]) => (a < b ? -1 : 1))) {
      out[address] = [...ids].sort();
    }
    return out;
  };
  return {
    departmentsByAddress: build(rows.departmentPairs),
    usersByAddress: build(rows.userPairs),
  };
}

/** The stored rows of a finished round → `PolicyRoundRows` (P8; trigger from the scan status). */
export function policyRoundRowsOf(
  message: FactsMessageRow,
  scan: FactsScanRow,
  rows: RoundFactRows,
  directory: PolicyRoundRows['directory'],
): PolicyRoundRows {
  const status = scan.status as 'completed' | 'failed' | 'timed_out';
  return {
    trigger: status === 'completed' ? 'scanned' : 'scan_failed',
    message: {
      direction: message.direction,
      envelopeFrom: message.envelopeFrom,
      headerFrom: message.headerFrom,
      clientIp: message.clientIp,
      clientName: message.clientName,
      sizeBytes: message.sizeBytes,
      recipientCount: message.recipientCount,
      attachmentCount: message.attachmentCount,
      // The round evaluated (the message row's round when the engine read it).
      lifecycleRound: scan.lifecycleRound,
    },
    recipients: rows.recipients,
    scan: {
      scanId: scan.id,
      lifecycleRound: scan.lifecycleRound,
      scanKind: scan.scanKind as 'initial' | 'rescan',
      status,
      scanVerdict: scan.scanVerdict,
      reasonCodes: scan.reasonCodes,
      requiredEngines: scan.requiredEngines,
      completedAt: scan.completedAt as Date,
    },
    parseFailedAt: null,
    finals: rows.finals,
    auth: rows.auth,
    bec: rows.bec,
    dlp: rows.dlp,
    risk: rows.risk,
    attachments: rows.attachments,
    attachmentResults: rows.attachmentResults,
    urls: rows.urls,
    urlResults: rows.urlResults,
    urlRewrite: rows.urlRewrite,
    directory,
  };
}
