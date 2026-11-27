/**
 * Clawback signals (step API-3, design note 37 C2.2, C2.5, C3.1): the dedupe key of an automatic
 * signal, the facts a signal hands to the remediation policy, and threat-intelligence eligibility.
 * Pure, with fixed vectors in the tests; changing the key derivation is a breaking change of
 * stored data (`api_clawbacks.signal_key`).
 */
import { createHash } from 'node:crypto';
import { riskLevelRank, type MessageVerdict, type RiskLevel } from '../remediation/vocabulary';
import { HARD_BLOCK_ID, SIGNAL_MAX_HARD_BLOCKS, type ClawbackSignalFacts } from './criteria';
import {
  CLAWBACK_HARD_BLOCKS,
  CLAWBACK_SIGNAL_LEVELS,
  CLAWBACK_TI_TYPES,
  type ClawbackSignalLevel,
  type ClawbackTiTable,
  type ThreatCategory,
  type ThreatIndicatorType,
  type ThreatSeverity,
} from './vocabulary';

/** Version prefix of the signal-key tuple (C2.5). */
export const CLAWBACK_SIGNAL_KEY_DOMAIN = 'api-clawback-signal/1';

const ID = /^[0-9]{1,20}$/;
const HEX64 = /^[0-9a-f]{64}$/;

export type ClawbackSignalKeyInput =
  | {
      source: 'late';
      /** Registry message id (`email_messages.id`). */
      messageId: bigint | number | string;
      receivedAt: Date;
      kind: 'sandbox_revision' | 'url_dynamic';
      /** Risk revision of a sandbox revision; null for a URL dynamic verdict. */
      revision: number | null;
      /** The inspected URL's identity hash (URL dynamic verdicts; used when `revision` is null). */
      urlSha256: string | null;
    }
  | {
      source: 'ti';
      table: ClawbackTiTable;
      /** `threat_indicators.id` / `malware_signatures.id`. */
      rowId: bigint | number | string;
    };

function idString(value: bigint | number | string, code: string): string {
  const text = value.toString();
  if (!ID.test(text)) throw new RangeError(code);
  return text;
}

/**
 * C2.5 `signal_key`: hex SHA-256 of the NUL-separated tuple
 * `api-clawback-signal/1 \0 <organizationId> \0 late \0 <messageId> \0 <receivedAt ISO> \0 <kind>
 * \0 <revision ?? urlSha256>` or `… \0 ti \0 <table> \0 <rowId>`. The organization is part of the
 * tuple (the design's "…"), so equal signals of two tenants never share a key; the UNIQUE
 * `(organization_id, signal_key)` dedupes redelivery and sweep replays.
 */
export function clawbackSignalKey(
  organizationId: bigint | number | string,
  input: ClawbackSignalKeyInput,
): string {
  const org = idString(organizationId, 'signal_key_invalid_organization');
  let parts: string[];
  if (input.source === 'late') {
    if (input.kind !== 'sandbox_revision' && input.kind !== 'url_dynamic') {
      throw new RangeError('signal_key_invalid_kind');
    }
    if (Number.isNaN(input.receivedAt.getTime())) {
      throw new RangeError('signal_key_invalid_received_at');
    }
    let discriminator: string;
    if (input.revision !== null) {
      if (!Number.isInteger(input.revision) || input.revision < 0 || input.revision > 255) {
        throw new RangeError('signal_key_invalid_revision');
      }
      discriminator = String(input.revision);
    } else {
      if (input.urlSha256 === null || !HEX64.test(input.urlSha256)) {
        throw new RangeError('signal_key_invalid_url_sha256');
      }
      discriminator = input.urlSha256;
    }
    parts = [
      'late',
      idString(input.messageId, 'signal_key_invalid_message_id'),
      input.receivedAt.toISOString(),
      input.kind,
      discriminator,
    ];
  } else {
    if (input.table !== 'threat_indicators' && input.table !== 'malware_signatures') {
      throw new RangeError('signal_key_invalid_table');
    }
    parts = ['ti', input.table, idString(input.rowId, 'signal_key_invalid_row_id')];
  }
  return createHash('sha256')
    .update([CLAWBACK_SIGNAL_KEY_DOMAIN, org, ...parts].join('\0'), 'utf8')
    .digest('hex');
}

// ---------------------------------------------------------------------------------------------
// signalFacts (C3.1)
// ---------------------------------------------------------------------------------------------

/** Verdicts an admin, campaign or analyst may choose for policy mode (C3.1 last row). */
export const CLAWBACK_CHOSEN_VERDICTS = [
  'malware',
  'phishing',
  'bec',
  'suspicious',
  'spam',
] as const;
export type ClawbackChosenVerdict = (typeof CLAWBACK_CHOSEN_VERDICTS)[number];

/** Confidence from which a TI signal carries `hb.clawback.threat_intel` (C3.1). */
export const TI_HARD_BLOCK_MIN_CONFIDENCE = 90;

export type SignalFactsInput =
  | {
      kind: 'sandbox_revision';
      /** The revision's risk verdict. */
      verdict: MessageVerdict;
      /** The revision's level (`none` is read as `low`: a signal always has a level). */
      level: RiskLevel;
      hardBlocks: readonly string[];
      /** The revision's risk score (0..1000), when known. */
      score?: number | null;
    }
  | { kind: 'url_dynamic'; urlVerdict: 'malicious' | 'suspicious' }
  | {
      kind: 'threat_indicator';
      indicatorType: Exclude<ThreatIndicatorType, 'ip'>;
      severity: ThreatSeverity;
      /** 0..100. */
      confidence: number;
      category: ThreatCategory | null;
    }
  | { kind: 'malware_signature'; severity: ThreatSeverity }
  | {
      /** An analyst resolved a report `malicious` (C11.5). */
      kind: 'report';
      /** The original's scan verdict (else the report copy's), null without a scan. */
      originalScanVerdict: MessageVerdict | null;
    }
  | {
      kind: 'admin' | 'campaign';
      verdict: ClawbackChosenVerdict;
      /** Default `critical`. */
      level?: ClawbackSignalLevel;
    };

const severityLevel = (severity: ThreatSeverity): ClawbackSignalLevel => severity;

function categoryVerdict(category: ThreatCategory | null): MessageVerdict {
  switch (category) {
    case 'malware':
    case 'c2':
      return 'malware';
    case 'phishing':
    case 'scam':
      return 'phishing';
    case 'spam':
      return 'spam';
    default:
      return 'suspicious';
  }
}

function tiHardBlocks(severity: ThreatSeverity, confidence: number): string[] {
  return severity === 'critical' || confidence >= TI_HARD_BLOCK_MIN_CONFIDENCE
    ? [CLAWBACK_HARD_BLOCKS.threatIntel]
    : [];
}

function signalLevel(level: RiskLevel): ClawbackSignalLevel {
  return riskLevelRank(level) <= riskLevelRank('low')
    ? 'low'
    : (CLAWBACK_SIGNAL_LEVELS.find((l) => l === level) ?? 'low');
}

/**
 * C3.1: the facts (`verdict`, `level`, `hardBlocks`, optional `score`) a signal hands to the
 * remediation policy. Malware signatures have no confidence column; they are confirmed hashes
 * (analyst, feed or a sandbox `malicious` verdict) and are read as confidence 100, so they carry
 * `hb.clawback.threat_intel` like an inline hit on the same hash carries a hard block.
 */
export function signalFacts(input: SignalFactsInput): ClawbackSignalFacts {
  switch (input.kind) {
    case 'sandbox_revision': {
      const hardBlocks = [...new Set(input.hardBlocks)]
        .filter((id) => HARD_BLOCK_ID.test(id))
        .slice(0, SIGNAL_MAX_HARD_BLOCKS);
      const facts: ClawbackSignalFacts = {
        verdict: input.verdict,
        level: signalLevel(input.level),
        hardBlocks,
      };
      if (typeof input.score === 'number' && Number.isFinite(input.score)) {
        facts.score = Math.min(1000, Math.max(0, Math.round(input.score)));
      }
      return facts;
    }
    case 'url_dynamic':
      return input.urlVerdict === 'malicious'
        ? { verdict: 'phishing', level: 'critical', hardBlocks: [CLAWBACK_HARD_BLOCKS.url] }
        : { verdict: 'suspicious', level: 'high', hardBlocks: [] };
    case 'threat_indicator':
      return {
        verdict:
          input.indicatorType === 'file_sha256' ? 'malware' : categoryVerdict(input.category),
        level: severityLevel(input.severity),
        hardBlocks: tiHardBlocks(input.severity, input.confidence),
      };
    case 'malware_signature':
      return {
        verdict: 'malware',
        level: severityLevel(input.severity),
        hardBlocks: tiHardBlocks(input.severity, 100),
      };
    case 'report': {
      const v = input.originalScanVerdict;
      return {
        verdict: v === 'malware' || v === 'phishing' || v === 'bec' ? v : 'phishing',
        level: 'critical',
        hardBlocks: [CLAWBACK_HARD_BLOCKS.analyst],
      };
    }
    case 'admin':
    case 'campaign': {
      const level = input.level ?? 'critical';
      return {
        verdict: input.verdict,
        level,
        hardBlocks: level === 'critical' ? [CLAWBACK_HARD_BLOCKS.analyst] : [],
      };
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Threat-intelligence eligibility (C2.2)
// ---------------------------------------------------------------------------------------------

export interface TiIndicatorFacts {
  indicatorType: ThreatIndicatorType;
  severity: ThreatSeverity;
  /** 0..100. */
  confidence: number;
  expiresAt: Date | null;
}

/**
 * C2.2: an indicator triggers clawbacks when it is not expired, its type is `url`, `domain`,
 * `file_sha256` or `email` (`ip` never), its severity is `high`/`critical` and its confidence is
 * at least the organization's `ti_min_confidence`.
 */
export function tiEligible(indicator: TiIndicatorFacts, minConfidence: number, now: Date): boolean {
  if (!(CLAWBACK_TI_TYPES as readonly string[]).includes(indicator.indicatorType)) return false;
  if (indicator.severity !== 'high' && indicator.severity !== 'critical') return false;
  if (!Number.isFinite(indicator.confidence) || indicator.confidence < minConfidence) return false;
  return indicator.expiresAt === null || indicator.expiresAt.getTime() > now.getTime();
}

/**
 * C2.2: a malware signature is eligible as a `file_sha256` indicator when it is not expired and
 * its severity is `high`/`critical` (the sandbox publishes `high`).
 */
export function signatureEligible(
  signature: { severity: ThreatSeverity; expiresAt: Date | null },
  now: Date,
): boolean {
  if (signature.severity !== 'high' && signature.severity !== 'critical') return false;
  return signature.expiresAt === null || signature.expiresAt.getTime() > now.getTime();
}
