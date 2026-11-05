import {
  type ArchiveFinding,
  ATTACHMENT_MAPPING_VERSION,
  type AttachmentCacheResult,
  type AttachmentEffectiveSettings,
  type AttachmentReasonCode,
  type AttachmentResult,
  type AttachmentRuleVerdict,
  type AttachmentVerdict,
  attachmentVerdictRank,
  type EngineSignal,
  type FileTypeId,
  fileType,
  type KnownHashSeverity,
  MAX_ARCHIVE_FINDINGS,
  MAX_REASON_CODES,
  MAX_SIGNALS,
} from '@email-gateway/security-contracts';
import type { ContentResult } from './content';
import { refineTextType } from './inspector/file-type';
import { executableDisguised, typeMismatch } from './type-rules';

/**
 * The attachment verdict mapping `attachment-map/1` (step 4.2 A6), pure. Per attachment every
 * rule that applies adds its reason code; the verdict is the most severe one raised
 * (`malicious > suspicious > unknown > clean`); `clean` only by rule C1 (a complete inspection
 * with a definite ClamAV `OK` and nothing raised, §2.0 invariant 1). Tenant settings (A8) can
 * only raise verdicts and add deny-list entries. The engine level adds A0 (no attachments →
 * `skipped`), E1 (incomplete parse → at least `suspicious`) and the attachment-count limit.
 */
export const MAPPING_VERSION = ATTACHMENT_MAPPING_VERSION;

/** `info`: informational codes (rule R) that raise no verdict. */
type Raise = AttachmentVerdict | 'info';

const RANK = (raise: Raise): number => (raise === 'info' ? -1 : attachmentVerdictRank(raise));

/** A `malware_signatures` hit (A3, A17). */
export interface KnownHashHit {
  severity: KnownHashSeverity;
  family: string | null;
}

/** What the parse row says about the attachment (never the filename itself). */
export interface AttachmentFacts {
  partIndex: number;
  sha256: string;
  sizeBytes: number;
  /** The part object exists (`object_key` not null). */
  stored: boolean;
  /** Type implied by the sanitized filename's extension, or null. */
  extensionType: FileTypeId | null;
  /** Type implied by a specific declared content type (generic types are null). */
  declaredType: FileTypeId | null;
  /** ATTACHMENT_FLAGS of step 3.1 (codes only). */
  flags: readonly string[];
}

export interface MapInput {
  facts: AttachmentFacts;
  /** Null when the content was not scanned (not stored, or above the size limit: rule S3). */
  content: ContentResult | null;
  hashes: { outer: KnownHashHit | null; inner: ReadonlyMap<string, KnownHashHit> };
  cache: AttachmentCacheResult;
  durationMs: number;
}

const isMaliciousHash = (hit: KnownHashHit): boolean =>
  hit.severity === 'high' || hit.severity === 'critical';

const HASH_RANK: Record<KnownHashSeverity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

const ruleVerdict = (value: AttachmentRuleVerdict): AttachmentVerdict => value;

/** ClamAV signature → reason code and verdict (rules M2, S1, S4). */
export function clamavRule(
  signature: string,
  encryptedVerdict: AttachmentRuleVerdict,
): { code: AttachmentReasonCode; verdict: AttachmentVerdict } {
  if (
    signature.startsWith('Heuristics.Limits.Exceeded') ||
    signature.startsWith('Heuristics.Exceeds')
  ) {
    return { code: 'limit.clamav', verdict: 'suspicious' };
  }
  if (signature.startsWith('Heuristics.Encrypted')) {
    return { code: 'archive.encrypted', verdict: ruleVerdict(encryptedVerdict) };
  }
  if (signature.startsWith('Heuristics.'))
    return { code: 'clamav.heuristic', verdict: 'suspicious' };
  if (signature.startsWith('PUA.')) return { code: 'clamav.pua', verdict: 'suspicious' };
  return { code: 'malware.clamav', verdict: 'malicious' };
}

/** Verdict a code raises on its own (entry findings ordering; mirrors the attachment rules). */
function codeRaise(code: AttachmentReasonCode, settings: AttachmentEffectiveSettings): Raise {
  switch (code) {
    case 'malware.known_hash':
    case 'malware.clamav':
    case 'yara.high':
      return 'malicious';
    case 'archive.encrypted':
      return ruleVerdict(settings.encryptedArchiveVerdict);
    case 'type.denied':
    case 'type.not_allowed':
    case 'type.denied_in_archive':
      return ruleVerdict(settings.deniedTypeVerdict);
    case 'type.mismatch':
    case 'type.executable_disguised':
      return ruleVerdict(settings.typeMismatchVerdict);
    case 'archive.unsupported_format':
      return 'unknown';
    case 'yara.low':
    case 'office.macros':
    case 'filename.double_extension':
    case 'filename.executable_extension':
    case 'filename.bidi_control':
      return 'info';
    case 'clean.no_findings':
      return 'clean';
    default:
      return 'suspicious';
  }
}

class Raised {
  private readonly codes = new Map<AttachmentReasonCode, Raise>();

  add(code: AttachmentReasonCode, raise: Raise): void {
    const previous = this.codes.get(code);
    if (previous === undefined || RANK(raise) > RANK(previous)) this.codes.set(code, raise);
  }

  get verdict(): AttachmentVerdict | null {
    let best: AttachmentVerdict | null = null;
    for (const raise of this.codes.values()) {
      if (raise === 'info') continue;
      if (best === null || attachmentVerdictRank(raise) > attachmentVerdictRank(best)) best = raise;
    }
    return best;
  }

  /** Ordered by the verdict that raised them, then by name (A6), at most `max`. */
  ordered(max: number): AttachmentReasonCode[] {
    return [...this.codes.entries()]
      .sort(([a, ra], [b, rb]) => RANK(rb) - RANK(ra) || (a < b ? -1 : a > b ? 1 : 0))
      .slice(0, max)
      .map(([code]) => code);
  }
}

const FILENAME_FLAGS: Readonly<Record<string, AttachmentReasonCode>> = {
  filename_double_extension: 'filename.double_extension',
  filename_executable_extension: 'filename.executable_extension',
  filename_bidi_control: 'filename.bidi_control',
};

function typeNotAllowed(types: readonly FileTypeId[], allowed: readonly FileTypeId[]): boolean {
  return types.length === 0 || types.some((t) => !allowed.includes(t));
}

/** The detected type after the extension refinement of text (A5; outside the cache). */
export function effectiveType(
  content: ContentResult | null,
  extensionType: FileTypeId | null,
): FileTypeId {
  if (!content) return 'unknown';
  return refineTextType(content.type.detected, content.type.textLike ? extensionType : null);
}

/** Maps one attachment (A6 table). */
export function mapAttachment(
  input: MapInput,
  settings: AttachmentEffectiveSettings,
): AttachmentResult {
  const { facts, content, hashes } = input;
  const raised = new Raised();
  const detected = effectiveType(content, facts.extensionType);

  // M1 / S2: known hashes (outer; inner below with the entries). Authoritative, never cached.
  if (hashes.outer) {
    if (isMaliciousHash(hashes.outer)) raised.add('malware.known_hash', 'malicious');
    else raised.add('hash.known_suspicious', 'suspicious');
  }

  // S3: not scanned.
  if (!content) {
    raised.add('limit.attachment_size', 'suspicious');
    raised.add('attachment.not_scanned', 'suspicious');
  }

  // S5: deny / allow on the detected and the extension-implied type.
  const types = [
    ...(content ? [detected] : []),
    ...(facts.extensionType !== null ? [facts.extensionType] : []),
  ];
  const deniedVerdict = ruleVerdict(settings.deniedTypeVerdict);
  if (types.some((t) => settings.deniedTypes.includes(t))) raised.add('type.denied', deniedVerdict);
  if (settings.allowedTypes !== null && typeNotAllowed(types, settings.allowedTypes)) {
    raised.add('type.not_allowed', deniedVerdict);
  }

  // R: 3.1 filename flags.
  for (const flag of facts.flags) {
    const code = FILENAME_FLAGS[flag];
    if (code) raised.add(code, 'info');
  }

  let mismatch = false;
  const findings = new Map<string, { type: FileTypeId; codes: Set<AttachmentReasonCode> }>();
  const entryFinding = (path: string, type: FileTypeId, code: AttachmentReasonCode) => {
    const current = findings.get(path) ?? { type, codes: new Set<AttachmentReasonCode>() };
    current.codes.add(code);
    findings.set(path, current);
  };

  if (content) {
    // M2 / S1: ClamAV.
    if (content.clamav.status === 'size_limit') raised.add('limit.clamav', 'suspicious');
    else if (content.clamav.status === 'found' && content.clamav.signature !== null) {
      const rule = clamavRule(content.clamav.signature, settings.encryptedArchiveVerdict);
      raised.add(rule.code, rule.verdict);
    }
    // M3 / S2 / R: YARA.
    for (const match of content.yara?.matches ?? []) {
      const code: AttachmentReasonCode =
        match.severity === 'high'
          ? 'yara.high'
          : match.severity === 'medium'
            ? 'yara.medium'
            : 'yara.low';
      raised.add(code, codeRaise(code, settings));
      if (match.scope !== 'attachment') {
        const type =
          content.archive?.entryHashes.find((e) => e.path === match.scope)?.type ?? 'unknown';
        entryFinding(match.scope, type, code);
      }
    }
    // S3: limits of the walk, YARA timeouts and inspector kills.
    for (const code of content.limits) raised.add(code, 'suspicious');
    // S4, S7, U1, R: inspector codes.
    for (const code of content.codes) raised.add(code, codeRaise(code, settings));
    // S6: mismatch / disguised executable.
    if (typeMismatch(detected, facts.extensionType, facts.declaredType)) {
      raised.add('type.mismatch', ruleVerdict(settings.typeMismatchVerdict));
      mismatch = true;
    }
    if (executableDisguised(detected, facts.extensionType)) {
      raised.add('type.executable_disguised', ruleVerdict(settings.typeMismatchVerdict));
      mismatch = true;
    }

    const archive = content.archive;
    if (archive) {
      for (const finding of archive.findings) {
        for (const code of finding.codes) {
          entryFinding(finding.path, finding.type, code);
          // Entry-level type rules count for the attachment too (A5 "also for archive entries").
          if (code === 'type.executable_disguised') {
            raised.add(code, ruleVerdict(settings.typeMismatchVerdict));
          }
        }
      }
      // Allow lists apply to the members of plain archives only (OOXML/ODF parts and the
      // containers nested in an archive are not "attachments" a tenant lists).
      const plainArchive = content.type.family === 'archive';
      for (const entry of archive.entryHashes) {
        const hit = hashes.inner.get(entry.path);
        if (hit) {
          const code = isMaliciousHash(hit) ? 'malware.known_hash' : 'hash.known_suspicious';
          raised.add(code, isMaliciousHash(hit) ? 'malicious' : 'suspicious');
          entryFinding(entry.path, entry.type, code);
        }
        const entryTypes = [entry.type, ...(entry.ext !== null ? [entry.ext] : [])];
        const denied = entryTypes.some((t) => settings.deniedTypes.includes(t));
        const notAllowed =
          plainArchive &&
          settings.allowedTypes !== null &&
          fileType(entry.type).family !== 'archive' &&
          typeNotAllowed(entryTypes, settings.allowedTypes);
        if (denied || notAllowed) {
          raised.add('type.denied_in_archive', deniedVerdict);
          entryFinding(entry.path, entry.type, 'type.denied_in_archive');
        }
      }
    }
  }

  // C1: clean only for a complete inspection with a definite ClamAV OK and nothing raised.
  let verdict = raised.verdict;
  if (verdict === null) {
    if (content && content.clamav.status === 'clean') {
      raised.add('clean.no_findings', 'clean');
      verdict = 'clean';
    } else {
      // Unreachable by construction (no content raises S3, FOUND raises M2/S1); never clean.
      raised.add('attachment.not_scanned', 'suspicious');
      verdict = 'suspicious';
    }
  }

  const knownHash = mostSevereHash([hashes.outer, ...hashes.inner.values()]);
  const rowFindings: ArchiveFinding[] = [...findings.entries()]
    .map(([path, f]) => ({
      path,
      type: f.type,
      codes: [...f.codes],
      rank: Math.max(...[...f.codes].map((c) => RANK(codeRaise(c, settings)))),
    }))
    .sort((a, b) => b.rank - a.rank || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
    .slice(0, MAX_ARCHIVE_FINDINGS)
    .map((f) => ({
      path: f.path,
      type: f.type,
      reasonCodes: [...f.codes]
        .sort(
          (a, b) => RANK(codeRaise(b, settings)) - RANK(codeRaise(a, settings)) || (a < b ? -1 : 1),
        )
        .slice(0, 16),
    }));

  return {
    partIndex: facts.partIndex,
    sha256: facts.sha256,
    sizeBytes: facts.sizeBytes,
    detectedType: detected,
    typeFamily: fileType(detected).family,
    typeMismatch: mismatch,
    verdict,
    reasonCodes: raised.ordered(MAX_REASON_CODES),
    clamav:
      content && content.clamav.status !== 'size_limit'
        ? {
            signature: content.clamav.status === 'found' ? content.clamav.signature : null,
            engineVersion: content.clamav.engineVersion,
            dbVersion: content.clamav.dbVersion,
          }
        : null,
    yara: content?.yara ? { bundleId: content.yara.bundleId, matches: content.yara.matches } : null,
    archive: content?.archive
      ? {
          format: content.archive.format,
          supported: content.archive.supported,
          entries: content.archive.entries,
          depthReached: content.archive.depthReached,
          decompressedBytes: content.archive.decompressedBytes,
          maxRatio: content.archive.maxRatio,
          encrypted: content.archive.encrypted,
          findings: rowFindings,
        }
      : null,
    knownHash,
    cache: input.cache,
    durationMs: Math.max(0, Math.round(input.durationMs)),
  };
}

function mostSevereHash(hits: ReadonlyArray<KnownHashHit | null>): AttachmentResult['knownHash'] {
  let best: KnownHashHit | null = null;
  for (const hit of hits) {
    if (hit && (best === null || HASH_RANK[hit.severity] > HASH_RANK[best.severity])) best = hit;
  }
  return best ? { severity: best.severity, family: best.family } : null;
}

/** Neutral settings: the verdict a content result implies on its own (cache TTL, A10). */
const NEUTRAL: AttachmentEffectiveSettings = {
  maxAttachmentBytes: Number.MAX_SAFE_INTEGER,
  deniedTypes: [],
  allowedTypes: null,
  deniedTypeVerdict: 'suspicious',
  typeMismatchVerdict: 'suspicious',
  encryptedArchiveVerdict: 'suspicious',
};

/** The verdict the content alone implies, before tenant rules and the hash catalog (A10). */
export function contentVerdict(content: ContentResult): AttachmentVerdict {
  return mapAttachment(
    {
      facts: {
        partIndex: 0,
        sha256: '0'.repeat(64),
        sizeBytes: 0,
        stored: true,
        extensionType: null,
        declaredType: null,
        flags: [],
      },
      content,
      hashes: { outer: null, inner: new Map() },
      cache: 'miss',
      durationMs: 0,
    },
    NEUTRAL,
  ).verdict;
}

// ---------------------------------------------------------------------------------------------
// Engine level (A0, E1, aggregation)
// ---------------------------------------------------------------------------------------------

export interface EngineMapInput {
  attachments: readonly AttachmentResult[];
  /** E1: the parse may have missed attachments. */
  parseIncomplete: boolean;
  /** More attachment rows than ATTACHMENT_MAX_PER_MESSAGE (the extra ones are not scanned). */
  countExceeded: boolean;
}

export interface EngineMapping {
  outcome: AttachmentVerdict | 'skipped';
  reasonCodes: AttachmentReasonCode[];
  signals: EngineSignal[];
}

const signal = (name: string, partIndex: number): EngineSignal => ({
  name: name.slice(0, 128),
  score: 0,
  options: [`part ${String(partIndex)}`],
});

/** The engine result of all attachments of a message (A6 engine level). */
export function mapEngine(input: EngineMapInput): EngineMapping {
  const { attachments } = input;
  if (attachments.length === 0 && !input.parseIncomplete && !input.countExceeded) {
    return { outcome: 'skipped', reasonCodes: ['attachment.none'], signals: [] };
  }
  const raised = new Raised();
  for (const attachment of attachments) {
    for (const code of attachment.reasonCodes) raised.add(code, attachmentRaise(code, attachment));
  }
  if (input.parseIncomplete) raised.add('attachment.parse_incomplete', 'suspicious');
  if (input.countExceeded) {
    raised.add('limit.attachment_count', 'suspicious');
    raised.add('attachment.not_scanned', 'suspicious');
  }
  let outcome: AttachmentVerdict = 'clean';
  for (const attachment of attachments) {
    if (attachmentVerdictRank(attachment.verdict) > attachmentVerdictRank(outcome)) {
      outcome = attachment.verdict;
    }
  }
  if ((input.parseIncomplete || input.countExceeded) && attachmentVerdictRank(outcome) < 2) {
    outcome = 'suspicious';
  }
  if (attachments.length === 0 && outcome === 'clean') outcome = 'suspicious';

  const signals: EngineSignal[] = [];
  const seen = new Set<string>();
  const push = (name: string, partIndex: number) => {
    const key = `${name}|${String(partIndex)}`;
    if (seen.has(key) || signals.length >= MAX_SIGNALS) return;
    seen.add(key);
    signals.push(signal(name, partIndex));
  };
  for (const attachment of attachments) {
    if (attachment.verdict === 'clean') continue;
    if (attachment.clamav?.signature)
      push(`clamav:${attachment.clamav.signature}`, attachment.partIndex);
    for (const match of attachment.yara?.matches ?? [])
      push(`yara:${match.rule}`, attachment.partIndex);
    if (attachment.knownHash) push(`hash:${attachment.sha256.slice(0, 12)}`, attachment.partIndex);
  }
  // Clean attachments keep `clean.no_findings` only when every attachment is clean.
  const codes = raised
    .ordered(MAX_REASON_CODES + 1)
    .filter((code) => code !== 'clean.no_findings' || outcome === 'clean');
  return { outcome, reasonCodes: codes.slice(0, MAX_REASON_CODES), signals };
}

/** The verdict a code of an attachment result carries at the engine level (ordering only). */
function attachmentRaise(code: AttachmentReasonCode, attachment: AttachmentResult): Raise {
  if (code === 'clean.no_findings') return 'clean';
  if (code === 'yara.low' || code === 'office.macros' || code.startsWith('filename.')) {
    return 'info';
  }
  if (code === 'malware.known_hash' || code === 'malware.clamav' || code === 'yara.high') {
    return 'malicious';
  }
  if (code === 'archive.unsupported_format') return 'unknown';
  // Tenant-tunable codes take the verdict of the attachment that raised them at most.
  return attachment.verdict === 'malicious' &&
    (code.startsWith('type.') || code === 'archive.encrypted')
    ? 'malicious'
    : 'suspicious';
}

/** A sandbox candidate (A11): a non-clean, non-malicious attachment with a stored part. */
export interface SandboxCandidate {
  index: number;
  verdict: 'suspicious' | 'unknown';
}

/** Selects the attachments to submit (A11): most severe first, at most `max`. */
export function selectSandbox(
  results: ReadonlyArray<{ result: AttachmentResult; stored: boolean }>,
  max: number,
): SandboxCandidate[] {
  return results
    .map((r, index) => ({
      index,
      verdict: r.result.verdict,
      stored: r.stored,
      part: r.result.partIndex,
    }))
    .filter(
      (
        r,
      ): r is { index: number; verdict: 'suspicious' | 'unknown'; stored: boolean; part: number } =>
        r.stored && (r.verdict === 'suspicious' || r.verdict === 'unknown'),
    )
    .sort(
      (a, b) =>
        attachmentVerdictRank(b.verdict) - attachmentVerdictRank(a.verdict) || a.part - b.part,
    )
    .slice(0, Math.max(0, max))
    .map(({ index, verdict }) => ({ index, verdict }));
}
