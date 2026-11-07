import type { DlpDetectorId } from '@email-gateway/security-contracts';
import type { Candidate } from '../detectors/types';

/**
 * Masking (step 4.5 D15): the only form of a matched value in `dlp_scan_results`, the scans
 * read API and the incidents API. The compact value is the detector's normalized form.
 * Examples are synthetic.
 */

/** Masked forms stay short (view schemas cap them at 96 characters). */
const MAX_STARS = 60;

/** `*` for every character but the last 4: `************0366`. */
export const maskLast4 = (compact: string): string =>
  compact.length <= 4
    ? '*'.repeat(compact.length)
    : '*'.repeat(Math.min(compact.length - 4, MAX_STARS)) + compact.slice(-4);

/** Last 4 only, padded: `******234F`. */
export const maskTail4 = (compact: string): string => maskLast4(compact);

/** All `*`. */
export const maskFull = (compact: string): string =>
  '*'.repeat(Math.min(Math.max(compact.length, 1), MAX_STARS));

/** IBAN: country + `*` + last 4: `GB**************1234`. */
export const maskIban = (compact: string): string =>
  compact.slice(0, 2) +
  '*'.repeat(Math.min(Math.max(compact.length - 6, 0), MAX_STARS)) +
  compact.slice(-4);

/** E-mail: first character of the local part + `***@` + domain. */
export const maskEmail = (address: string): string => {
  const at = address.lastIndexOf('@');
  if (at <= 0) return '***';
  return `${address[0]}***@${address.slice(at + 1)}`.slice(0, 96);
};

/** AWS access key id: first 4 + `*` + last 4. */
export const maskAwsKeyId = (compact: string): string =>
  compact.slice(0, 4) + '*'.repeat(Math.max(compact.length - 8, 0)) + compact.slice(-4);

/** Card numbers inside evidence (D16): first 6 + `*` + last 4 (never the full PAN). */
export const maskCardEvidence = (digits: string): string =>
  digits.slice(0, 6) + '*'.repeat(Math.max(digits.length - 10, 0)) + digits.slice(-4);

/** Type-only masks of credentials (CR1, CR3, CR4, CR5). */
export function credentialMask(candidate: Pick<Candidate, 'detector' | 'value' | 'extra'>): string {
  switch (candidate.detector) {
    case 'CR1':
      return `[private key: ${candidate.extra.keyType ?? 'unknown'}]`;
    case 'CR2':
      return maskAwsKeyId(candidate.value.toUpperCase());
    case 'CR3':
      return `[secret: ${candidate.value.length} chars]`;
    case 'CR4':
      return `[jwt alg=${candidate.extra.alg ?? 'unknown'}]`;
    case 'CR5':
      return `[token: ${candidate.extra.tokenKind ?? 'unknown'}]`;
    default:
      return '[secret]';
  }
}

const CREDENTIALS: ReadonlySet<DlpDetectorId> = new Set(['CR1', 'CR2', 'CR3', 'CR4', 'CR5']);
export const isCredentialDetector = (detector: DlpDetectorId): boolean => CREDENTIALS.has(detector);

/** The masked form of a candidate (D15 table). */
export function maskCandidate(
  candidate: Pick<Candidate, 'detector' | 'value' | 'compact' | 'extra'>,
): string {
  const { compact, extra } = candidate;
  switch (candidate.detector) {
    case 'PC1':
    case 'PI2':
    case 'NI2':
    case 'BA2':
    case 'PP1':
      return maskLast4(compact);
    case 'BA1':
      return maskIban(compact);
    case 'NI1':
    case 'PI4':
    case 'BA3':
      return maskTail4(compact);
    case 'PP2':
      return `MRZ:${maskLast4(extra.documentNumber ?? compact)}`;
    case 'PI1':
      return maskEmail(compact);
    case 'PI3':
      return '**/**/****';
    case 'CR1':
    case 'CR2':
    case 'CR3':
    case 'CR4':
    case 'CR5':
      return credentialMask(candidate);
    case 'CF1':
    case 'CF2':
      return extra.termId ?? 'term';
    case 'FI1':
      return `${extra.termId ?? 'term'}:${extra.finKind ?? 'document'}`;
    case 'DC1':
      // The dictionary's public id is the finding's `dictionaryId` (a UUID can hold digit runs
      // the masked-value schema refuses): the sample names the term index only, never its text.
      return `term #${extra.termIndex ?? 0}`;
    case 'SC1':
      return extra.language ?? 'unknown';
    case 'CU1':
      return extra.maskStyle === 'full' ? maskFull(compact) : maskLast4(compact);
  }
}
