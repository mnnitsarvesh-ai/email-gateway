import type { DlpDetectorId } from '@email-gateway/security-contracts';
import type { Candidate } from './types';

/** Everything a detector needs about the segment it scans (built by `detect()`). */
export interface DetectorContext {
  text: string;
  segment: number;
  /** D7 context window (code units before and after the candidate). */
  window: number;
  now: Date;
  aadhaarEnabled: boolean;
  /** Detectors switched off by the tenant (only the noisy ones may be). */
  disabled: ReadonlySet<DlpDetectorId>;
  /** IFSC token spans of the whole segment (BA2), sorted by start. */
  ifsc: readonly { start: number; end: number; value: string }[];
  /** The message's own envelope addresses, lower case (PI1 does not count them). */
  excludedAddresses: ReadonlySet<string>;
  /** Segment-level hint: the source is a source file by extension (SC1). */
  sourceFile: boolean;
  emit(candidate: Candidate): void;
}

export const enabled = (ctx: DetectorContext, id: DlpDetectorId): boolean => !ctx.disabled.has(id);
