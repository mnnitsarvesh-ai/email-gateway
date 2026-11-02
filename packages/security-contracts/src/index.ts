import { z } from 'zod';

/**
 * Contract every security engine adapter (Rspamd, ClamAV, YARA, URL, BEC, DLP) implements.
 * Engines are pure functions of the message: they read from S3 and return a verdict.
 * They never decide the final action; the policy engine does.
 */
export const SecurityStage = {
  Antispam: 'antispam',
  Antivirus: 'antivirus',
  Yara: 'yara',
  Url: 'url',
  Bec: 'bec',
  Dlp: 'dlp',
} as const;
export type SecurityStage = (typeof SecurityStage)[keyof typeof SecurityStage];

/**
 * `error` and `timeout` are first-class outcomes so policy can fail safe
 * (e.g. quarantine when antivirus is unavailable) instead of silently delivering.
 */
export const VerdictOutcome = {
  Clean: 'clean',
  Suspicious: 'suspicious',
  Malicious: 'malicious',
  Error: 'error',
  Timeout: 'timeout',
} as const;
export type VerdictOutcome = (typeof VerdictOutcome)[keyof typeof VerdictOutcome];

export const engineVerdictSchema = z.object({
  stage: z.enum(['antispam', 'antivirus', 'yara', 'url', 'bec', 'dlp']),
  engine: z.string().min(1),
  engineVersion: z.string().min(1),
  outcome: z.enum(['clean', 'suspicious', 'malicious', 'error', 'timeout']),
  /** Normalised 0..100; engine-native scores go in `details`. */
  score: z.number().min(0).max(100),
  signals: z.array(z.object({ id: z.string(), description: z.string().max(500) })).max(200),
  durationMs: z.number().int().nonnegative(),
  details: z.record(z.string(), z.unknown()).optional(),
});
export type EngineVerdict = z.infer<typeof engineVerdictSchema>;

export interface ScanInput {
  /**
   * The tenant's numeric `organizations.id` as a decimal string (ADR-0014), taken from the
   * event envelope, never from message content.
   */
  organizationId: string;
  /** The message registry id (`message_identities.id`) as a decimal string. */
  messageId: string;
  emlS3Key: string;
  sizeBytes: number;
}

export interface SecurityEngine {
  readonly stage: SecurityStage;
  readonly name: string;
  scan(input: ScanInput, signal: AbortSignal): Promise<EngineVerdict>;
}
