import type { Tone } from '@/lib/design/tokens';

/**
 * The only mapping from security values to tones (design-system.md "Semantic scales").
 * Badges always print the label, so colour is never the only cue.
 */
export const VERDICT_TONE: Readonly<Record<string, Tone>> = {
  clean: 'success',
  spam: 'warning',
  bulk: 'neutral',
  phishing: 'orange',
  malware: 'danger',
  bec: 'magenta',
  dlp_violation: 'purple',
  suspicious: 'warning',
  unknown: 'neutral',
  none: 'neutral',
};

export const SEVERITY_TONE: Readonly<Record<string, Tone>> = {
  none: 'neutral',
  info: 'info',
  low: 'info',
  medium: 'warning',
  high: 'orange',
  critical: 'danger',
};

export const DELIVERY_TONE: Readonly<Record<string, Tone>> = {
  delivered: 'success',
  pending: 'info',
  in_progress: 'info',
  queued: 'info',
  deferred: 'warning',
  bounced: 'danger',
  failed: 'danger',
  expired: 'orange',
  suppressed: 'neutral',
  unknown: 'neutral',
};

export const QUARANTINE_TONE: Readonly<Record<string, Tone>> = {
  held: 'warning',
  pending_approval: 'purple',
  releasing: 'info',
  released: 'success',
  rejected: 'danger',
  deleted: 'neutral',
  expired: 'neutral',
  superseded: 'neutral',
};

export const DIRECTION_TONE: Readonly<Record<string, Tone>> = {
  inbound: 'info',
  outbound: 'purple',
  internal: 'neutral',
};

export function toneOf(
  scale: Readonly<Record<string, Tone>>,
  value: string | null | undefined,
): Tone {
  return (value && scale[value]) || 'neutral';
}

/** Display band of a 0–1000 risk score (display only; an API risk level wins when present). */
export function riskBand(score: number): { tone: Tone; label: string } {
  if (score < 300) return { tone: 'success', label: 'Low' };
  if (score < 600) return { tone: 'warning', label: 'Medium' };
  if (score < 800) return { tone: 'orange', label: 'High' };
  return { tone: 'danger', label: 'Critical' };
}
