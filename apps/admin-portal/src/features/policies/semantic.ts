import type { Tone } from '@/lib/design/tokens';

/** Tones for policy values the shared scale lacks (recorded in design note §13, WP5). */
export const POLICY_STATUS_TONE: Readonly<Record<string, Tone>> = {
  draft: 'neutral',
  active: 'success',
  disabled: 'warning',
};

export const VERSION_STATUS_TONE: Readonly<Record<string, Tone>> = {
  draft: 'neutral',
  published: 'success',
  superseded: 'neutral',
  rolled_back: 'warning',
};

export const ENABLED_TONE: Readonly<Record<string, Tone>> = {
  enabled: 'success',
  disabled: 'neutral',
  expired: 'neutral',
};
