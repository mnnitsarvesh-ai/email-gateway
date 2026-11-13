import type { Tone } from '@/lib/design/tokens';

/** Tones for quarantine values the shared scale lacks (approval and release statuses). */
export const APPROVAL_STATUS_TONE: Readonly<Record<string, Tone>> = {
  pending: 'purple',
  approved: 'success',
  denied: 'danger',
  expired: 'neutral',
  cancelled: 'neutral',
};

export const RELEASE_STATUS_TONE: Readonly<Record<string, Tone>> = {
  pending: 'info',
  dispatched: 'success',
  delivered: 'success',
  failed: 'danger',
  blocked_by_revalidation: 'danger',
  approval_required: 'purple',
  rescan_required: 'warning',
  refused: 'danger',
  stale: 'neutral',
  message_busy: 'warning',
};

export const BULK_STATUS_TONE: Readonly<Record<string, Tone>> = {
  queued: 'info',
  approval_requested: 'purple',
  done: 'success',
  refused: 'danger',
  not_found: 'neutral',
  skipped: 'neutral',
};
