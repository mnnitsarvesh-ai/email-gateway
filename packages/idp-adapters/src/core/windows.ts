/**
 * Polling windows (design note D7.2): a poll covers `[watermark − overlap, now − settle]`, paged
 * completely before `watermark := windowEnd`. Late events inside the overlap are re-read and
 * deduplicated downstream by event id. Defaults are code constants per window family (changed
 * with the adapter version, no configuration keys).
 */
export type WindowFamily =
  'graph_sign_ins' | 'graph_risk' | 'graph_audits' | 'o365_management' | 'google_reports';

export interface WindowDefaults {
  overlapMs: number;
  settleMs: number;
  /** Longest window per request (Office 365 Management: 24 h). */
  maxWindowMs?: number;
  /** Oldest start the provider accepts (Office 365 Management: now − 7 days). */
  maxAgeMs?: number;
}

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export const WINDOW_DEFAULTS: Readonly<Record<WindowFamily, WindowDefaults>> = {
  graph_sign_ins: { overlapMs: 15 * MINUTE, settleMs: 2 * MINUTE },
  graph_risk: { overlapMs: 15 * MINUTE, settleMs: 2 * MINUTE },
  graph_audits: { overlapMs: 30 * MINUTE, settleMs: 5 * MINUTE },
  o365_management: {
    overlapMs: 60 * MINUTE,
    settleMs: 10 * MINUTE,
    maxWindowMs: DAY,
    maxAgeMs: 7 * DAY,
  },
  google_reports: { overlapMs: 60 * MINUTE, settleMs: 5 * MINUTE },
};

export interface TimeWindow {
  start: Date;
  end: Date;
}

/**
 * The next window to page, or `null` when nothing new is settled yet.
 * `watermark = null` (a stream without a watermark, or after `cursor_invalid`) starts at
 * `now − overlap` — never at the epoch. `retentionDays` clamps the start to the provider retention.
 */
export function nextWindow(input: {
  family: WindowFamily;
  watermark: Date | null;
  now: Date;
  retentionDays: number;
}): TimeWindow | null {
  const defaults = WINDOW_DEFAULTS[input.family];
  const nowMs = input.now.getTime();
  const end0 = nowMs - defaults.settleMs;
  let start =
    input.watermark === null
      ? nowMs - defaults.overlapMs
      : input.watermark.getTime() - defaults.overlapMs;
  const floors = [];
  if (input.retentionDays > 0) floors.push(nowMs - input.retentionDays * DAY);
  if (defaults.maxAgeMs !== undefined) floors.push(nowMs - defaults.maxAgeMs + MINUTE);
  for (const floor of floors) start = Math.max(start, floor);
  let end = end0;
  if (defaults.maxWindowMs !== undefined) end = Math.min(end, start + defaults.maxWindowMs);
  if (end <= start) return null;
  // A window that would re-read only the overlap (watermark already at now − settle) is skipped.
  if (input.watermark !== null && end <= input.watermark.getTime()) return null;
  return { start: new Date(start), end: new Date(end) };
}

/** Whether a stream that completed a window at `watermark` still has settled time to page. */
export function hasMoreWindows(input: {
  family: WindowFamily;
  watermark: Date;
  now: Date;
}): boolean {
  const defaults = WINDOW_DEFAULTS[input.family];
  // More than one overlap of new settled time remains (e.g. 24 h slices of a backfill).
  return input.now.getTime() - defaults.settleMs - input.watermark.getTime() > defaults.overlapMs;
}

/** Stream lag (D6, D11): seconds between now and the watermark. */
export function streamLagSeconds(watermark: Date | null, now: Date): number | null {
  if (watermark === null) return null;
  return Math.max(0, Math.round((now.getTime() - watermark.getTime()) / 1000));
}
