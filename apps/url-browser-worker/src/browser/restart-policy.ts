/** Why the browser is restarted (`url_browser_restarts_total{reason}`). */
export type RestartReason = 'max_jobs' | 'crash' | 'rss' | 'launch_failed';

/**
 * Restart policy (U15): after URL_BROWSER_MAX_JOBS_PER_BROWSER jobs, when the browser crashed or
 * disconnected, and when the browser process tree RSS exceeds URL_BROWSER_MAX_RSS_MB. Checked
 * between jobs (never while a context is open). `rssBytes` null = not measurable (no /proc).
 */
export function restartReason(state: {
  connected: boolean;
  jobsSinceLaunch: number;
  maxJobs: number;
  rssBytes: number | null;
  maxRssBytes: number;
}): RestartReason | null {
  if (!state.connected) return 'crash';
  if (state.jobsSinceLaunch >= state.maxJobs) return 'max_jobs';
  if (state.rssBytes !== null && state.rssBytes > state.maxRssBytes) return 'rss';
  return null;
}
