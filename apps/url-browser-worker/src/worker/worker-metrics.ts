import { Injectable } from '@nestjs/common';
import { MetricsService } from '@email-gateway/common';
import type { RestartReason } from '../browser/restart-policy';

/** url-browser-worker series (step 4.3 U18). Labels are bounded tokens. */
@Injectable()
export class WorkerMetrics {
  private readonly jobs;
  private readonly duration;
  private readonly restarts;
  private readonly rss;

  constructor(metrics: MetricsService) {
    this.jobs = metrics.counter('url_browser_jobs_total', 'Browser inspection jobs by result', [
      'result',
    ]);
    this.duration = metrics.histogram(
      'url_browser_job_duration_seconds',
      'Browser inspection job duration',
      [],
      [0.5, 1, 2, 3, 5, 8, 12, 16, 20, 30, 60],
    );
    this.restarts = metrics.counter('url_browser_restarts_total', 'Browser restarts by reason', [
      'reason',
    ]);
    this.rss = metrics.gauge(
      'url_browser_rss_bytes',
      'Resident memory of the browser process tree',
    );
  }

  /** `result`: `completed` or the bounded error code of a failed job. */
  job(result: string, seconds: number): void {
    this.jobs.inc({ result });
    this.duration.observe(seconds);
  }

  restart(reason: RestartReason): void {
    this.restarts.inc({ reason });
  }

  setRss(bytes: number): void {
    this.rss.set(bytes);
  }
}
