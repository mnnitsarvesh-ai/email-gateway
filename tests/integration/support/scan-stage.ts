import { ManagementApi } from './broker';
import { stack } from './env';

/**
 * Step 4.1 scan stage for the stack suites (docs/plan/steps/09-rspamd.md §9 "Stack", S1, S2,
 * S15). Since step 4.1 the dev pass-through approves only `mail.message.scanned.v1` with
 * `outcome = scanned` (E27), so EVERY stack suite that expects delivery needs:
 *
 * - an email-worker that runs the scan role (`SCAN_ENABLED=true`: the `scan_*` series in
 *   `/metrics`) next to the MIME role;
 * - a delivery-worker whose pass-through reads the scanned feed (its outbox poller reports
 *   `consumer="delivery-worker.dev-passthrough-scanned"`); an older image approves before the
 *   scan (retired E4) and would make the suites pass for the wrong reason;
 * - topology v4 on the broker (step 4.2 A2) with a consumer on `scan.spam` and on
 *   `scan.attachment`: since step 4.2 every round requires the `attachment` engine
 *   (`SCAN_ENGINES=rspamd,attachment`, A1), so a stack without the attachment consumer never
 *   completes a round;
 * - an email-worker whose readiness reports clamd and the attachment inspector (A19);
 * - since step 4.3 (U1, U2): topology v5 with a consumer on `scan.url` and `scan.url.results`
 *   (every round requires the `url` engine, `SCAN_ENGINES=rspamd,attachment,url`) and an
 *   email-worker that runs the URL engine (`scan_url_urls_total` in `/metrics`).
 *
 * `scanStageProblems()` returns what is missing (empty when everything is there); the routing,
 * MIME and scan gates include it.
 */
export const RSPAMD_LEDGER = 'email-worker.scan.rspamd';
export const ATTACHMENT_LEDGER = 'email-worker.scan.attachment';
export const URL_LEDGER = 'email-worker.scan.url';
/** The engines every round of the stack requires (step 4.2 A1, step 4.3 U1, `SCAN_ENGINES`). */
export const REQUIRED_ENGINES = ['rspamd', 'attachment', 'url'] as const;
export const TOPOLOGY_DESCRIPTION = 'email-gateway topology v5';
export const PASSTHROUGH_CONSUMER = 'delivery-worker.dev-passthrough-scanned';

export const SCAN_HOW_TO_START = [
  'The scan stage (step 4.1) needs the email-worker scan role and the scanned pass-through:',
  '  docker compose --profile apps build email-worker && docker compose --profile apps build delivery-worker',
  '  docker compose --profile apps up -d --wait email-worker delivery-worker',
  '  (or on the host: pnpm --filter @email-gateway/email-worker dev, SCAN_ENABLED=true)',
  '  pnpm rabbitmq:init   (topology v5 and the eg-scanner user on scan.spam, scan.attachment, scan.url)',
  '  (step 4.2: clamav healthy; step 4.3: SCAN_ENGINES=rspamd,attachment,url on the email-worker)',
].join('\n');

async function metricsOf(port: number): Promise<string | undefined> {
  try {
    const res = await fetch(`http://${stack.host}:${port}/metrics`, {
      signal: AbortSignal.timeout(3_000),
    });
    return res.ok ? await res.text() : undefined;
  } catch {
    return undefined;
  }
}

export async function scanStageProblems(): Promise<string[]> {
  const problems: string[] = [];
  const worker = await metricsOf(stack.ports.services['email-worker']);
  if (!worker || !/^# TYPE scan_engine_results_total /m.test(worker)) {
    problems.push(
      'the email-worker does not run the scan role (no scan_engine_results_total in /metrics): ' +
        'an image older than step 4.1, or SCAN_ENABLED=false',
    );
  } else if (!/^# TYPE scan_attachment_files_total /m.test(worker)) {
    problems.push(
      'the email-worker does not run the attachment engine (no scan_attachment_files_total ' +
        'in /metrics): an image older than step 4.2, or SCAN_CONSUMERS without attachment',
    );
  } else if (!/^# TYPE scan_url_urls_total /m.test(worker)) {
    problems.push(
      'the email-worker does not run the URL engine (no scan_url_urls_total in /metrics): ' +
        'an image older than step 4.3, or SCAN_CONSUMERS without url',
    );
  }
  const delivery = await metricsOf(stack.ports.services['delivery-worker']);
  if (!delivery || !delivery.includes(`consumer="${PASSTHROUGH_CONSUMER}"`)) {
    problems.push(
      `the delivery-worker pass-through does not read mail.message.scanned.v1 (no ${PASSTHROUGH_CONSUMER} ` +
        'poller in /metrics): an image older than step 4.1 approves before scanning',
    );
  }
  try {
    const api = new ManagementApi();
    const vhost = stack.rabbitmqVhost();
    const info = await api.get<{ description?: string }>(`/vhosts/${encodeURIComponent(vhost)}`);
    if (info.description !== TOPOLOGY_DESCRIPTION) {
      problems.push(`vhost ${vhost} is "${info.description ?? ''}", not topology v5`);
    }
    for (const queue of ['scan.spam', 'scan.attachment', 'scan.url', 'scan.url.results']) {
      if ((await api.queue(vhost, queue)).consumers < 1) problems.push(`${queue} has no consumer`);
    }
  } catch (err) {
    problems.push(`RabbitMQ management API: ${(err as Error).message}`);
  }
  return problems;
}
