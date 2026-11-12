import { TOPOLOGY_VERSION } from '@email-gateway/event-contracts';
import { ManagementApi } from './broker';
import { stack } from './env';

/**
 * Step 4.1 scan stage for the stack suites (docs/plan/steps/09-rspamd.md §9 "Stack", S1, S2,
 * S15). Since step 4.1 delivery is approved only after the scan; since step 5.2 (docs/plan/steps/
 * 16-policy-engine.md P13, P14, ADR-0044) the policy-engine approves it (E8/E10, approval
 * `source = policy`) and the delivery-worker's development pass-through (E27) is removed. So
 * EVERY stack suite that expects delivery needs:
 *
 * - an email-worker that runs the scan role (`SCAN_ENABLED=true`: the `scan_*` series in
 *   `/metrics`) next to the MIME role;
 * - a ready policy-engine consuming `email.policy.evaluate` (its `policy_evaluations_total` in
 *   `/metrics`); without it every message stays `scanned` (held), never delivered;
 * - topology v4 on the broker (step 4.2 A2) with a consumer on `scan.spam` and on
 *   `scan.attachment`: since step 4.2 every round requires the `attachment` engine
 *   (`SCAN_ENGINES=rspamd,attachment`, A1), so a stack without the attachment consumer never
 *   completes a round;
 * - an email-worker whose readiness reports clamd and the attachment inspector (A19);
 * - since step 4.3 (U1, U2): topology v5 with a consumer on `scan.url` and `scan.url.results`
 *   (every round requires the `url` engine, `SCAN_ENGINES=rspamd,attachment,url`) and an
 *   email-worker that runs the URL engine (`scan_url_urls_total` in `/metrics`);
 * - since step 4.4 (B1, B2, B3): topology v6 with a consumer on `scan.bec` (every round requires
 *   the `bec` engine, `SCAN_ENGINES=rspamd,attachment,url,bec`; it is a stage-2 engine triggered
 *   by `mail.message.scan_stage_ready.v1` once rspamd and url finalized) and an email-worker that
 *   runs the BEC engine (`scan_bec_results_total` in `/metrics`);
 * - since step 4.5 (D1, D2): topology v7 with a consumer on `scan.dlp` (every round requires the
 *   `dlp` engine, `SCAN_ENGINES=rspamd,attachment,url,bec,dlp`; a stage-1 engine on `parsed.v1`
 *   and `rescan_requested.v1`) and an email-worker that runs the DLP engine
 *   (`scan_dlp_results_total` in `/metrics`, readiness `dlp-engine` and `dlp-extractor`);
 * - since step 4.6 (X11, X13): topology v8 with consumers on `scan.sandbox.submissions` and
 *   `scan.sandbox.results` (the email-worker's asynchronous sandbox engine,
 *   `SANDBOX_ENABLED=true`: `scan_sandbox_submissions_total` in `/metrics`). The round never
 *   waits for the sandbox; without these consumers the attachment engine's sandbox requests
 *   would only pile up. The sandbox-controller (`scan.sandbox`) is the sandbox suites' own gate.
 * - since step 5.2 (P15): topology v9 (`TOPOLOGY_VERSION` of `@email-gateway/event-contracts`)
 *   with a consumer on `email.policy.evaluate`.
 * - since step 5.3 (17-quarantine.md Q27, Q28): topology v10 with a consumer on the work queue
 *   `email.quarantine` (the policy-engine's `quarantine` role: release executor, sweeper,
 *   digests); without it releases stay `releasing` and held entries never expire.
 *
 * `scanStageProblems()` returns what is missing (empty when everything is there); the routing,
 * MIME and scan gates include it.
 */
export const RSPAMD_LEDGER = 'email-worker.scan.rspamd';
export const ATTACHMENT_LEDGER = 'email-worker.scan.attachment';
export const URL_LEDGER = 'email-worker.scan.url';
export const BEC_LEDGER = 'email-worker.scan.bec';
export const DLP_LEDGER = 'email-worker.scan.dlp';
/**
 * The engines every round of the stack requires (step 4.2 A1, step 4.3 U1, step 4.4 B1, step
 * 4.5 D1, `SCAN_ENGINES`).
 */
export const REQUIRED_ENGINES = ['rspamd', 'attachment', 'url', 'bec', 'dlp'] as const;
/** The queues that must have a consumer for a round to complete (step 4.4 B3, step 4.5 D2). */
export const SCAN_CONSUMED_QUEUES = [
  'scan.spam',
  'scan.attachment',
  'scan.url',
  'scan.url.results',
  'scan.bec',
  'scan.dlp',
  'scan.sandbox.submissions',
  'scan.sandbox.results',
] as const;
export { TOPOLOGY_VERSION };
export const TOPOLOGY_DESCRIPTION = `email-gateway topology v${TOPOLOGY_VERSION}`;
/** Step 5.2: the queue of the delivery gate (policy-engine, ledger `policy-engine.evaluate`). */
export const POLICY_QUEUE = 'email.policy.evaluate';
/** Step 5.3: the release executor's work queue (policy-engine `quarantine` role). */
export const QUARANTINE_QUEUE = 'email.quarantine';

export const SCAN_HOW_TO_START = [
  'The scan stage (step 4.1) needs the email-worker scan role; delivery (step 5.2) needs the policy-engine:',
  '  docker compose --profile apps build email-worker && docker compose --profile apps build policy-engine',
  '  docker compose --profile apps up -d --wait email-worker policy-engine delivery-worker',
  '  (or on the host: pnpm --filter @email-gateway/email-worker dev, SCAN_ENABLED=true)',
  `  pnpm rabbitmq:init   (topology v${TOPOLOGY_VERSION}, the eg-scanner user on scan.spam, scan.attachment, scan.url, scan.bec, scan.dlp, scan.sandbox.submissions, scan.sandbox.results and the eg-policy-engine user on email.policy.evaluate and email.quarantine)`,
  '  (step 4.2: clamav healthy; step 4.5: SCAN_ENGINES=rspamd,attachment,url,bec,dlp and DLP_EVIDENCE_KEY on the email-worker;',
  '   step 4.6: SANDBOX_ENABLED=true with the sandbox bucket and keys on the email-worker)',
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
  } else if (!/^# TYPE scan_bec_results_total /m.test(worker)) {
    problems.push(
      'the email-worker does not run the BEC engine (no scan_bec_results_total in /metrics): ' +
        'an image older than step 4.4, or SCAN_CONSUMERS without bec',
    );
  } else if (!/^# TYPE scan_dlp_results_total /m.test(worker)) {
    problems.push(
      'the email-worker does not run the DLP engine (no scan_dlp_results_total in /metrics): ' +
        'an image older than step 4.5, or SCAN_CONSUMERS without dlp',
    );
  } else if (!/^# TYPE scan_sandbox_submissions_total /m.test(worker)) {
    problems.push(
      'the email-worker does not run the sandbox engine (no scan_sandbox_submissions_total in ' +
        '/metrics): an image older than step 4.6, or SANDBOX_ENABLED=false',
    );
  }
  const policy = await metricsOf(stack.ports.services['policy-engine']);
  if (!policy || !/^# TYPE policy_evaluations_total /m.test(policy)) {
    problems.push(
      'the policy-engine does not evaluate (no policy_evaluations_total in /metrics): an image ' +
        'older than step 5.2, or the container is not running; nothing is approved for delivery',
    );
  }
  const delivery = await metricsOf(stack.ports.services['delivery-worker']);
  if (delivery && /^# TYPE delivery_approvals_skipped_total /m.test(delivery)) {
    problems.push(
      'the delivery-worker still runs the development pass-through (delivery_approvals_skipped_total ' +
        'in /metrics): an image older than step 5.2; rebuild it',
    );
  }
  try {
    const api = new ManagementApi();
    const vhost = stack.rabbitmqVhost();
    const info = await api.get<{ description?: string }>(`/vhosts/${encodeURIComponent(vhost)}`);
    if (info.description !== TOPOLOGY_DESCRIPTION) {
      problems.push(
        `vhost ${vhost} is "${info.description ?? ''}", not topology v${TOPOLOGY_VERSION}`,
      );
    }
    for (const queue of [...SCAN_CONSUMED_QUEUES, POLICY_QUEUE, QUARANTINE_QUEUE]) {
      if ((await api.queue(vhost, queue)).consumers < 1) problems.push(`${queue} has no consumer`);
    }
  } catch (err) {
    problems.push(`RabbitMQ management API: ${(err as Error).message}`);
  }
  return problems;
}
