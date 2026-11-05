import { stack } from './env';
import { SCAN_HOW_TO_START, scanStageProblems } from './scan-stage';
import { smtpStackGate, type SmtpStackGate } from './smtp-stack';

/**
 * Gate of the step 3.1 MIME ingestion stack suite (tests/integration/mime-ingestion.test.ts,
 * docs/plan/steps/06-mime-ingestion.md §9): everything the step 2.2 SMTP suites need, plus a
 * ready email-worker on EMAIL_WORKER_HOST_PORT (the apps-profile container or a host process)
 * that actually runs the MIME ingestion stage. A phase-0 email-worker image is also "ready", so
 * the gate checks that `/metrics` exports the step 3.1 series (`MIME_INGESTION_ENABLED=true`).
 * Since step 4.1 every parsed message is scanned and then approved by the pass-through, so the
 * gate also requires the scan stage (`scanStageProblems`, docs/plan/steps/09-rspamd.md S15).
 * Missing pieces FAIL the suite with an explanation; only `SMTP_STACK_TESTS=skip` skips it.
 */
const HOW_TO_START = [
  'Start the email-worker with the step 3.1 code, either on the host:',
  '  pnpm --filter @email-gateway/email-worker dev   (stop the email-worker container first)',
  '  or as a container built from this tree (one image at a time on an 8 GB Docker VM):',
  '  docker compose --profile apps build email-worker && docker compose --profile apps up -d --wait email-worker',
  'MIME_INGESTION_ENABLED must be true.',
].join('\n');

const port = () => stack.ports.services['email-worker'];

/** True when the email-worker answers `/health/<kind>` with 2xx. */
export async function emailWorkerHealth(kind: 'live' | 'ready' = 'ready'): Promise<boolean> {
  try {
    const res = await fetch(`http://${stack.host}:${port()}/health/${kind}`, {
      signal: AbortSignal.timeout(3_000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/** The email-worker's Prometheus exposition, or undefined when it does not answer. */
export async function emailWorkerMetrics(): Promise<string | undefined> {
  try {
    const res = await fetch(`http://${stack.host}:${port()}/metrics`, {
      signal: AbortSignal.timeout(3_000),
    });
    return res.ok ? await res.text() : undefined;
  } catch {
    return undefined;
  }
}

let cached: Promise<SmtpStackGate> | undefined;

export function mimeStackGate(): Promise<SmtpStackGate> {
  cached ??= detect();
  return cached;
}

async function detect(): Promise<SmtpStackGate> {
  const base = await smtpStackGate();
  if (base.skip) return base;
  const problems: string[] = base.problem ? [base.problem] : [];
  if (!(await emailWorkerHealth('ready'))) {
    problems.push(`email-worker is not ready on ${stack.host}:${port()} (GET /health/ready)`);
  } else {
    const metrics = await emailWorkerMetrics();
    if (!metrics || !/^# TYPE mime_parse_messages_total /m.test(metrics)) {
      problems.push(
        'the email-worker does not run the MIME ingestion stage (no mime_parse_messages_total ' +
          'in /metrics): an image older than step 3.1, or MIME_INGESTION_ENABLED=false',
      );
    }
  }
  const scan = await scanStageProblems();
  problems.push(...scan);
  return {
    ...base,
    problem:
      problems.length > 0
        ? `${problems.join('\n')}\n${HOW_TO_START}${scan.length > 0 ? `\n${SCAN_HOW_TO_START}` : ''}`
        : undefined,
  };
}
