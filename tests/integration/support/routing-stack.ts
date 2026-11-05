import { runningServices } from './compose';
import { workerHealth } from './delivery-worker';
import { maillogOffset, maillogPath } from './maillog';
import { SCAN_HOW_TO_START, scanStageProblems } from './scan-stage';
import { smtpStackGate, type SmtpStackGate } from './smtp-stack';

/**
 * Gate of the step 2.3 routing stack suites (tests/integration/routing-*.test.ts,
 * docs/plan/steps/05-routing.md §9): everything the step 2.2 suites need, plus the step 2.3
 * sinks and forwarder, a ready delivery-worker with the DEVELOPMENT-ONLY pass-through
 * (`DELIVERY_DEV_PASSTHROUGH_ENABLED=true`: mail is delivered without policy, which does not
 * exist before step 5.x) and the delivery log on the host. Since step 4.1 the pass-through
 * approves only scanned mail (E27, docs/plan/steps/09-rspamd.md S15), so the gate also requires
 * the email-worker scan role and the scanned pass-through (`scanStageProblems`). Missing pieces
 * FAIL the suites with an explanation; only `SMTP_STACK_TESTS=skip` skips them.
 */
const REQUIRED_SERVICES = [
  'sink-m365',
  'sink-google',
  'sink-google-alt',
  'relay-sink',
  'reinject-forwarder',
];

const HOW_TO_START = [
  'Start them with:',
  '  docker compose --profile smtp-test up -d --wait',
  '  pnpm --filter @email-gateway/smtp-adapter dev     (or the apps profile)',
  '  pnpm --filter @email-gateway/delivery-worker dev  (DELIVERY_DEV_PASSTHROUGH_ENABLED=true in .env)',
].join('\n');

let cached: Promise<SmtpStackGate> | undefined;

export function routingStackGate(): Promise<SmtpStackGate> {
  cached ??= detect();
  return cached;
}

async function detect(): Promise<SmtpStackGate> {
  const base = await smtpStackGate();
  if (base.skip) return base;
  const problems: string[] = base.problem ? [base.problem] : [];
  const services = await runningServices();
  const missing = REQUIRED_SERVICES.filter((s) => !services.has(s));
  if (missing.length > 0) problems.push(`Compose services not running: ${missing.join(', ')}`);
  if (!(await workerHealth('ready'))) problems.push('delivery-worker is not ready (port 3040)');
  if (process.env.DELIVERY_DEV_PASSTHROUGH_ENABLED !== 'true') {
    problems.push('DELIVERY_DEV_PASSTHROUGH_ENABLED=true is required (local/CI only)');
  }
  if ((await maillogOffset()) === 0) problems.push(`delivery log ${maillogPath()} is missing`);
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
