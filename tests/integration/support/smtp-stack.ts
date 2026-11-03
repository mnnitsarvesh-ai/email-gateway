import { composeExec, runningServices } from './compose';
import { stack } from './env';

/**
 * Gate of the stack SMTP suites (tests/integration/smtp-*.test.ts). They need the mail plane
 * (default Compose services), the `smtp-test` profile and a running smtp-adapter that both
 * Postfix instances reach at SMTP_ADAPTER_HOST. Missing pieces FAIL the suites with an
 * explanation; only `SMTP_STACK_TESTS=skip` skips them (with a visible reason).
 */
export interface SmtpStackGate {
  /** True only when SMTP_STACK_TESTS=skip. */
  skip: boolean;
  /** Why the stack is not usable (undefined when it is). */
  problem: string | undefined;
  /** SMTP_ADAPTER_HOST as configured in Postfix (reachable from the containers). */
  adapterHost: string;
}

const REQUIRED_SERVICES = [
  'postfix',
  'postfix-outbound',
  'rspamd',
  'rspamd-outbound',
  'redis-dkim',
  'minio',
  'mail-sink',
  'dns-sink',
  'smtp-tools',
];

const HOW_TO_START = [
  'Start them with:',
  '  docker compose up -d --wait',
  '  docker compose --profile smtp-test up -d --wait mail-sink dns-sink smtp-tools',
  '  and smtp-adapter, either on the host (SMTP_ADAPTER_HOST=host.docker.internal in .env):',
  '    pnpm --filter @email-gateway/smtp-adapter dev',
  '  or as a container (SMTP_ADAPTER_HOST=smtp-adapter): docker compose --profile apps up -d --wait',
  'Set SMTP_STACK_TESTS=skip to skip these suites explicitly.',
].join('\n');

let cached: Promise<SmtpStackGate> | undefined;

export function smtpStackGate(): Promise<SmtpStackGate> {
  cached ??= detect();
  return cached;
}

async function detect(): Promise<SmtpStackGate> {
  if (process.env.SMTP_STACK_TESTS === 'skip') {
    process.stderr.write('[smtp-stack] SMTP_STACK_TESTS=skip: the stack SMTP suites are SKIPPED\n');
    return { skip: true, problem: undefined, adapterHost: '' };
  }
  const problems: string[] = [];
  const services = await runningServices();
  const missing = REQUIRED_SERVICES.filter((s) => !services.has(s));
  if (missing.length > 0) problems.push(`Compose services not running: ${missing.join(', ')}`);

  const adapterPort = stack.ports.services['smtp-adapter'];
  try {
    const res = await fetch(`http://${stack.host}:${adapterPort}/health/ready`, {
      signal: AbortSignal.timeout(3_000),
    });
    if (!res.ok) problems.push(`smtp-adapter is not ready (GET /health/ready → ${res.status})`);
  } catch {
    problems.push(`smtp-adapter does not answer on ${stack.host}:${adapterPort}`);
  }

  let adapterHost = '';
  if (services.has('postfix')) {
    const host = await composeExec('postfix', ['postconf', '-h', 'smtp_adapter_host']);
    adapterHost = host.stdout.trim();
    if (problems.length === 0) {
      // A real socketmap lookup from the inbound MX: NOTFOUND (exit 1) proves Postfix reaches
      // the adapter; a temporary error means SMTP_ADAPTER_HOST does not point at it.
      const probe = await composeExec('postfix', [
        'postmap',
        '-q',
        'reachability-probe.invalid',
        `socketmap:inet:${adapterHost}:10041:relay_domain`,
      ]);
      if (probe.exitCode !== 1) {
        problems.push(
          `postfix cannot reach smtp-adapter at ${adapterHost}:10041 (postmap exit ${probe.exitCode}); ` +
            'check SMTP_ADAPTER_HOST and recreate postfix/postfix-outbound',
        );
      }
    }
  }
  return {
    skip: false,
    problem: problems.length > 0 ? `${problems.join('\n')}\n${HOW_TO_START}` : undefined,
    adapterHost,
  };
}

/** Call in beforeAll: throws the explanation when the stack is not usable. */
export function assertStackReady(gate: SmtpStackGate): void {
  if (gate.problem) {
    throw new Error(`The stack SMTP suites cannot run:\n${gate.problem}`);
  }
}
