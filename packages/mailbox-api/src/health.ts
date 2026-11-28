/**
 * API-mode connection health (design D11.3, document `api-mode-health/1`). Pure: the health role
 * gathers the inputs (connection, grant, journal source, mailbox counts, counters of the last
 * hour, MX observations) and stores the result in `api_mode_connections.health_checks` /
 * `health_status`. Evidence strings carry counts, percentages and states only — never an address,
 * a token or a cursor.
 */
import { z } from 'zod';
import { coveragePercent } from './coverage';

export const API_MODE_HEALTH_SCHEMA_VERSION = 1;

/** The checks in evaluation (and display) order. */
export const API_MODE_HEALTH_CHECK_CODES = [
  'connection.active',
  'intake.present',
  'intake.journal_health',
  'mailbox_access.grant',
  'coverage.percent',
  'lag.p95_1h',
  'throttling.1h',
  'feeds.errors',
  'domains.api_mode_mx',
  // Step API-2 (note 36 R14): remediation checks, evaluated only with the `remediation` input.
  'remediation.failures_1h',
  'remediation.backlog',
  'remediation.access',
  'remediation.paused',
  // Step API-3 (note 37 C13): evaluated only with the `clawback` / `reports` inputs.
  'clawback.stalled',
  'reports.backlog',
  // Step API-4 (note 38 A11): evaluated only with the `policy` input (16th of 16 allowed).
  'policy.errors_1h',
] as const;
export type ApiModeHealthCheckCode = (typeof API_MODE_HEALTH_CHECK_CODES)[number];

export type ApiModeCheckStatus = 'pass' | 'warn' | 'fail';
export type ApiModeHealthStatus = 'healthy' | 'degraded' | 'failing';

export interface ApiModeHealthCheck {
  code: ApiModeHealthCheckCode;
  status: ApiModeCheckStatus;
  /** Non-secret, ≤ 512 characters. */
  evidence?: string;
}

/** `api-mode-health/1` as stored in `api_mode_connections.health_checks`. */
export const apiModeHealthDocumentSchema = z.strictObject({
  v: z.literal(API_MODE_HEALTH_SCHEMA_VERSION),
  checks: z
    .array(
      z.strictObject({
        code: z.enum(API_MODE_HEALTH_CHECK_CODES),
        status: z.enum(['pass', 'warn', 'fail']),
        evidence: z.string().max(512).optional(),
      }),
    )
    .max(16),
});
export type ApiModeHealthDocument = z.infer<typeof apiModeHealthDocumentSchema>;

/** 8.2 grant states (`provider_connection_grants.status`); null = no mailbox-access grant. */
export type MailboxGrantStatus = 'pending_consent' | 'verifying' | 'active' | 'error' | 'revoked';
/** 8.6 journal intake source health (`journal_intake_sources` health status). */
export type JournalSourceHealth = 'unknown' | 'healthy' | 'silent' | 'failing' | 'paused';

export interface ApiModeHealthInput {
  /** The 8.2 connection is `active` and its tenant is bound. */
  connection: { active: boolean; bound: boolean };
  /** A verified provider journal source bound to the connection, and its 8.6 health. */
  journal: { verifiedSource: boolean; sourceHealth: JournalSourceHealth | null };
  /** Status of the connection's `*.mailbox_remediation` grant (null: none). */
  grantStatus: MailboxGrantStatus | null;
  feeds: {
    enabled: boolean;
    /** Mailboxes with a feed (`feed_status` not `off`). */
    feedMailboxes: number;
    /** Feed mailboxes in `active`. */
    activeMailboxes: number;
    /** Feed mailboxes in `error`. */
    errorMailboxes: number;
  };
  coverage: {
    /** `inventory_status = ok`; without it coverage % is skipped. */
    inventoryOk: boolean;
    /** In-scope (`active`, domain effective api/hybrid) mailboxes. */
    inScopeMailboxes: number;
    covered: number;
    gap: number;
  };
  /** Bucket p95 of the last hour (`lagPercentileSeconds`), null without copies. */
  lagP95SecondsLastHour: number | null;
  /** Throttle events (429 + 503 pauses) in the last hour. */
  throttleEventsLastHour: number;
  /** Effective-`api` domains whose latest MX observation points to the gateway. */
  apiModeDomainsWithGatewayMx: number;
  /**
   * Step API-2 (R14): remediation facts of the connection. Optional so API-1 callers compile
   * unchanged; without it the four `remediation.*` checks are not evaluated (not in the result).
   */
  remediation?: ApiModeRemediationHealthInput;
  /**
   * Step API-3 (C13): clawback facts of the connection. Optional; without it `clawback.stalled`
   * is not evaluated (not in the result).
   */
  clawback?: ApiModeClawbackHealthInput;
  /**
   * Step API-3 (C13): report facts of the connection. Optional; without it `reports.backlog` is
   * not evaluated (not in the result).
   */
  reports?: ApiModeReportsHealthInput;
  /**
   * Step API-4 (A11): detect-mode policy evaluations of the connection's copies in the last hour.
   * Optional; without it `policy.errors_1h` is not evaluated (not in the result).
   */
  policy?: ApiModePolicyHealthInput;
}

/** A11 `policy.errors_1h` facts (counter sums of the last hour). */
export interface ApiModePolicyHealthInput {
  /** `api_mode_counters.policy_evaluations` (evaluated copies). */
  evaluations1h: number;
  /** `api_mode_counters.policy_errors` (evaluations that failed). */
  errors1h: number;
}

/** `policy.errors_1h` rates only with at least this many attempts in the hour (A11). */
export const POLICY_ERRORS_MIN_EVALUATIONS = 10;
/** A11 fixed thresholds of the error ratio (percent; not configuration). */
export const POLICY_ERRORS_WARN_PERCENT = 5;
export const POLICY_ERRORS_FAIL_PERCENT = 50;

/**
 * A11 `policy.errors_1h`: errors / (evaluations + errors) over the last hour; with at least ten
 * attempts > 5 % → warn, > 50 % → fail.
 */
export function evaluatePolicyHealth(input: ApiModePolicyHealthInput): ApiModeHealthCheck {
  const evaluations = Math.max(0, Math.trunc(input.evaluations1h));
  const errors = Math.max(0, Math.trunc(input.errors1h));
  const attempts = evaluations + errors;
  if (attempts < POLICY_ERRORS_MIN_EVALUATIONS) {
    return check(
      'policy.errors_1h',
      'pass',
      `${attempts} policy evaluation(s) in the last hour (${POLICY_ERRORS_MIN_EVALUATIONS} needed to rate)`,
    );
  }
  const percent = (errors / attempts) * 100;
  const status: ApiModeCheckStatus =
    percent > POLICY_ERRORS_FAIL_PERCENT
      ? 'fail'
      : percent > POLICY_ERRORS_WARN_PERCENT
        ? 'warn'
        : 'pass';
  return check(
    'policy.errors_1h',
    status,
    `${pct(percent)} of ${attempts} policy evaluations failed in the last hour (${errors} failed)`,
  );
}

/** C13 `clawback.stalled` facts (ages only). */
export interface ApiModeClawbackHealthInput {
  /**
   * Age of the oldest `queued`/`running` clawback of the connection's organization that has
   * targets on this connection; null when there is none.
   */
  oldestActiveAgeSeconds: number | null;
  thresholds: {
    /** `API_MODE_CLAWBACK_STALLED_WARN_MINUTES` (60). */
    stalledWarnMinutes: number;
    /** `API_MODE_CLAWBACK_STALLED_FAIL_MINUTES` (240). */
    stalledFailMinutes: number;
  };
}

/** C13 `reports.backlog` facts (ages and flags only). */
export interface ApiModeReportsHealthInput {
  /** The connection owns at least one report mailbox. */
  hasReportMailbox: boolean;
  /** Age of the oldest `pending_triage` report of those mailboxes; null when there is none. */
  oldestPendingTriageAgeSeconds: number | null;
  thresholds: {
    /** `API_MODE_REPORT_TRIAGE_WARN_HOURS` (24). */
    triageWarnHours: number;
  };
}

/** C13 `clawback.stalled`: older than the warn minutes → warn, the fail minutes → fail. */
export function evaluateClawbackHealth(input: ApiModeClawbackHealthInput): ApiModeHealthCheck {
  const age = input.oldestActiveAgeSeconds;
  if (age === null) return check('clawback.stalled', 'pass', 'no queued or running clawback');
  const seconds = Math.max(0, age);
  const minutes = seconds / 60;
  const t = input.thresholds;
  const status: ApiModeCheckStatus =
    minutes > t.stalledFailMinutes ? 'fail' : minutes > t.stalledWarnMinutes ? 'warn' : 'pass';
  return check(
    'clawback.stalled',
    status,
    `oldest queued or running clawback ${Math.floor(seconds)} s old`,
  );
}

/** C13 `reports.backlog`: oldest pending triage older than the warn hours → warn (never fail). */
export function evaluateReportsHealth(input: ApiModeReportsHealthInput): ApiModeHealthCheck {
  if (!input.hasReportMailbox) {
    return check('reports.backlog', 'pass', 'no report mailbox on this connection');
  }
  const age = input.oldestPendingTriageAgeSeconds;
  if (age === null) return check('reports.backlog', 'pass', 'no report pending triage');
  const seconds = Math.max(0, age);
  return check(
    'reports.backlog',
    seconds / 3600 > input.thresholds.triageWarnHours ? 'warn' : 'pass',
    `oldest report pending triage ${Math.floor(seconds)} s old`,
  );
}

/** Remediation facts of one connection for the R14 checks (counts, ages and flags only). */
export interface ApiModeRemediationHealthInput {
  /** Remediations (not reversals) that succeeded / failed in the last hour. */
  succeeded1h: number;
  failed1h: number;
  /** Age of the oldest `pending` policy/admin/release action (throttle-delayed included). */
  oldestPendingAgeSeconds: number | null;
  /** The effective policy is `enforce` for a domain of the connection but no grant is active. */
  enforceWithoutGrant: boolean;
  /** `api_mode_connections.remediation_paused`. */
  paused: boolean;
  thresholds: {
    /** `API_MODE_REMEDIATION_FAILURE_WARN_PERCENT` (10). */
    failureWarnPercent: number;
    /** `API_MODE_REMEDIATION_FAILURE_FAIL_PERCENT` (50). */
    failureFailPercent: number;
    /** `API_MODE_REMEDIATION_BACKLOG_WARN_MINUTES` (15). */
    backlogWarnMinutes: number;
    /** `API_MODE_REMEDIATION_BACKLOG_FAIL_MINUTES` (60). */
    backlogFailMinutes: number;
  };
}

/** The failure-rate check needs at least this many attempts in the hour (R14). */
export const REMEDIATION_FAILURE_MIN_ATTEMPTS = 5;

/** R14: the four remediation checks, in code order. */
export function evaluateRemediationHealth(
  input: ApiModeRemediationHealthInput,
): ApiModeHealthCheck[] {
  const checks: ApiModeHealthCheck[] = [];
  const t = input.thresholds;
  const succeeded = Math.max(0, input.succeeded1h);
  const failed = Math.max(0, input.failed1h);
  const attempts = succeeded + failed;
  if (attempts < REMEDIATION_FAILURE_MIN_ATTEMPTS) {
    checks.push(
      check(
        'remediation.failures_1h',
        'pass',
        `${attempts} remediation attempt(s) in the last hour (${REMEDIATION_FAILURE_MIN_ATTEMPTS} needed to rate)`,
      ),
    );
  } else {
    const percent = (failed / attempts) * 100;
    const status: ApiModeCheckStatus =
      percent > t.failureFailPercent ? 'fail' : percent > t.failureWarnPercent ? 'warn' : 'pass';
    checks.push(
      check(
        'remediation.failures_1h',
        status,
        `${pct(percent)} of ${attempts} remediations failed in the last hour (${failed} failed)`,
      ),
    );
  }

  const age = input.oldestPendingAgeSeconds;
  if (age === null) {
    checks.push(check('remediation.backlog', 'pass', 'no pending remediation'));
  } else {
    const minutes = Math.max(0, age) / 60;
    const status: ApiModeCheckStatus =
      minutes > t.backlogFailMinutes ? 'fail' : minutes > t.backlogWarnMinutes ? 'warn' : 'pass';
    checks.push(
      check(
        'remediation.backlog',
        status,
        `oldest pending remediation ${Math.floor(Math.max(0, age))} s old`,
      ),
    );
  }

  checks.push(
    input.enforceWithoutGrant
      ? check(
          'remediation.access',
          'warn',
          'remediation not possible: policy enforces but no active mailbox access grant',
        )
      : check('remediation.access', 'pass', 'mailbox access available where remediation enforces'),
  );

  checks.push(
    input.paused
      ? check('remediation.paused', 'warn', 'remediation paused for this connection')
      : check('remediation.paused', 'pass', 'remediation not paused'),
  );
  return checks;
}

export interface ApiModeHealthConfig {
  /** `API_MODE_COVERAGE_WARN_PERCENT` (95). */
  coverageWarnPercent: number;
  /** `API_MODE_COVERAGE_FAIL_PERCENT` (50). */
  coverageFailPercent: number;
  /** `API_MODE_LAG_WARN_SECONDS` (900). */
  lagWarnSeconds: number;
  /** `API_MODE_LAG_FAIL_SECONDS` (3600). */
  lagFailSeconds: number;
  /** `API_MODE_THROTTLE_WARN_PER_HOUR` (20). */
  throttleWarnPerHour: number;
}

/** The fixed ratios of D11.3 (not configuration). */
export const FEEDS_INTAKE_MIN_RATIO = 0.9;
export const FEEDS_ERROR_WARN_RATIO = 0.1;

export interface ApiModeHealthResult {
  status: ApiModeHealthStatus;
  checks: ApiModeHealthCheck[];
  /** The stored `api-mode-health/1` document. */
  document: ApiModeHealthDocument;
  /** Codes of the checks that are `fail` or `warn` (audit metadata `failingChecks`). */
  failingChecks: ApiModeHealthCheckCode[];
}

const pct = (value: number): string => `${Math.round(value * 10) / 10}%`;

function check(
  code: ApiModeHealthCheckCode,
  status: ApiModeCheckStatus,
  evidence: string,
): ApiModeHealthCheck {
  return { code, status, evidence: evidence.slice(0, 512) };
}

/** D11.3: every check, then the worst status (`fail` → failing, `warn` → degraded). */
export function evaluateApiModeHealth(
  input: ApiModeHealthInput,
  config: ApiModeHealthConfig,
): ApiModeHealthResult {
  const checks: ApiModeHealthCheck[] = [];
  const { connection, journal, feeds, coverage } = input;

  checks.push(
    connection.active && connection.bound
      ? check('connection.active', 'pass', 'connection active and tenant bound')
      : check(
          'connection.active',
          'fail',
          !connection.active ? 'provider connection not active' : 'tenant not bound',
        ),
  );

  const feedRatio =
    coverage.inScopeMailboxes > 0 ? feeds.activeMailboxes / coverage.inScopeMailboxes : 0;
  const feedsCarryIntake =
    feeds.enabled && coverage.inScopeMailboxes > 0 && feedRatio >= FEEDS_INTAKE_MIN_RATIO;
  checks.push(
    journal.verifiedSource
      ? check('intake.present', 'pass', 'verified provider journal source')
      : feedsCarryIntake
        ? check(
            'intake.present',
            'pass',
            `no journal source; feeds active on ${pct(feedRatio * 100)}`,
          )
        : check(
            'intake.present',
            'fail',
            feeds.enabled
              ? `no verified journal source; feeds active on ${pct(feedRatio * 100)} of in-scope mailboxes (90% needed)`
              : 'no verified journal source and feeds disabled',
          ),
  );

  if (!journal.verifiedSource || journal.sourceHealth === null) {
    checks.push(check('intake.journal_health', 'pass', 'no journal source'));
  } else if (journal.sourceHealth === 'failing') {
    checks.push(check('intake.journal_health', 'fail', 'journal source failing'));
  } else if (journal.sourceHealth === 'silent' || journal.sourceHealth === 'paused') {
    checks.push(check('intake.journal_health', 'warn', `journal source ${journal.sourceHealth}`));
  } else {
    checks.push(check('intake.journal_health', 'pass', `journal source ${journal.sourceHealth}`));
  }

  if (input.grantStatus === 'active') {
    checks.push(check('mailbox_access.grant', 'pass', 'mailbox access granted'));
  } else if (input.grantStatus === 'revoked' && feeds.enabled) {
    checks.push(
      check('mailbox_access.grant', 'fail', 'mailbox access revoked while feeds enabled'),
    );
  } else {
    checks.push(
      check(
        'mailbox_access.grant',
        'warn',
        input.grantStatus === null
          ? 'no mailbox access grant'
          : `mailbox access ${input.grantStatus}`,
      ),
    );
  }

  if (!coverage.inventoryOk) {
    checks.push(check('coverage.percent', 'pass', 'skipped: no mailbox inventory (total unknown)'));
  } else {
    const percent = coveragePercent(coverage);
    if (percent === null) {
      checks.push(check('coverage.percent', 'pass', 'no in-scope mailboxes'));
    } else {
      const status: ApiModeCheckStatus =
        percent < config.coverageFailPercent
          ? 'fail'
          : percent < config.coverageWarnPercent
            ? 'warn'
            : 'pass';
      checks.push(
        check(
          'coverage.percent',
          status,
          `${pct(percent)} covered (${coverage.covered} of ${coverage.covered + coverage.gap})`,
        ),
      );
    }
  }

  const lag = input.lagP95SecondsLastHour;
  if (lag === null) {
    checks.push(check('lag.p95_1h', 'pass', 'no copies in the last hour'));
  } else {
    const status: ApiModeCheckStatus =
      lag > config.lagFailSeconds ? 'fail' : lag > config.lagWarnSeconds ? 'warn' : 'pass';
    checks.push(check('lag.p95_1h', status, `p95 lag ${lag} s in the last hour`));
  }

  checks.push(
    check(
      'throttling.1h',
      input.throttleEventsLastHour > config.throttleWarnPerHour ? 'warn' : 'pass',
      `${input.throttleEventsLastHour} throttle events in the last hour`,
    ),
  );

  if (!feeds.enabled || feeds.feedMailboxes === 0) {
    checks.push(
      check('feeds.errors', 'pass', feeds.enabled ? 'no feed mailboxes' : 'feeds disabled'),
    );
  } else {
    const ratio = feeds.errorMailboxes / feeds.feedMailboxes;
    checks.push(
      check(
        'feeds.errors',
        ratio > FEEDS_ERROR_WARN_RATIO ? 'warn' : 'pass',
        `${feeds.errorMailboxes} of ${feeds.feedMailboxes} feed mailboxes in error`,
      ),
    );
  }

  checks.push(
    input.apiModeDomainsWithGatewayMx > 0
      ? check(
          'domains.api_mode_mx',
          'warn',
          `${input.apiModeDomainsWithGatewayMx} API-mode domain(s) with MX pointing to the gateway`,
        )
      : check('domains.api_mode_mx', 'pass', 'no API-mode domain points its MX to the gateway'),
  );

  if (input.remediation) checks.push(...evaluateRemediationHealth(input.remediation));
  if (input.clawback) checks.push(evaluateClawbackHealth(input.clawback));
  if (input.reports) checks.push(evaluateReportsHealth(input.reports));
  if (input.policy) checks.push(evaluatePolicyHealth(input.policy));

  const status: ApiModeHealthStatus = checks.some((c) => c.status === 'fail')
    ? 'failing'
    : checks.some((c) => c.status === 'warn')
      ? 'degraded'
      : 'healthy';
  return {
    status,
    checks,
    document: { v: API_MODE_HEALTH_SCHEMA_VERSION, checks },
    failingChecks: checks.filter((c) => c.status !== 'pass').map((c) => c.code),
  };
}
