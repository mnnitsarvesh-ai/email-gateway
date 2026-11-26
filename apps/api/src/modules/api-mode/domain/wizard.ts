/**
 * The API-mode setup wizard of one provider connection (step API-1 D12.2), computed from rows and
 * never stored (the 8.2 `computeWizard` / 8.6 `computeIntakeWizard` pattern, ADR-0080 decision
 * 1). Pure, so every combination is table-tested.
 *
 * Steps: `domains` (≥ 1 domain linked to the connection with effective mode `api`/`hybrid`),
 * `connection` (8.2 connection `active` and bound), `journal` (a verified provider journal source
 * on this connection whose health is not `failing`; `in_progress` but not blocking when feeds
 * are active), `mailbox_access` (the `*.mailbox_remediation` grant `active`), `feeds` (`skipped`
 * when disabled; done when ≥ 90 % of the in-scope mailboxes are `active`), `monitor` (health
 * `healthy` or `degraded`).
 */

export type ApiModeWizardStep =
  'domains' | 'connection' | 'journal' | 'mailbox_access' | 'feeds' | 'monitor';
export type ApiModeWizardStepStatus =
  'not_started' | 'in_progress' | 'done' | 'blocked' | 'skipped';

export type GrantStatusValue = 'pending_consent' | 'verifying' | 'active' | 'error' | 'revoked';
export type JournalHealthValue = 'unknown' | 'healthy' | 'silent' | 'failing' | 'paused';
export type ApiModeHealthValue = 'unknown' | 'healthy' | 'degraded' | 'failing';

export interface ApiModeWizardInput {
  /** Domains linked to the connection with effective mode `api` or `hybrid`. */
  apiModeDomains: number;
  connection: {
    status: 'draft' | 'connecting' | 'configuring' | 'active' | 'disabled';
    /** `active_tenant_key` and `external_tenant_id` set (8.2 D4). */
    bound: boolean;
  };
  /** The best provider journal source bound to the connection (verified first), or null. */
  journal: {
    status: 'pending_verification' | 'active' | 'paused' | 'disabled';
    verified: boolean;
    health: JournalHealthValue;
  } | null;
  /** The `*.mailbox_remediation` grant of the connection, or null. */
  grant: GrantStatusValue | null;
  feeds: {
    enabled: boolean;
    /** In-scope mailboxes (status `active`, domain effective `api`/`hybrid`) with a provider id. */
    inScopeMailboxes: number;
    /** Of those, mailboxes whose feed is `active`. */
    activeMailboxes: number;
  };
  health: ApiModeHealthValue;
}

export interface ApiModeWizardStepState {
  step: ApiModeWizardStep;
  status: ApiModeWizardStepStatus;
  blockers: string[];
}

export interface ApiModeWizardState {
  steps: ApiModeWizardStepState[];
  nextAction: { step: ApiModeWizardStep; action: string } | null;
}

/** Feeds are `done` from this share of active in-scope mailboxes (D12.2, D11.3). */
export const FEEDS_DONE_RATIO = 0.9;

const satisfied = (s: ApiModeWizardStepState): boolean =>
  s.status === 'done' || s.status === 'skipped';

const ACTIONS: Readonly<Record<ApiModeWizardStep, string>> = {
  domains: 'set_domain_api_mode',
  connection: 'bind_connection',
  journal: 'configure_journal',
  mailbox_access: 'grant_mailbox_access',
  feeds: 'wait_for_feeds',
  monitor: 'review_health',
};

const state = (
  step: ApiModeWizardStep,
  status: ApiModeWizardStepStatus,
  blockers: string[] = [],
): ApiModeWizardStepState => ({ step, status, blockers });

/** `true` when at least FEEDS_DONE_RATIO of the in-scope mailboxes have an active feed. */
export function feedsCoverEnough(feeds: ApiModeWizardInput['feeds']): boolean {
  return (
    feeds.inScopeMailboxes > 0 && feeds.activeMailboxes >= FEEDS_DONE_RATIO * feeds.inScopeMailboxes
  );
}

/** Steps and their states (D12.2). */
export function computeApiModeWizard(input: ApiModeWizardInput): ApiModeWizardState {
  const blockedBy = (
    step: ApiModeWizardStep,
    ...deps: ApiModeWizardStepState[]
  ): ApiModeWizardStepState | null => {
    const missing = deps.filter((d) => !satisfied(d)).map((d) => d.step);
    return missing.length > 0 ? state(step, 'blocked', missing) : null;
  };

  const domains =
    input.apiModeDomains > 0
      ? state('domains', 'done')
      : state('domains', 'not_started', ['no_api_mode_domain']);

  const connection = ((): ApiModeWizardStepState => {
    const c = input.connection;
    if (c.status === 'disabled') return state('connection', 'blocked', ['connection_disabled']);
    if (!c.bound) {
      return state('connection', c.status === 'draft' ? 'not_started' : 'in_progress', [
        'connection_not_bound',
      ]);
    }
    if (c.status !== 'active') return state('connection', 'in_progress', ['connection_not_active']);
    return state('connection', 'done');
  })();

  const mailboxAccess =
    blockedBy('mailbox_access', connection) ??
    ((): ApiModeWizardStepState => {
      switch (input.grant) {
        case 'active':
          return state('mailbox_access', 'done');
        case 'pending_consent':
        case 'verifying':
          return state('mailbox_access', 'in_progress', ['grant_pending']);
        case 'error':
          return state('mailbox_access', 'in_progress', ['grant_error']);
        default:
          return state('mailbox_access', 'not_started', ['grant_missing']);
      }
    })();

  const feeds = !input.feeds.enabled
    ? state('feeds', 'skipped')
    : (blockedBy('feeds', domains, mailboxAccess) ??
      (feedsCoverEnough(input.feeds)
        ? state('feeds', 'done')
        : state('feeds', 'in_progress', [
            input.feeds.inScopeMailboxes === 0 ? 'no_in_scope_mailboxes' : 'feeds_initializing',
          ])));

  const journal =
    blockedBy('journal', connection) ??
    ((): ApiModeWizardStepState => {
      const j = input.journal;
      // With active feeds the journal is still recommended (the primary intake) but not blocking.
      const missing = feeds.status === 'done' ? 'in_progress' : 'not_started';
      if (j === null || j.status === 'disabled') {
        return state('journal', missing, ['journal_source_missing']);
      }
      if (j.status === 'paused') return state('journal', 'in_progress', ['journal_source_paused']);
      if (!j.verified) return state('journal', 'in_progress', ['journal_not_verified']);
      if (j.health === 'failing') return state('journal', 'in_progress', ['journal_failing']);
      return state('journal', 'done');
    })();

  // Monitoring needs the domains, the connection and an intake path (journal or feeds).
  const intake = journal.status === 'done' || feeds.status === 'done';
  const monitor =
    blockedBy('monitor', domains, connection) ??
    (!intake
      ? state('monitor', 'blocked', ['intake_missing'])
      : input.health === 'healthy' || input.health === 'degraded'
        ? state('monitor', 'done')
        : state('monitor', 'in_progress', [
            input.health === 'failing' ? 'health_failing' : 'health_unknown',
          ]));

  const steps = [domains, connection, journal, mailboxAccess, feeds, monitor];
  const next = steps.find((s) => !satisfied(s) && s.status !== 'blocked') ?? null;
  return {
    steps,
    nextAction: next === null ? null : { step: next.step, action: ACTIONS[next.step] },
  };
}
