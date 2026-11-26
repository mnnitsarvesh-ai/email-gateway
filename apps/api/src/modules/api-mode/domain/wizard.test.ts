import { describe, expect, it } from 'vitest';
import {
  type ApiModeWizardInput,
  type ApiModeWizardStep,
  type ApiModeWizardStepStatus,
  computeApiModeWizard,
  feedsCoverEnough,
} from './wizard';

const READY: ApiModeWizardInput = {
  apiModeDomains: 2,
  connection: { status: 'active', bound: true },
  journal: { status: 'active', verified: true, health: 'healthy' },
  grant: 'active',
  feeds: { enabled: true, inScopeMailboxes: 100, activeMailboxes: 95 },
  health: 'healthy',
};

const statuses = (input: ApiModeWizardInput) =>
  Object.fromEntries(computeApiModeWizard(input).steps.map((s) => [s.step, s.status])) as Record<
    ApiModeWizardStep,
    ApiModeWizardStepStatus
  >;

const blockersOf = (input: ApiModeWizardInput, step: ApiModeWizardStep) =>
  computeApiModeWizard(input).steps.find((s) => s.step === step)!.blockers;

describe('computeApiModeWizard (step API-1 D12.2)', () => {
  it('a fully set up connection is done everywhere with no next action', () => {
    const state = computeApiModeWizard(READY);
    expect(state.steps.map((s) => s.step)).toEqual([
      'domains',
      'connection',
      'journal',
      'mailbox_access',
      'feeds',
      'monitor',
    ]);
    expect(state.steps.every((s) => s.status === 'done')).toBe(true);
    expect(state.nextAction).toBeNull();
  });

  it('feeds disabled: skipped; the journal alone is enough to monitor', () => {
    const input = { ...READY, feeds: { ...READY.feeds, enabled: false } };
    expect(statuses(input)).toEqual({
      domains: 'done',
      connection: 'done',
      journal: 'done',
      mailbox_access: 'done',
      feeds: 'skipped',
      monitor: 'done',
    });
  });

  it.each<
    [string, Partial<ApiModeWizardInput>, ApiModeWizardStep, ApiModeWizardStepStatus, string[]]
  >([
    ['no api-mode domain', { apiModeDomains: 0 }, 'domains', 'not_started', ['no_api_mode_domain']],
    [
      'draft connection',
      { connection: { status: 'draft', bound: false } },
      'connection',
      'not_started',
      ['connection_not_bound'],
    ],
    [
      'connecting, not bound',
      { connection: { status: 'connecting', bound: false } },
      'connection',
      'in_progress',
      ['connection_not_bound'],
    ],
    [
      'bound but configuring',
      { connection: { status: 'configuring', bound: true } },
      'connection',
      'in_progress',
      ['connection_not_active'],
    ],
    [
      'disabled connection',
      { connection: { status: 'disabled', bound: true } },
      'connection',
      'blocked',
      ['connection_disabled'],
    ],
    [
      'no journal source, feeds not done',
      { journal: null, feeds: { enabled: false, inScopeMailboxes: 0, activeMailboxes: 0 } },
      'journal',
      'not_started',
      ['journal_source_missing'],
    ],
    [
      'no journal source but active feeds: recommended, not blocking',
      { journal: null },
      'journal',
      'in_progress',
      ['journal_source_missing'],
    ],
    [
      'disabled journal source',
      {
        journal: { status: 'disabled', verified: true, health: 'healthy' },
        feeds: { enabled: false, inScopeMailboxes: 0, activeMailboxes: 0 },
      },
      'journal',
      'not_started',
      ['journal_source_missing'],
    ],
    [
      'paused journal source',
      { journal: { status: 'paused', verified: true, health: 'paused' } },
      'journal',
      'in_progress',
      ['journal_source_paused'],
    ],
    [
      'journal not verified',
      { journal: { status: 'pending_verification', verified: false, health: 'unknown' } },
      'journal',
      'in_progress',
      ['journal_not_verified'],
    ],
    [
      'journal failing',
      { journal: { status: 'active', verified: true, health: 'failing' } },
      'journal',
      'in_progress',
      ['journal_failing'],
    ],
    [
      'journal silent still counts',
      { journal: { status: 'active', verified: true, health: 'silent' } },
      'journal',
      'done',
      [],
    ],
    ['no grant', { grant: null }, 'mailbox_access', 'not_started', ['grant_missing']],
    ['revoked grant', { grant: 'revoked' }, 'mailbox_access', 'not_started', ['grant_missing']],
    [
      'consent pending',
      { grant: 'pending_consent' },
      'mailbox_access',
      'in_progress',
      ['grant_pending'],
    ],
    ['verifying', { grant: 'verifying' }, 'mailbox_access', 'in_progress', ['grant_pending']],
    ['grant error', { grant: 'error' }, 'mailbox_access', 'in_progress', ['grant_error']],
    [
      'grant blocked by the connection',
      { connection: { status: 'draft', bound: false } },
      'mailbox_access',
      'blocked',
      ['connection'],
    ],
    [
      'feeds below 90 %',
      { feeds: { enabled: true, inScopeMailboxes: 100, activeMailboxes: 89 } },
      'feeds',
      'in_progress',
      ['feeds_initializing'],
    ],
    [
      'feeds without in-scope mailboxes',
      { feeds: { enabled: true, inScopeMailboxes: 0, activeMailboxes: 0 } },
      'feeds',
      'in_progress',
      ['no_in_scope_mailboxes'],
    ],
    ['feeds blocked by the grant', { grant: 'error' }, 'feeds', 'blocked', ['mailbox_access']],
    ['feeds blocked by the domains', { apiModeDomains: 0 }, 'feeds', 'blocked', ['domains']],
    ['health degraded is done', { health: 'degraded' }, 'monitor', 'done', []],
    ['health unknown', { health: 'unknown' }, 'monitor', 'in_progress', ['health_unknown']],
    ['health failing', { health: 'failing' }, 'monitor', 'in_progress', ['health_failing']],
    [
      'no intake path',
      {
        journal: null,
        feeds: { enabled: true, inScopeMailboxes: 10, activeMailboxes: 1 },
      },
      'monitor',
      'blocked',
      ['intake_missing'],
    ],
    ['monitor blocked by the domains', { apiModeDomains: 0 }, 'monitor', 'blocked', ['domains']],
  ])('%s', (_name, patch, step, status, blockers) => {
    const input = { ...READY, ...patch };
    expect(statuses(input)[step]).toBe(status);
    expect(blockersOf(input, step)).toEqual(blockers);
  });

  it('the next action is the first unsatisfied, unblocked step', () => {
    expect(computeApiModeWizard({ ...READY, apiModeDomains: 0 }).nextAction).toEqual({
      step: 'domains',
      action: 'set_domain_api_mode',
    });
    expect(computeApiModeWizard({ ...READY, grant: null }).nextAction).toEqual({
      step: 'mailbox_access',
      action: 'grant_mailbox_access',
    });
    expect(
      computeApiModeWizard({ ...READY, journal: null, feeds: { ...READY.feeds, enabled: false } })
        .nextAction,
    ).toEqual({ step: 'journal', action: 'configure_journal' });
    expect(computeApiModeWizard({ ...READY, health: 'unknown' }).nextAction).toEqual({
      step: 'monitor',
      action: 'review_health',
    });
  });

  it('feedsCoverEnough: at least 90 % of a non-empty in-scope set', () => {
    expect(feedsCoverEnough({ enabled: true, inScopeMailboxes: 10, activeMailboxes: 9 })).toBe(
      true,
    );
    expect(feedsCoverEnough({ enabled: true, inScopeMailboxes: 10, activeMailboxes: 8 })).toBe(
      false,
    );
    expect(feedsCoverEnough({ enabled: true, inScopeMailboxes: 0, activeMailboxes: 0 })).toBe(
      false,
    );
  });
});
