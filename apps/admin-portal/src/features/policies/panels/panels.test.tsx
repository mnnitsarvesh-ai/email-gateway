import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { SuccessBody } from '@/lib/api/types';
import {
  apiErrorJson,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { TEST_RESPONSE } from '../builder/test-support/responses';
import { PolicyBuilder } from '../policy-builder';
import { MESSAGE_ID, POLICY_ID, REAL_CATALOG } from '../test-data';
import { sampleWindow } from './dry-run-panel';

type Sample = SuccessBody<'PolicyToolsController_sampleDryRun_v1'>;
type Item = Sample['items'][number];

const item = (n: number, changed: boolean): Item => ({
  messageId: `01933c3a-1b2c-7d4e-8f00-00000000b00${n}`,
  receivedAt: `2026-11-1${n}T09:00:00.000Z`,
  direction: 'inbound',
  lifecycleRound: 0,
  scanId: String(900_000 + n),
  trigger: 'scanned',
  outcome: 'evaluated',
  stored: {
    disposition: 'allow',
    source: 'platform_default',
    policyId: null,
    versionNo: null,
    ruleId: null,
    evaluatedAt: `2026-11-1${n}T09:00:04.000Z`,
  },
  dryRun: {
    disposition: changed ? 'quarantine' : 'allow',
    lifecycleDisposition: changed ? 'quarantine' : 'allow',
    source: changed ? 'tenant_rule' : 'platform_default',
    policyId: changed ? POLICY_ID : null,
    versionNo: changed ? 2 : null,
    ruleId: changed ? 'quarantine-confidential' : null,
    matchedRuleCount: changed ? 1 : 0,
    actionTypes: changed ? ['QUARANTINE'] : ['ALLOW'],
    recipientSplit: false,
    overrideApplied: false,
  },
  dispositionChanged: changed,
  decisiveChanged: changed,
  // Step 8.4 D23: where the round's account takeover facts came from.
  atoFactsSource: n === 2 ? 'stored' : 'none',
});

const SAMPLE: Sample = {
  target: { kind: 'active', policyId: null, versionNo: null },
  window: { from: '2026-11-09T09:00:00.000Z', to: '2026-11-16T09:00:00.000Z' },
  limit: 25,
  evaluated: 3,
  skipped: 0,
  truncated: true,
  exhausted: true,
  summary: {
    changed: 1,
    unchanged: 2,
    stored: { allow: 3, require_approval: 0, quarantine: 0, reject: 0 },
    dryRun: { allow: 2, require_approval: 0, quarantine: 1, reject: 0 },
    transitions: [{ from: 'allow', to: 'quarantine', count: 1 }],
  },
  items: [item(1, false), item(2, true), item(3, false)],
  invalidVersions: [],
};

function openBuilder(
  role: 'organization_admin' | 'security_analyst' | 'read_only_user' = 'organization_admin',
) {
  mockApi({ PolicyToolsController_catalog_v1: () => okJson(REAL_CATALOG) });
  return renderWithProviders(<PolicyBuilder />, { role, route: '/policies/builder' });
}

describe('Test panel (design B7)', () => {
  it('tests the active set with a preset and JSON facts; the request matches the contract; axe', async () => {
    const bodies: unknown[] = [];
    mockApi({
      PolicyToolsController_test_v1: ({ body }) => {
        bodies.push(body);
        return okJson(TEST_RESPONSE);
      },
    });
    const { user } = openBuilder();
    await user.click(await screen.findByRole('button', { name: 'Test with synthetic facts' }));
    const panel = await screen.findByRole('dialog', { name: 'Test with synthetic facts' });
    expect(within(panel).getByRole('radio', { name: 'Active policies' })).toBeChecked();
    expect(
      within(panel).queryByRole('radio', { name: /This draft|new policy/ }),
    ).not.toBeInTheDocument();
    await user.click(within(panel).getByRole('combobox', { name: 'Start from an example' }));
    await user.click(await screen.findByRole('option', { name: 'Phishing link' }));
    await user.click(within(panel).getByRole('radio', { name: 'Platform default only' }));
    await user.click(within(panel).getByRole('button', { name: 'Run test' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expectRequestMatchesContract('PolicyToolsController_test_v1', bodies[0]);
    expect(bodies[0]).toMatchObject({ target: 'platform', facts: { direction: 'inbound' } });
    expect(
      await within(panel).findByRole('heading', { name: 'Test result (evaluated by the server)' }),
    ).toBeInTheDocument();
    // The active set has no edited document: no "Show in editor".
    expect(within(panel).queryByRole('button', { name: /Show in editor/ })).not.toBeInTheDocument();
    await expectNoAxeViolations(panel);

    // Advanced (JSON): a non-object is refused locally; an object becomes the facts.
    await user.click(within(panel).getByRole('button', { name: 'Advanced (JSON)' }));
    const json = within(panel).getByLabelText(/Facts as JSON/);
    fireEvent.change(json, { target: { value: '[1, 2]' } });
    await user.click(within(panel).getByRole('button', { name: 'Apply JSON' }));
    expect(within(panel).getByText(/Enter a JSON object/)).toBeInTheDocument();
    fireEvent.change(json, { target: { value: '{ "direction": "outbound" }' } });
    await user.click(within(panel).getByRole('button', { name: 'Apply JSON' }));
    await user.click(within(panel).getByRole('button', { name: 'Run test' }));
    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies[1]).toEqual({ target: 'platform', facts: { direction: 'outbound' } });
    // The full facts form plus axe: 2–3 s alone, above the 20 s default under the whole
    // repository's parallel `pnpm test` (step 7.3 WP4 gate; as facts-form.test.tsx SLOW).
  }, 60_000);

  it('shows the server refusal of the facts (400 policy_test_facts_invalid)', async () => {
    mockApi({
      PolicyToolsController_test_v1: () =>
        apiErrorJson(400, 'policy_test_facts_invalid', [
          'facts.recipients[0].address: not an address',
        ]),
    });
    const { user } = openBuilder('security_analyst');
    await user.click(await screen.findByRole('button', { name: 'Test with synthetic facts' }));
    const panel = await screen.findByRole('dialog', { name: 'Test with synthetic facts' });
    await user.click(within(panel).getByRole('button', { name: 'Run test' }));
    expect(
      await within(panel).findByText('The server did not accept these facts'),
    ).toBeInTheDocument();
    expect(
      within(panel).getByText('facts.recipients[0].address: not an address'),
    ).toBeInTheDocument();
  });
});

describe('Dry-run panel (design B8)', () => {
  it('runs a sample dry-run (contract), shows the summary, transitions and items, filters changed ones', async () => {
    const bodies: unknown[] = [];
    mockApi({
      PolicyToolsController_sampleDryRun_v1: ({ body }) => {
        bodies.push(body);
        return okJson(SAMPLE);
      },
    });
    const { user } = openBuilder();
    await user.click(await screen.findByRole('button', { name: 'Dry run on stored messages' }));
    const panel = await screen.findByRole('dialog', { name: 'Dry run against stored messages' });
    expect(within(panel).getByText('At most 6 sample dry runs per minute.')).toBeInTheDocument();
    await user.click(within(panel).getByRole('combobox', { name: 'Direction' }));
    await user.click(await screen.findByRole('option', { name: 'Inbound' }));
    await user.click(within(panel).getByRole('button', { name: 'Run dry run' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expectRequestMatchesContract('PolicyToolsController_sampleDryRun_v1', bodies[0]);
    const body = bodies[0] as { target: unknown; sample: Record<string, unknown> };
    expect(body.target).toBe('active');
    expect(body.sample).toMatchObject({ direction: 'inbound', limit: 25 });
    expect(Date.parse(String(body.sample.to)) - Date.parse(String(body.sample.from))).toBe(
      7 * 86_400_000,
    );
    const result = await within(panel).findByTestId('sample-result');
    expect(within(result).getByText('1 changed, 2 unchanged')).toBeInTheDocument();
    expect(within(result).getByText(/time budget ended/)).toBeInTheDocument();
    expect(within(result).getByText(/fewer stored evaluations than the limit/)).toBeInTheDocument();
    expect(within(result).getByRole('list', { name: 'Disposition changes' })).toHaveTextContent(
      'Allow→toQuarantine: 1',
    );
    const table = within(result).getByRole('table', {
      name: 'Stored and dry-run decisions per message',
    });
    expect(within(table).getAllByRole('row')).toHaveLength(4);
    expect(within(table).getAllByRole('link')[0]).toHaveAttribute(
      'href',
      '/messages/01933c3a-1b2c-7d4e-8f00-00000000b001',
    );
    expect(within(table).getByRole('columnheader', { name: 'ATO facts' })).toBeInTheDocument();
    expect(within(table).getByText('Stored with the evaluation')).toBeInTheDocument();
    expect(within(table).getAllByText('None')).toHaveLength(2);
    await user.click(within(result).getByRole('checkbox', { name: 'Only changed decisions' }));
    expect(within(table).getAllByRole('row')).toHaveLength(2);
    expect(within(table).getByText('Disposition changed')).toBeInTheDocument();
    await expectNoAxeViolations(panel);
  });

  it('a 429 disables Run with a countdown', async () => {
    mockApi({
      PolicyToolsController_sampleDryRun_v1: () =>
        apiErrorJson(429, 'rate_limited', 'Too many', { headers: { 'retry-after': '42' } }),
    });
    const { user } = openBuilder();
    await user.click(await screen.findByRole('button', { name: 'Dry run on stored messages' }));
    const panel = await screen.findByRole('dialog', { name: 'Dry run against stored messages' });
    await user.click(within(panel).getByRole('button', { name: 'Run dry run' }));
    expect(await within(panel).findByText(/Run is available again in 4\d s/)).toBeInTheDocument();
    expect(within(panel).getByRole('button', { name: 'Run dry run' })).toBeDisabled();
  });

  it('a custom window longer than the history bound is refused before any request', async () => {
    const { user } = openBuilder();
    await user.click(await screen.findByRole('button', { name: 'Dry run on stored messages' }));
    const panel = await screen.findByRole('dialog', { name: 'Dry run against stored messages' });
    await user.click(within(panel).getByRole('combobox', { name: 'Window' }));
    await user.click(await screen.findByRole('option', { name: 'Custom window' }));
    fireEvent.change(within(panel).getByLabelText('From (your local time)'), {
      target: { value: '2026-09-01T00:00' },
    });
    fireEvent.change(within(panel).getByLabelText('To (your local time)'), {
      target: { value: '2026-11-01T00:00' },
    });
    await user.click(within(panel).getByRole('button', { name: 'Run dry run' }));
    expect(within(panel).getByRole('alert')).toHaveTextContent('at most 31 days');
    expect(
      sampleWindow(
        { window: 'custom', customFrom: '2026-11-02T10:00', customTo: '2026-11-01T10:00' },
        31,
      ),
    ).toEqual({
      problem: 'The start must be before the end.',
    });
  });

  it('one message: finds the rounds, dry-runs a completed one, shows stored vs recomputed and reproducible', async () => {
    const dryRuns: Array<{ params: Record<string, string>; body: unknown }> = [];
    mockApi({
      MessageScansController_scansOf_v1: () =>
        okJson({
          messageId: MESSAGE_ID,
          data: [
            {
              scanId: '900002',
              round: 1,
              scanKind: 'rescan',
              status: 'running',
              verdict: null,
              reasonCodes: [],
              requiredEngines: [],
              startedAt: '2026-11-12T09:20:00.000Z',
              completedAt: null,
              deadlineAt: null,
              auth: null,
              engines: [],
              risk: [],
              policy: null,
            },
            {
              scanId: '900001',
              round: 0,
              scanKind: 'initial',
              status: 'completed',
              verdict: 'clean',
              reasonCodes: [],
              requiredEngines: [],
              startedAt: '2026-11-12T09:14:03.000Z',
              completedAt: '2026-11-12T09:14:06.000Z',
              deadlineAt: null,
              auth: null,
              engines: [],
              risk: [],
              policy: null,
            },
          ],
          nextCursor: null,
        }),
      PolicyMessagesController_dryRun_v1: ({ params, body }) => {
        dryRuns.push({ params, body });
        return okJson({
          ...TEST_RESPONSE,
          stored: null,
          reproducible: false,
          atoFactsSource: 'current',
        });
      },
    });
    const { user } = openBuilder();
    await user.click(await screen.findByRole('button', { name: 'Dry run on stored messages' }));
    const panel = await screen.findByRole('dialog', { name: 'Dry run against stored messages' });
    await user.click(within(panel).getByRole('tab', { name: 'One message' }));
    await user.type(within(panel).getByLabelText('Message id'), 'nope');
    await user.click(within(panel).getByRole('button', { name: 'Find scan rounds' }));
    expect(within(panel).getByRole('alert')).toHaveTextContent('Enter the message id');
    await user.clear(within(panel).getByLabelText('Message id'));
    await user.type(within(panel).getByLabelText('Message id'), MESSAGE_ID);
    await user.click(within(panel).getByRole('button', { name: 'Find scan rounds' }));
    expect(
      await within(panel).findByText('1 round is still running and cannot be re-evaluated yet.'),
    ).toBeInTheDocument();
    await user.click(within(panel).getByRole('combobox', { name: 'Scan round' }));
    await user.click(await screen.findByRole('option', { name: /Round 0: Initial, Completed/ }));
    await user.click(within(panel).getByRole('button', { name: 'Run dry run' }));
    await waitFor(() => expect(dryRuns).toHaveLength(1));
    expect(dryRuns[0]?.params).toMatchObject({ messageId: MESSAGE_ID, scanId: '900001' });
    expectRequestMatchesContract('PolicyMessagesController_dryRun_v1', dryRuns[0]?.body);
    const result = await within(panel).findByTestId('message-result');
    expect(within(result).getByText('No stored evaluation for this round')).toBeInTheDocument();
    expect(within(result).getByText(/differ from the stored evaluation/)).toBeInTheDocument();
    expect(within(result).getByText('Account takeover facts')).toBeInTheDocument();
    expect(within(result).getByText('Current account state')).toBeInTheDocument();
  });

  it('is not offered without the permissions (read-only users)', async () => {
    openBuilder('read_only_user');
    expect(await screen.findByText('risk.score')).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Dry run on stored messages' }),
    ).not.toBeInTheDocument();
  });
});
