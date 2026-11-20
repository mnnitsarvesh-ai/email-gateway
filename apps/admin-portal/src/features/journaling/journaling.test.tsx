import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  makeMe,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { JournalingPanel, journalingBody, journalingDraftOf } from './journaling-panel';
import type { IntakeGuide, IntakeSource, IntakeWizard, JournalingSettings } from './model';
import {
  EMPTY_DRAFT,
  NewIntakeSourcePage,
  intakeCreateBody,
  intakeStepErrors,
} from './new-source-page';
import { IntakeSourcePage, intakeGuideFileName } from './source-page';

const SOURCE_ID = '01930000-0000-7000-8000-00000000d001';
const CONNECTION_ID = '01930000-0000-7000-8000-00000000d101';
const MASKED = 'journal-••••x7qa@journal.gateway.example.test';
const ADDRESS = 'journal-abcdefghijklmnopqrstuvx7qa@journal.gateway.example.test';

const SETTINGS: JournalingSettings = {
  enabled: true,
  entitled: true,
  intakeAvailable: true,
  intakeEntitled: true,
  journalEnabledAt: '2026-11-01T08:00:00.000Z',
  settings: {
    directions: { inbound: true, outbound: true, internal: false },
    include: { rejected: false, quarantined: true, failed: false },
    scope: { mode: 'all', domainIds: [], departmentIds: [], userIds: [], addresses: [] },
    policyArchive: { enabled: true },
    intake: { scanEnabled: false },
  },
  generation: 3,
  rowVersion: 5,
  updatedAt: '2026-11-10T08:00:00.000Z',
};

const SOURCE: IntakeSource = {
  id: SOURCE_ID,
  kind: 'exchange_onprem_journal',
  displayName: 'Head office Exchange',
  status: 'active',
  providerConnectionId: null,
  networks: ['203.0.113.0/28'],
  requireTls: true,
  clientCertFingerprints: [],
  maxMessageBytes: null,
  silenceAlertMinutes: 240,
  addressVersion: 1,
  address: MASKED,
  headerToken: null,
  revealed: false,
  previousAddressValidUntil: null,
  verifiedAt: '2026-11-02T08:00:00.000Z',
  lastAcceptedAt: '2026-11-19T09:00:00.000Z',
  lastRefusedAt: '2026-11-18T09:00:00.000Z',
  lastRefusalCode: 'refused_network',
  health: { status: 'silent', changedAt: '2026-11-19T13:00:00.000Z' },
  attestations: [],
  counters: [
    {
      day: '2026-11-19',
      accepted: 412,
      duplicates: 2,
      bytes: 9_000_000,
      refusedAddress: 0,
      refusedNetwork: 3,
      refusedTls: 0,
      refusedSize: 0,
      refusedRate: 0,
      refusedUnavailable: 0,
      droppedProof: 0,
      unwrapFailed: 0,
    },
  ],
  disabledAt: null,
  rowVersion: 4,
  createdAt: '2026-11-01T08:00:00.000Z',
  updatedAt: '2026-11-19T13:00:00.000Z',
};

const { counters: _counters, ...SOURCE_ROW } = SOURCE;

const WIZARD: IntakeWizard = {
  sourceId: SOURCE_ID,
  kind: 'exchange_onprem_journal',
  steps: [
    { step: 'archiving', status: 'done', blockers: [] },
    { step: 'domains', status: 'done', blockers: [] },
    { step: 'connection', status: 'skipped', blockers: [] },
    { step: 'configure', status: 'in_progress', blockers: [] },
    { step: 'verify', status: 'done', blockers: [] },
    { step: 'monitor', status: 'blocked', blockers: ['health_silent'] },
  ],
  missingAttestations: ['journal.onprem.send_connector_tls'],
  nextAction: { step: 'configure', action: 'Confirm the Send connector uses TLS.' },
};

const GUIDE: IntakeGuide = {
  schema: 'journal-intake-guide/1',
  kind: 'exchange_onprem_journal',
  source: { id: SOURCE_ID, displayName: SOURCE.displayName, kind: SOURCE.kind },
  address: MASKED,
  revealed: false,
  notice: 'EXAMPLE notice: you make these changes in your own mail system.',
  sections: [
    {
      id: 'journal-recipient',
      number: 1,
      title: 'Create the journal recipient',
      paragraphs: ['Create a mail contact with the intake address.'],
      steps: [
        {
          id: 'contact',
          title: 'Mail contact',
          paragraphs: ['Run in the Exchange Management Shell.'],
          commands: [{ language: 'powershell', code: 'New-MailContact -Name "Gateway journal"' }],
        },
      ],
    },
  ],
  attestations: [
    {
      code: 'journal.onprem.journal_recipient_created',
      statement: 'A journal recipient with the intake address exists.',
      attested: true,
      attestedAt: '2026-11-02T08:00:00.000Z',
    },
    {
      code: 'journal.onprem.send_connector_tls',
      statement: 'A Send connector delivers to the gateway with TLS.',
      attested: false,
      attestedAt: null,
    },
  ],
  generatedAt: '2026-11-20T08:00:00.000Z',
};

const mfaMe = (role: 'organization_admin' | 'read_only_user' = 'organization_admin') =>
  makeMe({
    role,
    overrides: {
      mfaEnabled: true,
      session: { id: '01930000-0000-7000-8000-000000000501', mfaAuthenticated: true },
    },
  });

function mockPanel(extra: Parameters<typeof mockApi>[0] = {}) {
  mockApi({
    JournalingController_get_v1: () => okJson(SETTINGS),
    JournalingController_status_v1: () =>
      okJson({
        generatedAt: '2026-11-20T08:00:00.000Z',
        settings: {
          enabled: true,
          entitled: true,
          intakeAvailable: true,
          intakeEntitled: true,
          generation: 3,
        },
        capture: {
          pending: 2,
          capturedOpen: 4,
          closed: 90,
          failed: 0,
          lost: 0,
          skipped: 1,
          oldestPendingAt: null,
        },
        sources: { total: 1, byStatus: { active: 1 }, byHealth: { silent: 1 } },
        intakeToday: {
          day: '2026-11-20',
          accepted: 412,
          duplicates: 2,
          refused: 3,
          droppedProof: 0,
          unwrapFailed: 0,
          bytes: 9_000_000,
        },
      }),
    IntakeSourcesController_list_v1: () => okJson({ data: [SOURCE_ROW], nextCursor: null }),
    ArchiveRetentionController_list_v1: () => okJson({ data: [], nextCursor: null }),
    DomainsController_list_v1: () => okJson({ data: [], nextCursor: null }),
    DepartmentsController_list_v1: () => okJson({ data: [], nextCursor: null }),
    UsersController_list_v1: () => okJson({ data: [], nextCursor: null }),
    ...extra,
  });
}

describe('Settings → Journaling (step 8.6 D14)', () => {
  it('builds contract-valid bodies for the journaling settings and new sources', () => {
    const body = journalingBody(
      {
        ...journalingDraftOf(SETTINGS),
        intakeScan: true,
        scopeMode: 'include',
        addresses: ['a@corp.example.test'],
      },
      5,
    );
    expectRequestMatchesContract('JournalingController_update_v1', body);
    expect(body).toMatchObject({
      expectedRowVersion: 5,
      settings: { intake: { scanEnabled: true } },
    });
    const m365 = intakeCreateBody({
      ...EMPTY_DRAFT,
      kind: 'microsoft_365_journal',
      providerConnectionId: CONNECTION_ID,
      displayName: 'Contoso Microsoft 365',
    });
    expectRequestMatchesContract('IntakeSourcesController_create_v1', m365);
    expect(m365).not.toHaveProperty('networks');
    const bcc = intakeCreateBody({
      ...EMPTY_DRAFT,
      kind: 'smtp_bcc',
      networks: '203.0.113.10/32\n2001:db8:10::/48',
      displayName: 'Branch Postfix',
      silenceAlert: false,
      maxMessageMiB: '25',
    });
    expectRequestMatchesContract('IntakeSourcesController_create_v1', bcc);
    expect(bcc).toMatchObject({
      networks: ['203.0.113.10/32', '2001:db8:10::/48'],
      requireTls: true,
      silenceAlertMinutes: null,
      maxMessageBytes: 25 * 1_048_576,
    });
  });

  it('checks each wizard step before moving on', () => {
    expect(
      intakeStepErrors('sender', { ...EMPTY_DRAFT, kind: 'microsoft_365_journal' }),
    ).toHaveProperty('providerConnectionId');
    expect(intakeStepErrors('sender', { ...EMPTY_DRAFT, kind: 'smtp_bcc' })).toHaveProperty(
      'networks',
    );
    expect(
      intakeStepErrors('sender', { ...EMPTY_DRAFT, kind: 'smtp_bcc', networks: 'not-a-cidr' })
        .networks,
    ).toMatch(/Not a CIDR/);
    expect(
      intakeStepErrors('details', { ...EMPTY_DRAFT, displayName: 'x', silenceAlertMinutes: '1' }),
    ).toHaveProperty('silenceAlertMinutes');
    expect(intakeStepErrors('details', { ...EMPTY_DRAFT, displayName: 'ok' })).toEqual({});
  });

  it('explains the two layers and lists intake sources with health (axe clean)', async () => {
    mockPanel();
    const { container } = renderWithProviders(<JournalingPanel />, { me: mfaMe() });
    expect(
      await screen.findByRole('heading', { name: 'Journaling and the archive' }),
    ).toBeInTheDocument();
    expect(screen.getByText(/1\. Journaling \(this page\)/)).toBeInTheDocument();
    expect(screen.getByText(/2\. Archive/)).toBeInTheDocument();
    const link = await screen.findByRole('link', { name: 'Head office Exchange' });
    expect(link).toHaveAttribute('href', `/settings/journaling/intake/${SOURCE_ID}`);
    const row = link.closest('tr')!;
    expect(within(row).getByText('Silent')).toBeInTheDocument();
    expect(within(row).getByText('On-premises Exchange journaling')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Add source' })).toHaveAttribute(
      'href',
      '/settings/journaling/intake/new',
    );
    expect(await screen.findByText(/412 accepted · 3 refused/)).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('saves journaling with CAS and an Idempotency-Key; explains a missing default retention', async () => {
    const bodies: unknown[] = [];
    mockPanel({
      JournalingController_update_v1: ({ body, request }) => {
        bodies.push(body);
        expect(request.headers.get('idempotency-key')).toBeTruthy();
        return bodies.length === 1
          ? apiErrorJson(422, 'archive_default_retention_required', 'no default policy')
          : okJson({
              ...SETTINGS,
              settings: { ...SETTINGS.settings, intake: { scanEnabled: true } },
              rowVersion: 6,
            });
      },
    });
    const { user } = renderWithProviders(<JournalingPanel />, { me: mfaMe() });
    const form = await screen.findByRole('form', { name: 'Journaling settings' });
    await user.click(within(form).getByRole('switch', { name: 'Scan journal intake copies' }));
    await user.click(within(form).getByRole('button', { name: 'Save journaling settings' }));
    expect(
      await within(form).findAllByText(
        /A compliance officer chooses it in Archive → Retention and lock/,
      ),
    ).not.toHaveLength(0);
    await user.click(within(form).getByRole('button', { name: 'Save journaling settings' }));
    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies[1]).toMatchObject({
      expectedRowVersion: 5,
      enabled: true,
      settings: { intake: { scanEnabled: true } },
    });
    expectRequestMatchesContract('JournalingController_update_v1', bodies[1]);
  });

  it('is read-only for a read-only user (journal:read): no form, no Add source', async () => {
    mockPanel();
    renderWithProviders(<JournalingPanel />, { role: 'read_only_user' });
    expect(
      await screen.findByText(/changing journaling needs the journal:manage permission/),
    ).toBeInTheDocument();
    expect(screen.queryByRole('form', { name: 'Journaling settings' })).not.toBeInTheDocument();
    expect(await screen.findByRole('link', { name: 'Head office Exchange' })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Add source' })).not.toBeInTheDocument();
  });

  it('warns when the platform has no intake domain and hides Add source', async () => {
    mockPanel({
      JournalingController_get_v1: () => okJson({ ...SETTINGS, intakeAvailable: false }),
      IntakeSourcesController_list_v1: () => okJson({ data: [], nextCursor: null }),
    });
    renderWithProviders(<JournalingPanel />, { me: mfaMe() });
    expect(
      await screen.findByText(/Journal intake is not configured on this platform/),
    ).toBeInTheDocument();
    expect(await screen.findByText('No journal intake sources')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Add source' })).not.toBeInTheDocument();
  });
});

describe('/settings/journaling/intake/new (step 8.6 D14)', () => {
  it('walks kind → networks → name → review → created, showing the address once with a copy button', async () => {
    let created: unknown = null;
    mockApi({
      IntakeSourcesController_create_v1: ({ body, request }) => {
        created = body;
        expect(request.headers.get('idempotency-key')).toBeTruthy();
        return okJson({ source: SOURCE_ROW, address: ADDRESS, headerToken: null }, 201);
      },
    });
    const { user, container } = renderWithProviders(<NewIntakeSourcePage />, {
      me: mfaMe(),
      route: '/settings/journaling/intake/new',
    });
    await user.click(await screen.findByRole('radio', { name: /SMTP BCC copy/ }));
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Next' }));
    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(await screen.findAllByText('Enter at least one network (CIDR).')).not.toHaveLength(0);
    await user.type(screen.getByLabelText(/Sending networks/), '203.0.113.10/32');
    await user.click(screen.getByRole('button', { name: 'Next' }));
    await user.type(screen.getByLabelText('Name (required)'), 'Branch Postfix');
    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByText('203.0.113.10/32')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Create intake source' }));
    const dialog = await screen.findByRole('dialog', { name: 'Intake source created' });
    expect(within(dialog).getByText(ADDRESS)).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Copy Intake address' })).toBeInTheDocument();
    expectRequestMatchesContract('IntakeSourcesController_create_v1', created);
    expect(created).toMatchObject({
      kind: 'smtp_bcc',
      networks: ['203.0.113.10/32'],
      displayName: 'Branch Postfix',
    });
    const done = within(dialog).getByRole('button', { name: 'Done' });
    expect(done).toBeDisabled();
    await user.click(within(dialog).getByRole('checkbox'));
    await user.click(done);
    await waitFor(() =>
      expect(currentTestUrl()).toBe(`/settings/journaling/intake/${SOURCE_ID}?tab=guide`),
    );
    expect(screen.queryByText(ADDRESS)).not.toBeInTheDocument();
  });

  it('picks a Microsoft 365 connection and links the 8.2 wizard', async () => {
    mockApi({
      ProviderConnectionsController_list_v1: ({ url }) => {
        expect(url.searchParams.get('provider')).toBe('microsoft_365');
        return okJson({
          data: [
            {
              id: CONNECTION_ID,
              provider: 'microsoft_365',
              displayName: 'Contoso tenant',
              status: 'active',
              health: 'healthy',
              healthChangedAt: null,
              tenantName: 'contoso.onmicrosoft.com',
              domainCount: 2,
              outboundMode: 'off',
              internalRouting: false,
              createdAt: '2026-11-01T08:00:00.000Z',
            },
          ],
          nextCursor: null,
        });
      },
    });
    const { user } = renderWithProviders(<NewIntakeSourcePage />, {
      me: mfaMe(),
      route: '/settings/journaling/intake/new?kind=microsoft_365_journal',
    });
    const group = await screen.findByRole('radiogroup', { name: 'Microsoft 365 connection' });
    expect(screen.getByRole('link', { name: /Connect Microsoft 365/ })).toHaveAttribute(
      'href',
      '/integrations/providers/new?provider=microsoft_365',
    );
    await user.click(within(group).getByRole('radio', { name: /Contoso tenant/ }));
    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(await screen.findByLabelText('Name (required)')).toBeInTheDocument();
  });

  it('is forbidden without journal:manage', async () => {
    renderWithProviders(<NewIntakeSourcePage />, { role: 'read_only_user' });
    expect(await screen.findByText('You do not have access to this page')).toBeInTheDocument();
  });
});

describe('/settings/journaling/intake/[sourceId] (step 8.6 D14)', () => {
  function mockSource(extra: Parameters<typeof mockApi>[0] = {}) {
    mockApi({
      IntakeSourcesController_get_v1: ({ url }) =>
        okJson(
          url.searchParams.get('reveal') === 'true'
            ? { ...SOURCE, address: ADDRESS, revealed: true }
            : SOURCE,
        ),
      IntakeSourcesController_wizard_v1: () => okJson(WIZARD),
      IntakeSourcesController_guide_v1: () => okJson(GUIDE),
      ...extra,
    });
  }

  it('shows setup steps and statements; records a statement (axe clean)', async () => {
    let attest: unknown = null;
    mockSource({
      IntakeSourcesController_attest_v1: ({ body }) => {
        attest = body;
        return okJson({ sourceId: SOURCE_ID, attestations: [], rowVersion: 5 });
      },
    });
    const { user, container } = renderWithProviders(<IntakeSourcePage sourceId={SOURCE_ID} />, {
      me: mfaMe(),
      route: `/settings/journaling/intake/${SOURCE_ID}?tab=setup`,
    });
    expect(
      await screen.findByRole('heading', { name: 'Head office Exchange' }),
    ).toBeInTheDocument();
    expect(await screen.findByText(/Next: Configure your mail system/)).toBeInTheDocument();
    expect(screen.getByText('health_silent')).toBeInTheDocument();
    await user.click(
      await screen.findByRole('checkbox', { name: /Send connector delivers to the gateway/ }),
    );
    await waitFor(() =>
      expect(attest).toEqual({ code: 'journal.onprem.send_connector_tls', attested: true }),
    );
    expectRequestMatchesContract('IntakeSourcesController_attest_v1', attest);
    await expectNoAxeViolations(container);
  });

  it('renders the guide with a Markdown download', async () => {
    mockSource();
    const { user } = renderWithProviders(<IntakeSourcePage sourceId={SOURCE_ID} />, {
      me: mfaMe(),
      route: `/settings/journaling/intake/${SOURCE_ID}?tab=guide`,
    });
    expect(
      await screen.findByRole('heading', { name: '1. Create the journal recipient' }),
    ).toBeInTheDocument();
    expect(screen.getByText('New-MailContact -Name "Gateway journal"')).toBeInTheDocument();
    expect(screen.getByText(/The intake address is masked in this guide/)).toBeInTheDocument();
    expect(intakeGuideFileName(SOURCE)).toBe(
      'journal-intake-exchange-onprem-journal-head-office-exchange.md',
    );
    expect(screen.getByRole('button', { name: 'Download Markdown' })).toBeEnabled();
    void user;
  });

  it('masks the address, reveals it on request (audited) and rotates it with a one-time display', async () => {
    mockSource({
      IntakeSourcesController_rotate_v1: ({ request }) => {
        expect(request.headers.get('idempotency-key')).toBeTruthy();
        return okJson({
          source: { ...SOURCE_ROW, addressVersion: 2 },
          address: 'journal-newnewnewnewnewnewnewnewne@journal.gateway.example.test',
          headerToken: null,
        });
      },
    });
    const { user } = renderWithProviders(<IntakeSourcePage sourceId={SOURCE_ID} />, {
      me: mfaMe(),
      route: `/settings/journaling/intake/${SOURCE_ID}?tab=address`,
    });
    expect(await screen.findByText(MASKED)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Copy the address' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Reveal' }));
    expect(await screen.findByText(ADDRESS)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy the address' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Rotate address' }));
    const confirm = await screen.findByRole('alertdialog');
    await user.click(within(confirm).getByRole('button', { name: 'Rotate address' }));
    const dialog = await screen.findByRole('dialog', { name: 'New intake address' });
    expect(
      within(dialog).getByText('journal-newnewnewnewnewnewnewnewne@journal.gateway.example.test'),
    ).toBeInTheDocument();
  });

  it('shows health, the last refusal and the 7-day counters', async () => {
    mockSource();
    renderWithProviders(<IntakeSourcePage sourceId={SOURCE_ID} />, {
      me: mfaMe(),
      route: `/settings/journaling/intake/${SOURCE_ID}?tab=health`,
    });
    expect(await screen.findByText(/sender not in the provider egress ranges/)).toBeInTheDocument();
    const table = screen.getByRole('table', { name: 'Daily intake counters' });
    expect(within(table).getByText('412')).toBeInTheDocument();
  });

  it('pauses with a confirmation and disables only after the typed confirmation', async () => {
    const patches: unknown[] = [];
    let disabled = false;
    mockSource({
      IntakeSourcesController_update_v1: ({ body }) => {
        patches.push(body);
        return okJson({ ...SOURCE_ROW, status: 'paused', rowVersion: 5 });
      },
      IntakeSourcesController_disable_v1: () => {
        disabled = true;
        return okJson({ ...SOURCE_ROW, status: 'disabled', rowVersion: 6 });
      },
    });
    const { user } = renderWithProviders(<IntakeSourcePage sourceId={SOURCE_ID} />, {
      me: mfaMe(),
      route: `/settings/journaling/intake/${SOURCE_ID}?tab=settings`,
    });
    await user.click(await screen.findByRole('button', { name: 'Pause intake' }));
    const pause = await screen.findByRole('alertdialog');
    expect(within(pause).getByText(/temporary error \(450\)/)).toBeInTheDocument();
    await user.click(within(pause).getByRole('button', { name: 'Pause' }));
    await waitFor(() => expect(patches).toEqual([{ expectedRowVersion: 4, status: 'paused' }]));
    expectRequestMatchesContract('IntakeSourcesController_update_v1', patches[0]);
    await user.click(screen.getByRole('button', { name: 'Disable source' }));
    const dialog = await screen.findByRole('alertdialog');
    const confirm = within(dialog).getByRole('button', { name: 'Disable source' });
    expect(confirm).toBeDisabled();
    await user.type(within(dialog).getByLabelText(/Type disable to confirm/), 'disable');
    await user.click(confirm);
    await waitFor(() => expect(disabled).toBe(true));
  });

  it('is read-only for a read-only user and renders an unknown id as not found', async () => {
    mockSource({
      IntakeSourcesController_get_v1: ({ params }) =>
        params.sourceId === SOURCE_ID
          ? okJson(SOURCE)
          : apiErrorJson(404, 'journal_intake_source_not_found', 'not found'),
    });
    const first = renderWithProviders(<IntakeSourcePage sourceId={SOURCE_ID} />, {
      role: 'read_only_user',
      route: `/settings/journaling/intake/${SOURCE_ID}?tab=address`,
    });
    expect(
      await screen.findByText(/revealing or rotating it needs the journal:manage permission/),
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Reveal' })).not.toBeInTheDocument();
    first.unmount();
    renderWithProviders(<IntakeSourcePage sourceId="01930000-0000-7000-8000-00000000dfff" />, {
      role: 'read_only_user',
    });
    expect(await screen.findByRole('heading', { name: 'Page not found' })).toBeInTheDocument();
  });
});
