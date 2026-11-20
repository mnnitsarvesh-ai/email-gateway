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
import {
  ACCOUNT_ID,
  INCIDENT_ID,
  MESSAGE_ID,
  MFA_SESSION,
  account,
  authEvent,
  incident,
  incidentSummary,
  page,
  response,
  settings,
  signal,
  summaryOf,
} from '@/features/ato/test-data';
import { IncidentPage } from './incident-page';
import { IncidentsPage } from './incidents-page';
import { IncidentReportPage } from './report-page';

function mockIncident(extra: Parameters<typeof mockApi>[0] = {}, detail = incident()) {
  mockApi({
    IncidentsController_get_v1: ({ params }) =>
      params.incidentId === INCIDENT_ID
        ? okJson(detail)
        : apiErrorJson(404, 'incident_not_found', 'Not found'),
    IncidentsController_timeline_v1: () =>
      okJson(
        page([
          {
            id: 'd1b2c3d4e5f6a7b8c9d0',
            at: '2026-11-18T09:00:00.000Z',
            type: 'created',
            actor: { type: 'system', id: null },
            fromStatus: null,
            toStatus: 'open',
            fromSeverity: null,
            toSeverity: 'critical',
            note: null,
            details: null,
          },
        ]),
      ),
    IncidentsController_messages_v1: () =>
      okJson(
        page([
          {
            id: MESSAGE_ID,
            receivedAt: '2026-11-18T08:50:00.000Z',
            direction: 'outbound',
            finalVerdict: 'phishing',
            finalAction: 'quarantine',
            riskScore: 880,
            riskLevel: 'critical',
            recipientCount: 40,
            externalDomainCount: 31,
            findingCodes: ['url.phishing_high_confidence'],
          },
        ]),
      ),
    AtoIncidentEvidenceController_signals_v1: () => okJson(page([signal()])),
    AtoIncidentEvidenceController_authEvents_v1: () => okJson(page([authEvent()])),
    AtoResponsesController_list_v1: () => okJson(page([summaryOf(response())])),
    AtoSettingsController_get_v1: () => okJson(settings()),
    ...extra,
  });
}

describe('Incidents (/incidents)', () => {
  it('lists readable categories with filters in the URL; axe', async () => {
    const queries: URLSearchParams[] = [];
    mockApi({
      IncidentsController_list_v1: ({ url }) => {
        queries.push(url.searchParams);
        return okJson(page([incidentSummary()]));
      },
    });
    const { user, container } = renderWithProviders(<IncidentsPage />, {
      route: '/incidents?category=account_takeover',
    });
    const table = await screen.findByRole('table', { name: 'Security incidents' });
    expect(within(table).getByRole('link', { name: 'finance@alpha.example.test' })).toHaveAttribute(
      'href',
      `/incidents/${INCIDENT_ID}`,
    );
    expect(within(table).getByText(/Account takeover/)).toBeInTheDocument();
    expect(queries[0]?.get('category')).toBe('account_takeover');
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('combobox', { name: 'Assignee' }));
    await user.click(await screen.findByRole('option', { name: 'Assigned to me' }));
    await waitFor(() => expect(queries.at(-1)?.get('assignee')).toBe('me'));
    expect(currentTestUrl()).toContain('assignee=me');
  });

  it('drops an unreadable category from the URL filter', async () => {
    const queries: URLSearchParams[] = [];
    mockApi({
      IncidentsController_list_v1: ({ url }) => {
        queries.push(url.searchParams);
        return okJson(page([]));
      },
    });
    renderWithProviders(<IncidentsPage />, { route: '/incidents?category=message_threat' });
    expect(await screen.findByText('No incidents')).toBeInTheDocument();
    expect(queries[0]?.get('category')).toBeNull();
  });

  it('opens a manual incident for an account (contract) and goes to it', async () => {
    const bodies: unknown[] = [];
    mockApi({
      IncidentsController_list_v1: () => okJson(page([])),
      AtoAccountsController_list_v1: ({ url }) => {
        expect(url.searchParams.get('q')).toBe('fin');
        return okJson(page([account({ activeIncident: null })]));
      },
      IncidentsController_create_v1: ({ body }) => {
        bodies.push(body);
        return okJson(incident({ origin: 'manual' }), 201);
      },
    });
    const { user } = renderWithProviders(<IncidentsPage />, { route: '/incidents' });
    await user.click(await screen.findByRole('button', { name: 'New incident' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByLabelText('Account (address starts with)'), 'fin');
    await user.click(
      await within(dialog).findByRole('button', { name: /finance@alpha.example.test/ }),
    );
    await user.type(within(dialog).getByLabelText(/Why/), 'User reported an unexpected MFA prompt');
    await user.click(within(dialog).getByRole('button', { name: 'Open incident' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expectRequestMatchesContract('IncidentsController_create_v1', bodies[0]);
    expect(bodies[0]).toEqual({
      category: 'account_takeover',
      subject: { type: 'ato_account', id: ACCOUNT_ID },
      severity: 'medium',
      reason: 'User reported an unexpected MFA prompt',
    });
    await waitFor(() => expect(currentTestUrl()).toBe(`/incidents/${INCIDENT_ID}`));
  });

  it('is not offered without a category permission; read-only categories cannot open incidents', async () => {
    renderWithProviders(<IncidentsPage />, { role: 'read_only_user' });
    expect(await screen.findByText(/ato:read/)).toBeInTheDocument();
  });

  it('a compliance auditor reads but cannot open incidents', async () => {
    mockApi({ IncidentsController_list_v1: () => okJson(page([incidentSummary()])) });
    renderWithProviders(<IncidentsPage />, { role: 'compliance_auditor' });
    expect(await screen.findByRole('table', { name: 'Security incidents' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'New incident' })).not.toBeInTheDocument();
  });
});

describe('Incident details (/incidents/[incidentId])', () => {
  it('shows the generic layout and the ATO panels; axe', async () => {
    mockIncident();
    const { container } = renderWithProviders(<IncidentPage incidentId={INCIDENT_ID} />, {
      me: makeMe({ role: 'security_analyst', overrides: MFA_SESSION }),
    });
    expect(
      await screen.findByRole('heading', {
        name: 'Account takeover: finance@alpha.example.test',
        level: 1,
      }),
    ).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Account and scores' })).toBeInTheDocument();
    expect(screen.getByRole('list', { name: 'Contributions' })).toHaveTextContent(
      'Phishing sent from the account +45',
    );
    const recommendations = screen.getByRole('list', { name: 'Recommendations' });
    expect(within(recommendations).getByRole('button', { name: 'Request' })).toBeInTheDocument();
    expect(
      within(recommendations).getByText(
        /Needs a connected identity provider with this action available/,
      ),
    ).toBeInTheDocument();
    expect(
      within(recommendations).getByRole('link', { name: 'Create a hold rule' }),
    ).toHaveAttribute('href', '/policies/new?testPreset=outbound_high_risk_account');
    expect(
      await screen.findByRole('table', { name: 'Signals linked to the incident' }),
    ).toBeInTheDocument();
    expect(
      await screen.findByRole('table', { name: 'Sign-ins linked to the incident' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'Related IP addresses' })).toHaveTextContent(
      '203.0.113.77',
    );
    const messages = await screen.findByRole('table', { name: 'Messages linked to the incident' });
    expect(within(messages).getByRole('link', { name: /Open message/ })).toHaveAttribute(
      'href',
      `/messages/${MESSAGE_ID}`,
    );
    expect(await screen.findByRole('list', { name: 'Incident timeline' })).toHaveTextContent(
      'Created',
    );
    expect(screen.getByRole('link', { name: 'Report' })).toHaveAttribute(
      'href',
      `/incidents/${INCIDENT_ID}/report`,
    );
    await expectNoAxeViolations(container);
  });

  it('starts the investigation, assigns, confirms with a note (contract bodies with rowVersion)', async () => {
    const bodies: unknown[] = [];
    mockIncident({
      IncidentsController_update_v1: ({ body }) => {
        bodies.push(body);
        return okJson(incident());
      },
    });
    const { user } = renderWithProviders(<IncidentPage incidentId={INCIDENT_ID} />);
    await user.click(await screen.findByRole('button', { name: 'Start investigating' }));
    let dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Start investigating' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toEqual({ expectedRowVersion: 4, status: 'investigating' });
    await user.click(screen.getByRole('button', { name: 'Assign to me' }));
    dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Assign to me' }));
    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies[1]).toEqual({
      expectedRowVersion: 4,
      assigneeId: '01930000-0000-7000-8000-000000000101',
    });
    await user.click(screen.getByRole('button', { name: 'Confirm compromise' }));
    dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Confirm compromise' }));
    expect(await within(dialog).findByText(/Enter a reason/)).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText(/Note/), 'Phishing confirmed with the user');
    await user.click(within(dialog).getByRole('button', { name: 'Confirm compromise' }));
    await waitFor(() => expect(bodies).toHaveLength(3));
    for (const body of bodies) expectRequestMatchesContract('IncidentsController_update_v1', body);
    expect(bodies[2]).toEqual({
      expectedRowVersion: 4,
      status: 'confirmed',
      note: 'Phishing confirmed with the user',
    });
  });

  it('resolves as a false positive with feedback (dismiss signals, a trusted context)', async () => {
    const bodies: unknown[] = [];
    mockIncident({
      IncidentsController_update_v1: ({ body }) => {
        bodies.push(body);
        return okJson(incident({ status: 'false_positive' }));
      },
    });
    const { user } = renderWithProviders(<IncidentPage incidentId={INCIDENT_ID} />);
    await user.click(await screen.findByRole('button', { name: 'Resolve as false positive' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('combobox', { name: 'Resolution' }));
    await user.click(await screen.findByRole('option', { name: 'Benign activity' }));
    await user.type(within(dialog).getByLabelText('Value'), '198.51.100.0/24');
    await user.click(within(dialog).getByRole('button', { name: 'Add trusted context' }));
    expect(within(dialog).getByRole('list', { name: 'Trusted contexts to add' })).toHaveTextContent(
      '198.51.100.0/24',
    );
    await user.type(
      within(dialog).getByLabelText(/Resolution note/),
      'The user travelled with a new laptop',
    );
    await user.click(within(dialog).getByRole('button', { name: 'Resolve as false positive' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expectRequestMatchesContract('IncidentsController_update_v1', bodies[0]);
    expect(bodies[0]).toEqual({
      expectedRowVersion: 4,
      status: 'false_positive',
      resolution: { code: 'benign_activity', note: 'The user travelled with a new laptop' },
      categoryFeedback: {
        dismissSignals: true,
        trustedContexts: [
          {
            kind: 'ip_cidr',
            value: '198.51.100.0/24',
            expiresInDays: 90,
            reason: 'false positive feedback',
          },
        ],
      },
    });
  });

  it('requests restrict_smtp_sending from a recommendation (contract) and adds a note', async () => {
    const requests: unknown[] = [];
    const notes: unknown[] = [];
    mockIncident({
      AtoResponsesController_request_v1: ({ body, params }) => {
        expect(params.incidentId).toBe(INCIDENT_ID);
        requests.push(body);
        return okJson(response(), 201);
      },
      IncidentsController_addNote_v1: ({ body }) => {
        notes.push(body);
        return okJson(
          {
            id: 'e1b2c3d4e5f6a7b8c9d0',
            at: '2026-11-18T09:10:00.000Z',
            type: 'note_added',
            actor: { type: 'user', id: '01930000-0000-7000-8000-000000000101' },
            fromStatus: null,
            toStatus: null,
            fromSeverity: null,
            toSeverity: null,
            note: 'Called the user',
            details: null,
          },
          201,
        );
      },
    });
    const { user } = renderWithProviders(<IncidentPage incidentId={INCIDENT_ID} />);
    const recommendations = await screen.findByRole('list', { name: 'Recommendations' });
    await user.click(within(recommendations).getByRole('button', { name: 'Request' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByRole('combobox', { name: 'Response' })).toHaveTextContent(
      'Restrict SMTP sending',
    );
    await user.type(within(dialog).getByLabelText(/Reason/), 'Stop the ongoing phishing run');
    await user.click(within(dialog).getByRole('button', { name: 'Request' }));
    await waitFor(() => expect(requests).toHaveLength(1));
    expectRequestMatchesContract('AtoResponsesController_request_v1', requests[0]);
    expect(requests[0]).toEqual({
      actionType: 'restrict_smtp_sending',
      reason: 'Stop the ongoing phishing run',
      durationMinutes: 240,
      mode: 'reject',
    });
    await user.type(screen.getByLabelText('Investigation note'), 'Called the user');
    await user.click(screen.getByRole('button', { name: 'Add note' }));
    await waitFor(() => expect(notes).toEqual([{ note: 'Called the user' }]));
  });

  it('read-only analysts see no triage controls; unknown ids look missing', async () => {
    mockIncident({}, incident({ canManage: false, allowedTransitions: [] }));
    renderWithProviders(<IncidentPage incidentId={INCIDENT_ID} />, { role: 'compliance_auditor' });
    expect(await screen.findByText(/triage needs the category/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Start investigating' })).not.toBeInTheDocument();
  });

  it('a foreign incident id renders the not-found state', async () => {
    mockIncident();
    renderWithProviders(<IncidentPage incidentId="01933c3a-1b2c-7d4e-8f00-0000000affff" />);
    expect(await screen.findByText(/Page not found/i)).toBeInTheDocument();
  });
});

describe('Incident report (/incidents/[incidentId]/report)', () => {
  it('renders the generic and ATO sections with masked senders and a print button; axe', async () => {
    mockApi({
      IncidentsController_report_v1: () =>
        okJson({
          version: 'security-incident-report/1',
          generatedAt: '2026-11-18T09:30:00.000Z',
          incident: {
            id: INCIDENT_ID,
            category: 'account_takeover',
            status: 'open',
            severity: 'critical',
          },
          resolution: null,
          timeline: [{ at: '2026-11-18T09:00:00.000Z', type: 'created', toStatus: 'open' }],
          notes: [
            {
              at: '2026-11-18T09:05:00.000Z',
              actorType: 'user',
              actorId: null,
              note: 'Looked at it',
            },
          ],
          evidence: { ato_signal: 2 },
          messages: [
            {
              messageId: MESSAGE_ID,
              receivedAt: '2026-11-18T08:50:00.000Z',
              direction: 'outbound',
              senderMasked: 'f***@alpha.example.test',
            },
          ],
          truncated: false,
          sections: [
            {
              id: 'ato.signals',
              title: 'Signals',
              data: [
                {
                  code: 'ato.content.phishing_sent',
                  title: 'Phishing sent from the account',
                  category: 'outbound_content',
                  strength: 'strong',
                  status: 'active',
                  lastOccurredAt: '2026-11-18T08:51:00.000Z',
                  explanation: 'Phishing',
                },
              ],
            },
            { id: 'ato.responses', title: 'Responses', data: [] },
          ],
        }),
    });
    const { container } = renderWithProviders(<IncidentReportPage incidentId={INCIDENT_ID} />);
    expect(
      await screen.findByRole('heading', {
        name: 'Security incident report: Account takeover',
        level: 1,
      }),
    ).toBeInTheDocument();
    expect(screen.getByText('f***@alpha.example.test')).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'Signals' })).toHaveTextContent(
      'Phishing sent from the account',
    );
    expect(screen.getByRole('button', { name: 'Print or save as PDF' })).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });
});
