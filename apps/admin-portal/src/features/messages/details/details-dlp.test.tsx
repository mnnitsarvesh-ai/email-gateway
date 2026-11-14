import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import type { OperationId } from '@/lib/api/types';
import { onSessionEvent, type SessionEvent } from '@/lib/session/events';
import {
  apiErrorJson,
  createTestQueryClient,
  expectNoAxeViolations,
  okJson,
  permissionsOf,
  renderWithProviders,
  type MockHandler,
} from '@/test';
import { MessageDetails } from './message-details';
import { MESSAGE_ID, detailsRoute, fullRound, mockDetails } from './test-helpers';

const SECRET_LOOKING = ['4111', '1111', '1111', '1111'].join(' ');

const evidenceBody = {
  messageId: MESSAGE_ID,
  scanId: '900001',
  matchCount: 1,
  expiresAt: '2026-12-12T09:14:05.000Z',
  evidence: {
    format: 'dlp-evidence/1' as const,
    textDerivationVersion: 'text/2',
    extractorVersion: 'extractor/3',
    aadhaar: 'disabled' as const,
    matches: [
      {
        detector: 'PC1' as const,
        code: 'dlp.payment_card',
        source: { kind: 'body_text' as const, segment: 0 },
        start: 118,
        end: 137,
        value: SECRET_LOOKING,
        context: { before: 'charge card ', after: ' <b>today</b>' },
      },
    ],
    dropped: 0,
  },
};

let unsubscribe: (() => void) | null = null;
afterEach(() => {
  unsubscribe?.();
  unsubscribe = null;
});

function renderDlp(
  options: {
    permissions?: readonly string[];
    overrides?: Partial<Record<OperationId, MockHandler>>;
  } = {},
) {
  const mocks = mockDetails(options.overrides);
  const queryClient = createTestQueryClient();
  const view = renderWithProviders(<MessageDetails messageId={MESSAGE_ID} />, {
    role: 'compliance_auditor',
    permissions: options.permissions,
    route: detailsRoute('section=dlp'),
    queryClient,
  });
  return { ...mocks, ...view, queryClient };
}

describe('Email details: DLP results and evidence (§2 E11)', () => {
  it('opens the evidence only on click, shows it once and forgets it on close', async () => {
    const { calls, user, queryClient, container } = renderDlp({
      overrides: {
        DlpMessageEvidenceController_read_v1: () =>
          okJson(evidenceBody, 200, { 'cache-control': 'no-store' }),
      },
    });
    await screen.findByText('Findings (masked samples)');
    expect(calls('DlpMessageEvidenceController_read_v1')).toHaveLength(0);
    await user.click(screen.getByRole('button', { name: 'Show matched values' }));
    const dialog = await screen.findByRole('dialog', { name: 'Matched values' });
    expect(await within(dialog).findByText(SECRET_LOOKING)).toBeInTheDocument();
    expect(calls('DlpMessageEvidenceController_read_v1')[0]?.url.pathname).toContain(
      `/messages/${MESSAGE_ID}/scans/900001/dlp-evidence`,
    );
    await expectNoAxeViolations(document.body);
    await user.click(within(dialog).getByRole('button', { name: 'Close and forget the values' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.queryByText(SECRET_LOOKING)).not.toBeInTheDocument();
    const cached = JSON.stringify(
      queryClient
        .getQueryCache()
        .getAll()
        .map((query) => query.state.data),
    );
    expect(cached).not.toContain(SECRET_LOOKING);
    expect(
      queryClient.getQueryCache().findAll({ queryKey: ['DlpMessageEvidenceController_read_v1'] }),
    ).toHaveLength(0);
    expect(calls('DlpMessageEvidenceController_read_v1')).toHaveLength(1);
    void container;
  });

  it('403 mfa_required opens the 7.1 MFA dialog (session event) and shows no value', async () => {
    const events: SessionEvent[] = [];
    unsubscribe = onSessionEvent((event) => events.push(event));
    const { user } = renderDlp({
      overrides: {
        DlpMessageEvidenceController_read_v1: () =>
          apiErrorJson(403, 'mfa_required', 'MFA required', { requestId: 'req-mfa' }),
      },
    });
    await user.click(await screen.findByRole('button', { name: 'Show matched values' }));
    const dialog = await screen.findByRole('dialog', { name: 'Matched values' });
    expect(
      await within(dialog).findByText(/needs a session signed in with MFA/),
    ).toBeInTheDocument();
    await waitFor(() => expect(events).toContainEqual({ type: 'mfa-required' }));
  });

  it('without dlp:evidence_read there is no evidence button', async () => {
    const permissions = permissionsOf('compliance_auditor').filter(
      (p) => p !== 'dlp:evidence_read',
    );
    renderDlp({ permissions });
    expect(await screen.findByText(/needs the dlp:evidence_read permission/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Show matched values' })).toBeNull();
  });

  it('purged or absent evidence offers no button', async () => {
    renderDlp({
      overrides: {
        MessageScansController_scansOf_v1: () => {
          const round = fullRound();
          return okJson({
            messageId: MESSAGE_ID,
            data: [
              {
                ...round,
                engines: round.engines.map((engine) =>
                  engine.engine === 'dlp' && engine.dlp
                    ? {
                        ...engine,
                        dlp: {
                          ...engine.dlp,
                          evidence: { status: 'stored', expiresAt: null, purged: true },
                        },
                      }
                    : engine,
                ),
              },
            ],
            nextCursor: null,
          });
        },
      },
    });
    expect(await screen.findByText('Yes (crypto-shredded)')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Show matched values' })).toBeNull();
  });
});
