import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  apiErrorJson,
  createTestQueryClient,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  makeMe,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import type { Me } from '@/lib/api/types';
import { ArchiveDetails } from './archive-details';
import { archiveDownloadNavigation } from './download-dialog';
import {
  HOLD_ID,
  MESSAGE_ID,
  SECRET_RECIPIENT,
  SECRET_SUBJECT,
  SETTINGS,
  detail,
} from './test-data';

afterEach(() => vi.restoreAllMocks());

const mfaAdmin = (overrides: Partial<Me> = {}) =>
  makeMe({
    role: 'organization_admin',
    overrides: {
      mfaEnabled: true,
      session: { id: '01930000-0000-7000-8000-000000000501', mfaAuthenticated: true },
      ...overrides,
    },
  });

function mockDetail(body = detail(), extra: Parameters<typeof mockApi>[0] = {}) {
  const calls: string[] = [];
  mockApi({
    ArchiveMessagesController_detail_v1: () => {
      calls.push('detail');
      return okJson(body);
    },
    ArchiveAdminController_get_v1: () => okJson({ ...SETTINGS, enabled: true }),
    ArchiveMessagesController_preview_v1: () => {
      calls.push('preview');
      return okJson({
        version: 'preview/1',
        subject: SECRET_SUBJECT,
        headers: [{ name: 'From', value: 'sender@partner.example.test' }],
        body: {
          source: 'text',
          text: 'EXAMPLE body <script>x</script>',
          truncated: false,
          unavailableReason: null,
        },
        links: [],
        linksTruncated: false,
        attachments: [],
        dlp: { masked: 0, categories: [] },
      });
    },
    ArchiveMessagesController_journal_v1: () => {
      calls.push('journal');
      return okJson({
        messageId: MESSAGE_ID,
        captureId: '01930000-0000-7000-8000-00000000c801',
        capturedAt: '2026-11-16T09:01:30.000Z',
        category: 'delivered',
        message: {
          internetMessageId: '<EXAMPLE-1@mail.example.test>',
          envelopeFrom: 'sender@partner.example.test',
          headerFrom: 'sender@partner.example.test',
          subject: null,
          subjectMasked: true,
          sizeBytes: 4096,
          emlSha256: 'a'.repeat(64),
          clientIp: '192.0.2.10',
          clientHelo: 'mx.partner.example.test',
        },
        envelope: {
          recipients: [
            {
              seq: 0,
              address: 'p***@corp.example.test',
              direction: 'inbound',
              status: 'delivered',
            },
          ],
        },
        headers: [
          { name: 'From', value: 'sender@partner.example.test', masked: false },
          { name: 'To', value: null, masked: true },
        ],
        parse: { status: 'parsed', codes: [] },
        body: {
          textAvailable: true,
          htmlAvailable: false,
          truncated: false,
          unavailableReason: null,
        },
        attachments: [
          {
            partIndex: 2,
            fileName: 'EXAMPLE-report.pdf',
            contentType: 'application/pdf',
            detectedType: 'pdf',
            sizeBytes: 2048,
            sha256: null,
          },
        ],
        deliveries: [{ seq: 0, status: 'delivered', finalAt: '2026-11-16T09:00:40.000Z' }],
      });
    },
    ...extra,
  });
  return calls;
}

describe('/archive/[messageId] (A19, A28)', () => {
  it('shows summary, masked parties, retention with hold names, integrity; content only on request; axe clean', async () => {
    const calls = mockDetail();
    const { container, user } = renderWithProviders(<ArchiveDetails messageId={MESSAGE_ID} />, {
      me: mfaAdmin(),
    });
    expect(await screen.findByRole('heading', { name: 'Archived message' })).toBeInTheDocument();
    const parties = screen.getByRole('region', { name: 'Parties' });
    expect(within(parties).getByText('p***@corp.example.test')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'EXAMPLE board hold' })).toHaveAttribute(
      'href',
      `/legal-holds/${HOLD_ID}`,
    );
    expect(screen.getByText('archive-object/1 · key version 1')).toBeInTheDocument();
    // Journal, security and preview are loaded only on request (each is audited).
    expect(calls).toEqual(['detail']);
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Load the journal' }));
    expect(
      await screen.findByText('mx.partner.example.test', { exact: false }),
    ).toBeInTheDocument();
    expect(calls).toContain('journal');
    await user.click(screen.getByRole('button', { name: 'Show sanitized preview' }));
    const text = await screen.findByTestId('preview-text');
    expect(text.textContent).toContain('<script>x</script>');
    expect(text.querySelector('script')).toBeNull();
    expect(text.children).toHaveLength(0);
    expect(calls.filter((c) => c === 'preview')).toHaveLength(1);
  });

  it('hides hold names from a caller without hold permissions (holds: null) and content actions without archive:retrieve', async () => {
    mockDetail(detail({ holds: null }));
    renderWithProviders(<ArchiveDetails messageId={MESSAGE_ID} />, { role: 'security_analyst' });
    await screen.findByRole('heading', { name: 'Archived message' });
    expect(screen.queryByRole('link', { name: 'EXAMPLE board hold' })).not.toBeInTheDocument();
    expect(screen.getByText(/Which holds cover a message is confidential/)).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Sanitized preview' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Download original' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Dispose' })).not.toBeInTheDocument();
  });

  it('reveals once on request; revealed values are never cached and hidden again on demand', async () => {
    mockDetail();
    const bodies: unknown[] = [];
    mockApi({
      ArchiveMessagesController_reveal_v1: ({ body }) => {
        bodies.push(body);
        expectRequestMatchesContract('ArchiveMessagesController_reveal_v1', body);
        return okJson({
          messageId: MESSAGE_ID,
          revealedAt: '2026-11-17T08:00:00.000Z',
          subject: SECRET_SUBJECT,
          recipients: [{ seq: 0, address: SECRET_RECIPIENT }],
          headers: [{ name: 'To', value: SECRET_RECIPIENT }],
        });
      },
    });
    const queryClient = createTestQueryClient();
    const { user } = renderWithProviders(<ArchiveDetails messageId={MESSAGE_ID} />, {
      me: mfaAdmin(),
      queryClient,
    });
    await screen.findByRole('heading', { name: 'Archived message' });
    expect(screen.queryByText(SECRET_SUBJECT)).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Reveal' }));
    expect(await screen.findByText(SECRET_SUBJECT)).toBeInTheDocument();
    expect(screen.getAllByText(SECRET_RECIPIENT).length).toBeGreaterThan(0);
    expect(bodies).toEqual([{ fields: ['subject', 'recipients', 'headers'] }]);
    const cached = JSON.stringify([
      queryClient
        .getQueryCache()
        .getAll()
        .map((q) => q.state.data),
      queryClient
        .getMutationCache()
        .getAll()
        .map((m) => m.state.data),
    ]);
    expect(cached).not.toContain(SECRET_SUBJECT);
    expect(cached).not.toContain(SECRET_RECIPIENT);
    await user.click(screen.getByRole('button', { name: 'Hide again' }));
    expect(screen.queryByText(SECRET_SUBJECT)).not.toBeInTheDocument();
  });

  it('downloads through re-authentication: grant → BFF door, token never kept', async () => {
    mockDetail();
    let grantBody: unknown = null;
    mockApi({
      ArchiveMessagesController_grant_v1: ({ body }) => {
        grantBody = body;
        return okJson(
          {
            token: 'v1.EXAMPLE-token.sig',
            expiresAt: '2026-11-17T08:01:00.000Z',
            filename: `archive-${MESSAGE_ID}.eml`,
            sizeBytes: 4096,
            sha256: 'a'.repeat(64),
          },
          201,
        );
      },
    });
    const assign = vi
      .spyOn(archiveDownloadNavigation, 'assign')
      .mockImplementation(() => undefined);
    const queryClient = createTestQueryClient();
    const { user } = renderWithProviders(<ArchiveDetails messageId={MESSAGE_ID} />, {
      me: mfaAdmin(),
      queryClient,
    });
    await user.click(await screen.findByRole('button', { name: 'Download original' }));
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('button', { name: 'Download' }));
    expect(await within(dialog).findByText('Enter your password')).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText('Your password (required)'), 'EXAMPLE-password');
    await user.click(within(dialog).getByRole('button', { name: 'Download' }));
    expect(within(dialog).getByText(/Enter the 6-digit code/)).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText('Authenticator code (required)'), '123456');
    await user.click(within(dialog).getByRole('button', { name: 'Download' }));
    await waitFor(() =>
      expect(assign).toHaveBeenCalledWith('/bff/api/v1/archive/downloads/v1.EXAMPLE-token.sig'),
    );
    expect(grantBody).toEqual({ password: 'EXAMPLE-password', totpCode: '123456' });
    expectRequestMatchesContract('ArchiveMessagesController_grant_v1', grantBody);
    expect(
      JSON.stringify(
        queryClient
          .getMutationCache()
          .getAll()
          .map((m) => m.state.data),
      ),
    ).not.toContain('EXAMPLE-token');
  });

  it('explains a failed re-authentication inside the dialog', async () => {
    mockDetail();
    mockApi({
      ArchiveMessagesController_grant_v1: () =>
        apiErrorJson(401, 'quarantine_reauth_failed', 'Password or verification code is incorrect'),
    });
    const { user } = renderWithProviders(<ArchiveDetails messageId={MESSAGE_ID} />, {
      me: mfaAdmin({ mfaEnabled: false }),
    });
    await user.click(await screen.findByRole('button', { name: 'Download original' }));
    const dialog = await screen.findByRole('dialog');
    await user.type(within(dialog).getByLabelText('Your password (required)'), 'wrong');
    await user.click(within(dialog).getByRole('button', { name: 'Download' }));
    expect(
      await within(dialog).findByText(/password or authenticator code is not correct/),
    ).toBeInTheDocument();
  });

  it('blocks content for malicious records, without MFA and under a platform override', async () => {
    mockDetail(detail({ malicious: true }));
    const first = renderWithProviders(<ArchiveDetails messageId={MESSAGE_ID} />, {
      me: mfaAdmin(),
    });
    expect(
      await screen.findByText(/classified as malicious: it cannot be downloaded interactively/),
    ).toBeInTheDocument();
    first.unmount();

    mockDetail();
    const second = renderWithProviders(<ArchiveDetails messageId={MESSAGE_ID} />, {
      role: 'organization_admin',
    });
    expect(
      await screen.findAllByText(/needs a session signed in with multi-factor authentication/),
    ).toHaveLength(2);
    second.unmount();

    mockDetail();
    renderWithProviders(<ArchiveDetails messageId={MESSAGE_ID} />, {
      me: makeMe({
        role: 'super_admin',
        overrides: {
          session: { id: '01930000-0000-7000-8000-000000000501', mfaAuthenticated: true },
          override: {
            id: '01930000-0000-7000-8000-000000000901',
            reason: 'EXAMPLE support',
            organizationId: '01930000-0000-7000-8000-00000000a001',
            expiresAt: '2026-11-17T09:00:00.000Z',
          },
        },
      }),
    });
    expect(
      await screen.findAllByText(
        /customer-only: previews and downloads are not available under a platform override/,
      ),
    ).toHaveLength(2);
  });

  it('disposes an expiry_review record with a reason (MFA, Idempotency-Key)', async () => {
    mockDetail(detail({ status: 'expiry_review' }));
    let disposeBody: unknown = null;
    let key: string | null = null;
    mockApi({
      ArchiveMessagesController_dispose_v1: ({ body, request }) => {
        disposeBody = body;
        key = request.headers.get('idempotency-key');
        return okJson(
          {
            messageId: MESSAGE_ID,
            status: 'disposing',
            disposalRequestedAt: '2026-11-17T08:00:00.000Z',
          },
          202,
        );
      },
    });
    const { user } = renderWithProviders(<ArchiveDetails messageId={MESSAGE_ID} />, {
      me: mfaAdmin(),
    });
    await user.click(await screen.findByRole('button', { name: 'Dispose' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Dispose' }));
    expect(within(dialog).getByText(/Enter a reason/)).toBeInTheDocument();
    await user.type(
      within(dialog).getByLabelText('Reason (required)'),
      'EXAMPLE reviewed by counsel',
    );
    await user.click(within(dialog).getByRole('button', { name: 'Dispose' }));
    await waitFor(() => expect(disposeBody).toEqual({ reason: 'EXAMPLE reviewed by counsel' }));
    expect(key).toBeTruthy();
    expectRequestMatchesContract('ArchiveMessagesController_dispose_v1', disposeBody);
  });

  it('renders a foreign or unknown id like a missing record', async () => {
    mockApi({
      ArchiveMessagesController_detail_v1: () =>
        apiErrorJson(404, 'archive_message_not_found', 'Archived message not found'),
    });
    renderWithProviders(<ArchiveDetails messageId={MESSAGE_ID} />, { me: mfaAdmin() });
    expect(
      await screen.findByText('It does not exist, or you do not have access to it.'),
    ).toBeInTheDocument();
    renderWithProviders(<ArchiveDetails messageId="not-a-uuid" />, { me: mfaAdmin() });
    expect(screen.getByRole('heading', { name: 'Page not found' })).toBeInTheDocument();
  });
});
