import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  MIGRATED_ADMIN_PERMISSIONS,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  makeMe,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { ArchiveDetails } from './archive-details';
import { ArchiveSearchPage } from './archive-search-page';
import { archiveDownloadNavigation } from './download-dialog';
import { MESSAGE_ID, SETTINGS, detail, message } from './test-data';

/** Step 8.6 additions of the archive pages (D7, D14): copy sources, intake, merged copies. */

const SOURCE_ID = '01930000-0000-7000-8000-00000000d001';
const COPY_ID = '01930000-0000-7000-8000-00000000d201';

const mfaAdmin = () =>
  makeMe({
    role: 'organization_admin',
    permissions: MIGRATED_ADMIN_PERMISSIONS,
    overrides: {
      mfaEnabled: true,
      session: { id: '01930000-0000-7000-8000-000000000501', mfaAuthenticated: true },
    },
  });

const MERGED = detail({
  ingestSources: ['gateway', 'journal_intake'],
  intake: {
    kind: 'microsoft_365_journal',
    sourceId: SOURCE_ID,
    sourceDisplayName: 'Contoso Microsoft 365',
  },
  mergedCopies: [
    {
      id: COPY_ID,
      source: 'journal_intake',
      receivedAt: '2026-11-16T09:00:30.000Z',
      mergedAt: '2026-11-16T09:03:00.000Z',
      sizeBytes: 4400,
      sha256: 'b'.repeat(64),
      contentVariant: true,
      recipientsAdded: 1,
    },
  ],
});
MERGED.parties.recipients = [
  { ...MERGED.parties.recipients[0]!, field: 'to', ingestSources: ['gateway', 'journal_intake'] },
  {
    seq: 1,
    address: 'l***@corp.example.test',
    direction: 'internal',
    status: 'journaled',
    finalAction: null,
    field: 'bcc',
    ingestSources: ['journal_intake'],
  },
];
MERGED.parties.recipientCount = 2;

function mockDetail(extra: Parameters<typeof mockApi>[0] = {}) {
  mockApi({
    ArchiveMessagesController_detail_v1: () => okJson(MERGED),
    ArchiveAdminController_get_v1: () => okJson({ ...SETTINGS, enabled: true }),
    ArchiveMessagesController_journal_v1: () =>
      okJson({
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
          clientIp: '192.0.2.70',
          clientHelo: 'mail.protection.example.test',
        },
        envelope: {
          recipients: [
            {
              seq: 1,
              address: 'l***@corp.example.test',
              direction: 'internal',
              status: 'journaled',
              field: 'bcc',
            },
          ],
        },
        intake: {
          sourceId: SOURCE_ID,
          kind: 'microsoft_365_journal',
          format: 'journal_report',
          envelope: {
            sender: 'sender@partner.example.test',
            onBehalfOf: null,
            messageId: '<EXAMPLE-1@mail.example.test>',
            recipients: [
              { address: 'p***@corp.example.test', field: 'to' },
              {
                address: 'l***@corp.example.test',
                field: 'bcc',
                expandedFrom: 'l***@corp.example.test',
              },
            ],
            truncated: false,
          },
          envelopeMismatch: false,
          proof: {
            network: 'provider_egress',
            tls: true,
            clientCert: 'n/a',
            tenantHeader: 'match',
            headerToken: 'n/a',
            dkim: 'pass',
          },
        },
        headers: [{ name: 'From', value: 'sender@partner.example.test', masked: false }],
        parse: { status: 'parsed', codes: [] },
        body: {
          textAvailable: true,
          htmlAvailable: false,
          truncated: false,
          unavailableReason: null,
        },
        attachments: [],
        deliveries: [],
      }),
    ...extra,
  });
}

afterEach(() => vi.restoreAllMocks());

describe('archive search: copy sources (step 8.6)', () => {
  it('filters by copy source through the URL and shows the sources of each record', async () => {
    const urls: URL[] = [];
    mockApi({
      ArchiveMessagesController_list_v1: ({ url }) => {
        urls.push(url);
        return okJson({
          data: [message({ ingestSources: ['gateway', 'journal_intake'] })],
          nextCursor: null,
        });
      },
      LegalHoldsController_list_v1: () => okJson({ data: [], nextCursor: null }),
    });
    const { container } = renderWithProviders(<ArchiveSearchPage />, {
      role: 'compliance_officer',
      route: '/archive?ingestSource=journal_intake',
    });
    await waitFor(() =>
      expect(urls.at(-1)?.searchParams.get('ingestSource')).toBe('journal_intake'),
    );
    expect(await screen.findAllByText('Journal intake')).not.toHaveLength(0);
    expect(screen.getAllByText('Gateway').length).toBeGreaterThan(0);
    expect(currentTestUrl()).toContain('ingestSource=journal_intake');
    await expectNoAxeViolations(container);
  });

  it('is refused to an organization admin without archive access (step 8.6)', async () => {
    renderWithProviders(<ArchiveSearchPage />, { role: 'organization_admin', route: '/archive' });
    expect(await screen.findByText(/You do not have access/)).toBeInTheDocument();
  });
});

describe('archived message: intake, merged copies and variants (step 8.6)', () => {
  it('shows copies from both sources, the intake source, recipient fields and merged copies (axe clean)', async () => {
    mockDetail();
    const { container } = renderWithProviders(<ArchiveDetails messageId={MESSAGE_ID} />, {
      me: mfaAdmin(),
    });
    expect(await screen.findByRole('heading', { name: 'Archived message' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Contoso Microsoft 365' })).toHaveAttribute(
      'href',
      `/settings/journaling/intake/${SOURCE_ID}`,
    );
    expect(screen.getByRole('columnheader', { name: 'Field' })).toBeInTheDocument();
    expect(screen.getByRole('cell', { name: /^Bcc/ })).toBeInTheDocument();
    const merged = screen.getByRole('table', { name: 'Merged copies' });
    expect(within(merged).getByText('Different body (stored as a variant)')).toBeInTheDocument();
    expect(within(merged).getByRole('button', { name: 'Download variant' })).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('downloads a content variant through the same re-authenticated grant (variant id sent)', async () => {
    let grantBody: unknown = null;
    mockDetail({
      ArchiveMessagesController_grant_v1: ({ body }) => {
        grantBody = body;
        return okJson(
          {
            token: 'v1.EXAMPLE-variant.sig',
            expiresAt: '2026-11-17T08:01:00.000Z',
            filename: `archive-${MESSAGE_ID}.variant-1.eml`,
            sizeBytes: 4400,
            sha256: 'b'.repeat(64),
          },
          201,
        );
      },
    });
    const assign = vi
      .spyOn(archiveDownloadNavigation, 'assign')
      .mockImplementation(() => undefined);
    const { user } = renderWithProviders(<ArchiveDetails messageId={MESSAGE_ID} />, {
      me: mfaAdmin(),
    });
    await user.click(await screen.findByRole('button', { name: 'Download variant' }));
    const dialog = await screen.findByRole('dialog', { name: 'Download a content variant' });
    await user.type(within(dialog).getByLabelText('Your password (required)'), 'EXAMPLE-password');
    await user.type(within(dialog).getByLabelText('Authenticator code (required)'), '123456');
    await user.click(within(dialog).getByRole('button', { name: 'Download' }));
    await waitFor(() =>
      expect(assign).toHaveBeenCalledWith('/bff/api/v1/archive/downloads/v1.EXAMPLE-variant.sig'),
    );
    expect(grantBody).toEqual({
      password: 'EXAMPLE-password',
      totpCode: '123456',
      variant: COPY_ID,
    });
    expectRequestMatchesContract('ArchiveMessagesController_grant_v1', grantBody);
  });

  it('shows the journal intake block (envelope fields, expansion, proof codes) in the journal', async () => {
    mockDetail();
    const { user } = renderWithProviders(<ArchiveDetails messageId={MESSAGE_ID} />, {
      me: mfaAdmin(),
    });
    await user.click(await screen.findByRole('button', { name: 'Load the journal' }));
    expect(await screen.findByRole('heading', { name: 'Journal intake' })).toBeInTheDocument();
    expect(screen.getByText('Journal report (unwrapped)')).toBeInTheDocument();
    expect(screen.getByText('tenant header match')).toBeInTheDocument();
    expect(screen.getByText(/Journal envelope recipients \(2\)/)).toBeInTheDocument();
    expect(screen.getAllByText('Bcc').length).toBeGreaterThan(0);
    expect(screen.getByText(/expanded from/)).toBeInTheDocument();
  });
});
