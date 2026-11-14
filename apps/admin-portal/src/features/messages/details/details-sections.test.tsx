import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { OperationId } from '@/lib/api/types';
import {
  apiErrorJson,
  expectNoAxeViolations,
  okJson,
  permissionsOf,
  renderWithProviders,
  type MockHandler,
  type SystemRoleKey,
} from '@/test';
import { expectNoInjectedMarkup, scanRound } from '../test-data';
import { MessageDetails } from './message-details';
import { sectionAllowed, sectionById, type SectionId } from './sections';
import {
  MESSAGE_ID,
  deliveriesBody,
  detailHandlers,
  detailsRoute,
  fullRound,
  headersBody,
  mockDetails,
} from './test-helpers';

function renderSection(
  section: SectionId,
  options: {
    role?: SystemRoleKey;
    permissions?: readonly string[];
    overrides?: Partial<Record<OperationId, MockHandler>>;
    query?: string;
  } = {},
) {
  const mocks = mockDetails(options.overrides);
  const view = renderWithProviders(<MessageDetails messageId={MESSAGE_ID} />, {
    role: options.role ?? 'organization_admin',
    permissions: options.permissions,
    route: detailsRoute(`section=${section}${options.query ? `&${options.query}` : ''}`),
  });
  return { ...mocks, ...view };
}

const slow =
  (handler: MockHandler): MockHandler =>
  async (context) => {
    await new Promise((resolve) => setTimeout(resolve, 30));
    return handler(context);
  };

const failing: MockHandler = () =>
  apiErrorJson(500, 'internal_error', 'Something failed', { requestId: 'req-section-500' });

interface SectionCase {
  readonly section: SectionId;
  readonly heading: string;
  /** The main read of the section (its error and loading states). */
  readonly op: OperationId;
  readonly loading: RegExp;
  readonly success: (string | RegExp)[];
  readonly empty: Partial<Record<OperationId, MockHandler>>;
  readonly emptyText: string | RegExp;
}

const emptyScans: MockHandler = () => okJson({ messageId: MESSAGE_ID, data: [], nextCursor: null });
const bareRound: MockHandler = () =>
  okJson({
    messageId: MESSAGE_ID,
    data: [scanRound({ auth: null, engines: [], risk: [], policy: null })],
    nextCursor: null,
  });

const CASES: SectionCase[] = [
  {
    section: 'summary',
    heading: 'Message summary',
    op: 'MessagesController_detail_v1',
    loading: /Loading message/,
    success: ['Identifiers and transport', 'policy_quarantine'],
    empty: {
      MessageLifecycleController_lifecycle_v1: () =>
        okJson({
          messageId: MESSAGE_ID,
          receivedAt: '2026-11-12T09:14:03.120Z',
          direction: 'inbound',
          state: 'scanning',
          statusReason: null,
          version: 3,
          lifecycleRound: 0,
          statusChangedAt: '2026-11-12T09:14:04.000Z',
          parse: null,
          recipients: { total: 1, byStatus: {} },
          deliverySeq: null,
          actions: { rescan: true, release: false },
        }),
    },
    emptyText: 'No parse recorded',
  },
  {
    section: 'people',
    heading: 'Sender and recipients',
    op: 'MessagesController_recipients_v1',
    loading: /Loading/,
    success: ['p***@alpha.example.test', 'm***@alpha.example.test'],
    empty: { MessagesController_recipients_v1: () => okJson({ data: [], nextCursor: null }) },
    emptyText: 'No recipients',
  },
  {
    section: 'headers',
    heading: 'Email headers',
    op: 'MessageHeadersController_headers_v1',
    loading: /Loading headers/,
    success: [
      'Return-Path',
      '<abc.1@mail.example.test>',
      /full header block stays in the stored message/,
    ],
    empty: { MessageHeadersController_headers_v1: () => okJson(headersBody('retention_expired')) },
    emptyText: /removed by retention/,
  },
  {
    section: 'authentication',
    heading: 'Authentication results',
    op: 'MessageScansController_scansOf_v1',
    loading: /Loading scan rounds/,
    success: ['SPF', 'DMARC', /spf=softfail smtp.mailfrom/],
    empty: { MessageScansController_scansOf_v1: bareRound },
    emptyText: /No authentication results for round 0/,
  },
  {
    section: 'spam',
    heading: 'Spam score',
    op: 'MessageScansController_scansOf_v1',
    loading: /Loading scan rounds/,
    success: ['FROM_NEQ_ENVFROM', 'Threshold', 'no action'],
    empty: { MessageScansController_scansOf_v1: bareRound },
    emptyText: 'No spam engine result in round 0.',
  },
  {
    section: 'phishing',
    heading: 'Phishing analysis',
    op: 'MessageScansController_scansOf_v1',
    loading: /Loading scan rounds/,
    success: [
      'bec.impersonation.executive_name',
      'AI assessments',
      'fb-0001',
      'microsoft-example.example.test',
    ],
    empty: { MessageScansController_scansOf_v1: bareRound },
    emptyText: 'No BEC engine result in round 0.',
  },
  {
    section: 'urls',
    heading: 'URL analysis',
    op: 'UrlProtectionController_ofMessage_v1',
    loading: /Loading/,
    success: ['javascript:alert(document.domain)', 'Link rewrite', 'Links rewritten'],
    empty: { UrlProtectionController_ofMessage_v1: () => okJson({ data: [], nextCursor: null }) },
    emptyText: 'No URLs',
  },
  {
    section: 'attachments',
    heading: 'Attachment analysis',
    op: 'AttachmentsController_ofMessage_v1',
    loading: /Loading/,
    success: ['invoice.pdf', 'static.pe_packed · high × 1', '<img src=x onerror=alert(1)>.pdf'],
    empty: { AttachmentsController_ofMessage_v1: () => okJson({ data: [], nextCursor: null }) },
    emptyText: 'No attachments',
  },
  {
    section: 'dlp',
    heading: 'DLP results',
    op: 'MessageScansController_scansOf_v1',
    loading: /Loading scan rounds/,
    success: ['4111 11•• •••• 1111', 'Findings (masked samples)'],
    empty: { MessageScansController_scansOf_v1: bareRound },
    emptyText: 'No DLP engine result in round 0.',
  },
  {
    section: 'risk',
    heading: 'Risk score',
    op: 'MessageScansController_scansOf_v1',
    loading: /Loading scan rounds/,
    success: ['url_known_phishing', 'Signal contributions', 'Groups'],
    empty: { MessageScansController_scansOf_v1: bareRound },
    emptyText: /No risk score for round 0/,
  },
  {
    section: 'policy',
    heading: 'Policy decisions',
    op: 'PolicyMessagesController_evaluations_v1',
    loading: /Loading policy evaluations/,
    success: ['Decided by', 'Floor and recommendation'],
    empty: {
      PolicyMessagesController_evaluations_v1: () => okJson({ messageId: MESSAGE_ID, data: [] }),
    },
    emptyText: 'No policy evaluations',
  },
  {
    section: 'delivery',
    heading: 'Delivery timeline',
    op: 'DeliveriesController_forMessage_v1',
    loading: /Loading deliveries/,
    success: ['250 2.0.0 Ok: queued as 4XABC for <p***@alpha.example.test>', 'Lifecycle history'],
    empty: {
      DeliveriesController_forMessage_v1: () => okJson({ ...deliveriesBody(), deliveries: [] }),
      DeliveriesController_events_v1: () => okJson({ data: [], nextCursor: null }),
    },
    emptyText: 'No deliveries',
  },
  {
    section: 'quarantine',
    heading: 'Quarantine actions',
    op: 'QuarantineEntriesController_search_v1',
    loading: /Loading quarantine entries/,
    success: ['priya.rao4@alpha.example.test', 'Details and actions'],
    empty: { QuarantineEntriesController_search_v1: () => okJson({ items: [], nextCursor: null }) },
    emptyText: /No preview: message bodies are shown only as the sanitized preview/,
  },
  {
    section: 'audit',
    heading: 'Audit history',
    op: 'AuditLogsController_search_v1',
    loading: /Loading message events/,
    success: ['message.revealed', 'dlp_evidence.read', 'Quarantine entry histories'],
    empty: { AuditLogsController_search_v1: () => okJson({ data: [], nextCursor: null }) },
    emptyText: 'No event recorded in this window.',
  },
];

describe('Email details: every section', () => {
  it.each(CASES)(
    '$section: success with the api data; hostile strings stay text; axe',
    async (c) => {
      const { container } = renderSection(c.section);
      expect(await screen.findByRole('heading', { name: c.heading, level: 2 })).toBeInTheDocument();
      for (const text of c.success) {
        expect((await screen.findAllByText(text)).length).toBeGreaterThan(0);
      }
      expectNoInjectedMarkup(container);
      await expectNoAxeViolations(container);
    },
  );

  it.each(CASES)('$section: loading state first', async (c) => {
    const base = detailHandlers()[c.op];
    if (!base) throw new Error(`no default handler for ${c.op}`);
    renderSection(c.section, { overrides: { [c.op]: slow(base) } });
    expect(await screen.findByText(c.loading)).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByText(c.loading)).not.toBeInTheDocument());
  });

  it.each(CASES)('$section: an error shows the code and the request id', async (c) => {
    renderSection(c.section, { overrides: { [c.op]: failing } });
    const alerts = await screen.findAllByRole('alert');
    const alert = alerts.find((element) => within(element).queryByText('req-section-500'));
    expect(alert).toBeDefined();
    expect(within(alert as HTMLElement).getByText('internal_error')).toBeInTheDocument();
  });

  it.each(CASES)('$section: an honest empty or unavailable state', async (c) => {
    const { container } = renderSection(c.section, { overrides: c.empty });
    expect((await screen.findAllByText(c.emptyText)).length).toBeGreaterThan(0);
    await expectNoAxeViolations(container);
  });
});

describe('Email details: section details', () => {
  it('headers: every availability state is explained; masked values say so', async () => {
    for (const availability of ['not_parsed', 'none_stored'] as const) {
      const { unmount } = renderSection('headers', {
        overrides: { MessageHeadersController_headers_v1: () => okJson(headersBody(availability)) },
      });
      expect(
        await screen.findByText(
          availability === 'not_parsed' ? /has not been parsed yet/ : /none of the stored headers/,
        ),
      ).toBeInTheDocument();
      unmount();
    }
    renderSection('headers', { role: 'read_only_user' });
    expect(await screen.findByText(/2 values are masked/)).toBeInTheDocument();
    expect(
      screen.getByText(/Revealing them needs the message:reveal permission/),
    ).toBeInTheDocument();
    expect(screen.getAllByText('Hidden')).toHaveLength(2);
  });

  it('scan sections: the round selector picks ?round= and offers older rounds', async () => {
    const pages: Record<string, unknown> = {
      first: {
        messageId: MESSAGE_ID,
        data: [fullRound({ round: 1, scanId: '900002', scanKind: 'rescan' }), fullRound()],
        nextCursor: 'MTA',
      },
      MTA: { messageId: MESSAGE_ID, data: [], nextCursor: null },
    };
    const { user } = renderSection('spam', {
      query: 'round=0',
      overrides: {
        MessageScansController_scansOf_v1: ({ url }) =>
          okJson(pages[url.searchParams.get('cursor') ?? 'first'] as never),
      },
    });
    const select = await screen.findByRole('combobox', { name: 'Scan round' });
    expect((select as HTMLSelectElement).value).toBe('0');
    expect(
      within(select).getByRole('option', { name: /Round 1 · Rescan · Completed \(newest\)/ }),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Older rounds/ })).toBeEnabled();
    await user.selectOptions(select, '1');
    await waitFor(() => expect((select as HTMLSelectElement).value).toBe('1'));
    expect(screen.getByText('Rspamd symbols of round 1')).toBeInTheDocument();
  });

  it('scan sections: a requested round that is not loaded is stated', async () => {
    renderSection('risk', { query: 'round=7' });
    expect(await screen.findByText(/Round 7 is not among the loaded rounds/)).toBeInTheDocument();
  });

  it('scan sections: no rounds yet', async () => {
    renderSection('authentication', {
      overrides: { MessageScansController_scansOf_v1: emptyScans },
    });
    expect(await screen.findByText('No scan rounds yet')).toBeInTheDocument();
  });

  it('dlp: without dlp:read the masked findings are absent (api returns null) and stated', async () => {
    renderSection('dlp', {
      role: 'compliance_auditor',
      overrides: {
        MessageScansController_scansOf_v1: () =>
          okJson({
            messageId: MESSAGE_ID,
            data: [
              {
                ...fullRound(),
                engines: fullRound().engines.map((e) =>
                  e.engine === 'dlp' ? { ...e, dlp: null } : e,
                ),
              },
            ],
            nextCursor: null,
          }),
      },
    });
    expect(await screen.findByText(/No masked DLP result for this round/)).toBeInTheDocument();
  });

  it('delivery: events can be narrowed to one recipient and the history pages with the v0 cursor', async () => {
    const seen: (string | null)[] = [];
    const { user } = renderSection('delivery', {
      overrides: {
        DeliveriesController_forMessage_v1: () =>
          okJson({
            ...deliveriesBody(),
            deliveries: [
              ...deliveriesBody().deliveries,
              {
                ...deliveriesBody().deliveries[0]!,
                rcptSeq: 1,
                recipient: 'm***@alpha.example.test',
              },
            ],
          }),
        DeliveriesController_events_v1: ({ url }) => {
          seen.push(url.searchParams.get('rcptSeq'));
          return okJson({ data: [], nextCursor: null });
        },
        MessageLifecycleController_history_v1: ({ url }) =>
          okJson(
            url.searchParams.get('cursor')
              ? { data: [], nextCursor: null }
              : { data: [], nextCursor: 'MjU' },
          ),
      },
    });
    const select = await screen.findByRole('combobox', { name: 'Recipient' });
    await user.selectOptions(select, '1');
    await waitFor(() => expect(seen).toEqual([null, '1']));
  });

  it('audit: three groups with their own cursors over the 90-day resource window', async () => {
    const { calls } = renderSection('audit');
    await screen.findByText('message.revealed');
    const audit = calls('AuditLogsController_search_v1');
    expect(audit.map((r) => r.url.searchParams.get('resourceType')).sort()).toEqual([
      'dlp_evidence',
      'message',
    ]);
    for (const request of audit) {
      expect(request.url.searchParams.get('resourceId')).toBe(MESSAGE_ID);
      expect(request.url.searchParams.get('sort')).toBe('-createdAt');
      const from = Date.parse(request.url.searchParams.get('from') ?? '');
      expect(from).toBe(Date.parse('2026-11-12T09:13:03.120Z'));
    }
    expect(await screen.findByText('Quarantine entry histories')).toBeInTheDocument();
    expect(calls('QuarantineEntriesController_history_v1')).toHaveLength(1);
  });

  it('audit: without quarantine:read the entry histories are not loaded', async () => {
    const { calls } = renderSection('audit', { permissions: ['message:read', 'audit:read'] });
    expect(await screen.findByText('message.revealed')).toBeInTheDocument();
    expect(screen.queryByText('Quarantine entry histories')).not.toBeInTheDocument();
    expect(calls('QuarantineEntriesController_search_v1')).toHaveLength(0);
  });
});

const MATRIX_ROLES: readonly SystemRoleKey[] = [
  'organization_admin',
  'security_analyst',
  'compliance_auditor',
  'read_only_user',
  'quarantine_reviewer',
];

describe('Email details: every section for every role fixture', () => {
  it.each(MATRIX_ROLES)(
    '%s: permitted sections render, others are forbidden; axe',
    async (role) => {
      const permissions = new Set(permissionsOf(role));
      for (const c of CASES) {
        const allowed = sectionAllowed(sectionById(c.section), permissions);
        const { container, unmount, calls } = renderSection(c.section, { role });
        expect(
          await screen.findByRole('heading', { name: c.heading, level: 2 }),
        ).toBeInTheDocument();
        if (allowed) {
          expect((await screen.findAllByText(c.success[0] ?? '')).length).toBeGreaterThan(0);
          expect(screen.queryByText('You do not have access to this section')).toBeNull();
        } else {
          expect(screen.getByText('You do not have access to this section')).toBeInTheDocument();
          expect(calls(c.op)).toHaveLength(c.op === 'MessagesController_detail_v1' ? 1 : 0);
        }
        expectNoInjectedMarkup(container);
        await expectNoAxeViolations(container);
        unmount();
      }
    },
  );
});
