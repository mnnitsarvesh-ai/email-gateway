import { screen, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { expectNoAxeViolations, mockApi, okJson, renderWithProviders } from '@/test';
import { AccessAuditPage } from './access-audit-page';

const ROW = {
  id: '91001',
  createdAt: '2026-11-20T08:00:00.000Z',
  actor: { type: 'user' as const, id: '01930000-0000-7000-8000-000000000101' },
  action: 'rbac.archive_access_granted',
  resourceType: 'user',
  resourceId: '01930000-0000-7000-8000-000000000102',
  correlationId: null,
  sourceIp: '192.0.2.10',
  metadata: { roleKey: 'compliance_officer' },
};

describe('Archive → Access audit (step 8.6 D14)', () => {
  it('searches one category at a time: archive. by default, the exact rbac action on demand (axe clean)', async () => {
    const queries: URLSearchParams[] = [];
    mockApi({
      AuditLogsController_search_v1: ({ url }) => {
        queries.push(url.searchParams);
        return okJson({
          data: url.searchParams.get('action') === 'rbac.archive_access_granted' ? [ROW] : [],
          nextCursor: null,
        });
      },
    });
    const { user, container } = renderWithProviders(<AccessAuditPage />, {
      role: 'compliance_officer',
      route: '/archive/access-audit',
    });
    expect(await screen.findByRole('heading', { name: 'Access audit' })).toBeInTheDocument();
    await waitFor(() => expect(queries.at(-1)?.get('actionPrefix')).toBe('archive.'));
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('radio', { name: 'Access granted' }));
    await waitFor(() => expect(queries.at(-1)?.get('action')).toBe('rbac.archive_access_granted'));
    expect(queries.at(-1)?.get('actionPrefix')).toBeNull();
    expect(
      await screen.findByRole('button', { name: /Details of rbac.archive_access_granted/ }),
    ).toBeInTheDocument();
    await user.click(screen.getByRole('radio', { name: 'eDiscovery' }));
    await waitFor(() => expect(queries.at(-1)?.get('actionPrefix')).toBe('ediscovery.'));
  });

  it('is refused to an organization admin without archive access', async () => {
    renderWithProviders(<AccessAuditPage />, { role: 'organization_admin' });
    expect(await screen.findByText('You do not have access to this page')).toBeInTheDocument();
  });
});
