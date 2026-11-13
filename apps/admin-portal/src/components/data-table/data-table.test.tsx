import { screen, waitFor, within } from '@testing-library/react';
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { useCursorList } from '@/lib/api/hooks';
import type { ListItem } from '@/lib/api/types';
import { apiErrorJson, expectNoAxeViolations, mockApi, okJson, renderWithProviders } from '@/test';
import { DataTable, type DataTableColumn } from '.';

type Domain = { id: string; name: string; status: string };
const domain = (i: number): Domain => ({
  id: `d${i}`,
  name: `d${i}.example.test`,
  status: i % 2 ? 'active' : 'verified',
});

const columns: DataTableColumn<Domain>[] = [
  { id: 'name', header: 'Name', accessorKey: 'name', meta: { label: 'Name' } },
  { id: 'status', header: 'Status', accessorKey: 'status', meta: { label: 'Status' } },
];

function DomainsTable({
  withActions = false,
  selection = false,
}: {
  withActions?: boolean;
  selection?: boolean;
}) {
  const [status, setStatus] = useState<string | undefined>(undefined);
  const [q, setQ] = useState('');
  const list = useCursorList(
    'DomainsController_list_v1',
    { ...(status ? { status } : {}), ...(q ? { q } : {}) } as never,
    { limit: 2 },
  );
  return (
    <DataTable
      tableId="domains-test"
      caption="Domains"
      columns={columns}
      list={list}
      getRowId={(row) => row.id}
      getRowLabel={(row) => row.name}
      isFiltered={Boolean(status || q)}
      onClearFilters={() => {
        setStatus(undefined);
        setQ('');
      }}
      search={{ value: q, onChange: setQ, label: 'Search domains' }}
      filters={
        <button type="button" onClick={() => setStatus('active')}>
          Only active
        </button>
      }
      rowActions={
        withActions
          ? (row) => [{ label: `Open ${row.name}`, onSelect: () => undefined }]
          : undefined
      }
      enableSelection={selection}
      bulkActions={(rows) => <span>bulk: {rows.map((r) => r.id).join(',')}</span>}
      mobileCard={(row) => <span>card {row.name}</span>}
    />
  );
}

function pagedDomains(total: number, shortFirstPage = false) {
  const all = Array.from({ length: total }, (_, i) => domain(i + 1));
  const requests: URL[] = [];
  mockApi({
    DomainsController_list_v1: ({ url }) => {
      requests.push(url);
      const offset = Number(url.searchParams.get('cursor') ?? '0');
      const status = url.searchParams.get('status');
      const filtered = status ? all.filter((d) => d.status === status) : all;
      const limit = Number(url.searchParams.get('limit'));
      const page =
        shortFirstPage && offset === 0
          ? filtered.slice(0, 1)
          : filtered.slice(offset, offset + limit);
      const next = offset + limit < filtered.length ? String(offset + limit) : null;
      return okJson({ data: page, nextCursor: next });
    },
  });
  return requests;
}

afterEach(() => vi.restoreAllMocks());

describe('DataTable (design §9)', () => {
  it('shows skeleton rows, then rows with "Page N · R rows" and a captioned table', async () => {
    pagedDomains(5);
    const { container } = renderWithProviders(<DomainsTable />);
    expect(screen.getByText('Loading Domains …')).toBeInTheDocument();
    expect(await screen.findByRole('cell', { name: 'd1.example.test' })).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'Domains' })).toBeInTheDocument();
    expect(screen.getByText('Page 1 · 2 rows')).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('walks forward with Next and back with Previous (cursor stack)', async () => {
    const requests = pagedDomains(5);
    const { user } = renderWithProviders(<DomainsTable />);
    await screen.findByRole('cell', { name: 'd1.example.test' });
    expect(screen.getByRole('button', { name: /Previous/ })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: /Next/ }));
    expect(await screen.findByRole('cell', { name: 'd3.example.test' })).toBeInTheDocument();
    expect(screen.getByText('Page 2 · 2 rows')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Next/ }));
    expect(await screen.findByRole('cell', { name: 'd5.example.test' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Next/ })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: /Previous/ }));
    expect(await screen.findByRole('cell', { name: 'd3.example.test' })).toBeInTheDocument();
    expect(requests.map((r) => r.searchParams.get('cursor'))).toEqual([null, '2', '4']);
  });

  it('resets to page 1 when a filter changes', async () => {
    const requests = pagedDomains(6);
    const { user } = renderWithProviders(<DomainsTable />);
    await screen.findByRole('cell', { name: 'd1.example.test' });
    await user.click(screen.getByRole('button', { name: /Next/ }));
    await screen.findByText('Page 2 · 2 rows');
    await user.click(screen.getByRole('button', { name: 'Only active' }));
    await waitFor(() => expect(screen.getByText(/Page 1/)).toBeInTheDocument());
    const last = requests.at(-1)!;
    expect(last.searchParams.get('status')).toBe('active');
    expect(last.searchParams.get('cursor')).toBeNull();
  });

  it('debounces the search before querying', async () => {
    const requests = pagedDomains(3);
    const { user } = renderWithProviders(<DomainsTable />);
    await screen.findByRole('cell', { name: 'd1.example.test' });
    const before = requests.length;
    await user.type(screen.getByRole('searchbox', { name: 'Search domains' }), 'd2');
    expect(requests.length).toBe(before);
    await waitFor(() => expect(requests.at(-1)?.searchParams.get('q')).toBe('d2'), {
      timeout: 2000,
    });
    expect(requests.filter((r) => r.searchParams.get('q') === 'd')).toHaveLength(0);
  });

  it('notes short pages with a next cursor', async () => {
    pagedDomains(5, true);
    renderWithProviders(<DomainsTable />);
    expect(await screen.findByText('More results may exist further back.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Load next page' })).toBeInTheDocument();
  });

  it('shows the empty, filtered-empty and error states', async () => {
    mockApi({
      DomainsController_list_v1: ({ url }) =>
        url.searchParams.get('status')
          ? okJson({ data: [], nextCursor: null })
          : okJson({ data: [], nextCursor: null }),
    });
    const { user } = renderWithProviders(<DomainsTable />);
    expect(await screen.findByText('Nothing here yet')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Only active' }));
    expect(await screen.findByText('No results match these filters')).toBeInTheDocument();
    mockApi({
      DomainsController_list_v1: () =>
        apiErrorJson(500, 'internal_error', 'Down', { requestId: 'req-dt-1' }),
    });
    renderWithProviders(<DomainsTable />);
    expect(await screen.findByText('req-dt-1')).toBeInTheDocument();
  });

  it('persists column visibility in localStorage (and survives storage errors)', async () => {
    pagedDomains(2);
    const { user, unmount } = renderWithProviders(<DomainsTable />);
    await screen.findByRole('cell', { name: 'd1.example.test' });
    await user.click(screen.getByRole('button', { name: 'Columns' }));
    await user.click(await screen.findByRole('menuitemcheckbox', { name: 'Status' }));
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('columnheader', { name: 'Status' })).not.toBeInTheDocument();
    expect(JSON.parse(localStorage.getItem('eg:table:domains-test:columns') ?? '{}')).toEqual({
      status: false,
    });
    unmount();
    renderWithProviders(<DomainsTable />);
    await screen.findByRole('cell', { name: 'd1.example.test' });
    expect(screen.queryByRole('columnheader', { name: 'Status' })).not.toBeInTheDocument();
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('SecurityError');
    });
    renderWithProviders(<DomainsTable />);
    expect(
      (await screen.findAllByRole('cell', { name: 'd1.example.test' })).length,
    ).toBeGreaterThan(0);
  });

  it('offers row actions named after the row and bulk actions for selected rows', async () => {
    pagedDomains(2);
    const { user } = renderWithProviders(<DomainsTable withActions selection />);
    await screen.findByRole('cell', { name: 'd1.example.test' });
    await user.click(screen.getByRole('button', { name: 'Actions for d1.example.test' }));
    expect(
      await screen.findByRole('menuitem', { name: 'Open d1.example.test' }),
    ).toBeInTheDocument();
    await user.keyboard('{Escape}');
    await user.click(screen.getByRole('checkbox', { name: 'Select d2.example.test' }));
    expect(
      within(screen.getByRole('region', { name: 'Bulk actions' })).getByText('bulk: d2'),
    ).toBeInTheDocument();
    await user.click(screen.getByRole('checkbox', { name: 'Select all rows on this page' }));
    expect(screen.getByText('bulk: d1,d2')).toBeInTheDocument();
  });

  it('renders stacked cards on mobile', async () => {
    vi.spyOn(window, 'matchMedia').mockImplementation(
      (query: string) =>
        ({
          matches: query.includes('max-width: 767px'),
          media: query,
          addEventListener: () => undefined,
          removeEventListener: () => undefined,
          addListener: () => undefined,
          removeListener: () => undefined,
        }) as unknown as MediaQueryList,
    );
    pagedDomains(2);
    renderWithProviders(<DomainsTable />);
    expect(await screen.findByText('card d1.example.test')).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });
});

function MessagesTable() {
  const [sort, setSort] = useState<string | undefined>(undefined);
  const list = useCursorList('MessagesController_list_v1', (sort ? { sort } : {}) as never);
  return (
    <DataTable<ListItem<'MessagesController_list_v1'>>
      tableId="messages-test"
      caption="Messages"
      columns={[{ id: 'receivedAt', header: 'Received', accessorKey: 'receivedAt' }]}
      list={list}
      getRowId={(row) => row.id}
      sort={{
        operationId: 'MessagesController_list_v1',
        columnId: 'receivedAt',
        value: sort,
        onChange: setSort,
      }}
    />
  );
}

describe('DataTable sorting', () => {
  it('sorts only through the values the operation allows', async () => {
    const sorts: (string | null)[] = [];
    mockApi({
      MessagesController_list_v1: ({ url }) => {
        sorts.push(url.searchParams.get('sort'));
        return okJson({
          data: [{ id: 'm1', receivedAt: '2026-11-13T09:00:00.000Z' }],
          nextCursor: null,
        } as never);
      },
    });
    const { user } = renderWithProviders(<MessagesTable />);
    const header = await screen.findByRole('columnheader', { name: /Received/ });
    expect(header).not.toHaveAttribute('aria-sort', 'descending');
    await user.click(within(header).getByRole('button'));
    await waitFor(() => expect(sorts.at(-1)).toBe('-receivedAt'));
    expect(screen.getByRole('columnheader', { name: /Received/ })).toHaveAttribute(
      'aria-sort',
      'descending',
    );
    await user.click(
      within(screen.getByRole('columnheader', { name: /Received/ })).getByRole('button'),
    );
    await waitFor(() => expect(sorts.at(-1)).toBe('receivedAt'));
  });

  it('shows no sort control for v0 lists without sort', async () => {
    pagedDomains(1);
    function V0() {
      const list = useCursorList('DomainsController_list_v1', {});
      return (
        <DataTable
          tableId="v0"
          caption="Domains"
          columns={columns}
          list={list}
          getRowId={(r: Domain) => r.id}
          sort={{
            operationId: 'DomainsController_list_v1',
            columnId: 'name',
            value: undefined,
            onChange: () => undefined,
          }}
        />
      );
    }
    renderWithProviders(<V0 />);
    const header = await screen.findByRole('columnheader', { name: 'Name' });
    expect(within(header).queryByRole('button')).not.toBeInTheDocument();
  });
});
