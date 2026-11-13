'use client';

import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
  type RowData,
  type RowSelectionState,
  type VisibilityState,
} from '@tanstack/react-table';
import {
  ArrowDownIcon,
  ArrowUpDownIcon,
  ArrowUpIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  Columns3Icon,
  MoreHorizontalIcon,
  Rows3Icon,
  SearchIcon,
} from 'lucide-react';
import { useEffect, useId, useMemo, useState, type ReactNode } from 'react';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { useDebouncedValue } from '@/hooks/use-debounced-value';
import { MOBILE_QUERY, useMediaQuery } from '@/hooks/use-media-query';
import { operations } from '@/lib/api/operations.gen';
import type { OperationId } from '@/lib/api/types';
import {
  isBoolean,
  isBooleanRecord,
  readPreference,
  writePreference,
} from '@/lib/local-preference';
import { cn } from '@/lib/utils';

declare module '@tanstack/react-table' {
  // Column metadata used by DataTable (label, column menu, cell classes).
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  interface ColumnMeta<TData extends RowData, TValue> {
    label?: string;
    hideable?: boolean;
    className?: string;
  }
}

export interface DataTableColumnMeta {
  /** Human label (column menu, mobile cards, header when `header` is not a string). */
  label?: string;
  /** The column can be hidden from the column menu (default true; never the first column). */
  hideable?: boolean;
  className?: string;
}

export type DataTableColumn<Row> = ColumnDef<Row, unknown> & { meta?: DataTableColumnMeta };

export interface RowAction {
  readonly label: string;
  readonly onSelect: () => void;
  readonly destructive?: boolean;
  readonly disabled?: boolean;
}

/** What the table needs from `useCursorList` (or any list source with the same shape). */
export interface DataTableList<Row> {
  readonly rows: readonly Row[];
  readonly page: number;
  readonly hasNext: boolean;
  readonly hasPrevious: boolean;
  readonly isShortPage: boolean;
  readonly next: () => void;
  readonly previous: () => void;
  readonly query: {
    readonly isLoading: boolean;
    readonly isFetching: boolean;
    readonly error: unknown;
    readonly refetch: () => unknown;
  };
}

export interface DataTableSort {
  /** The list operation; sorting is offered only when it declares `sort` values. */
  readonly operationId: OperationId;
  /** Column whose header toggles the sort. */
  readonly columnId: string;
  readonly value: string | undefined;
  readonly onChange: (value: string | undefined) => void;
}

export interface DataTableProps<Row> {
  /** Stable id: the column-visibility preference key. */
  tableId: string;
  /** Visually hidden table caption (what the table lists). */
  caption: string;
  columns: readonly DataTableColumn<Row>[];
  list: DataTableList<Row>;
  getRowId: (row: Row) => string;
  /** Accessible row name for action menus and checkboxes. */
  getRowLabel?: (row: Row) => string;
  filters?: ReactNode;
  search?: {
    value: string;
    onChange: (value: string) => void;
    label: string;
    placeholder?: string;
  };
  sort?: DataTableSort;
  rowActions?: (row: Row) => readonly RowAction[];
  enableSelection?: boolean;
  bulkActions?: (rows: Row[], clearSelection: () => void) => ReactNode;
  emptyState?: ReactNode;
  /** True when filters or search are applied (shows the filtered-empty state). */
  isFiltered?: boolean;
  onClearFilters?: () => void;
  /** Stacked card per row below 768 px. */
  mobileCard?: (row: Row) => ReactNode;
  stickyFirstColumn?: boolean;
  className?: string;
}

function sortState(
  value: string | undefined,
  columnValues: readonly string[],
): 'ascending' | 'descending' | 'none' {
  if (!value || !columnValues.includes(value)) return 'none';
  return value.startsWith('-') ? 'descending' : 'ascending';
}

/** Server-side cursor list table (design-system.md "Tables"). */
export function DataTable<Row>({
  tableId,
  caption,
  columns,
  list,
  getRowId,
  getRowLabel,
  filters,
  search,
  sort,
  rowActions,
  enableSelection = false,
  bulkActions,
  emptyState,
  isFiltered = false,
  onClearFilters,
  mobileCard,
  stickyFirstColumn = true,
  className,
}: DataTableProps<Row>) {
  const isMobile = useMediaQuery(MOBILE_QUERY);
  const captionId = useId();
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({});
  const [comfortable, setComfortable] = useState(false);
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [searchText, setSearchText] = useState(search?.value ?? '');
  const debouncedSearch = useDebouncedValue(searchText, 300);

  useEffect(() => {
    setColumnVisibility(readPreference(`table:${tableId}:columns`, {}, isBooleanRecord));
    setComfortable(readPreference(`table:${tableId}:comfortable`, false, isBoolean));
  }, [tableId]);

  useEffect(() => {
    if (search && debouncedSearch !== search.value) search.onChange(debouncedSearch);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only the debounced text drives it
  }, [debouncedSearch]);

  useEffect(() => {
    if (search && search.value !== debouncedSearch && search.value !== searchText)
      setSearchText(search.value);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- external resets (Clear filters)
  }, [search?.value]);

  // Selection is per page: a new page or new rows clear it.
  const rowKey = list.rows.map((row) => getRowId(row)).join('|');
  useEffect(
    () => setRowSelection((current) => (Object.keys(current).length === 0 ? current : {})),
    [list.page, rowKey],
  );

  const sortValues: readonly string[] | null = sort
    ? (operations[sort.operationId].sort ?? null)
    : null;

  const allColumns = useMemo<DataTableColumn<Row>[]>(() => {
    const out: DataTableColumn<Row>[] = [];
    if (enableSelection) {
      out.push({
        id: '__select',
        enableHiding: false,
        meta: { label: 'Select', hideable: false },
        header: ({ table }) => (
          <Checkbox
            aria-label="Select all rows on this page"
            checked={
              table.getIsAllPageRowsSelected()
                ? true
                : table.getIsSomePageRowsSelected()
                  ? 'indeterminate'
                  : false
            }
            onCheckedChange={(value) => table.toggleAllPageRowsSelected(value === true)}
          />
        ),
        cell: ({ row }) => (
          <Checkbox
            aria-label={`Select ${getRowLabel ? getRowLabel(row.original) : `row ${row.index + 1}`}`}
            checked={row.getIsSelected()}
            onCheckedChange={(value) => row.toggleSelected(value === true)}
          />
        ),
      });
    }
    out.push(...columns);
    if (rowActions) {
      out.push({
        id: '__actions',
        enableHiding: false,
        meta: { label: 'Actions', hideable: false, className: 'w-10 text-right' },
        header: () => <span className="sr-only">Actions</span>,
        cell: ({ row }) => (
          <RowActionsMenu
            actions={rowActions(row.original)}
            label={getRowLabel?.(row.original) ?? `row ${row.index + 1}`}
          />
        ),
      });
    }
    return out;
  }, [columns, enableSelection, getRowLabel, rowActions]);

  const table = useReactTable({
    data: list.rows as Row[],
    columns: allColumns,
    getRowId: (row) => getRowId(row),
    getCoreRowModel: getCoreRowModel(),
    manualPagination: true,
    manualSorting: true,
    state: { columnVisibility, rowSelection },
    onColumnVisibilityChange: (updater) => {
      setColumnVisibility((current) => {
        const next = typeof updater === 'function' ? updater(current) : updater;
        writePreference(`table:${tableId}:columns`, next);
        return next;
      });
    },
    enableRowSelection: enableSelection,
    onRowSelectionChange: setRowSelection,
  });

  const selectedRows = table.getSelectedRowModel().rows.map((row) => row.original);
  const clearSelection = () => setRowSelection({});
  const { isLoading, isFetching, error } = list.query;
  const hasRows = list.rows.length > 0;
  const hideable = table.getAllLeafColumns().filter((column, index) => {
    const meta = column.columnDef.meta;
    return (
      column.getCanHide() &&
      meta?.hideable !== false &&
      !(index === 0 && !enableSelection) &&
      column.id !== '__select'
    );
  });
  const rowHeight = comfortable ? 'h-11' : 'h-9';

  const toggleSort = () => {
    if (!sort || !sortValues || sortValues.length === 0) return;
    const index = sort.value ? sortValues.indexOf(sort.value) : -1;
    const next = sortValues[(index + 1) % sortValues.length];
    sort.onChange(next);
  };

  const body = (() => {
    if (isLoading && !hasRows) {
      return (
        <div role="status" aria-busy="true" className="grid gap-1 p-3">
          <span className="sr-only">Loading {caption} …</span>
          {Array.from({ length: 6 }, (_, i) => (
            <Skeleton key={i} className={cn('w-full', rowHeight)} />
          ))}
        </div>
      );
    }
    if (error && !hasRows) {
      return <ErrorState error={error} onRetry={() => void list.query.refetch()} className="m-3" />;
    }
    if (!hasRows) {
      if (list.hasNext) {
        return (
          <EmptyState
            title="No rows on this page"
            description="More results may exist further back."
            action={
              <Button variant="outline" size="sm" onClick={list.next}>
                Load next page
              </Button>
            }
          />
        );
      }
      if (isFiltered) {
        return (
          <EmptyState
            icon={SearchIcon}
            title="No results match these filters"
            action={
              onClearFilters ? (
                <Button variant="outline" size="sm" onClick={onClearFilters}>
                  Clear filters
                </Button>
              ) : undefined
            }
          />
        );
      }
      return emptyState ?? <EmptyState title="Nothing here yet" />;
    }
    if (isMobile && mobileCard) {
      return (
        <ul aria-labelledby={captionId} className="grid gap-2 p-2" data-testid="data-table-cards">
          {list.rows.map((row) => (
            <li key={getRowId(row)} className="rounded-md border bg-card p-3">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0 flex-1">{mobileCard(row)}</div>
                {rowActions ? (
                  <RowActionsMenu actions={rowActions(row)} label={getRowLabel?.(row) ?? 'row'} />
                ) : null}
              </div>
            </li>
          ))}
        </ul>
      );
    }
    return (
      <div className="relative w-full overflow-x-auto" data-testid="data-table-scroll">
        <table
          className="w-full border-collapse text-sm"
          aria-labelledby={captionId}
          aria-busy={isFetching || undefined}
        >
          <caption id={captionId} className="sr-only">
            {caption}
          </caption>
          <thead className="bg-muted/50">
            {table.getHeaderGroups().map((group) => (
              <tr key={group.id} className="border-b">
                {group.headers.map((header, index) => {
                  const meta = header.column.columnDef.meta;
                  const sortable =
                    sort &&
                    sortValues &&
                    sortValues.length > 0 &&
                    header.column.id === sort.columnId;
                  const ariaSort = sortable ? sortState(sort?.value, sortValues ?? []) : undefined;
                  const sticky = stickyFirstColumn && index === (enableSelection ? 1 : 0);
                  return (
                    <th
                      key={header.id}
                      scope="col"
                      aria-sort={ariaSort}
                      className={cn(
                        'h-9 px-3 text-left align-middle text-xs font-semibold whitespace-nowrap text-muted-foreground',
                        sticky && 'sticky left-0 z-10 bg-muted',
                        meta?.className,
                      )}
                    >
                      {header.isPlaceholder ? null : sortable ? (
                        <button
                          type="button"
                          onClick={toggleSort}
                          className="inline-flex items-center gap-1 rounded-sm hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                        >
                          {flexRender(header.column.columnDef.header, header.getContext())}
                          {ariaSort === 'descending' ? (
                            <ArrowDownIcon className="size-3.5" aria-hidden />
                          ) : ariaSort === 'ascending' ? (
                            <ArrowUpIcon className="size-3.5" aria-hidden />
                          ) : (
                            <ArrowUpDownIcon className="size-3.5" aria-hidden />
                          )}
                          <span className="sr-only">, change sort order</span>
                        </button>
                      ) : (
                        flexRender(header.column.columnDef.header, header.getContext())
                      )}
                    </th>
                  );
                })}
              </tr>
            ))}
          </thead>
          <tbody className={cn(isFetching && 'opacity-70')}>
            {table.getRowModel().rows.map((row) => (
              <tr
                key={row.id}
                data-state={row.getIsSelected() ? 'selected' : undefined}
                className={cn(
                  'border-b last:border-0 hover:bg-muted/60 data-[state=selected]:bg-accent',
                  rowHeight,
                )}
              >
                {row.getVisibleCells().map((cell, index) => {
                  const meta = cell.column.columnDef.meta;
                  const sticky = stickyFirstColumn && index === (enableSelection ? 1 : 0);
                  return (
                    <td
                      key={cell.id}
                      className={cn(
                        'px-3 py-1.5 align-middle',
                        sticky && 'sticky left-0 z-[1] bg-card',
                        meta?.className,
                      )}
                    >
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  })();

  return (
    <section
      className={cn('flex flex-col rounded-lg border bg-card shadow-xs', className)}
      aria-label={caption}
    >
      {(filters || search || hideable.length > 0) && (
        <div className="flex flex-wrap items-center gap-2 border-b p-2">
          {search ? (
            <div className="relative min-w-48 flex-1 sm:max-w-xs">
              <SearchIcon
                className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground"
                aria-hidden
              />
              <Input
                type="search"
                aria-label={search.label}
                placeholder={search.placeholder ?? search.label}
                value={searchText}
                onChange={(event) => setSearchText(event.target.value)}
                className="h-8 pl-8"
              />
            </div>
          ) : null}
          {filters}
          {isFiltered && onClearFilters ? (
            <Button variant="ghost" size="sm" onClick={onClearFilters}>
              Clear filters
            </Button>
          ) : null}
          <div className="ml-auto flex items-center gap-1">
            <Button
              variant="ghost"
              size="sm"
              aria-pressed={comfortable}
              onClick={() => {
                setComfortable((value) => {
                  writePreference(`table:${tableId}:comfortable`, !value);
                  return !value;
                });
              }}
            >
              <Rows3Icon aria-hidden />
              <span className="hidden sm:inline">{comfortable ? 'Comfortable' : 'Compact'}</span>
              <span className="sr-only sm:hidden">Row density</span>
            </Button>
            {hideable.length > 0 ? (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="sm">
                    <Columns3Icon aria-hidden />
                    <span>Columns</span>
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuLabel>Visible columns</DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  {hideable.map((column) => {
                    const meta = column.columnDef.meta;
                    const label =
                      meta?.label ??
                      (typeof column.columnDef.header === 'string'
                        ? column.columnDef.header
                        : column.id);
                    return (
                      <DropdownMenuCheckboxItem
                        key={column.id}
                        checked={column.getIsVisible()}
                        onCheckedChange={(value) => column.toggleVisibility(value === true)}
                        onSelect={(event) => event.preventDefault()}
                      >
                        {label}
                      </DropdownMenuCheckboxItem>
                    );
                  })}
                </DropdownMenuContent>
              </DropdownMenu>
            ) : null}
          </div>
        </div>
      )}
      {enableSelection && selectedRows.length > 0 && bulkActions ? (
        <div
          className="flex flex-wrap items-center gap-2 border-b bg-accent px-3 py-2 text-sm text-accent-foreground"
          role="region"
          aria-label="Bulk actions"
        >
          <span>{selectedRows.length} selected</span>
          {bulkActions(selectedRows, clearSelection)}
          <Button variant="ghost" size="sm" onClick={clearSelection}>
            Clear selection
          </Button>
        </div>
      ) : null}
      {error && hasRows ? (
        <ErrorState
          error={error}
          onRetry={() => void list.query.refetch()}
          compact
          className="m-2"
        />
      ) : null}
      {body}
      {list.isShortPage && hasRows ? (
        <div className="flex flex-wrap items-center justify-between gap-2 border-t bg-muted/40 px-3 py-2 text-xs text-muted-foreground">
          <span>More results may exist further back.</span>
          <Button variant="outline" size="sm" onClick={list.next}>
            Load next page
          </Button>
        </div>
      ) : null}
      <nav
        aria-label={`${caption} pagination`}
        className="flex items-center justify-between gap-2 border-t px-3 py-2"
      >
        <p className="text-xs text-muted-foreground" aria-live="polite">
          Page {list.page}
          {!isLoading ? ` · ${list.rows.length} ${list.rows.length === 1 ? 'row' : 'rows'}` : ''}
        </p>
        <div className="flex items-center gap-1">
          <Button
            variant="outline"
            size="sm"
            onClick={list.previous}
            disabled={!list.hasPrevious || isFetching}
          >
            <ChevronLeftIcon aria-hidden />
            Previous
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={list.next}
            disabled={!list.hasNext || isFetching}
          >
            Next
            <ChevronRightIcon aria-hidden />
          </Button>
        </div>
      </nav>
    </section>
  );
}

function RowActionsMenu({ actions, label }: { actions: readonly RowAction[]; label: string }) {
  if (actions.length === 0) return null;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" aria-label={`Actions for ${label}`}>
          <MoreHorizontalIcon aria-hidden />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {actions.map((action) => (
          <DropdownMenuItem
            key={action.label}
            variant={action.destructive ? 'destructive' : 'default'}
            disabled={action.disabled}
            onSelect={action.onSelect}
          >
            {action.label}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
