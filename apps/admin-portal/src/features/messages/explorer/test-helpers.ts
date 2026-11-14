import type { ListItem, SuccessBody } from '@/lib/api/types';
import { mockApi, okJson, type MockHandler } from '@/test';
import { messageRow } from '../test-data';

/** Test builders and MSW wiring of the explorer tests (synthetic values only). */
export type SavedViewBody = SuccessBody<'SavedViewsController_get_v1'>;
type DomainItem = ListItem<'DomainsController_list_v1'>;

export const DOMAIN_ID = '01933c3a-1b2c-7d4e-8f00-00000000d001';
export const VIEW_ID = '01933c3a-1b2c-7d4e-8f00-0000000f0001';

export function domainItem(overrides: Partial<DomainItem> = {}): DomainItem {
  return {
    id: DOMAIN_ID,
    name: 'alpha-1.example.test',
    unicodeName: 'alpha-1.example.test',
    status: 'active',
    statusReason: null,
    inboundEnabled: true,
    outboundEnabled: true,
    verifiedAt: '2026-10-01T00:00:00.000Z',
    activatedAt: '2026-10-01T00:00:00.000Z',
    lastCheckedAt: '2026-11-12T00:00:00.000Z',
    nextCheckAt: null,
    createdAt: '2026-10-01T00:00:00.000Z',
    updatedAt: '2026-10-01T00:00:00.000Z',
    ...overrides,
  };
}

export function savedView(overrides: Partial<SavedViewBody> = {}): SavedViewBody {
  return {
    id: VIEW_ID,
    kind: 'message_explorer',
    name: 'Inbound phishing',
    definition: {
      version: 1,
      filters: { direction: 'inbound', verdict: 'phishing' },
      sort: '-receivedAt',
      range: { kind: 'relative', preset: '7d' },
      columns: null,
    },
    rowVersion: 3,
    createdAt: '2026-11-10T09:00:00.000Z',
    updatedAt: '2026-11-10T09:00:00.000Z',
    ...overrides,
  };
}

/** `n` distinct message rows (masked subjects, as the api returns them). */
export function rows(n: number, offset = 0): ListItem<'MessagesController_list_v1'>[] {
  return Array.from({ length: n }, (_, i) =>
    messageRow({
      id: `01933c3a-1b2c-7d4e-8f00-${String(offset + i + 1).padStart(12, '0')}`,
      receivedAt: new Date(Date.UTC(2026, 10, 12, 9, 0, 0) - (offset + i) * 60_000).toISOString(),
    }),
  );
}

export interface ExplorerMocks {
  /** Query strings of every `GET /messages` request, in order. */
  readonly requests: URLSearchParams[];
  readonly last: () => URLSearchParams;
}

/**
 * Mocks the reads of the explorer page: the message list (pages by cursor, or a handler), the
 * saved views list and the domains list.
 */
export function mockExplorer(
  options: {
    pages?: Record<
      string,
      { data: ListItem<'MessagesController_list_v1'>[]; nextCursor: string | null }
    >;
    list?: MockHandler;
    views?: SavedViewBody[];
    viewsHandler?: MockHandler;
    domains?: DomainItem[];
  } = {},
): ExplorerMocks {
  const requests: URLSearchParams[] = [];
  const pages = options.pages ?? { first: { data: rows(1), nextCursor: null } };
  mockApi({
    MessagesController_list_v1: (context) => {
      requests.push(context.url.searchParams);
      if (options.list) return options.list(context);
      const page = pages[context.url.searchParams.get('cursor') ?? 'first'] ?? pages.first;
      return okJson(page as never);
    },
    SavedViewsController_list_v1:
      options.viewsHandler ?? (() => okJson({ data: options.views ?? [], nextCursor: null })),
    DomainsController_list_v1: () =>
      okJson({ data: options.domains ?? [domainItem()], nextCursor: null }),
  });
  return { requests, last: () => requests[requests.length - 1] ?? new URLSearchParams() };
}
