import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, type RenderOptions, type RenderResult } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ThemeProvider } from 'next-themes';
import type { ReactElement, ReactNode } from 'react';
import { Toaster } from '@/components/toaster';
import { TooltipProvider } from '@/components/ui/tooltip';
import type { Me } from '@/lib/api/types';
import { ME_QUERY_KEY, SESSION_QUERY_KEY } from '@/lib/auth/me';
import type { SessionState } from '@/lib/session/session-client';
import { makeMe, makeSession } from './fixtures';
import type { SystemRoleKey } from './roles';
import { setTestRoute, testRouter } from './router';

export interface RenderWithProvidersOptions extends Omit<RenderOptions, 'wrapper'> {
  /** Current user from a system role (default `organization_admin`); `null` = no user cached. */
  role?: SystemRoleKey | null;
  /** Explicit permission set (overrides the role's). */
  permissions?: readonly string[];
  /** Full `GET /auth/me` body (overrides role and permissions). */
  me?: Me;
  /** URL the mocked router starts at, e.g. `/domains?status=active`. */
  route?: string;
  /** `GET /bff/session` state (default: authenticated). */
  session?: SessionState | null;
  queryClient?: QueryClient;
}

export function createTestQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: Infinity, refetchOnWindowFocus: false },
      mutations: { retry: false },
    },
  });
}

export interface RenderWithProvidersResult extends RenderResult {
  queryClient: QueryClient;
  router: typeof testRouter;
  user: ReturnType<typeof userEvent.setup>;
}

/** Renders inside the portal providers with an injected user, session and route. */
export function renderWithProviders(
  ui: ReactElement,
  options: RenderWithProvidersOptions = {},
): RenderWithProvidersResult {
  const {
    role = 'organization_admin',
    permissions,
    me,
    route = '/',
    session,
    queryClient: given,
    ...rest
  } = options;
  setTestRoute(route);
  const queryClient = given ?? createTestQueryClient();
  const user = me ?? (role === null ? null : makeMe({ role, permissions }));
  if (user) queryClient.setQueryData(ME_QUERY_KEY, user);
  if (session !== null) queryClient.setQueryData(SESSION_QUERY_KEY, session ?? makeSession());
  const Wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider attribute="class" defaultTheme="light" enableSystem={false}>
        <TooltipProvider delayDuration={0}>
          {children}
          <Toaster />
        </TooltipProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
  const result = render(ui, { wrapper: Wrapper, ...rest });
  return { ...result, queryClient, router: testRouter, user: userEvent.setup() };
}
