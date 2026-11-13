'use client';

import { useQueryClient } from '@tanstack/react-query';
import { ArrowLeftRightIcon, MenuIcon, PanelLeftCloseIcon, PanelLeftOpenIcon } from 'lucide-react';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetDescription, SheetTitle } from '@/components/ui/sheet';
import { DESKTOP_QUERY, MOBILE_QUERY, useMediaQuery } from '@/hooks/use-media-query';
import { SESSION_QUERY_KEY, useMe, useSession } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { isBoolean, readPreference, writePreference } from '@/lib/local-preference';
import { navItemForPath } from '@/lib/navigation';
import { scheduleProactiveRefresh } from '@/lib/session/refresh';
import { cn } from '@/lib/utils';
import { DevFixturesBadge } from './dev-fixtures-badge';
import { OverrideBanner } from './override-banner';
import { ShellSlotProvider, useShellSlots } from './shell-context';
import { Brand, SidebarNav } from './sidebar-nav';
import { TenantSwitcher } from './tenant-switcher';
import { ThemeToggle } from './theme-toggle';
import { UserMenu } from './user-menu';

/**
 * The authenticated console frame (design P11): navy sidebar (expanded ≥ 1280 px, icon rail at
 * 768–1279 px, modal drawer below 768 px), sticky top bar, tenant indicator and switcher,
 * override banner, theme toggle, user menu; keeps the session fresh (P4) and sends users who
 * must enroll in MFA to /mfa/enroll. The navigation item owning the route gates it.
 */
export function AppShell({ children }: { children: ReactNode }) {
  return (
    <ShellSlotProvider>
      <ShellFrame>{children}</ShellFrame>
    </ShellSlotProvider>
  );
}

function ShellFrame({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const queryClient = useQueryClient();
  const session = useSession();
  const me = useMe();
  const isMobile = useMediaQuery(MOBILE_QUERY);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const isDesktop = useMediaQuery(DESKTOP_QUERY);
  const [desktopCollapsed, setDesktopCollapsed] = useState(false);
  const [tabletExpanded, setTabletExpanded] = useState(false);
  // The width animates only after the viewer toggles it. On load the breakpoint is known only after
  // the first effect (the media query starts false), so the sidebar would otherwise animate from
  // the rail to full width on every desktop page load.
  const [animateWidth, setAnimateWidth] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [switcherOpen, setSwitcherOpen] = useState(false);
  const { topBarSlot } = useShellSlots();

  useEffect(() => setDesktopCollapsed(readPreference('sidebar:collapsed', false, isBoolean)), []);
  useEffect(() => {
    setDrawerOpen(false);
    setTabletExpanded(false);
  }, [pathname]);

  const accessExpiresAt = session.data?.accessExpiresAt ?? null;
  useEffect(() => {
    if (!session.data?.authenticated) return;
    return scheduleProactiveRefresh(
      () => accessExpiresAt,
      (state) => queryClient.setQueryData(SESSION_QUERY_KEY, state),
    );
  }, [accessExpiresAt, queryClient, session.data?.authenticated]);

  const meData = me.data;
  const mustEnroll = Boolean(session.data?.mfaEnrollmentRequired || meData?.mfaEnrollmentRequired);
  useEffect(() => {
    if (session.data && !session.data.authenticated) {
      router.replace(`/login?next=${encodeURIComponent(pathname)}`);
    } else if (mustEnroll) {
      router.replace('/mfa/enroll');
    }
  }, [mustEnroll, pathname, router, session.data]);

  const collapsed = isMobile ? false : isDesktop ? desktopCollapsed : !tabletExpanded;
  const toggleCollapsed = () => {
    setAnimateWidth(true);
    if (isDesktop) {
      setDesktopCollapsed((value) => {
        writePreference('sidebar:collapsed', !value);
        return !value;
      });
    } else {
      setTabletExpanded((value) => !value);
    }
  };

  const permissions = meData?.permissions ?? [];
  const navItem = navItemForPath(pathname);
  const override = session.data?.override ?? null;
  const canOverride = permissions.includes('platform:tenant_override') && !override;

  const content = (() => {
    if (me.isLoading || session.isLoading || mustEnroll)
      return <LoadingState label="Loading your workspace" rows={5} />;
    if (me.error) return <ErrorState error={me.error} onRetry={() => void me.refetch()} />;
    return navItem ? <RouteGate gate={navItem.gate}>{children}</RouteGate> : children;
  })();

  return (
    <div className="flex min-h-screen bg-background">
      {!isMobile ? (
        <aside
          className={cn(
            'sticky top-0 z-30 flex h-screen shrink-0 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground',
            animateWidth && 'transition-[width] duration-[var(--motion-base)]',
            collapsed ? 'w-16' : 'w-64',
          )}
          aria-label="Sidebar"
        >
          <Brand collapsed={collapsed} />
          <SidebarNav permissions={permissions} collapsed={collapsed} />
          <div className="border-t border-sidebar-border p-2">
            <Button
              variant="ghost"
              size={collapsed ? 'icon' : 'sm'}
              onClick={toggleCollapsed}
              aria-expanded={!collapsed}
              aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              className={cn(
                'text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground',
                collapsed ? 'mx-auto flex' : 'w-full justify-start',
              )}
            >
              {collapsed ? <PanelLeftOpenIcon aria-hidden /> : <PanelLeftCloseIcon aria-hidden />}
              {!collapsed ? <span>Collapse</span> : null}
            </Button>
          </div>
        </aside>
      ) : null}
      {isMobile ? (
        <Sheet open={drawerOpen} onOpenChange={setDrawerOpen}>
          <SheetContent
            side="left"
            className="w-72 border-sidebar-border bg-sidebar p-0 text-sidebar-foreground"
            // The drawer opens from a plain button (not a SheetTrigger): return focus to it.
            onCloseAutoFocus={(event) => {
              event.preventDefault();
              menuButtonRef.current?.focus();
            }}
          >
            <SheetTitle className="sr-only">Navigation</SheetTitle>
            <SheetDescription className="sr-only">
              Main navigation of the admin portal
            </SheetDescription>
            <Brand collapsed={false} />
            <SidebarNav
              permissions={permissions}
              collapsed={false}
              onNavigate={() => setDrawerOpen(false)}
            />
          </SheetContent>
        </Sheet>
      ) : null}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex h-14 items-center gap-2 border-b bg-card/95 px-3 backdrop-blur md:px-4">
          {isMobile ? (
            <Button
              ref={menuButtonRef}
              variant="ghost"
              size="icon"
              aria-label="Open navigation"
              aria-expanded={drawerOpen}
              onClick={() => setDrawerOpen(true)}
            >
              <MenuIcon aria-hidden />
            </Button>
          ) : null}
          <p className="min-w-0 truncate text-sm font-medium text-muted-foreground">
            {navItem?.label ?? ''}
          </p>
          <div className="ml-auto flex min-w-0 items-center gap-1.5 md:gap-2">
            {topBarSlot ? <div className="hidden md:block">{topBarSlot}</div> : null}
            {session.data?.devFixtures ? <DevFixturesBadge /> : null}
            {meData ? (
              <span
                className="hidden max-w-48 items-center gap-1.5 truncate rounded-md border px-2 py-1 text-xs sm:inline-flex"
                title={`Organization: ${meData.organization.name} (${meData.organization.kind})`}
              >
                <span className="truncate font-medium">{meData.organization.name}</span>
                <span className="text-muted-foreground">
                  {meData.organization.kind === 'platform' ? 'Platform' : 'Customer'}
                </span>
              </span>
            ) : null}
            {canOverride ? (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSwitcherOpen(true)}
                aria-label="Switch tenant"
              >
                <ArrowLeftRightIcon aria-hidden />
                <span className="hidden lg:inline">Switch tenant</span>
              </Button>
            ) : null}
            <ThemeToggle />
            {meData ? <UserMenu me={meData} /> : null}
          </div>
        </header>
        {override ? (
          <OverrideBanner
            organizationName={override.organizationName}
            operator={meData?.user.displayName ?? 'you'}
            expiresAt={override.expiresAt}
            reason={meData?.override?.reason ?? null}
          />
        ) : null}
        <main id="main" tabIndex={-1} className="flex-1 px-4 py-5 outline-none md:px-6 lg:px-8">
          {content}
        </main>
      </div>
      {canOverride || switcherOpen ? (
        <TenantSwitcher open={switcherOpen} onOpenChange={setSwitcherOpen} />
      ) : null}
    </div>
  );
}
