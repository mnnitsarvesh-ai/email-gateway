'use client';

import { ShieldIcon } from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { navItemForPath, visibleNavigation } from '@/lib/navigation';
import { cn } from '@/lib/utils';

/** Permission-filtered navigation (design P11); `collapsed` renders the icon rail with tooltips. */
export function SidebarNav({
  permissions,
  collapsed,
  onNavigate,
}: {
  permissions: readonly string[];
  collapsed: boolean;
  onNavigate?: () => void;
}) {
  const pathname = usePathname();
  const active = navItemForPath(pathname);
  const sections = visibleNavigation(permissions);
  return (
    <nav aria-label="Main" className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-2 py-3">
      {sections.map((section) => (
        <div key={section.id} className="grid gap-1">
          <p
            className={cn(
              'px-2 text-xs font-semibold tracking-wide text-sidebar-muted uppercase',
              collapsed && 'sr-only',
            )}
          >
            {section.label}
          </p>
          <ul className="grid gap-0.5">
            {section.items.map((item) => {
              const isActive = active?.id === item.id;
              const link = (
                <Link
                  href={item.href}
                  onClick={onNavigate}
                  aria-current={isActive ? 'page' : undefined}
                  className={cn(
                    'relative flex h-9 items-center gap-3 rounded-md px-2 text-sm text-sidebar-foreground outline-none hover:bg-sidebar-accent hover:text-sidebar-accent-foreground focus-visible:ring-2 focus-visible:ring-sidebar-ring',
                    isActive && 'bg-sidebar-accent font-medium text-sidebar-accent-foreground',
                    collapsed && 'justify-center px-0',
                  )}
                >
                  {isActive ? (
                    <span
                      aria-hidden
                      className="absolute top-1.5 bottom-1.5 left-0 w-0.5 rounded-full bg-sidebar-primary"
                    />
                  ) : null}
                  <item.icon className="size-4 shrink-0" aria-hidden />
                  <span className={cn('truncate', collapsed && 'sr-only')}>{item.label}</span>
                </Link>
              );
              return (
                <li key={item.id}>
                  {collapsed ? (
                    <Tooltip>
                      <TooltipTrigger asChild>{link}</TooltipTrigger>
                      <TooltipContent side="right">{item.label}</TooltipContent>
                    </Tooltip>
                  ) : (
                    link
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}

export function Brand({ collapsed }: { collapsed: boolean }) {
  return (
    <Link
      href="/"
      className={cn(
        'flex h-14 shrink-0 items-center gap-2 border-b border-sidebar-border px-4 font-semibold text-sidebar-foreground outline-none focus-visible:ring-2 focus-visible:ring-sidebar-ring',
        collapsed && 'justify-center px-0',
      )}
      aria-label="Email Security Gateway home"
    >
      <ShieldIcon className="size-5 text-sidebar-primary" aria-hidden />
      <span className={cn('truncate', collapsed && 'sr-only')}>Email Security Gateway</span>
    </Link>
  );
}
