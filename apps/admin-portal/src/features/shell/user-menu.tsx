'use client';

import { useQueryClient } from '@tanstack/react-query';
import { LogOutIcon, MonitorSmartphoneIcon, ShieldCheckIcon } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { toast } from 'sonner';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { isApiError } from '@/lib/api/errors';
import type { Me } from '@/lib/api/types';
import { logout, logoutAll } from '@/lib/session/session-client';

function initials(name: string): string {
  const parts = name.trim().split(/\s+/);
  return (
    (
      (parts[0]?.[0] ?? '') + (parts.length > 1 ? (parts[parts.length - 1]?.[0] ?? '') : '')
    ).toUpperCase() || '?'
  );
}

/** Profile, account security, sign out, sign out everywhere (design P11). */
export function UserMenu({ me }: { me: Me }) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const [confirmAll, setConfirmAll] = useState(false);

  const signOut = async () => {
    try {
      await logout();
    } catch (error) {
      // The BFF clears the cookies even when the api call fails; say so when the server session
      // may still be active.
      if (isApiError(error) && error.code === 'logout_incomplete') {
        toast.error(
          `You are signed out of this browser, but the server session could not be ended${error.requestId ? ` (request ID ${error.requestId})` : ''}. Sign in and use "Sign out everywhere" to end it.`,
        );
      }
    }
    queryClient.clear();
    router.replace('/login');
  };

  const signOutEverywhere = async () => {
    try {
      await logoutAll();
      toast.success('Signed out of every session.');
    } catch (error) {
      if (isApiError(error) && error.code === 'csrf_failed') {
        // Refused before anything changed: the session (and its cookies) are untouched.
        toast.error('Signing out everywhere was refused. Reload the page and try again.');
        return;
      }
      toast.error(
        `Signing out of other sessions failed${isApiError(error) && error.requestId ? ` (request ID ${error.requestId})` : ''}. You are signed out here.`,
      );
    }
    queryClient.clear();
    router.replace('/login');
  };

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" className="h-9 gap-2 px-1.5">
            {/* The name comes from the content (no aria-label): "Account menu for <name>", so the
                visible name is part of the accessible name (WCAG 2.5.3); the initials are
                decorative. */}
            <Avatar className="size-7" aria-hidden>
              <AvatarFallback>{initials(me.user.displayName)}</AvatarFallback>
            </Avatar>
            <span className="sr-only">Account menu for</span>{' '}
            <span className="max-w-36 truncate text-sm max-lg:sr-only">{me.user.displayName}</span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-64">
          <DropdownMenuLabel className="grid gap-0.5">
            <span className="truncate">{me.user.displayName}</span>
            <span className="truncate text-xs font-normal text-muted-foreground">
              {me.user.email}
            </span>
            <span className="truncate text-xs font-normal text-muted-foreground">
              {me.roles.join(', ') || 'No role'}
            </span>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem asChild>
            <Link href="/settings?tab=security">
              <ShieldCheckIcon aria-hidden /> Account security
            </Link>
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => void signOut()}>
            <LogOutIcon aria-hidden /> Sign out
          </DropdownMenuItem>
          <DropdownMenuItem variant="destructive" onSelect={() => setConfirmAll(true)}>
            <MonitorSmartphoneIcon aria-hidden /> Sign out everywhere
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <ConfirmDialog
        open={confirmAll}
        onOpenChange={setConfirmAll}
        title="Sign out everywhere?"
        description="Every session of your account ends, on all devices, including this one."
        confirmLabel="Sign out everywhere"
        destructive
        onConfirm={signOutEverywhere}
      />
    </>
  );
}
