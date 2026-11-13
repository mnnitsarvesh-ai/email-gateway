'use client';

// Must stay the first import: configures zod before any schema parses (CSP, design P10).
import '@/lib/zod-config';
import { QueryClient, QueryClientProvider, useQueryClient } from '@tanstack/react-query';
import { ThemeProvider } from 'next-themes';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useState, type ReactNode } from 'react';
import { toast } from 'sonner';
import { Toaster } from '@/components/toaster';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { TooltipProvider } from '@/components/ui/tooltip';
import { shouldRetry } from '@/lib/api/hooks';
import { ME_QUERY_KEY, SESSION_QUERY_KEY } from '@/lib/auth/me';
import { onSessionEvent } from '@/lib/session/events';
import { logout } from '@/lib/session/session-client';

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: shouldRetry, staleTime: 30_000, refetchOnWindowFocus: true },
      mutations: { retry: false },
    },
  });
}

/** Reacts to session events from the client and the refresh coordinator (design P4, P8). */
export function SessionEventsBridge() {
  const queryClient = useQueryClient();
  const router = useRouter();
  const pathname = usePathname();
  const [mfaDialog, setMfaDialog] = useState(false);

  useEffect(
    () =>
      onSessionEvent((event) => {
        if (event.type === 'session-expired') {
          queryClient.clear();
          toast.error('Your session has ended. Sign in again.');
          const next =
            typeof window !== 'undefined'
              ? `${window.location.pathname}${window.location.search}`
              : pathname;
          router.replace(`/login?next=${encodeURIComponent(next)}&reason=expired`);
        } else if (event.type === 'override-expired') {
          toast.info(
            'The tenant override has ended. You are acting in your own organization again.',
          );
          queryClient.clear();
          void queryClient.invalidateQueries({ queryKey: ME_QUERY_KEY });
          void queryClient.invalidateQueries({ queryKey: SESSION_QUERY_KEY });
        } else if (event.type === 'mfa-required') {
          setMfaDialog(true);
        } else if (event.type === 'session-refreshed') {
          void queryClient.invalidateQueries({ queryKey: SESSION_QUERY_KEY });
        }
      }),
    [pathname, queryClient, router],
  );

  const signInAgain = async () => {
    try {
      await logout();
    } finally {
      queryClient.clear();
      setMfaDialog(false);
      router.replace(`/login?next=${encodeURIComponent(pathname)}&reason=mfa`);
    }
  };

  return (
    <Dialog open={mfaDialog} onOpenChange={setMfaDialog}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>This action needs an MFA session</DialogTitle>
          <DialogDescription>
            Sign in again with your authenticator code to continue. Your current session was not
            signed in with MFA.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={() => setMfaDialog(false)}>
            Not now
          </Button>
          <Button onClick={() => void signInAgain()}>Sign in again with MFA</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function Providers({ children, nonce }: { children: ReactNode; nonce?: string }) {
  const [queryClient] = useState(createQueryClient);
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider
        attribute="class"
        defaultTheme="system"
        enableSystem
        disableTransitionOnChange
        nonce={nonce}
      >
        <TooltipProvider>
          {children}
          <SessionEventsBridge />
          <Toaster />
        </TooltipProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}
