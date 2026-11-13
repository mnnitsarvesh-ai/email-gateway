'use client';

import { useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { toast } from 'sonner';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DateTime } from '@/components/domain/date-time';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { ListItem } from '@/lib/api/types';
import { logoutAll } from '@/lib/session/session-client';

type Session = ListItem<'SessionsController_list_v1'>;

/** The caller's sessions: list, revoke one, sign out everywhere (Settings → Security). */
export function SessionsPanel() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const sessions = useApiQuery('SessionsController_list_v1');
  const revoke = useApiMutation('SessionsController_revoke_v1', {
    successMessage: 'Session signed out.',
    invalidates: ['SessionsController_list_v1'],
  });
  const [target, setTarget] = useState<Session | null>(null);
  const [everywhere, setEverywhere] = useState(false);

  const rows = sessions.data?.data ?? [];
  return (
    <Card>
      <CardHeader>
        <CardTitle>Active sessions</CardTitle>
        <CardDescription>
          Where your account is signed in. New sessions can take a moment to appear.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3">
        {sessions.isLoading ? (
          <LoadingState rows={3} variant="table" />
        ) : sessions.error ? (
          <ErrorState error={sessions.error} onRetry={() => void sessions.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyState title="No active sessions" />
        ) : (
          <ul className="divide-y rounded-md border" aria-label="Active sessions">
            {rows.map((session) => (
              <li key={session.id} className="flex flex-wrap items-center gap-3 p-3 text-sm">
                <div className="grid min-w-0 flex-1 gap-0.5">
                  <span className="flex items-center gap-2">
                    <UntrustedText
                      value={session.userAgent}
                      emptyLabel="Unknown device"
                      maxLength={80}
                    />
                    {session.current ? <Badge variant="info">This session</Badge> : null}
                    {session.mfaAuthenticated ? <Badge variant="success">MFA</Badge> : null}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {session.ipAddress ?? 'Unknown address'} · signed in{' '}
                    <DateTime value={session.authenticatedAt} /> · last used{' '}
                    <DateTime value={session.lastUsedAt} />
                  </span>
                </div>
                {!session.current ? (
                  <Button variant="outline" size="sm" onClick={() => setTarget(session)}>
                    Sign out
                  </Button>
                ) : null}
              </li>
            ))}
          </ul>
        )}
        <Button
          variant="outline"
          className="justify-self-start"
          onClick={() => setEverywhere(true)}
        >
          Sign out everywhere
        </Button>
      </CardContent>
      <ConfirmDialog
        open={target !== null}
        onOpenChange={(open) => !open && setTarget(null)}
        title="Sign out this session?"
        description="The device is signed out at its next request."
        confirmLabel="Sign out session"
        destructive
        error={revoke.error ? <ErrorState error={revoke.error} compact /> : undefined}
        onConfirm={async () => {
          if (!target) return false;
          const outcome = await revoke.submit({ path: { sessionId: target.id } });
          return outcome.ok;
        }}
      />
      <ConfirmDialog
        open={everywhere}
        onOpenChange={setEverywhere}
        title="Sign out everywhere?"
        description="Every session of your account ends, including this one."
        confirmLabel="Sign out everywhere"
        destructive
        onConfirm={async () => {
          try {
            await logoutAll();
          } catch {
            toast.error('Signing out of other sessions failed. You are signed out here.');
          }
          queryClient.clear();
          router.replace('/login');
        }}
      />
    </Card>
  );
}
