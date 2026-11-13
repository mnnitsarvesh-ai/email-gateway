'use client';

import { useQueryClient } from '@tanstack/react-query';
import { useRouter, useSearchParams } from 'next/navigation';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import type { Me } from '@/lib/api/types';
import { useMe } from '@/lib/auth/me';
import { logout } from '@/lib/session/session-client';
import { MfaEnrollment } from './mfa-enrollment';
import { safeNextPath } from './safe-next';

/** `/mfa/enroll`: authenticated, outside the console chrome (design §3.1). */
export function MfaEnrollPage() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const next = safeNextPath(useSearchParams().get('next'));
  const me = useMe();
  if (me.isLoading) return <LoadingState rows={3} />;
  if (me.error) return <ErrorState error={me.error} onRetry={() => void me.refetch()} />;
  const data = me.data as Me;
  return (
    <div className="grid gap-4">
      <MfaEnrollment account={data.user.email} onComplete={() => router.replace(next)} />
      <Button
        variant="link"
        className="h-auto justify-self-start px-0 text-xs"
        onClick={() => {
          void logout().finally(() => {
            queryClient.clear();
            router.replace('/login');
          });
        }}
      >
        Sign out
      </Button>
    </div>
  );
}
