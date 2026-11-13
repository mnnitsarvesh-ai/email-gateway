'use client';

import { useRouter } from 'next/navigation';
import { useEffect } from 'react';
import { LoadingState } from '@/components/states/loading-state';
import { useMe } from '@/lib/auth/me';
import { firstPermittedHref } from '@/lib/navigation';

/** `/` → the first navigation entry the user may use (design P1). */
export default function ConsoleIndexPage() {
  const router = useRouter();
  const me = useMe();
  const permissions = me.data?.permissions;
  useEffect(() => {
    if (permissions) router.replace(firstPermittedHref(permissions));
  }, [permissions, router]);
  return <LoadingState label="Opening your start page" rows={4} />;
}
