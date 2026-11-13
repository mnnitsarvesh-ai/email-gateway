'use client';

import { TriangleAlertIcon } from 'lucide-react';
import { useState } from 'react';
import { toast } from 'sonner';
import { DateTime } from '@/components/domain/date-time';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { Button } from '@/components/ui/button';
import { isApiError } from '@/lib/api/errors';
import { useEndOverride } from '@/lib/auth/me';

/** Persistent while a platform override is active (design P11). */
export function OverrideBanner({
  organizationName,
  operator,
  expiresAt,
  reason,
}: {
  organizationName: string;
  operator: string;
  expiresAt: string;
  reason: string | null;
}) {
  const endOverride = useEndOverride();
  const [pending, setPending] = useState(false);
  const end = async () => {
    setPending(true);
    try {
      await endOverride();
      toast.success('Override ended.');
    } catch (error) {
      toast.error(`Ending the override failed${isApiError(error) ? `: ${error.message}` : ''}`);
    } finally {
      setPending(false);
    }
  };
  return (
    <div
      role="region"
      aria-label="Tenant override"
      className="flex flex-wrap items-center gap-x-3 gap-y-1 bg-banner px-4 py-2 text-sm text-banner-foreground"
    >
      <TriangleAlertIcon className="size-4 shrink-0" aria-hidden />
      <p className="min-w-0 flex-1">
        Acting in <strong>{organizationName}</strong> as <strong>{operator}</strong> until{' '}
        <DateTime value={expiresAt} mode="absolute" />
        {reason ? (
          <>
            {' '}
            — reason: <UntrustedText value={reason} maxLength={80} />
          </>
        ) : null}
      </p>
      <Button
        size="sm"
        variant="outline"
        className="border-banner-foreground/40 bg-transparent text-banner-foreground hover:bg-banner-foreground/10"
        onClick={() => void end()}
        disabled={pending}
      >
        {pending ? 'Ending …' : 'End now'}
      </Button>
    </div>
  );
}
