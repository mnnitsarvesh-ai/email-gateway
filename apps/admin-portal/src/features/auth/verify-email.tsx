'use client';

import Link from 'next/link';
import { useEffect, useRef, useState } from 'react';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { callOperation } from '@/lib/api/call';
import { ApiError } from '@/lib/api/errors';
import { InvalidLink } from './reset-password-form';
import { useHashToken } from './use-hash-token';

/** `/auth/verify-email#token=…`: verifies once on load. */
export function VerifyEmail() {
  const token = useHashToken();
  const [state, setState] = useState<
    { status: 'idle' | 'pending' | 'done' | 'invalid' } | { status: 'error'; error: unknown }
  >({ status: 'idle' });
  const sent = useRef(false);

  useEffect(() => {
    if (token.status !== 'present' || sent.current) return;
    sent.current = true;
    setState({ status: 'pending' });
    callOperation('AuthController_verifyEmail_v1', { body: { token: token.token } })
      .then(() => setState({ status: 'done' }))
      .catch((error: unknown) =>
        setState(
          error instanceof ApiError && error.status === 400
            ? { status: 'invalid' }
            : { status: 'error', error },
        ),
      );
  }, [token]);

  if (token.status === 'missing' || state.status === 'invalid')
    return <InvalidLink what="verification" />;
  if (state.status === 'error') return <ErrorState error={state.error} />;
  if (state.status === 'done') {
    return (
      <div className="grid gap-4" role="status">
        <p className="text-sm">Your email address is verified.</p>
        <Button asChild>
          <Link href="/">Continue</Link>
        </Button>
      </div>
    );
  }
  return <LoadingState label="Verifying your email address" rows={2} />;
}
