import type { Metadata } from 'next';
import { Suspense } from 'react';
import { LoadingState } from '@/components/states/loading-state';
import { AuthFrame } from '@/features/auth/auth-frame';
import { MfaForm } from '@/features/auth/mfa-form';

export const metadata: Metadata = { title: 'Verify sign-in · Email Security Gateway' };

export default function LoginMfaPage() {
  return (
    <AuthFrame
      title="Two-step verification"
      description="Enter the code from your authenticator app."
    >
      <Suspense fallback={<LoadingState rows={2} />}>
        <MfaForm />
      </Suspense>
    </AuthFrame>
  );
}
