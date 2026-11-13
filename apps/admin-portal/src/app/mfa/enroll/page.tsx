import type { Metadata } from 'next';
import { Suspense } from 'react';
import { LoadingState } from '@/components/states/loading-state';
import { AuthFrame } from '@/features/auth/auth-frame';
import { MfaEnrollPage } from '@/features/auth/mfa-enroll-page';

export const metadata: Metadata = { title: 'Set up MFA · Email Security Gateway' };

export default function MfaEnrollRoute() {
  return (
    <AuthFrame
      title="Set up multi-factor authentication"
      description="Your organization requires MFA before you continue."
    >
      <Suspense fallback={<LoadingState rows={3} />}>
        <MfaEnrollPage />
      </Suspense>
    </AuthFrame>
  );
}
