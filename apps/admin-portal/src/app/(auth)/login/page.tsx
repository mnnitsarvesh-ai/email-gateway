import type { Metadata } from 'next';
import { Suspense } from 'react';
import { LoadingState } from '@/components/states/loading-state';
import { AuthFrame } from '@/features/auth/auth-frame';
import { LoginForm } from '@/features/auth/login-form';

export const metadata: Metadata = { title: 'Sign in · Email Security Gateway' };

export default function LoginPage() {
  return (
    <AuthFrame title="Sign in" description="Use your work email address and password.">
      <Suspense fallback={<LoadingState rows={3} />}>
        <LoginForm />
      </Suspense>
    </AuthFrame>
  );
}
