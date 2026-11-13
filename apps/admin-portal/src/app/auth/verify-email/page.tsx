import type { Metadata } from 'next';
import { AuthFrame } from '@/features/auth/auth-frame';
import { VerifyEmail } from '@/features/auth/verify-email';

export const metadata: Metadata = {
  title: 'Verify email · Email Security Gateway',
  referrer: 'no-referrer',
};

export default function VerifyEmailPage() {
  return (
    <AuthFrame title="Verify your email address">
      <VerifyEmail />
    </AuthFrame>
  );
}
