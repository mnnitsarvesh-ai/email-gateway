import type { Metadata } from 'next';
import { AuthFrame } from '@/features/auth/auth-frame';
import { ResetPasswordForm } from '@/features/auth/reset-password-form';

export const metadata: Metadata = {
  title: 'Choose a new password · Email Security Gateway',
  referrer: 'no-referrer',
};

export default function ResetPasswordPage() {
  return (
    <AuthFrame title="Choose a new password">
      <ResetPasswordForm />
    </AuthFrame>
  );
}
