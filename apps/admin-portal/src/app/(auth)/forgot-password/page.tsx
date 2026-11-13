import type { Metadata } from 'next';
import { AuthFrame } from '@/features/auth/auth-frame';
import { ForgotPasswordForm } from '@/features/auth/forgot-password-form';

export const metadata: Metadata = { title: 'Reset password · Email Security Gateway' };

export default function ForgotPasswordPage() {
  return (
    <AuthFrame
      title="Reset your password"
      description="We send a reset link to the verified email address of your account."
    >
      <ForgotPasswordForm />
    </AuthFrame>
  );
}
