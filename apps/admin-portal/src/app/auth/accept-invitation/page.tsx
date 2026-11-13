import type { Metadata } from 'next';
import { AcceptInvitationForm } from '@/features/auth/accept-invitation-form';
import { AuthFrame } from '@/features/auth/auth-frame';

export const metadata: Metadata = {
  title: 'Accept invitation · Email Security Gateway',
  referrer: 'no-referrer',
};

export default function AcceptInvitationPage() {
  return (
    <AuthFrame
      title="Accept your invitation"
      description="Set your name and password to activate your account."
    >
      <AcceptInvitationForm />
    </AuthFrame>
  );
}
