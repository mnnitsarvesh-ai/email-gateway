import { Suspense } from 'react';
import { DomainOnboardingPage } from '@/features/domains';

export default function Page() {
  return (
    <Suspense>
      <DomainOnboardingPage />
    </Suspense>
  );
}
