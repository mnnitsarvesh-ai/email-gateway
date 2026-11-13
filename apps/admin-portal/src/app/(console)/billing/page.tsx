import { Suspense } from 'react';
import { BillingPage } from '@/features/billing/billing-page';

export default function Page() {
  return (
    <Suspense>
      <BillingPage />
    </Suspense>
  );
}
