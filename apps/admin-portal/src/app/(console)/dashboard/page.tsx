import { Suspense } from 'react';
import { DashboardPage } from '@/features/dashboard/dashboard-page';

export default function Page() {
  return (
    <Suspense>
      <DashboardPage />
    </Suspense>
  );
}
