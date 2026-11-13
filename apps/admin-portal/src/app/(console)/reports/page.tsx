import { Suspense } from 'react';
import { ReportsPage } from '@/features/reports/reports-page';

export default function Page() {
  return (
    <Suspense>
      <ReportsPage />
    </Suspense>
  );
}
