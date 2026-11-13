import { Suspense } from 'react';
import { OrganizationsPage } from '@/features/organizations/organizations-page';

export default function Page() {
  return (
    <Suspense>
      <OrganizationsPage />
    </Suspense>
  );
}
