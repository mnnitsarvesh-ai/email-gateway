import { Suspense } from 'react';
import { RolesPage } from '@/features/roles';

export default function Page() {
  return (
    <Suspense>
      <RolesPage />
    </Suspense>
  );
}
