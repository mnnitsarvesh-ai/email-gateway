import { Suspense } from 'react';
import { DomainsPage } from '@/features/domains';

export default function Page() {
  return (
    <Suspense>
      <DomainsPage />
    </Suspense>
  );
}
