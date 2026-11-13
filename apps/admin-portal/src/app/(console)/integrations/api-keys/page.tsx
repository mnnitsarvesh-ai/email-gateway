import { Suspense } from 'react';
import { ApiKeysPage } from '@/features/integrations';

export default function Page() {
  return (
    <Suspense>
      <ApiKeysPage />
    </Suspense>
  );
}
