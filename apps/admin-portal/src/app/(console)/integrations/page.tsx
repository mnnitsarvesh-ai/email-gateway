import { Suspense } from 'react';
import { IntegrationsPage } from '@/features/integrations';

export default function Page() {
  return (
    <Suspense>
      <IntegrationsPage />
    </Suspense>
  );
}
