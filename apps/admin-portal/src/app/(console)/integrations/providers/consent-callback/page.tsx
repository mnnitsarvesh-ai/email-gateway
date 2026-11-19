import { Suspense } from 'react';
import { ConsentCallbackPage } from '@/features/integrations/providers';

/** Microsoft's admin-consent redirect target (`PROVIDER_CONSENT_REDIRECT_URL`, step 8.2 D3). */
export default function Page() {
  return (
    <Suspense>
      <ConsentCallbackPage />
    </Suspense>
  );
}
