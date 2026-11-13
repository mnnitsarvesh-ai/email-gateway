import { Suspense } from 'react';
import { UrlProtectionPage } from '@/features/url-protection/url-protection-page';

export default function Page() {
  return (
    <Suspense>
      <UrlProtectionPage />
    </Suspense>
  );
}
