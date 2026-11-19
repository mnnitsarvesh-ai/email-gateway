import { Suspense } from 'react';
import { NewConnectionPage } from '@/features/integrations/providers';

export default function Page() {
  return (
    <Suspense>
      <NewConnectionPage />
    </Suspense>
  );
}
