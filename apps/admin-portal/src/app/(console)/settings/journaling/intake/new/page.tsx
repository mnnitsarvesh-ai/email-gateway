import { Suspense } from 'react';
import { NewIntakeSourcePage } from '@/features/journaling';

/** Settings → Journaling → new journal intake source (step 8.6 D14). */
export default function Page() {
  return (
    <Suspense>
      <NewIntakeSourcePage />
    </Suspense>
  );
}
