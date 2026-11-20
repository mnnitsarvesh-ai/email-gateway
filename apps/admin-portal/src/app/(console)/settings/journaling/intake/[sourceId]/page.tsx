import { Suspense } from 'react';
import { IntakeSourcePage } from '@/features/journaling';

/** Settings → Journaling → journal intake source (step 8.6 D14). */
export default async function Page({ params }: { params: Promise<{ sourceId: string }> }) {
  const { sourceId } = await params;
  return (
    <Suspense>
      <IntakeSourcePage sourceId={sourceId} />
    </Suspense>
  );
}
