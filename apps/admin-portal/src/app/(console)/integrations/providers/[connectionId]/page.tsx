import { Suspense } from 'react';
import { ConnectionPage } from '@/features/integrations/providers';

export default async function Page({ params }: { params: Promise<{ connectionId: string }> }) {
  const { connectionId } = await params;
  return (
    <Suspense>
      <ConnectionPage connectionId={connectionId} />
    </Suspense>
  );
}
