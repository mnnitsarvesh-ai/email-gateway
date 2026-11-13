import { Suspense } from 'react';
import { DomainDetailPage } from '@/features/domains';

export default async function Page({ params }: { params: Promise<{ domainId: string }> }) {
  const { domainId } = await params;
  return (
    <Suspense>
      <DomainDetailPage domainId={domainId} />
    </Suspense>
  );
}
