import { Suspense } from 'react';
import { OrganizationDetailPage } from '@/features/organizations/organization-detail-page';

export default async function Page({ params }: { params: Promise<{ organizationId: string }> }) {
  const { organizationId } = await params;
  return (
    <Suspense>
      <OrganizationDetailPage organizationId={organizationId} />
    </Suspense>
  );
}
