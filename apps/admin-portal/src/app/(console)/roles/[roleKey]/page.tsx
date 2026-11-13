import { Suspense } from 'react';
import { RoleDetailPage } from '@/features/roles';

export default async function Page({ params }: { params: Promise<{ roleKey: string }> }) {
  const { roleKey } = await params;
  return (
    <Suspense>
      <RoleDetailPage roleKey={roleKey} />
    </Suspense>
  );
}
