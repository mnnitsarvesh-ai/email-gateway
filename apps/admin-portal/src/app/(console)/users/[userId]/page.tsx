import { Suspense } from 'react';
import { UserDetailPage } from '@/features/users';

export default async function Page({ params }: { params: Promise<{ userId: string }> }) {
  const { userId } = await params;
  return (
    <Suspense>
      <UserDetailPage userId={userId} />
    </Suspense>
  );
}
