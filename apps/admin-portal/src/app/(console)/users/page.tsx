import { Suspense } from 'react';
import { UsersPage } from '@/features/users';

export default function Page() {
  return (
    <Suspense>
      <UsersPage />
    </Suspense>
  );
}
