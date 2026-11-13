import { Suspense } from 'react';
import { MailServersPage } from '@/features/mail-servers';

export default function Page() {
  return (
    <Suspense>
      <MailServersPage />
    </Suspense>
  );
}
