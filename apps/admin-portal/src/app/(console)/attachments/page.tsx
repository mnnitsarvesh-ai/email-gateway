import { Suspense } from 'react';
import { AttachmentsPage } from '@/features/attachments/attachments-page';

export default function Page() {
  return (
    <Suspense>
      <AttachmentsPage />
    </Suspense>
  );
}
