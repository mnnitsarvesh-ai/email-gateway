import { Suspense } from 'react';
import { AssistantAdminPage } from '@/features/assistant-admin/admin-page';

/** Tenant AI administration (step AI-6 D1). */
export default function Page() {
  return (
    <Suspense>
      <AssistantAdminPage />
    </Suspense>
  );
}
