import { Suspense } from 'react';
import { AccessAuditPage } from '@/features/audit/access-audit-page';

/** Archive → Access audit (step 8.6 D14). */
export default function Page() {
  return (
    <Suspense>
      <AccessAuditPage />
    </Suspense>
  );
}
