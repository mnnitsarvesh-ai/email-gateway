import { Suspense } from 'react';
import { AssistantPage } from '@/features/assistant/assistant-page';

export default function Page() {
  return (
    <Suspense>
      <AssistantPage />
    </Suspense>
  );
}
