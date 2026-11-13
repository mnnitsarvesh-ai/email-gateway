import { Suspense } from 'react';
import { WebhookDetailPage } from '@/features/integrations';

export default async function Page({ params }: { params: Promise<{ webhookId: string }> }) {
  const { webhookId } = await params;
  return (
    <Suspense>
      <WebhookDetailPage webhookId={webhookId} />
    </Suspense>
  );
}
