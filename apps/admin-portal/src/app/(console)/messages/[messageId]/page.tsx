import { MessageDetails } from '@/features/messages';

/** Email details (step 7.2 §2 E11; linked from threat alert e-mails, 7.1 §3.1). */
export default async function MessageDetailPage({
  params,
}: {
  params: Promise<{ messageId: string }>;
}) {
  const { messageId } = await params;
  return <MessageDetails messageId={messageId} />;
}
