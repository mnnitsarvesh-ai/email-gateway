import { MessageDetail } from '@/features/messages';

/** Email details (design §1.3 row 10; linked from threat alert e-mails, §3.1). */
export default async function MessageDetailPage({
  params,
}: {
  params: Promise<{ messageId: string }>;
}) {
  const { messageId } = await params;
  return <MessageDetail messageId={messageId} />;
}
