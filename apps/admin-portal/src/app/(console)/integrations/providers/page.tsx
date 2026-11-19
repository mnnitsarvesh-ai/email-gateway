import { redirect } from 'next/navigation';

/** The connections are listed on `/integrations` (step 8.2 §6). */
export default function Page() {
  redirect('/integrations');
}
