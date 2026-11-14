'use client';

import { useQueryClient, type QueryClient } from '@tanstack/react-query';
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import type { ApiError } from '@/lib/api/errors';
import { useApiMutation } from '@/lib/api/hooks';
import type { SuccessBody } from '@/lib/api/types';

const REVEAL_OPERATION = 'MessageRevealController_reveal_v1';
/** Recipients per reveal call (the api maximum, `recipientsLimit` 1–100). */
export const RECIPIENTS_PER_REVEAL = 100;

type RevealBody = SuccessBody<'MessageRevealController_reveal_v1'>;
export type RevealedHeader = NonNullable<RevealBody['headers']>[number];

export interface RevealedRecipient {
  readonly address: string;
  readonly userId: string | null;
}

/** What one page view has revealed (component state only; ADR-0062). */
export interface RevealedValues {
  readonly revealedAt: string;
  /** `undefined` = not revealed; `null` = the message has no subject. */
  readonly subject: string | null | undefined;
  /** Stored To, Cc and Subject header rows by `seq`. */
  readonly headers: ReadonlyMap<number, RevealedHeader>;
  /** Recipient addresses (and matched users) by `rcptSeq`. */
  readonly recipients: ReadonlyMap<number, RevealedRecipient>;
  /** Cursor of the next recipients page (`null` when every recipient is revealed). */
  readonly recipientsCursor: string | null;
}

export interface MessageReveal {
  /** `null` until revealed, and again after "Hide again". */
  readonly values: RevealedValues | null;
  readonly pending: boolean;
  readonly error: ApiError | null;
  /** Seconds until a rate-limited reveal may be retried (429 countdown). */
  readonly retryAfterSeconds: number;
  /** The polite announcement of the last reveal or hide (`aria-live`). */
  readonly announcement: string;
  /** Reveals subject, To/Cc/Subject and the first recipients (one audited call). */
  readonly reveal: () => Promise<void>;
  /** Reveals the next recipients page with `recipientsCursor` (one audited call). */
  readonly revealMoreRecipients: () => Promise<void>;
  /** Forgets every revealed value of this page view. */
  readonly hide: () => void;
}

/** Removes settled reveal mutations (and their clear values) from the TanStack mutation cache. */
export function forgetMessageRevealMutations(queryClient: QueryClient): void {
  const cache = queryClient.getMutationCache();
  for (const mutation of cache.findAll({ mutationKey: [REVEAL_OPERATION] })) {
    if (mutation.state.status !== 'pending') cache.remove(mutation);
  }
}

function plural(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`;
}

/**
 * The details page's reveal (step 7.2 §2 E11, ADR-0062): `POST /messages/{id}/reveal` with
 * `['subject', 'headers', 'recipients']`, then "Reveal more recipients" with `recipientsCursor`.
 * Revealed values live **only in this hook's React state**: never in the query or mutation cache
 * (the mutation is reset and removed right after each call), the URL or browser storage. "Hide
 * again" forgets them; unmounting the page drops them. Each call is audited by the api.
 */
export function useMessageReveal(messageId: string): MessageReveal {
  const queryClient = useQueryClient();
  // The audit history section moves its window forward on success (the new row is in it).
  const mutation = useApiMutation(REVEAL_OPERATION, { successMessage: null });
  const [values, setValues] = useState<RevealedValues | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [pending, setPending] = useState(false);
  const [announcement, setAnnouncement] = useState('');
  const mounted = useRef(true);
  const generation = useRef(0);
  const submitRef = useRef(mutation.submit);
  submitRef.current = mutation.submit;
  const resetRef = useRef(mutation.reset);
  resetRef.current = mutation.reset;
  const valuesRef = useRef(values);
  valuesRef.current = values;

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      generation.current += 1;
      forgetMessageRevealMutations(queryClient);
    };
  }, [queryClient]);

  // Another message (client navigation between details pages): forget everything.
  useEffect(() => {
    generation.current += 1;
    setValues(null);
    setError(null);
    setPending(false);
    setAnnouncement('');
  }, [messageId]);

  const run = useCallback(
    async (more: boolean) => {
      const current = valuesRef.current;
      if (more && !current?.recipientsCursor) return;
      const run = generation.current;
      setPending(true);
      setError(null);
      const outcome = await submitRef.current({
        path: { messageId },
        body: more
          ? {
              fields: ['recipients'],
              recipientsCursor: current?.recipientsCursor ?? undefined,
              recipientsLimit: RECIPIENTS_PER_REVEAL,
            }
          : {
              fields: ['subject', 'headers', 'recipients'],
              recipientsLimit: RECIPIENTS_PER_REVEAL,
            },
      });
      // Never keep clear values in the TanStack caches (§2 E11).
      resetRef.current();
      forgetMessageRevealMutations(queryClient);
      if (!mounted.current || run !== generation.current) return;
      setPending(false);
      if (!outcome.ok) {
        setError(outcome.error);
        return;
      }
      const body = outcome.data;
      const base: RevealedValues =
        more && current
          ? current
          : {
              revealedAt: body.revealedAt,
              subject: undefined,
              headers: new Map(),
              recipients: new Map(),
              recipientsCursor: null,
            };
      const headers = new Map(base.headers);
      for (const header of body.headers ?? []) headers.set(header.seq, header);
      const recipients = new Map(base.recipients);
      for (const recipient of body.recipients?.data ?? []) {
        recipients.set(recipient.rcptSeq, { address: recipient.address, userId: recipient.userId });
      }
      const next: RevealedValues = {
        revealedAt: body.revealedAt,
        subject: 'subject' in body ? (body.subject ?? null) : base.subject,
        headers,
        recipients,
        recipientsCursor: body.recipients ? body.recipients.nextCursor : base.recipientsCursor,
      };
      setValues(next);
      const added = body.recipients?.data.length ?? 0;
      setAnnouncement(
        more
          ? `Revealed ${plural(added, 'more recipient address', 'more recipient addresses')}. The reveal is recorded in the audit log.`
          : `Revealed the subject, ${plural(body.headers?.length ?? 0, 'header value', 'header values')} and ${plural(added, 'recipient address', 'recipient addresses')}. The reveal is recorded in the audit log.`,
      );
    },
    [messageId, queryClient],
  );

  const reveal = useCallback(() => run(false), [run]);
  const revealMoreRecipients = useCallback(() => run(true), [run]);
  const hide = useCallback(() => {
    generation.current += 1;
    setValues(null);
    setError(null);
    setPending(false);
    setAnnouncement('Revealed values are hidden again.');
  }, []);

  return useMemo(
    () => ({
      values,
      pending,
      error,
      retryAfterSeconds: mutation.retryAfterSeconds,
      announcement,
      reveal,
      revealMoreRecipients,
      hide,
    }),
    [
      values,
      pending,
      error,
      mutation.retryAfterSeconds,
      announcement,
      reveal,
      revealMoreRecipients,
      hide,
    ],
  );
}

const NO_REVEAL: MessageReveal = {
  values: null,
  pending: false,
  error: null,
  retryAfterSeconds: 0,
  announcement: '',
  reveal: () => Promise.resolve(),
  revealMoreRecipients: () => Promise.resolve(),
  hide: () => undefined,
};

export const MessageRevealContext = createContext<MessageReveal>(NO_REVEAL);

/** The page's reveal state (sections read revealed values by `seq` / `rcptSeq`). */
export function useRevealed(): MessageReveal {
  return useContext(MessageRevealContext);
}
