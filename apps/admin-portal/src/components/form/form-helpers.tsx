'use client';

import { zodResolver } from '@hookform/resolvers/zod';
import { AlertCircleIcon, EyeIcon, EyeOffIcon } from 'lucide-react';
import { forwardRef, useState, type ComponentProps } from 'react';
import {
  useForm,
  type DefaultValues,
  type FieldValues,
  type Path,
  type UseFormProps,
  type UseFormReturn,
} from 'react-hook-form';
import type { z } from 'zod';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ApiError, mapValidationErrors } from '@/lib/api/errors';
import { cn } from '@/lib/utils';

/** react-hook-form with a zod (v4) schema; validation on submit, re-validation on change. */
export function useZodForm<S extends z.ZodType<FieldValues, FieldValues>>(
  schema: S,
  options: Omit<UseFormProps<z.input<S>, unknown, z.output<S>>, 'resolver'> & {
    defaultValues?: DefaultValues<z.input<S>>;
  } = {},
): UseFormReturn<z.input<S>, unknown, z.output<S>> {
  return useForm<z.input<S>, unknown, z.output<S>>({
    mode: 'onSubmit',
    reValidateMode: 'onChange',
    ...options,
    resolver: zodResolver(schema as never) as never,
  });
}

/**
 * Applies an ApiError to a form (design P8): `400 validation_failed` lines `"<path>: <issue>"`
 * go to matching fields; everything else (and every other 4xx/5xx) becomes form-level messages,
 * returned for `FormErrorSummary`.
 */
export function applyApiErrors<T extends FieldValues>(
  form: UseFormReturn<T, unknown, unknown>,
  error: unknown,
): string[] {
  if (!(error instanceof ApiError)) return error ? ['An unexpected error occurred.'] : [];
  const fields = Object.keys(form.getValues());
  const { fieldErrors, formErrors } = mapValidationErrors(error, fields);
  for (const [field, message] of Object.entries(fieldErrors)) {
    form.setError(field as Path<T>, { type: 'server', message });
  }
  if (error.status === 429 && error.retryAfterSeconds) {
    return [`Too many requests. Try again in ${error.retryAfterSeconds} s.`];
  }
  return formErrors.length > 0 || Object.keys(fieldErrors).length > 0 ? formErrors : error.messages;
}

/** Form-level errors at the top of a form (`role="alert"`), with the request id when known. */
export function FormErrorSummary({
  messages,
  requestId,
  className,
}: {
  messages: readonly string[];
  requestId?: string | null;
  className?: string;
}) {
  if (messages.length === 0) return null;
  return (
    <div
      role="alert"
      className={cn(
        'flex gap-2 rounded-md border border-destructive/40 bg-tone-danger px-3 py-2 text-sm text-tone-danger-foreground',
        className,
      )}
    >
      <AlertCircleIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div className="grid gap-1">
        {messages.map((message, index) => (
          <p key={index}>{message}</p>
        ))}
        {requestId ? (
          <p className="text-xs">
            Request ID: <span className="font-mono">{requestId}</span>
          </p>
        ) : null}
      </div>
    </div>
  );
}

/** Password input with a show/hide toggle (the toggle never submits). */
export const PasswordInput = forwardRef<
  HTMLInputElement,
  Omit<ComponentProps<typeof Input>, 'type'>
>(function PasswordInput({ className, ...props }, ref) {
  const [visible, setVisible] = useState(false);
  return (
    <div className="relative">
      <Input
        ref={ref}
        type={visible ? 'text' : 'password'}
        className={cn('pr-10', className)}
        {...props}
      />
      <Button
        variant="ghost"
        size="icon"
        className="absolute top-1/2 right-1 size-7 -translate-y-1/2"
        onClick={() => setVisible((v) => !v)}
        aria-label={visible ? 'Hide password' : 'Show password'}
        aria-pressed={visible}
      >
        {visible ? <EyeOffIcon aria-hidden /> : <EyeIcon aria-hidden />}
      </Button>
    </div>
  );
});

/** The api's password policy (docs/security/authentication.md): 12–128 characters. */
export const PASSWORD_MIN = 12;
export const PASSWORD_MAX = 128;
export const PASSWORD_HINT =
  'Use 12 to 128 characters. Avoid your email address, common passwords and repeated characters.';
