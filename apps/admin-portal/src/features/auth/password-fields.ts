import { z } from 'zod';
import { PASSWORD_MAX, PASSWORD_MIN } from '@/components/form';

/** The api's policy (12–128 characters); the api also checks common passwords and the email. */
export const newPasswordField = z
  .string()
  .min(PASSWORD_MIN, `Use at least ${PASSWORD_MIN} characters`)
  .max(PASSWORD_MAX, `Use at most ${PASSWORD_MAX} characters`)
  .refine((value) => !/^(.)\1*$/.test(value), 'Do not use one repeated character');
