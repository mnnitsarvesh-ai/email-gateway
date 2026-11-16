import { z } from 'zod';
import type { RequestBody } from '@/lib/api/types';
import { enumOf, futureDay, futureDayProblem, lineList, optionalText, text } from './fields';
import {
  TRUSTED_KINDS,
  dayOf,
  endOfDayIso,
  listOf,
  sameList,
  textOf,
  type Executive,
  type TrustedSender,
  type Vendor,
} from './model';

/**
 * Forms of the BEC configuration editors (step 7.3 WP5, design §2 B13): executives, vendors and
 * trusted senders. Strict zod schemas mirror the OpenAPI request bodies; update bodies carry
 * `version` and only the changed fields. The API normalizes names, addresses and domains.
 */

const aliases = lineList({ max: 10, itemMin: 2, itemMax: 128, noun: 'aliases' });

// ---------------------------------------------------------------------------------------------
// Executives (POST /bec/executives, PATCH /bec/executives/{id})
// ---------------------------------------------------------------------------------------------

export const executiveSchema = z
  .object({
    displayName: text(2, 128, 'Enter the display name'),
    title: optionalText(128),
    aliases,
    knownAddresses: lineList({
      max: 20,
      itemMin: 3,
      itemMax: 320,
      check: 'address',
      noun: 'addresses',
    }),
    enabled: z.boolean(),
  })
  .strict();
export type ExecutiveInput = z.infer<typeof executiveSchema>;

export function executiveDefaults(executive?: Executive): ExecutiveInput {
  return {
    displayName: executive?.displayName ?? '',
    title: executive?.title ?? '',
    aliases: textOf(executive?.aliases),
    knownAddresses: textOf(executive?.knownAddresses),
    enabled: executive?.enabled ?? true,
  };
}

export function executiveCreateBody(
  values: ExecutiveInput,
): RequestBody<'BecExecutivesController_create_v1'> {
  return {
    displayName: values.displayName,
    aliases: listOf(values.aliases),
    knownAddresses: listOf(values.knownAddresses),
    ...(values.title ? { title: values.title } : {}),
    enabled: values.enabled,
  };
}

export function executiveUpdateBody(
  executive: Executive,
  values: ExecutiveInput,
): RequestBody<'BecExecutivesController_update_v1'> {
  const title = values.title || null;
  const aliasList = listOf(values.aliases);
  const knownAddresses = listOf(values.knownAddresses);
  return {
    version: executive.version,
    ...(values.displayName !== executive.displayName ? { displayName: values.displayName } : {}),
    ...(!sameList(aliasList, executive.aliases) ? { aliases: aliasList } : {}),
    ...(!sameList(knownAddresses, executive.knownAddresses) ? { knownAddresses } : {}),
    ...(title !== executive.title ? { title } : {}),
    ...(values.enabled !== executive.enabled ? { enabled: values.enabled } : {}),
  };
}

// ---------------------------------------------------------------------------------------------
// Vendors (POST /bec/vendors, PATCH /bec/vendors/{id})
// ---------------------------------------------------------------------------------------------

export const vendorSchema = z
  .object({
    name: text(2, 128, 'Enter the vendor name'),
    aliases,
    domains: lineList({
      min: 1,
      max: 20,
      itemMax: 253,
      check: 'domain',
      noun: 'domains',
      one: 'domain',
    }),
    knownSenders: lineList({
      max: 50,
      itemMin: 3,
      itemMax: 320,
      check: 'address',
      noun: 'addresses',
    }),
    paymentChangeSensitive: z.boolean(),
    enabled: z.boolean(),
  })
  .strict();
export type VendorInput = z.infer<typeof vendorSchema>;

export function vendorDefaults(vendor?: Vendor): VendorInput {
  return {
    name: vendor?.name ?? '',
    aliases: textOf(vendor?.aliases),
    domains: textOf(vendor?.domains),
    knownSenders: textOf(vendor?.knownSenders),
    paymentChangeSensitive: vendor?.paymentChangeSensitive ?? true,
    enabled: vendor?.enabled ?? true,
  };
}

export function vendorCreateBody(
  values: VendorInput,
): RequestBody<'BecVendorsController_create_v1'> {
  return {
    name: values.name,
    aliases: listOf(values.aliases),
    domains: listOf(values.domains),
    knownSenders: listOf(values.knownSenders),
    paymentChangeSensitive: values.paymentChangeSensitive,
    enabled: values.enabled,
  };
}

export function vendorUpdateBody(
  vendor: Vendor,
  values: VendorInput,
): RequestBody<'BecVendorsController_update_v1'> {
  const aliasList = listOf(values.aliases);
  const domains = listOf(values.domains);
  const knownSenders = listOf(values.knownSenders);
  return {
    version: vendor.version,
    ...(values.name !== vendor.name ? { name: values.name } : {}),
    ...(!sameList(aliasList, vendor.aliases) ? { aliases: aliasList } : {}),
    ...(!sameList(domains, vendor.domains) ? { domains } : {}),
    ...(!sameList(knownSenders, vendor.knownSenders) ? { knownSenders } : {}),
    ...(values.paymentChangeSensitive !== vendor.paymentChangeSensitive
      ? { paymentChangeSensitive: values.paymentChangeSensitive }
      : {}),
    ...(values.enabled !== vendor.enabled ? { enabled: values.enabled } : {}),
  };
}

// ---------------------------------------------------------------------------------------------
// Trusted senders (POST /bec/trusted-senders, PATCH /bec/trusted-senders/{id})
// ---------------------------------------------------------------------------------------------

export const trustedSenderSchema = z
  .object({
    kind: enumOf(TRUSTED_KINDS),
    value: text(3, 320, 'Enter an address or a domain'),
    reason: text(1, 512, 'Enter a reason'),
    expiresOn: futureDay({ optional: true }),
  })
  .strict()
  .superRefine((values, ctx) => {
    if (values.kind === 'address' && !/^[^\s@]+@[^\s@]+$/.test(values.value)) {
      ctx.addIssue({
        code: 'custom',
        path: ['value'],
        message: 'Enter an address such as name@example.com',
      });
    }
    if (values.kind === 'domain' && (values.value.includes('@') || /\s/.test(values.value))) {
      ctx.addIssue({
        code: 'custom',
        path: ['value'],
        message: 'Enter a domain such as example.com',
      });
    }
  });
export type TrustedSenderInput = z.infer<typeof trustedSenderSchema>;

export const TRUSTED_DEFAULTS: TrustedSenderInput = {
  kind: 'domain',
  value: '',
  reason: '',
  expiresOn: '',
};

export function trustedSenderCreateBody(
  values: TrustedSenderInput,
): RequestBody<'BecTrustedSendersController_create_v1'> {
  return {
    kind: values.kind,
    value: values.value,
    reason: values.reason,
    ...(values.expiresOn ? { expiresAt: endOfDayIso(values.expiresOn) } : {}),
  };
}

/** Reason and expiry only: kind and value are fixed (delete and add instead). */
export function trustedSenderEditSchema(sender: Pick<TrustedSender, 'expiresAt'>) {
  const original = dayOf(sender.expiresAt);
  return z
    .object({
      reason: text(1, 512, 'Enter a reason'),
      expiresOn: z.string(),
    })
    .strict()
    .superRefine((values, ctx) => {
      if (values.expiresOn === original) return;
      const problem = futureDayProblem(values.expiresOn, true);
      if (problem) ctx.addIssue({ code: 'custom', path: ['expiresOn'], message: problem });
    });
}
export type TrustedSenderEditInput = z.infer<ReturnType<typeof trustedSenderEditSchema>>;

export function trustedSenderEditDefaults(sender: TrustedSender): TrustedSenderEditInput {
  return { reason: sender.reason, expiresOn: dayOf(sender.expiresAt) };
}

export function trustedSenderUpdateBody(
  sender: TrustedSender,
  values: TrustedSenderEditInput,
): RequestBody<'BecTrustedSendersController_update_v1'> {
  const expiryChanged = values.expiresOn !== dayOf(sender.expiresAt);
  return {
    version: sender.version,
    ...(values.reason !== sender.reason ? { reason: values.reason } : {}),
    ...(expiryChanged
      ? { expiresAt: values.expiresOn ? endOfDayIso(values.expiresOn) : null }
      : {}),
  };
}
