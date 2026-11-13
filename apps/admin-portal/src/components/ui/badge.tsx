import { Slot } from '@radix-ui/react-slot';
import { cva, type VariantProps } from 'class-variance-authority';
import * as React from 'react';
import { cn } from '@/lib/utils';

const badgeVariants = cva(
  'inline-flex w-fit shrink-0 items-center justify-center gap-1 rounded-sm border px-1.5 py-0.5 text-xs font-medium whitespace-nowrap [&>svg]:size-3 [&>svg]:pointer-events-none',
  {
    variants: {
      variant: {
        default: 'border-transparent bg-primary text-primary-foreground',
        secondary: 'border-transparent bg-secondary text-secondary-foreground',
        outline: 'border-border text-foreground',
        success: 'border-transparent bg-tone-success text-tone-success-foreground',
        destructive: 'border-transparent bg-tone-danger text-tone-danger-foreground',
        neutral: 'border-transparent bg-tone-neutral text-tone-neutral-foreground',
        info: 'border-transparent bg-tone-info text-tone-info-foreground',
        warning: 'border-transparent bg-tone-warning text-tone-warning-foreground',
        orange: 'border-transparent bg-tone-orange text-tone-orange-foreground',
        danger: 'border-transparent bg-tone-danger text-tone-danger-foreground',
        purple: 'border-transparent bg-tone-purple text-tone-purple-foreground',
        magenta: 'border-transparent bg-tone-magenta text-tone-magenta-foreground',
      },
    },
    defaultVariants: { variant: 'default' },
  },
);

function Badge({
  className,
  variant,
  asChild = false,
  ...props
}: React.ComponentProps<'span'> & VariantProps<typeof badgeVariants> & { asChild?: boolean }) {
  const Comp = asChild ? Slot : 'span';
  return (
    <Comp data-slot="badge" className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
