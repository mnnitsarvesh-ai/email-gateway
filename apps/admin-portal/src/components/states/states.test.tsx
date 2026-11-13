import { screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/lib/api/errors';
import { expectNoAxeViolations, renderWithProviders } from '@/test';
import { EmptyState, ErrorState, LoadingState, UnavailableState } from '.';

const apiError = (status: number, code = 'x', message: string | string[] = 'Something') =>
  new ApiError({
    status,
    code,
    message,
    requestId: 'req-42',
    operationId: 'DomainsController_create_v1',
  });

describe('states', () => {
  it('LoadingState announces loading and is busy', async () => {
    const { container } = renderWithProviders(<LoadingState label="Loading domains" />);
    expect(screen.getByRole('status')).toHaveAttribute('aria-busy', 'true');
    expect(screen.getByText('Loading domains …')).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('EmptyState shows title, description and action', async () => {
    const { container } = renderWithProviders(
      <EmptyState
        title="No domains yet"
        description="Add one."
        action={<button type="button">Add domain</button>}
      />,
    );
    expect(screen.getByText('No domains yet')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Add domain' })).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('ErrorState shows the status title, message, code, request id (copyable) and Retry', async () => {
    const onRetry = vi.fn();
    const { container, user } = renderWithProviders(
      <ErrorState
        error={apiError(409, 'domain_exists', 'The domain already exists')}
        onRetry={onRetry}
      />,
    );
    expect(screen.getByRole('alert')).toHaveTextContent('Conflict');
    expect(screen.getByText('The domain already exists')).toBeInTheDocument();
    expect(screen.getByText('domain_exists')).toBeInTheDocument();
    expect(screen.getByText('req-42')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Copy request ID' }));
    expect(await screen.findByText('Copied to clipboard')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(onRetry).toHaveBeenCalled();
    await expectNoAxeViolations(container);
  });

  it('ErrorState lists required permissions on 403 and reads like not-found on 404', () => {
    const { rerender } = renderWithProviders(<ErrorState error={apiError(403, 'forbidden')} />);
    expect(screen.getByText('You do not have access')).toBeInTheDocument();
    expect(screen.getByText('domain:manage')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument();
    rerender(<ErrorState error={apiError(404, 'domain_not_found', 'Domain not found')} />);
    expect(screen.getByText('Not found')).toBeInTheDocument();
    expect(
      screen.getByText('It does not exist, or you do not have access to it.'),
    ).toBeInTheDocument();
  });

  it('ErrorState handles validation lists, network errors and unknown errors', () => {
    const { rerender } = renderWithProviders(
      <ErrorState error={apiError(400, 'validation_failed', ['a: x', 'b: y'])} />,
    );
    expect(screen.getByText('a: x b: y')).toBeInTheDocument();
    rerender(
      <ErrorState error={new ApiError({ status: 0, code: 'network_error', message: 'offline' })} />,
    );
    expect(screen.getByText('Cannot reach the portal')).toBeInTheDocument();
    rerender(<ErrorState error={new Error('boom')} />);
    expect(screen.getByText('Something went wrong')).toBeInTheDocument();
  });

  it('UnavailableState names the step and the plan, or "Not offered"', async () => {
    const { container, rerender } = renderWithProviders(
      <UnavailableState
        step="8.1"
        title="Archive settings"
        description="Archive and retention settings are not available yet."
      />,
    );
    expect(screen.getByText('Arrives in step 8.1')).toBeInTheDocument();
    expect(screen.getByText(/Journaling and compliance archiving/)).toBeInTheDocument();
    await expectNoAxeViolations(container);
    rerender(
      <UnavailableState
        step={null}
        title="Invoices"
        description="Pricing is not managed by the platform."
      />,
    );
    expect(screen.getByText('Not offered')).toBeInTheDocument();
  });
});
