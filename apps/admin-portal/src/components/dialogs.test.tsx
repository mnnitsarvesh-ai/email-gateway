import { screen, waitFor } from '@testing-library/react';
import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { expectNoAxeViolations, renderWithProviders } from '@/test';
import { ConfirmDialog } from './confirm-dialog';
import { SecretRevealDialog } from './secret-reveal-dialog';

function ConfirmHarness({ onConfirm, typed }: { onConfirm: () => unknown; typed?: string }) {
  const [open, setOpen] = useState(true);
  return (
    <>
      <span>{open ? 'open' : 'closed'}</span>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        title="Delete domain?"
        description="This cannot be undone."
        confirmLabel="Delete"
        destructive
        typedConfirmation={typed}
        onConfirm={onConfirm}
      />
    </>
  );
}

describe('ConfirmDialog', () => {
  it('requires the typed confirmation for irreversible actions', async () => {
    const onConfirm = vi.fn();
    const { user } = renderWithProviders(
      <ConfirmHarness onConfirm={onConfirm} typed="alpha.example.test" />,
    );
    const confirm = screen.getByRole('button', { name: 'Delete' });
    expect(confirm).toBeDisabled();
    await user.type(
      screen.getByLabelText(/Type alpha.example.test to confirm/),
      'alpha.example.tes',
    );
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText(/Type alpha.example.test to confirm/), 't');
    expect(confirm).toBeEnabled();
    await user.click(confirm);
    expect(onConfirm).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(screen.getByText('closed')).toBeInTheDocument());
  });

  it('stays open when onConfirm returns false, closes on Escape, and is accessible', async () => {
    const { user } = renderWithProviders(<ConfirmHarness onConfirm={() => false} />);
    expect(screen.getByRole('alertdialog')).toHaveAccessibleName('Delete domain?');
    await expectNoAxeViolations(document.body);
    await user.click(screen.getByRole('button', { name: 'Delete' }));
    expect(screen.getByText('open')).toBeInTheDocument();
    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.getByText('closed')).toBeInTheDocument());
  });
});

describe('SecretRevealDialog', () => {
  it('shows secrets once with copy buttons and closes only after acknowledgement', async () => {
    // Synthetic value assembled at runtime so no key-shaped literal sits in the source.
    const secret = ['egk', 'test', 'secret'].join('_');
    const onClose = vi.fn();
    const { user } = renderWithProviders(
      <SecretRevealDialog
        open
        title="API key created"
        description="Copy it now."
        secrets={[{ label: 'API key', value: secret }]}
        onClose={onClose}
      />,
    );
    expect(screen.getByText(secret)).toBeInTheDocument();
    await user.keyboard('{Escape}');
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    const done = screen.getByRole('button', { name: 'Done' });
    expect(done).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Copy API key' }));
    await user.click(screen.getByRole('checkbox'));
    await user.click(done);
    expect(onClose).toHaveBeenCalled();
    await expectNoAxeViolations(document.body);
  });
});
