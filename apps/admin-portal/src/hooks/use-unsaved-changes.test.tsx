import { act, fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { useUnsavedChanges, type UnsavedChangesGuard } from './use-unsaved-changes';

let guard: UnsavedChangesGuard | null = null;

function Page({ dirty, navigate }: { dirty: boolean; navigate: (href: string) => void }) {
  guard = useUnsavedChanges(dirty, navigate);
  return (
    <div>
      <a href="/policies?tab=email">Policy management</a>
      <a href="/policies/new" target="_blank" rel="noreferrer">
        In a new tab
      </a>
      <span data-testid="pending">{String(guard.pending)}</span>
    </div>
  );
}

function beforeUnload(): Event {
  const event = new Event('beforeunload', { cancelable: true });
  window.dispatchEvent(event);
  return event;
}

describe('useUnsavedChanges (step 7.3 design B6)', () => {
  it('asks the browser before unloading only while there are unsaved changes', () => {
    const navigate = vi.fn();
    const { rerender } = render(<Page dirty={false} navigate={navigate} />);
    expect(beforeUnload().defaultPrevented).toBe(false);
    rerender(<Page dirty navigate={navigate} />);
    expect(beforeUnload().defaultPrevented).toBe(true);
    rerender(<Page dirty={false} navigate={navigate} />);
    expect(beforeUnload().defaultPrevented).toBe(false);
  });

  it('holds an in-app link click while dirty and replays it after "Discard and leave"', () => {
    const navigate = vi.fn();
    render(<Page dirty navigate={navigate} />);
    const click = fireEvent.click(screen.getByRole('link', { name: 'Policy management' }));
    expect(click).toBe(false); // default prevented: the browser does not follow the link
    expect(screen.getByTestId('pending')).toHaveTextContent('true');
    expect(navigate).not.toHaveBeenCalled();
    act(() => guard?.confirm());
    expect(navigate).toHaveBeenCalledWith('/policies?tab=email');
    expect(screen.getByTestId('pending')).toHaveTextContent('false');
  });

  it('"Stay" forgets the navigation; clean pages and new-tab links are never held', () => {
    const navigate = vi.fn();
    const { rerender } = render(<Page dirty navigate={navigate} />);
    fireEvent.click(screen.getByRole('link', { name: 'Policy management' }));
    act(() => guard?.cancel());
    expect(navigate).not.toHaveBeenCalled();
    expect(screen.getByTestId('pending')).toHaveTextContent('false');
    fireEvent.click(screen.getByRole('link', { name: 'In a new tab' }));
    fireEvent.click(screen.getByRole('link', { name: 'Policy management' }), { ctrlKey: true });
    expect(screen.getByTestId('pending')).toHaveTextContent('false');
    rerender(<Page dirty={false} navigate={navigate} />);
    fireEvent.click(screen.getByRole('link', { name: 'Policy management' }));
    expect(screen.getByTestId('pending')).toHaveTextContent('false');
  });

  it('guard() runs a programmatic navigation at once when clean, after confirmation when dirty', () => {
    const navigate = vi.fn();
    const proceed = vi.fn();
    const { rerender } = render(<Page dirty={false} navigate={navigate} />);
    act(() => guard?.guard(proceed));
    expect(proceed).toHaveBeenCalledTimes(1);
    rerender(<Page dirty navigate={navigate} />);
    act(() => guard?.guard(proceed));
    expect(proceed).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('pending')).toHaveTextContent('true');
    act(() => guard?.confirm());
    expect(proceed).toHaveBeenCalledTimes(2);
  });
});
