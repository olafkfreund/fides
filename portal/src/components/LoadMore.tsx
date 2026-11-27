export function LoadMore({ next, loading, more }: {
  next: URL | null;
  loading: boolean;
  more: () => void;
}) {
  if (!next) return null;
  return (
    <button type="button" onClick={more} disabled={loading}
      className="mt-3 rounded-md border border-border px-3 py-1.5 text-sm disabled:opacity-50">
      {loading ? "Loading…" : "Load more"}
    </button>
  );
}
