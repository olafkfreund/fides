import { useCallback, useRef, useState } from "react";
import { apiListPage, type ListPage } from "./api";

export function usePagedList<T>() {
  const [items, setItems] = useState<T[]>([]);
  const [next, setNext] = useState<URL | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const request = useRef(0);
  const seen = useRef(new Set<string>());

  const read = useCallback(async (path: string | URL, stopAt?: (item: T) => boolean) => {
    const id = ++request.current;
    const first = typeof path === "string";
    if (first) {
      seen.current = new Set();
      setItems([]);
      setNext(null);
    }
    const visited = seen.current;
    setLoading(true);
    setError("");
    try {
      const loaded: T[] = [];
      let page: string | URL | null = path;
      do {
        const result: ListPage<T> = await apiListPage<T>(page, visited);
        if (id !== request.current) return;
        loaded.push(...result.items);
        page = result.next;
        if (!stopAt || result.items.some(stopAt)) break;
      } while (page);
      setItems((prev) => first ? loaded : [...prev, ...loaded]);
      setNext(page);
      return loaded;
    } catch (e) {
      if (id === request.current) setError(String((e as Error).message || e));
    } finally {
      if (id === request.current) setLoading(false);
    }
  }, []);

  return { items, next, loading, error, load: read, more: () => {
    if (next && !loading) return read(next);
  } };
}
