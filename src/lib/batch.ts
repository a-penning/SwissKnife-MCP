import { toMessage } from "./errors.js";
/**
 * Shared batch envelope pattern.
 *
 * Tools that accept an array for their primary input return
 * `{ results: [...], failures: [...] }` with per-item isolation: a single
 * bad item lands in `failures` while the rest still produce `results`.
 * `failures` is always present (empty array when nothing failed) so callers
 * never have to defensively check for the key.
 */

export interface BatchFailure<V> {
  index: number;
  value: V;
  error: string;
}

export interface BatchResult<R, V> {
  results: R[];
  failures: BatchFailure<V>[];
}

export function batchProcess<V, R>(
  items: V[],
  fn: (value: V, index: number) => R,
): BatchResult<R, V> {
  const results: R[] = [];
  const failures: BatchFailure<V>[] = [];
  items.forEach((value, index) => {
    try {
      results.push(fn(value, index));
    } catch (e) {
      failures.push({ index, value, error: toMessage(e) });
    }
  });
  return { results, failures };
}

export async function batchProcessAsync<V, R>(
  items: V[],
  fn: (value: V, index: number) => Promise<R>,
): Promise<BatchResult<R, V>> {
  const settled = await Promise.all(
    items.map(async (value, index) => {
      try {
        return {
          ok: true as const,
          value,
          index,
          result: await fn(value, index),
        };
      } catch (e) {
        return { ok: false as const, value, index, error: toMessage(e) };
      }
    }),
  );
  const results: R[] = [];
  const failures: BatchFailure<V>[] = [];
  for (const entry of settled) {
    if (entry.ok) results.push(entry.result);
    else
      failures.push({
        index: entry.index,
        value: entry.value,
        error: entry.error,
      });
  }
  return { results, failures };
}
