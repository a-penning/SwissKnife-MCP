/**
 * Minimal FIFO concurrency limiter. `script` (a 64 MiB QuickJS VM) and `regex`
 * (a worker thread) are the two tools whose per-call cost is unbounded enough
 * that N simultaneous invocations can exhaust memory or CPU. Wrapping each in a
 * semaphore caps the worst case to `max × per-run cost` without changing any
 * tool's observable behaviour — excess calls queue rather than fail.
 */
export interface Semaphore {
  run<T>(fn: () => Promise<T>): Promise<T>;
}

export function createSemaphore(max: number): Semaphore {
  if (!Number.isInteger(max) || max < 1) {
    throw new Error(`semaphore size must be a positive integer, got ${max}`);
  }
  let active = 0;
  const waiters: Array<() => void> = [];

  function release(): void {
    active--;
    const next = waiters.shift();
    if (next) next();
  }

  return {
    async run<T>(fn: () => Promise<T>): Promise<T> {
      if (active >= max) {
        await new Promise<void>((resolve) => waiters.push(resolve));
      }
      active++;
      try {
        return await fn();
      } finally {
        release();
      }
    },
  };
}

/** Concurrency cap for the `script` and `regex` tools. Override via env; min 1. */
const DEFAULT_MAX_CONCURRENT = 4;

export function maxConcurrentFromEnv(): number {
  const raw = process.env.SWISSKNIFE_MAX_CONCURRENT_VM;
  if (raw === undefined || raw === "") return DEFAULT_MAX_CONCURRENT;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 1 ? n : DEFAULT_MAX_CONCURRENT;
}
