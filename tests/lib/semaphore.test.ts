import { describe, expect, it } from "vitest";
import { createSemaphore } from "../../src/lib/semaphore.js";

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

const flush = () => new Promise<void>((r) => setImmediate(r));

describe("createSemaphore", () => {
  it.each([0, -1, 1.5, Number.NaN])(
    "rejects a non-positive-integer size (%p)",
    (size) => {
      expect(() => createSemaphore(size)).toThrow(/positive integer/);
    },
  );

  it.each([1, 2, 3])(
    "admits at most max=%i and queues the rest (FIFO)",
    async (max) => {
      const sem = createSemaphore(max);
      const total = max + 2;
      const gates = Array.from({ length: total }, deferred);
      const order: number[] = [];
      let active = 0;
      let peak = 0;
      const tasks = gates.map((g, i) =>
        sem.run(async () => {
          active++;
          peak = Math.max(peak, active);
          order.push(i);
          await g.promise;
          active--;
        }),
      );

      await flush();
      // Exactly `max` admitted; the first `max` in submission order.
      expect(active).toBe(max);
      expect(order).toEqual([...Array(max).keys()]);

      // Releasing one admits exactly one more, in order.
      const [first] = gates;
      first?.resolve();
      await flush();
      expect(active).toBe(max);
      expect(order).toEqual([...Array(max + 1).keys()]);

      for (const g of gates) g.resolve();
      await Promise.all(tasks);
      expect(peak).toBe(max);
    },
  );

  it("releases the slot when a task throws", async () => {
    const sem = createSemaphore(1);
    await expect(
      sem.run(async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    // If the failed run hadn't released, this would deadlock.
    await expect(sem.run(async () => 42)).resolves.toBe(42);
  });

  it("returns the wrapped function's value", async () => {
    const sem = createSemaphore(2);
    await expect(sem.run(async () => "ok")).resolves.toBe("ok");
  });
});
